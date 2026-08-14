"""Autonomous CTF auto-solve client.

Continuously runs the Manager over every unsolved challenge in the shared
notebook until each one reaches an evidence-backed solved state, retry
budgets are exhausted, or the operator stops the loop. Scope controls
(allowed hosts, active-probe intent) stay exactly as strict as the single
challenge `run` command.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from forgeflag.domain import RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook

SOLVED_STATUSES = frozenset({"flag_found", "exploit_verified"})


@dataclass
class AutoClientConfig:
    max_rounds: int = 10
    attempts_per_challenge: int = 2
    poll_interval_seconds: float = 5.0
    watch: bool = False


@dataclass
class ChallengeProgress:
    challenge_id: str
    attempts: int = 0
    status: str = "pending"
    accepted_flags: list[str] = field(default_factory=list)
    token_usage: dict[str, object] = field(default_factory=dict)


class AutoSolveClient:
    def __init__(
        self,
        notebook: SQLiteNotebook,
        run_config: RunConfig | None = None,
        config: AutoClientConfig | None = None,
        manager_factory: Callable[[SQLiteNotebook, RunConfig], Manager] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.notebook = notebook
        self.run_config = run_config or RunConfig()
        self.config = config or AutoClientConfig()
        self._manager_factory = manager_factory or (lambda nb, cfg: Manager(nb, config=cfg))
        self._sleep = sleep
        self.progress: dict[str, ChallengeProgress] = {}
        self._round = 0

    def pending_challenges(self) -> list[str]:
        pending = []
        for challenge in self.notebook.list_challenges():
            status = self.notebook.latest_run_status(challenge.challenge_id)
            if status in SOLVED_STATUSES:
                continue
            progress = self.progress.get(challenge.challenge_id)
            if progress is not None and progress.status in SOLVED_STATUSES:
                continue
            if progress is not None and progress.attempts >= self.config.attempts_per_challenge:
                continue
            pending.append(challenge.challenge_id)
        return pending

    def run_once(self) -> dict[str, object]:
        manager = self._manager_factory(self.notebook, self.run_config)
        results = []
        for challenge_id in self.pending_challenges():
            progress = self.progress.setdefault(challenge_id, ChallengeProgress(challenge_id))
            try:
                summary = manager.run_challenge(challenge_id)
            except KeyError:
                progress.status = "missing"
                results.append({"challenge_id": challenge_id, "status": "missing"})
                continue
            except Exception as exc:  # keep the autonomous loop alive on solver crashes
                progress.attempts += 1
                progress.status = "error"
                results.append(
                    {"challenge_id": challenge_id, "status": "error", "error": str(exc)}
                )
                continue
            progress.attempts += 1
            progress.status = str(summary.get("status") or "unknown")
            flags = summary.get("accepted_flags")
            progress.accepted_flags = list(flags) if isinstance(flags, list) else []
            usage = summary.get("token_usage")
            progress.token_usage = dict(usage) if isinstance(usage, dict) else {}
            results.append(
                {
                    "challenge_id": challenge_id,
                    "status": progress.status,
                    "attempts": progress.attempts,
                    "accepted_flags": progress.accepted_flags,
                    "token_usage": progress.token_usage,
                }
            )
        return {
            "round": self._round,
            "results": results,
            "remaining": self.pending_challenges(),
        }

    def run(self) -> dict[str, object]:
        """Run rounds until every challenge is solved, retries are exhausted, or limits hit.

        With ``watch`` enabled the loop keeps polling for newly added challenges
        instead of exiting once the current queue is drained.
        """
        self._round = 0
        rounds: list[dict[str, object]] = []
        stopped_reason = "completed"
        while True:
            self._round += 1
            rounds.append(self.run_once())
            remaining = self.pending_challenges()
            if remaining and self._round < self.config.max_rounds:
                continue
            if not remaining and not self.config.watch:
                break
            if self._round >= self.config.max_rounds:
                if remaining:
                    stopped_reason = "max_rounds_reached"
                elif self.config.watch:
                    stopped_reason = "max_rounds_reached"
                break
            # watch mode: nothing pending now, poll for new challenges
            self._sleep(self.config.poll_interval_seconds)
        return {
            "status": stopped_reason,
            "rounds_executed": len(rounds),
            "rounds": rounds,
            "progress": {
                challenge_id: {
                    "attempts": p.attempts,
                    "status": p.status,
                    "accepted_flags": p.accepted_flags,
                    "token_usage": p.token_usage,
                }
                for challenge_id, p in sorted(self.progress.items())
            },
            "token_usage": {
                "challenges_tracked": len(
                    [p for p in self.progress.values() if p.token_usage.get("calls")]
                ),
                "calls": sum(int(p.token_usage.get("calls") or 0) for p in self.progress.values()),
                "prompt_tokens": sum(int(p.token_usage.get("prompt_tokens") or 0) for p in self.progress.values()),
                "completion_tokens": sum(int(p.token_usage.get("completion_tokens") or 0) for p in self.progress.values()),
                "total_tokens": sum(int(p.token_usage.get("total_tokens") or 0) for p in self.progress.values()),
            },
            "unsolved": [
                challenge_id
                for challenge_id, p in sorted(self.progress.items())
                if p.status not in SOLVED_STATUSES | {"missing"}
            ],
        }
