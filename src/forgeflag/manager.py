from __future__ import annotations

from typing import Any

from forgeflag.agent_roster import AgentRoster, load_agent_roster, agent_roster_path_for_db
from forgeflag.domain import ChallengeCategory, Observation, RunConfig
from forgeflag.harness import Harness
from forgeflag.ida import IDAAdapter, build_ida_adapter
from forgeflag.llm import TokenLedger, TrackingLLMProvider, UnavailableLLMProvider, build_llm_provider
from forgeflag.llm_critic import build_post_run_critic_observation
from forgeflag.notebook import SQLiteNotebook
from forgeflag.observer import Observer
from forgeflag.report import ReportBuilder
from forgeflag.reviewer import ReviewerAgent, reviewer_observation
from forgeflag.safety import ScopePolicy
from forgeflag.solvers import (
    CryptoSolver,
    LLMExecuteSolver,
    ForensicsSolver,
    InfraSolver,
    LLMSolver,
    MiscSolver,
    PwnSolver,
    ReconSolver,
    ReverseSolver,
    Solver,
    SolverContext,
    TrafficSolver,
    WebSolver,
)
from forgeflag.trace import build_solve_trace_step
from forgeflag.verifier import Verifier


class Manager:
    def __init__(
        self,
        notebook: SQLiteNotebook,
        config: RunConfig | None = None,
        solvers: list[Solver] | None = None,
        ida_adapter: IDAAdapter | None = None,
        agent_roster: AgentRoster | None = None,
    ) -> None:
        self.notebook = notebook
        self.config = config or RunConfig()
        self.ida_adapter = ida_adapter or build_ida_adapter(self.config.ida_mcp_config)
        self.solvers = solvers or self._default_solvers()
        self.token_ledger = TokenLedger()
        self._instrument_llm_providers()
        self.agent_roster = agent_roster or load_agent_roster(agent_roster_path_for_db(notebook.path))
        self.verifier = Verifier()
        self.observer = Observer()
        self.report_builder = ReportBuilder()

    def _default_solvers(self) -> list[Solver]:
        solvers: list[Solver] = [ReconSolver()]
        try:
            llm_provider = build_llm_provider(self.config.llm_config)
        except ValueError as exc:
            llm_provider = UnavailableLLMProvider(
                self.config.llm_config.provider,
                self.config.llm_config.model,
                str(exc),
            )
        if llm_provider.enabled:
            solvers.append(LLMSolver(llm_provider))
        solvers.extend(
            [
                WebSolver(),
                CryptoSolver(),
                ReverseSolver(self.ida_adapter),
                PwnSolver(self.ida_adapter),
                ForensicsSolver(),
                TrafficSolver(),
                MiscSolver(),
                InfraSolver(),
            ]
        )
        if llm_provider.enabled:
            # execution solver runs last so every deterministic solver's
            # findings are already in the notebook as prior evidence
            solvers.append(LLMExecuteSolver(llm_provider))
        return solvers

    def _instrument_llm_providers(self) -> None:
        """Wrap every LLM-backed solver provider so token usage lands in the ledger."""
        for solver in self.solvers:
            if not isinstance(solver, (LLMSolver, LLMExecuteSolver)):
                continue
            if not isinstance(solver.provider, TrackingLLMProvider):
                solver.provider = TrackingLLMProvider(solver.provider, self.token_ledger, source="solver")

    def run_challenge(self, challenge_id: str) -> dict[str, object]:
        challenge = self.notebook.get_challenge(challenge_id)
        self.token_ledger.begin(challenge_id)
        harness = Harness(self.config)
        scope = ScopePolicy(
            allowed_hosts=self.config.allowed_hosts,
            active_probe=self.config.active_probe,
        )
        selected = self._select_solvers(challenge.category)
        solver_results = []
        flag_candidates: list[str] = []

        index = 0
        while index < len(selected):
            solver = selected[index]
            decision = harness.before_solver(solver.name)
            if not decision.allowed:
                solver_results.append({"solver": solver.name, "status": "skipped", "reason": decision.reason})
                index += 1
                continue
            context = SolverContext(
                challenge=challenge,
                notebook=self.notebook,
                scope=scope,
                observations=tuple(self.notebook.observations_for(challenge_id)),
            )
            result = solver.solve(context)
            harness.after_solver(solver.name)
            solver_results.append({"solver": result.solver, "status": result.status, "findings": len(result.findings)})
            flag_candidates.extend(result.flag_candidates)
            for observation in self.observer.observe_solver_result(
                challenge_id,
                result.solver,
                result.findings,
                result.flag_candidates,
            ):
                self.notebook.add_observation(observation)
            self.notebook.add_observation(
                build_solve_trace_step(
                    challenge_id,
                    index + 1,
                    result,
                    context.observations,
                )
            )
            if result.solver == "LLMSolver":
                selected, action_observation = self._apply_llm_solver_plan(
                    selected,
                    index + 1,
                    self.notebook.observations_for(challenge_id),
                    challenge_id,
                )
                if action_observation is not None:
                    self.notebook.add_observation(action_observation)
            index += 1

        findings = self.notebook.findings_for(challenge_id)
        verification = self.verifier.verify(findings, tuple(flag_candidates))
        proof = _proof_status(challenge.category, findings, tuple(verification.accepted))
        status = str(proof["status"])
        roster_solver_names = [solver.name for solver in selected]
        roster_solver_names.append("Verifier")
        has_replay_material = bool(verification.accepted) or _has_pwn_exploit_plan(findings)
        if has_replay_material:
            roster_solver_names.append("ReportBuilder")
        summary = {
            "challenge_id": challenge_id,
            "status": status,
            "solvers": solver_results,
            "agent_roster": self.agent_roster.to_run_summary(
                challenge.category,
                tuple(roster_solver_names),
            ),
            "accepted_flags": list(verification.accepted),
            "rejected_flags": list(verification.rejected),
            "proof_status": proof["status"],
            "proof": proof,
            "observations": len(self.notebook.observations_for(challenge_id)),
            "harness": harness.summary(),
            "llm_status": _llm_status(self.config, solver_results, findings),
        }
        if has_replay_material:
            summary["replay_report"] = self.report_builder.build(
                challenge_id,
                verification.accepted,
                findings,
                self.notebook.observations_for(challenge_id),
                challenge=challenge,
            )
        if not verification.accepted and _ran_non_llm_solver(summary.get("solvers")):
            critic = self._post_run_critic(challenge, summary, findings)
            if critic is not None:
                self.notebook.add_observation(critic)
                summary["post_run_critic"] = critic.evidence
            reviewer_provider = self._critic_provider()
            verdict = ReviewerAgent(reviewer_provider).review_challenge(self.notebook, challenge_id)
            self.notebook.add_observation(reviewer_observation(verdict))
            summary["reviewer"] = {
                "quality": verdict.quality,
                "issues": verdict.issues,
                "reflection_hint": verdict.reflection_hint,
            }
        token_usage = self.token_ledger.summary_for(challenge_id)
        if token_usage["calls"]:
            summary["token_usage"] = token_usage
            self.notebook.add_observation(
                Observation(
                    challenge_id=challenge_id,
                    source="Manager",
                    kind="token_usage",
                    summary=(
                        f"LLM token usage: {token_usage['total_tokens']} tokens "
                        f"across {token_usage['calls']} call(s) "
                        f"({token_usage['prompt_tokens']} prompt + {token_usage['completion_tokens']} completion)"
                    ),
                    evidence=token_usage,
                )
            )
        self.notebook.record_run(challenge_id, status, summary)
        return summary

    def _post_run_critic(
        self,
        challenge,
        summary: dict[str, object],
        findings,
    ) -> Observation | None:
        solver_rows = summary.get("solvers")
        if not _ran_non_llm_solver(solver_rows):
            return None
        provider = self._critic_provider()
        if provider is None:
            return None
        return build_post_run_critic_observation(
            challenge=challenge,
            provider=provider,
            run_summary=summary,
            findings=list(findings),
            observations=list(self.notebook.observations_for(challenge.challenge_id)),
        )

    def _critic_provider(self):
        for solver in self.solvers:
            if isinstance(solver, LLMSolver):
                provider = solver.provider
                if isinstance(provider, TrackingLLMProvider):
                    provider = provider.inner
                return TrackingLLMProvider(provider, self.token_ledger, source="critic")
        try:
            provider = build_llm_provider(self.config.llm_config)
        except ValueError:
            return None
        return TrackingLLMProvider(provider, self.token_ledger, source="critic") if provider.enabled else None

    def _select_solvers(self, category: ChallengeCategory) -> list[Solver]:
        selected: list[Solver] = []
        for solver in self.solvers:
            if isinstance(solver, ReconSolver):
                selected.append(solver)
                continue
            if category in solver.supported_categories:
                selected.append(solver)
        if category == ChallengeCategory.UNKNOWN:
            selected.extend(
                solver
                for solver in self.solvers
                if solver not in selected and ChallengeCategory.UNKNOWN in solver.supported_categories
            )
        return self._apply_roster_solver_order(category, selected)

    def _apply_roster_solver_order(self, category: ChallengeCategory, selected: list[Solver]) -> list[Solver]:
        roster_order = self.agent_roster.solver_names_for(category)
        managed_names = set(self.agent_roster.managed_solver_names())
        by_name = {solver.name: solver for solver in selected}
        ordered = [by_name[name] for name in roster_order if name in by_name]
        ordered_names = {solver.name for solver in ordered}
        passthrough = [
            solver
            for solver in selected
            if solver.name not in managed_names and solver.name not in ordered_names
        ]
        return ordered + passthrough

    def _apply_llm_solver_plan(
        self,
        selected: list[Solver],
        insertion_index: int,
        observations,
        challenge_id: str,
    ) -> tuple[list[Solver], Observation | None]:
        requested = []
        analysis_modes = []
        next_actions = []
        tool_hints = []
        artifact_requirements = []
        blocked_by_missing_artifacts = []
        manual_replay_needed = []
        risk_notes = []
        for observation in observations:
            if observation.kind != "llm_solver_plan":
                continue
            analysis_mode = observation.evidence.get("analysis_mode")
            if isinstance(analysis_mode, str):
                analysis_modes.append(analysis_mode)
            suggested = observation.evidence.get("suggested_solvers")
            if isinstance(suggested, list):
                requested.extend(name for name in suggested if isinstance(name, str))
            actions = observation.evidence.get("next_actions")
            if isinstance(actions, list):
                next_actions.extend(action for action in actions if isinstance(action, str))
            hints = observation.evidence.get("tool_hints")
            if isinstance(hints, list):
                tool_hints.extend(hint for hint in hints if isinstance(hint, str))
            requirements = observation.evidence.get("artifact_requirements")
            if isinstance(requirements, list):
                artifact_requirements.extend(item for item in requirements if isinstance(item, str))
            blocked = observation.evidence.get("blocked_by_missing_artifacts")
            if isinstance(blocked, list):
                blocked_by_missing_artifacts.extend(item for item in blocked if isinstance(item, str))
            manual = observation.evidence.get("manual_replay_needed")
            if isinstance(manual, list):
                manual_replay_needed.extend(item for item in manual if isinstance(item, str))
            risks = observation.evidence.get("risk_notes")
            if isinstance(risks, list):
                risk_notes.extend(item for item in risks if isinstance(item, str))

        requested_solvers = _dedupe(requested)
        guidance_available = any(
            (
                requested_solvers,
                analysis_modes,
                next_actions,
                tool_hints,
                artifact_requirements,
                blocked_by_missing_artifacts,
                manual_replay_needed,
                risk_notes,
            )
        )
        if not guidance_available:
            return selected, None

        by_name = {solver.name: solver for solver in self.solvers}
        result = list(selected)
        insert_at = insertion_index
        existing_names = {solver.name for solver in result}
        queued_solvers: list[str] = []
        already_present_solvers: list[str] = []
        unknown_solvers: list[str] = []
        for solver_name in requested_solvers:
            solver = by_name.get(solver_name)
            if solver is None:
                unknown_solvers.append(solver_name)
                continue
            if solver.name in existing_names:
                already_present_solvers.append(solver.name)
                continue
            result.insert(insert_at, solver)
            existing_names.add(solver.name)
            queued_solvers.append(solver.name)
            insert_at += 1
        summary = (
            f"LLM queued solver(s): {', '.join(queued_solvers)}"
            if queued_solvers
            else (
                "LLM solver plan did not change the current solver queue"
                if requested_solvers
                else "LLM provided manual guidance without changing the solver queue"
            )
        )
        return result, Observation(
            challenge_id=challenge_id,
            source="Manager",
            kind="llm_action_queue",
            summary=summary,
            evidence={
                "requested_solvers": requested_solvers,
                "queued_solvers": queued_solvers,
                "already_present_solvers": already_present_solvers,
                "unknown_solvers": unknown_solvers,
                "next_actions": _dedupe(next_actions),
                "tool_hints": _dedupe(tool_hints),
                "analysis_mode": _dedupe(analysis_modes)[0] if _dedupe(analysis_modes) else "",
                "artifact_requirements": _dedupe(artifact_requirements),
                "blocked_by_missing_artifacts": _dedupe(blocked_by_missing_artifacts),
                "manual_replay_needed": _dedupe(manual_replay_needed),
                "risk_notes": _dedupe(risk_notes),
            },
        )


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


def _ran_non_llm_solver(solver_rows: object) -> bool:
    if not isinstance(solver_rows, list):
        return False
    for row in solver_rows:
        if not isinstance(row, dict):
            continue
        if row.get("solver") != "LLMSolver" and row.get("status") != "skipped":
            return True
    return False


def _llm_status(config: RunConfig, solver_rows: object, findings: object) -> dict[str, object]:
    enabled = bool(config.llm_config.enabled)
    status = "disabled"
    row: dict[str, object] | None = None
    if isinstance(solver_rows, list):
        for candidate in solver_rows:
            if isinstance(candidate, dict) and candidate.get("solver") == "LLMSolver":
                row = candidate
                status = str(candidate.get("status") or "unknown")
                break
    if enabled and row is None:
        status = "not_run"

    error = ""
    if row is not None and isinstance(findings, list):
        for finding in findings:
            if getattr(finding, "solver", "") != "LLMSolver":
                continue
            evidence = getattr(finding, "evidence", {})
            if isinstance(evidence, dict):
                error = str(evidence.get("error") or "")
            break

    result: dict[str, object] = {
        "enabled": enabled,
        "status": status,
        "provider": config.llm_config.provider,
        "model": config.llm_config.model,
    }
    if error:
        result["error"] = error
    return result


def _has_pwn_exploit_plan(findings: object) -> bool:
    if not isinstance(findings, list):
        return False
    for finding in findings:
        if getattr(finding, "solver", "") != "PwnSolver":
            continue
        evidence = getattr(finding, "evidence", {})
        if isinstance(evidence, dict) and isinstance(evidence.get("exploit_plan"), dict):
            return True
    return False


def _proof_status(
    category: ChallengeCategory,
    findings: list[object],
    accepted_flags: tuple[str, ...],
) -> dict[str, Any]:
    if accepted_flags:
        return {
            "status": "flag_found",
            "label": "Flag verified",
            "verified": True,
            "summary": "Verifier accepted an evidence-backed flag candidate.",
            "accepted_flags": list(accepted_flags),
            "next_action": "Preserve replay steps and write the casebook/playbook note.",
        }
    if category != ChallengeCategory.PWN:
        return {
            "status": "completed",
            "label": "Analysis completed",
            "verified": False,
            "summary": "Solvers completed without an accepted flag.",
            "next_action": "Review findings, collect missing evidence, and rerun the most relevant solver.",
        }

    replay = _first_pwn_replay_proof(findings)
    if replay:
        return {
            "status": "exploit_verified",
            "label": "Exploit verified",
            "verified": True,
            "summary": "A bounded exploit replay demonstrated shell, command execution, or equivalent challenge control.",
            "evidence": replay,
            "next_action": "Preserve the transcript, environment details, and exploit command in the write-up.",
        }
    if _has_pwn_exploit_plan(findings):
        return {
            "status": "exploit_plan",
            "label": "Exploit plan only",
            "verified": False,
            "summary": "Exploit plan exists but no replay transcript has verified shell, command execution, or flag retrieval.",
            "next_action": "Run the exploit against the local or authorized CTF service and capture shell, command output, or flag evidence.",
            "required_evidence": [
                "exploit.py or exact pwntools command",
                "local or authorized target scope",
                "stdout transcript showing shell, command execution, or flag retrieval",
                "libc/environment details when relevant",
            ],
        }
    return {
        "status": "analysis_only",
        "label": "Analysis only",
        "verified": False,
        "summary": "Pwn triage ran, but no exploit plan or replay proof has been recorded yet.",
        "next_action": "Build a bounded proof-of-solve harness, reproduce the primitive, and capture replay evidence.",
    }


def _first_pwn_replay_proof(findings: list[object]) -> dict[str, Any] | None:
    for finding in findings:
        if getattr(finding, "solver", "") != "PwnSolver":
            continue
        evidence = getattr(finding, "evidence", {})
        if not isinstance(evidence, dict):
            continue
        for key in ("exploit_replay", "replay_proof", "proof"):
            proof = evidence.get(key)
            if _pwn_replay_verified(proof):
                return proof
    return None


def _pwn_replay_verified(proof: object) -> bool:
    if not isinstance(proof, dict):
        return False
    status = str(proof.get("status") or proof.get("result") or "").lower()
    if status in {"success", "verified", "shell", "command_executed", "flag_found"}:
        return True
    transcript = str(proof.get("transcript") or proof.get("stdout") or proof.get("output") or "").lower()
    return any(marker in transcript for marker in ("uid=", "gid=", "$ ", "# ", "forgeflag_pwned", "flag{"))
