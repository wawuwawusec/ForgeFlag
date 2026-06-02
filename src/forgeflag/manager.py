from __future__ import annotations

from forgeflag.domain import ChallengeCategory, Observation, RunConfig
from forgeflag.harness import Harness
from forgeflag.ida import IDAAdapter, build_ida_adapter
from forgeflag.llm import UnavailableLLMProvider, build_llm_provider
from forgeflag.llm_critic import build_post_run_critic_observation
from forgeflag.notebook import SQLiteNotebook
from forgeflag.observer import Observer
from forgeflag.report import ReportBuilder
from forgeflag.safety import ScopePolicy
from forgeflag.solvers import (
    CryptoSolver,
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
    ) -> None:
        self.notebook = notebook
        self.config = config or RunConfig()
        self.ida_adapter = ida_adapter or build_ida_adapter(self.config.ida_mcp_config)
        self.solvers = solvers or self._default_solvers()
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
        return solvers

    def run_challenge(self, challenge_id: str) -> dict[str, object]:
        challenge = self.notebook.get_challenge(challenge_id)
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
        status = "flag_found" if verification.accepted else "completed"
        summary = {
            "challenge_id": challenge_id,
            "status": status,
            "solvers": solver_results,
            "accepted_flags": list(verification.accepted),
            "rejected_flags": list(verification.rejected),
            "observations": len(self.notebook.observations_for(challenge_id)),
            "harness": harness.summary(),
        }
        if verification.accepted:
            summary["replay_report"] = self.report_builder.build(
                challenge_id,
                verification.accepted,
                findings,
                self.notebook.observations_for(challenge_id),
                challenge=challenge,
            )
        else:
            critic = self._post_run_critic(challenge, summary, findings)
            if critic is not None:
                self.notebook.add_observation(critic)
                summary["post_run_critic"] = critic.evidence
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
                return solver.provider
        try:
            provider = build_llm_provider(self.config.llm_config)
        except ValueError:
            return None
        return provider if provider.enabled else None

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
        return selected

    def _apply_llm_solver_plan(
        self,
        selected: list[Solver],
        insertion_index: int,
        observations,
        challenge_id: str,
    ) -> tuple[list[Solver], Observation | None]:
        requested = []
        next_actions = []
        tool_hints = []
        for observation in observations:
            if observation.kind != "llm_solver_plan":
                continue
            suggested = observation.evidence.get("suggested_solvers")
            if isinstance(suggested, list):
                requested.extend(name for name in suggested if isinstance(name, str))
            actions = observation.evidence.get("next_actions")
            if isinstance(actions, list):
                next_actions.extend(action for action in actions if isinstance(action, str))
            hints = observation.evidence.get("tool_hints")
            if isinstance(hints, list):
                tool_hints.extend(hint for hint in hints if isinstance(hint, str))
        if not requested:
            return selected, None

        by_name = {solver.name: solver for solver in self.solvers}
        result = list(selected)
        insert_at = insertion_index
        existing_names = {solver.name for solver in result}
        requested_solvers = _dedupe(requested)
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
            else "LLM solver plan did not change the current solver queue"
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
