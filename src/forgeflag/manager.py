from __future__ import annotations

from forgeflag.domain import ChallengeCategory, RunConfig
from forgeflag.harness import Harness
from forgeflag.ida import IDAAdapter, build_ida_adapter
from forgeflag.llm import UnavailableLLMProvider, build_llm_provider
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
            selected = self._apply_llm_solver_plan(selected, index + 1, self.notebook.observations_for(challenge_id))
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
        self.notebook.record_run(challenge_id, status, summary)
        return summary

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
    ) -> list[Solver]:
        requested = []
        for observation in observations:
            if observation.kind != "llm_solver_plan":
                continue
            suggested = observation.evidence.get("suggested_solvers")
            if isinstance(suggested, list):
                requested.extend(name for name in suggested if isinstance(name, str))
        if not requested:
            return selected

        by_name = {solver.name: solver for solver in self.solvers}
        result = list(selected)
        insert_at = insertion_index
        existing_names = {solver.name for solver in result}
        for solver_name in requested:
            solver = by_name.get(solver_name)
            if solver is None or solver.name in existing_names:
                continue
            result.insert(insert_at, solver)
            existing_names.add(solver.name)
            insert_at += 1
        return result
