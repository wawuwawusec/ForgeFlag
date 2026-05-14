from __future__ import annotations

from forgeflag.domain import ChallengeCategory, RunConfig
from forgeflag.harness import Harness
from forgeflag.notebook import SQLiteNotebook
from forgeflag.safety import ScopePolicy
from forgeflag.solvers import (
    CryptoSolver,
    ForensicsSolver,
    InfraSolver,
    MiscSolver,
    PwnSolver,
    ReconSolver,
    ReverseSolver,
    Solver,
    SolverContext,
    WebSolver,
)
from forgeflag.verifier import Verifier


class Manager:
    def __init__(
        self,
        notebook: SQLiteNotebook,
        config: RunConfig | None = None,
        solvers: list[Solver] | None = None,
    ) -> None:
        self.notebook = notebook
        self.config = config or RunConfig()
        self.solvers = solvers or [
            ReconSolver(),
            WebSolver(),
            CryptoSolver(),
            ReverseSolver(),
            PwnSolver(),
            ForensicsSolver(),
            MiscSolver(),
            InfraSolver(),
        ]
        self.verifier = Verifier()

    def run_challenge(self, challenge_id: str) -> dict[str, object]:
        challenge = self.notebook.get_challenge(challenge_id)
        harness = Harness(self.config)
        scope = ScopePolicy(
            allowed_hosts=self.config.allowed_hosts,
            active_probe=self.config.active_probe,
        )
        context = SolverContext(challenge=challenge, notebook=self.notebook, scope=scope)

        selected = self._select_solvers(challenge.category)
        solver_results = []
        flag_candidates: list[str] = []

        for solver in selected:
            decision = harness.before_solver(solver.name)
            if not decision.allowed:
                solver_results.append({"solver": solver.name, "status": "skipped", "reason": decision.reason})
                continue
            result = solver.solve(context)
            harness.after_solver(solver.name)
            solver_results.append({"solver": result.solver, "status": result.status, "findings": len(result.findings)})
            flag_candidates.extend(result.flag_candidates)

        findings = self.notebook.findings_for(challenge_id)
        verification = self.verifier.verify(findings, tuple(flag_candidates))
        status = "flag_found" if verification.accepted else "completed"
        summary = {
            "challenge_id": challenge_id,
            "status": status,
            "solvers": solver_results,
            "accepted_flags": list(verification.accepted),
            "rejected_flags": list(verification.rejected),
            "harness": harness.summary(),
        }
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
