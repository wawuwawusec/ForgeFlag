from __future__ import annotations

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.solvers.base import SolverContext


class ReverseSolver:
    name = "ReverseSolver"
    supported_categories = {ChallengeCategory.REVERSE}

    def solve(self, context: SolverContext) -> SolverResult:
        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Reverse solver placeholder registered",
            evidence={"planned_adapters": ["strings", "r2", "ghidra-headless", "z3"]},
            hypothesis="Future implementation should recover constraints and produce solve scripts.",
            confidence=0.4,
            next_action="Implement static triage and constraint note extraction.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))

