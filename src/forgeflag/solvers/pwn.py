from __future__ import annotations

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.solvers.base import SolverContext


class PwnSolver:
    name = "PwnSolver"
    supported_categories = {ChallengeCategory.PWN}

    def solve(self, context: SolverContext) -> SolverResult:
        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Pwn solver placeholder registered",
            evidence={"planned_adapters": ["checksec", "gdb", "pwntools", "ropper"]},
            hypothesis="Future implementation should reproduce crashes and generate exploit workspaces.",
            confidence=0.4,
            next_action="Implement binary triage and crash reproduction harness.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))

