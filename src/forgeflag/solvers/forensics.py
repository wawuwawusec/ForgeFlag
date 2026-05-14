from __future__ import annotations

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.solvers.base import SolverContext


class ForensicsSolver:
    name = "ForensicsSolver"
    supported_categories = {ChallengeCategory.FORENSICS}

    def solve(self, context: SolverContext) -> SolverResult:
        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Forensics solver placeholder registered",
            evidence={"planned_adapters": ["file", "binwalk", "exiftool", "tshark", "volatility"]},
            hypothesis="Future implementation should triage files and preserve artifacts.",
            confidence=0.4,
            next_action="Implement file triage and artifact extraction pipeline.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))

