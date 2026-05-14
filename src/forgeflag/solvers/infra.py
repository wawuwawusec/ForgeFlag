from __future__ import annotations

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.solvers.base import SolverContext


class InfraSolver:
    name = "InfraSolver"
    supported_categories = {ChallengeCategory.INFRA}

    def solve(self, context: SolverContext) -> SolverResult:
        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Infrastructure lab solver placeholder registered",
            evidence={"boundary": "authorized CTF lab networks only", "planned_adapters": ["nmap", "service probes", "credential graph"]},
            hypothesis="Future implementation should map lab assets, evidence, and privilege boundaries without persistence.",
            confidence=0.35,
            next_action="Implement scoped asset inventory and credential/evidence graphing.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))

