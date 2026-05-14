from __future__ import annotations

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.solvers.base import SolverContext


class CryptoSolver:
    name = "CryptoSolver"
    supported_categories = {ChallengeCategory.CRYPTO}

    def solve(self, context: SolverContext) -> SolverResult:
        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Crypto solver placeholder registered",
            evidence={"planned_adapters": ["z3", "sage", "hash/fingerprint classifiers"]},
            hypothesis="Future implementation should extract parameters and generate reproducible solve scripts.",
            confidence=0.4,
            next_action="Implement primitive fingerprinting and solver script workspace.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))

