from __future__ import annotations

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.solvers.base import SolverContext


class WebSolver:
    name = "WebSolver"
    supported_categories = {ChallengeCategory.WEB, ChallengeCategory.UNKNOWN}

    def solve(self, context: SolverContext) -> SolverResult:
        challenge = context.challenge
        checklist = [
            "map visible routes and forms",
            "identify auth/session boundaries",
            "test input handling only inside declared scope",
            "capture request/response evidence before flag submission",
        ]
        finding = Finding(
            challenge_id=challenge.challenge_id,
            solver=self.name,
            finding="Prepared scoped web challenge workflow",
            evidence={"target": challenge.target, "checklist": checklist},
            hypothesis="The challenge likely requires route, auth, or input-behavior analysis.",
            confidence=0.62,
            next_action="Add Playwright/HAR capture and route enumeration in the next milestone.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(
            solver=self.name,
            challenge_id=challenge.challenge_id,
            status="ok",
            findings=(finding,),
        )

