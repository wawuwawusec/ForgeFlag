from __future__ import annotations

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.solvers.base import SolverContext
from forgeflag.tools.http_probe import HttpProbeTool
from forgeflag.web_analysis import HtmlSummary, summarize_html


class WebSolver:
    name = "WebSolver"
    supported_categories = {ChallengeCategory.WEB, ChallengeCategory.UNKNOWN}

    def solve(self, context: SolverContext) -> SolverResult:
        challenge = context.challenge
        findings: list[Finding] = []
        flag_candidates: list[str] = []
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
            next_action="Probe the scoped HTTP target and parse visible HTML structure.",
        )
        context.notebook.add_finding(finding)
        findings.append(finding)

        if not challenge.target or not challenge.target.startswith(("http://", "https://")):
            return SolverResult(
                solver=self.name,
                challenge_id=challenge.challenge_id,
                status="no_http_target",
                findings=tuple(findings),
            )

        if not context.scope.active_probe:
            inactive = Finding(
                challenge_id=challenge.challenge_id,
                solver=self.name,
                finding="Skipped HTTP analysis because active probing is disabled",
                evidence={"target": challenge.target},
                hypothesis="Enable --active-probe with --allow-host for authorized challenge targets.",
                confidence=0.5,
                next_action="Rerun with explicit scope if this is an authorized CTF target.",
            )
            context.notebook.add_finding(inactive)
            findings.append(inactive)
            return SolverResult(
                solver=self.name,
                challenge_id=challenge.challenge_id,
                status="scope_required",
                findings=tuple(findings),
            )

        tool_result = HttpProbeTool(context.scope).run(challenge.target)
        context.notebook.add_tool_result(challenge.challenge_id, tool_result)
        sample = str(tool_result.raw.get("sample", ""))
        flags = extract_flags(sample)
        flag_candidates.extend(flags)

        html = summarize_html(sample)
        analysis = Finding(
            challenge_id=challenge.challenge_id,
            solver=self.name,
            finding="Analyzed scoped HTTP response structure",
            evidence={
                "target": challenge.target,
                "tool_status": tool_result.status,
                "tool_evidence": tool_result.evidence,
                "html": html.as_evidence(),
                "flag_candidates": list(flags),
            },
            hypothesis=_web_hypothesis(html, flags),
            confidence=0.82 if tool_result.status == "success" else 0.35,
            next_action=_next_action(html, flags),
        )
        context.notebook.add_finding(analysis)
        findings.append(analysis)

        return SolverResult(
            solver=self.name,
            challenge_id=challenge.challenge_id,
            status="flag_candidate" if flags else "ok",
            findings=tuple(findings),
            flag_candidates=tuple(flag_candidates),
        )


def _web_hypothesis(html: HtmlSummary, flags: tuple[str, ...]) -> str:
    if flags:
        return "The first scoped response contains a flag-like token that should be verified."
    if html.forms:
        return "The target exposes forms; auth, parameter handling, and route behavior are likely relevant."
    if html.links:
        return "The target exposes links; route mapping is the next useful step."
    return "The target responded, but visible HTML structure is sparse."


def _next_action(html: HtmlSummary, flags: tuple[str, ...]) -> str:
    if flags:
        return "Send candidates to Verifier and record the minimal reproduction path."
    if html.forms:
        return "Add scoped form request capture and low-risk parameter analysis."
    if html.links:
        return "Add route queueing with same-host scope checks."
    return "Capture headers and expand content-type specific analyzers."
