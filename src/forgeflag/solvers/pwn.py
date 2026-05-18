from __future__ import annotations

import json

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.ida import DisabledIDAAdapter, IDAAdapter, IDAAnalysis
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf


class PwnSolver:
    name = "PwnSolver"
    supported_categories = {ChallengeCategory.PWN}

    def __init__(self, ida_adapter: IDAAdapter | None = None) -> None:
        self.ida_adapter = ida_adapter or DisabledIDAAdapter()

    def solve(self, context: SolverContext) -> SolverResult:
        if self.ida_adapter.enabled and context.challenge.attachment_paths:
            return self._solve_with_ida(context)

        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Pwn solver placeholder registered",
            evidence={"planned_adapters": ["checksec", "ida-mcp", "gdb", "pwntools", "ropper"]},
            hypothesis="Future implementation should reproduce crashes and generate exploit workspaces.",
            confidence=0.4,
            next_action="Implement binary triage and crash reproduction harness.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))

    def _solve_with_ida(self, context: SolverContext) -> SolverResult:
        findings: list[Finding] = []
        flag_candidates: list[str] = []

        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = ctf.ensure_existing_file(attachment_path)
            except FileNotFoundError as exc:
                finding = Finding(
                    challenge_id=context.challenge.challenge_id,
                    solver=self.name,
                    finding="Pwn attachment unavailable",
                    evidence={"attachment_path": attachment_path, "error": str(exc)},
                    hypothesis="The binary attachment must exist before IDA MCP analysis can run.",
                    confidence=0.2,
                    next_action="Check the attachment path and rerun.",
                )
                context.notebook.add_finding(finding)
                findings.append(finding)
                continue

            analysis = self.ida_adapter.analyze_binary(resolved, mode="pwn")
            flags = _analysis_flags(analysis)
            flag_candidates.extend(flags)
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed pwn binary with IDA MCP",
                evidence={
                    "artifact": resolved,
                    "ida_mcp": _analysis_evidence(analysis),
                    "flag_candidates": list(flags),
                },
                hypothesis=_hypothesis(analysis, flags),
                confidence=0.82 if flags else 0.66,
                next_action=_next_action(flags),
            )
            context.notebook.add_finding(finding)
            findings.append(finding)

        return SolverResult(
            self.name,
            context.challenge.challenge_id,
            "flag_candidate" if flag_candidates else "ok",
            tuple(findings),
            tuple(dict.fromkeys(flag_candidates)),
        )


def _analysis_evidence(analysis: IDAAnalysis) -> dict[str, object]:
    return {
        "status": analysis.status,
        "function_names": list(analysis.function_names),
        "strings": list(analysis.strings[:30]),
        "tool_calls": [
            {"name": call.name, "status": call.status, "evidence": call.evidence} for call in analysis.tool_calls
        ],
        "notes": analysis.notes,
    }


def _analysis_flags(analysis: IDAAnalysis) -> tuple[str, ...]:
    haystack = "\n".join(analysis.strings) + "\n" + json.dumps(_analysis_evidence(analysis), ensure_ascii=False)
    return extract_flags(haystack)


def _hypothesis(analysis: IDAAnalysis, flags: tuple[str, ...]) -> str:
    if flags:
        return "IDA MCP analysis surfaced a flag-like token that should be verified."
    if analysis.function_names:
        return "IDA MCP identified pwn-relevant functions for input-flow and vulnerability triage."
    return "IDA MCP was configured, but did not return enough binary analysis evidence."


def _next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send candidates to Verifier and preserve IDA MCP tool outputs as replay evidence."
    return "Pivot into checksec, dangerous function callers, decompiled input paths, and exploit harness setup."
