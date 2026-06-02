from __future__ import annotations

import json
from pathlib import Path
import re

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

        if context.challenge.attachment_paths:
            return self._solve_with_local_tools(context)

        if context.challenge.target:
            return self._solve_with_service_interaction(context)

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

    def _solve_with_service_interaction(self, context: SolverContext) -> SolverResult:
        result = ctf.tcp_interact(context.challenge.target or "", scope=context.scope)
        context.notebook.add_tool_result(context.challenge.challenge_id, result)
        transcript = str(result.raw.get("transcript", ""))
        flags = extract_flags(transcript)
        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Interacted with scoped pwn service",
            evidence={
                "target": context.challenge.target,
                "tool_status": result.status,
                "transcript": transcript[:1000],
                "flag_candidates": list(flags),
            },
            hypothesis=_service_hypothesis(result.status, flags),
            confidence=0.78 if flags else (0.55 if result.status == "success" else 0.25),
            next_action=_service_next_action(result.status, flags),
        )
        context.notebook.add_finding(finding)
        return SolverResult(
            self.name,
            context.challenge.challenge_id,
            "flag_candidate" if flags else result.status,
            (finding,),
            flags,
        )

    def _solve_with_local_tools(self, context: SolverContext) -> SolverResult:
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
                    hypothesis="The binary attachment must exist before local pwn triage can run.",
                    confidence=0.2,
                    next_action="Check the attachment path and rerun.",
                )
                context.notebook.add_finding(finding)
                findings.append(finding)
                continue

            source_finding = _source_vulnerability_finding(context, resolved)
            if source_finding:
                context.notebook.add_finding(source_finding)
                findings.append(source_finding)
                continue

            labeled_results = [
                ("file_identify", ctf.file_identify(resolved, context.scope)),
                ("strings_extract", ctf.strings_extract(resolved, min_length=4, scope=context.scope)),
                ("checksec_binary", ctf.checksec_binary(resolved, context.scope)),
                ("ropgadget_scan", ctf.ropgadget_scan(resolved, scope=context.scope)),
                ("ropper_scan", ctf.ropper_scan(resolved, scope=context.scope)),
            ]
            for _, result in labeled_results:
                context.notebook.add_tool_result(context.challenge.challenge_id, result)

            flags = _tool_result_flags(labeled_results)
            flag_candidates.extend(flags)
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed pwn binary artifact",
                evidence={
                    "artifact": resolved,
                    "tool_statuses": {label: result.status for label, result in labeled_results},
                    "tool_samples": {label: _tool_sample(result) for label, result in labeled_results},
                    "flag_candidates": list(flags),
                },
                hypothesis=_local_hypothesis(flags),
                confidence=0.78 if flags else 0.6,
                next_action=_local_next_action(flags),
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


def _tool_result_flags(labeled_results) -> tuple[str, ...]:
    haystack = "\n".join(
        str(result.raw.get("stdout", "")) + "\n" + str(result.raw.get("stderr", ""))
        for _, result in labeled_results
    )
    return extract_flags(haystack)


def _tool_sample(result) -> dict[str, str]:
    stdout = str(result.raw.get("stdout", ""))
    stderr = str(result.raw.get("stderr", ""))
    return {"stdout": stdout[:500], "stderr": stderr[:500]}


def _source_vulnerability_finding(context: SolverContext, resolved: str) -> Finding | None:
    path = Path(resolved)
    if path.suffix.lower() not in {".c", ".cc", ".cpp", ".h", ".hpp"}:
        return None
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    if not _has_format_string_sink(source):
        return None
    return Finding(
        challenge_id=context.challenge.challenge_id,
        solver=PwnSolver.name,
        finding="Identified pwn source vulnerability pattern",
        evidence={
            "artifact": resolved,
            "pattern": "format string",
            "dangerous_calls": ["printf"],
            "source_sample": "\n".join(_matching_source_lines(source, ("printf", "fgets", "scanf"))),
        },
        hypothesis="User-controlled data appears to reach printf as the format argument, which is a format string vulnerability.",
        confidence=0.74,
        next_action="Build a pwntools harness, find the stack offset with %p probes, then plan leak/write primitives against the provided binary or service.",
    )


def _has_format_string_sink(source: str) -> bool:
    return bool(re.search(r"\bprintf\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)", source))


def _matching_source_lines(source: str, terms: tuple[str, ...], limit: int = 8) -> list[str]:
    lines: list[str] = []
    lowered_terms = tuple(term.lower() for term in terms)
    for line in source.splitlines():
        if any(term in line.lower() for term in lowered_terms):
            lines.append(line.strip()[:220])
        if len(lines) >= limit:
            break
    return lines


def _local_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "Local binary triage surfaced a flag-like token that should be verified."
    return "Local pwn triage collected file type, strings, hardening, and gadget-tool availability."


def _local_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send candidates to Verifier and preserve local tool outputs as replay evidence."
    return "Use checksec results to choose exploit strategy, then generate a pwntools workspace."


def _service_hypothesis(status: str, flags: tuple[str, ...]) -> str:
    if flags:
        return "A scoped TCP service interaction returned a flag-like token in the initial transcript."
    if status == "success":
        return "The service is reachable and produced a transcript suitable for pwntools follow-up."
    return "The scoped service interaction did not complete, so exploit workflow needs target or scope correction."


def _service_next_action(status: str, flags: tuple[str, ...]) -> str:
    if flags:
        return "Send candidates to Verifier and preserve the TCP transcript as replay evidence."
    if status == "success":
        return "Use the transcript to build a minimal pwntools harness with expected prompts and payload steps."
    return "Check target host/port and active probe scope before retrying service interaction."


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
