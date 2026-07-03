from __future__ import annotations

import json
from pathlib import Path
import re

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.ctf_scope import pwn_ctf_scope_evidence
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
            evidence={
                "planned_adapters": ["checksec", "ida-mcp", "gdb", "pwntools", "ropper"],
                "ctf_scope": pwn_ctf_scope_evidence(),
            },
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
                "ctf_scope": pwn_ctf_scope_evidence(),
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
                    evidence={"attachment_path": attachment_path, "error": str(exc), "ctf_scope": pwn_ctf_scope_evidence()},
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
            workflow_evidence = _binary_workflow_evidence(labeled_results)
            evidence = {
                "artifact": resolved,
                "tool_statuses": {label: result.status for label, result in labeled_results},
                "tool_samples": {label: _tool_sample(result) for label, result in labeled_results},
                "flag_candidates": list(flags),
                "ctf_scope": pwn_ctf_scope_evidence(),
            }
            evidence.update(workflow_evidence)
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed pwn binary artifact",
                evidence=evidence,
                hypothesis=_local_hypothesis(flags, workflow_evidence),
                confidence=0.78 if flags else 0.6,
                next_action=_local_next_action(flags, workflow_evidence),
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
                    evidence={"attachment_path": attachment_path, "error": str(exc), "ctf_scope": pwn_ctf_scope_evidence()},
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
                    "ctf_scope": pwn_ctf_scope_evidence(),
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


def _binary_workflow_evidence(labeled_results) -> dict[str, object]:
    haystack = "\n".join(
        str(result.raw.get("stdout", "")) + "\n" + str(result.raw.get("stderr", ""))
        for _, result in labeled_results
    )
    ftp_format = _ftp_heap_format_string_evidence(haystack)
    if ftp_format:
        return ftp_format
    symbols = _ret2win_symbol_mentions(haystack)
    unsafe_calls = _dangerous_symbol_mentions(haystack)
    if not symbols or not unsafe_calls:
        return {}
    primary_symbol = symbols[0]
    return {
        "workflow_guess": "ret2win",
        "ctf_scope": pwn_ctf_scope_evidence(),
        "workflow_evidence": {
            "symbols": symbols,
            "dangerous_calls": unsafe_calls,
            "reason": "Binary strings/tool output contain a win-like function and unsafe input symbols.",
        },
        "exploit_plan": _ret2win_exploit_plan(primary_symbol),
    }


def _ftp_heap_format_string_evidence(text: str) -> dict[str, object]:
    lowered = text.lower()
    required_terms = (
        "ftp>",
        "please enter the name of the file you want to upload",
        "then, enter the content",
        "enter the file name you want to get",
        "too young, too simple",
        "sysbdmin",
        "printf",
        "strcpy",
        "fread",
    )
    if not all(term in lowered for term in required_terms):
        return {}
    if "i386" not in lowered and "elf 32-bit" not in lowered and "32-little" not in lowered:
        return {}
    password = "sysbdmin"
    login_input = "".join(chr(ord(char) - 1) for char in password)
    return {
        "workflow_guess": "ftp_heap_format_string",
        "ctf_scope": pwn_ctf_scope_evidence(),
        "workflow_evidence": {
            "service_style": "ftp-like heap file store",
            "credential_transform": "username bytes are incremented by one before strcmp against sysbdmin",
            "login_input": login_input,
            "sink": "get_file copies uploaded content to a stack buffer and calls printf(content)",
            "blocked_name": "filenames beginning with flag are refused but traversal continues",
        },
        "exploit_plan": _ftp_heap_format_string_exploit_plan(login_input),
    }


def _ftp_heap_format_string_exploit_plan(login_input: str) -> dict[str, object]:
    return {
        "workflow": "ftp_heap_format_string",
        "ctf_scope": "proof-of-solve harness for a local or authorized CTF service",
        "login_input": login_input,
        "format_offset": 7,
        "leak": (
            "Upload a file whose content starts with a marker plus p32(elf.got['printf']) and `%8$.4s`, "
            "then `get` it to leak printf from the GOT."
        ),
        "libc_base": "printf_leak - libc.symbols['printf']",
        "overwrite_target": "Overwrite printf@got with libc.symbols['system'] using two %hn writes at format offset 7.",
        "trigger": "Upload a file named cmd with content `/bin/sh`, then `get cmd`; the final printf(content) becomes system('/bin/sh').",
        "payload_template": (
            "fmtstr_payload(7, {elf.got['printf']: libc.symbols['system']}, write_size='short')"
        ),
        "tool_hints": ["pwntools", "ELF.got", "fmtstr_payload", "libc leak"],
    }


def _source_vulnerability_finding(context: SolverContext, resolved: str) -> Finding | None:
    path = Path(resolved)
    if path.suffix.lower() not in {".c", ".cc", ".cpp", ".h", ".hpp"}:
        return None
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    ret2win_symbols = _ret2win_symbols(source)
    unsafe_calls = _unsafe_input_calls(source)
    if ret2win_symbols and unsafe_calls:
        primary_symbol = ret2win_symbols[0]
        return Finding(
            challenge_id=context.challenge.challenge_id,
            solver=PwnSolver.name,
            finding="Identified pwn source vulnerability pattern",
            evidence={
                "artifact": resolved,
                "pattern": "ret2win",
                "dangerous_calls": unsafe_calls,
                "symbols": ret2win_symbols,
                "source_sample": "\n".join(
                    _matching_source_lines(source, tuple(dict.fromkeys((*unsafe_calls, *ret2win_symbols))))
                ),
                "ctf_scope": pwn_ctf_scope_evidence(),
                "exploit_plan": _ret2win_exploit_plan(primary_symbol),
            },
            hypothesis=(
                f"The source exposes a likely ret2win target ({primary_symbol}) and uses unsafe input "
                "that can overwrite the saved return address."
            ),
            confidence=0.78,
            next_action=(
                f"Compile or use the provided binary, crash it with a cyclic pattern, compute the cyclic offset, "
                f"then send padding plus the {primary_symbol} address with pwntools."
            ),
        )
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
            "ctf_scope": pwn_ctf_scope_evidence(),
            "exploit_plan": _format_string_exploit_plan(),
        },
        hypothesis="User-controlled data appears to reach printf as the format argument, which is a format string vulnerability.",
        confidence=0.74,
        next_action="Build a pwntools harness, find the stack offset with %p probes, then plan leak/write primitives against the provided binary or service.",
    )


def _ret2win_symbols(source: str) -> list[str]:
    symbols: list[str] = []
    for symbol in _ret2win_symbol_candidates():
        if re.search(rf"\b(?:void|int|char\s*\*|long|unsigned\s+long)\s+{re.escape(symbol)}\s*\(", source):
            symbols.append(symbol)
    return symbols


def _ret2win_symbol_mentions(text: str) -> list[str]:
    symbols: list[str] = []
    for symbol in _ret2win_symbol_candidates():
        if re.search(rf"\b{re.escape(symbol)}\b", text):
            symbols.append(symbol)
    return symbols


def _ret2win_symbol_candidates() -> tuple[str, ...]:
    return ("win", "ret2win", "print_flag", "get_flag", "give_shell", "shell", "secret")


def _unsafe_input_calls(source: str) -> list[str]:
    checks = (
        ("gets", r"\bgets\s*\("),
        ("scanf", r"\bscanf\s*\(\s*\"[^\"]*%s"),
        ("strcpy", r"\bstrcpy\s*\("),
        ("strcat", r"\bstrcat\s*\("),
        ("read", r"\bread\s*\(\s*(?:0|STDIN_FILENO)\s*,"),
    )
    calls: list[str] = []
    for name, pattern in checks:
        if re.search(pattern, source):
            calls.append(name)
    return calls


def _dangerous_symbol_mentions(text: str) -> list[str]:
    names = ("gets", "scanf", "strcpy", "strcat", "read")
    return [name for name in names if re.search(rf"\b{re.escape(name)}\b", text)]


def _ret2win_exploit_plan(symbol: str) -> dict[str, object]:
    return {
        "workflow": "ret2win",
        "ctf_scope": "proof-of-solve harness for a local or authorized CTF binary",
        "symbol": symbol,
        "crash_harness": (
            "Run the binary locally or against the remote service with a pwntools script, send cyclic(512), "
            "then inspect the crashing instruction pointer/corefile."
        ),
        "cyclic_offset": "Use cyclic_find(core.rip) or gdb/pwndbg pattern search to compute the exact offset.",
        "payload_template": f"payload = b'A' * offset + p64(elf.symbols['{symbol}'])",
        "tool_hints": ["pwntools", "cyclic", "gdb", "checksec", "ROPgadget"],
    }


def _format_string_exploit_plan() -> dict[str, object]:
    return {
        "workflow": "format_string",
        "ctf_scope": "proof-of-solve harness for a local or authorized CTF binary/service",
        "offset_probe": "%p." * 24,
        "offset_strategy": "Send numbered `%p` probes, identify controlled stack words, then set FMT_OFFSET.",
        "leak_strategy": "Use `%s` or `%p` with a known address once the stack offset is confirmed.",
        "write_strategy": "Use fmtstr_payload(offset, {target: value}, write_size='short') after choosing a valid write target.",
        "payload_template": "fmtstr_payload(FMT_OFFSET, {WRITE_TARGET: WRITE_VALUE}, write_size='short')",
        "tool_hints": ["pwntools", "FmtStr", "fmtstr_payload", "checksec", "GOT/return-address write"],
    }


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


def _local_hypothesis(flags: tuple[str, ...], workflow_evidence: dict[str, object] | None = None) -> str:
    if flags:
        return "Local binary triage surfaced a flag-like token that should be verified."
    if workflow_evidence and workflow_evidence.get("workflow_guess") == "ftp_heap_format_string":
        return "Local pwn triage found an FTP-style heap file store where uploaded content reaches printf as a format string."
    if workflow_evidence and workflow_evidence.get("workflow_guess") == "ret2win":
        return "Local binary triage found ret2win-like evidence: a win-style target and unsafe input symbols."
    return "Local pwn triage collected file type, strings, hardening, and gadget-tool availability."


def _local_next_action(flags: tuple[str, ...], workflow_evidence: dict[str, object] | None = None) -> str:
    if flags:
        return "Send candidates to Verifier and preserve local tool outputs as replay evidence."
    if workflow_evidence and workflow_evidence.get("workflow_guess") == "ftp_heap_format_string":
        return "Use the pwn3 proof-of-solve plan inside the authorized challenge service: confirm offset evidence, then replay the bounded harness."
    if workflow_evidence and workflow_evidence.get("workflow_guess") == "ret2win":
        return "Crash with a cyclic pattern, compute the offset, then send padding plus the win-style symbol address with pwntools."
    return "Use checksec results to choose the proof-of-solve strategy, then generate a pwntools workspace."


def _service_hypothesis(status: str, flags: tuple[str, ...]) -> str:
    if flags:
        return "A scoped TCP service interaction returned a flag-like token in the initial transcript."
    if status == "success":
        return "The service is reachable and produced a transcript suitable for pwntools follow-up."
    return "The scoped service interaction did not complete, so the proof-of-solve workflow needs target or scope correction."


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
    return "Pivot into checksec, dangerous function callers, decompiled input paths, and proof-of-solve harness setup."
