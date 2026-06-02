from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shutil

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
from forgeflag.traffic_analysis import dns_summary_from_tshark, tcp_stream_shortlist
from forgeflag.transforms import transform_candidates


class TrafficSolver:
    name = "TrafficSolver"
    supported_categories = {ChallengeCategory.FORENSICS, ChallengeCategory.TRAFFIC}

    def solve(self, context: SolverContext) -> SolverResult:
        challenge = context.challenge
        findings: list[Finding] = []
        flag_candidates: list[str] = []
        pcap_paths = self._pcap_paths(context)

        if not pcap_paths:
            finding = Finding(
                challenge_id=challenge.challenge_id,
                solver=self.name,
                finding="Traffic solver found no packet captures",
                evidence={"attachment_paths": list(challenge.attachment_paths)},
                hypothesis="Traffic analysis applies only when a registered attachment is a packet capture.",
                confidence=0.35,
                next_action="Register a .pcap, .pcapng, or .cap artifact if this challenge includes traffic data.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(self.name, challenge.challenge_id, "not_applicable", (finding,))

        for pcap_path in pcap_paths:
            findings.append(self._analyze_pcap(context, pcap_path, flag_candidates))

        return SolverResult(
            self.name,
            challenge.challenge_id,
            "flag_candidate" if flag_candidates else "ok",
            tuple(findings),
            tuple(dict.fromkeys(flag_candidates)),
        )

    def _pcap_paths(self, context: SolverContext) -> list[str]:
        paths: list[str] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = ctf.ensure_existing_file(attachment_path)
            except FileNotFoundError:
                continue
            if _looks_like_pcap_path(resolved):
                paths.append(resolved)
                continue
            result = ctf.file_identify(resolved, context.scope)
            context.notebook.add_tool_result(context.challenge.challenge_id, result)
            if _looks_like_pcap_result(result):
                paths.append(resolved)
        return paths

    def _analyze_pcap(
        self,
        context: SolverContext,
        pcap_path: str,
        flag_candidates: list[str],
    ) -> Finding:
        challenge_id = context.challenge.challenge_id
        labeled_results = [
            ("tshark_pcap_summary", ctf.tshark_pcap_summary(pcap_path, packet_limit=50, scope=context.scope)),
            ("tshark_traffic_analysis", ctf.tshark_traffic_analysis(pcap_path, context.scope)),
            ("tshark_flag_scan", ctf.tshark_flag_scan(pcap_path, scope=context.scope)),
            ("tshark_dns_summary", ctf.tshark_dns_summary(pcap_path, context.scope)),
            ("tshark_tcp_streams", ctf.tshark_tcp_streams(pcap_path, scope=context.scope)),
            ("tshark_http_requests", ctf.tshark_http_requests(pcap_path, context.scope)),
            ("tshark_http_artifact_scan", ctf.tshark_http_artifact_scan(pcap_path, context.scope)),
        ]
        for _, result in labeled_results:
            context.notebook.add_tool_result(challenge_id, result)

        combined_output = "\n".join(
            str(result.raw.get("stdout", "")) + "\n" + str(result.raw.get("stderr", ""))
            for _, result in labeled_results
        )
        decoded_http_artifacts = _decoded_http_artifacts(
            str(dict(labeled_results)["tshark_http_artifact_scan"].raw.get("stdout", ""))
        )
        http_object_exports = _export_http_objects(
            context,
            pcap_path,
            "\n".join(
                [
                    str(dict(labeled_results)["tshark_pcap_summary"].raw.get("stdout", "")),
                    str(dict(labeled_results)["tshark_traffic_analysis"].raw.get("stdout", "")),
                    str(dict(labeled_results)["tshark_tcp_streams"].raw.get("stdout", "")),
                    str(dict(labeled_results)["tshark_http_requests"].raw.get("stdout", "")),
                    str(dict(labeled_results)["tshark_http_artifact_scan"].raw.get("stdout", "")),
                ]
            ),
        )
        dns_summary = dns_summary_from_tshark(str(dict(labeled_results)["tshark_dns_summary"].raw.get("stdout", "")))
        tcp_streams = tcp_stream_shortlist(
            str(dict(labeled_results)["tshark_tcp_streams"].raw.get("stdout", "")),
            http_requests_output=str(dict(labeled_results)["tshark_http_requests"].raw.get("stdout", "")),
            decoded_payloads=decoded_http_artifacts,
        )
        tcp_stream_payloads = _follow_tcp_stream_payloads(context, pcap_path, tcp_streams)
        protocol_streams = _protocol_stream_summaries(tcp_stream_payloads)
        decoded_dns_hints = [str(value) for value in dns_summary.get("decoded_query_hints", [])]
        stream_payload_text = "\n".join(str(item.get("sample", "")) for item in tcp_stream_payloads)
        exported_object_text = "\n".join(
            "\n".join([str(item.get("text_preview", "")), *[str(flag) for flag in item.get("flags", [])]])
            for item in http_object_exports
        )
        flags = extract_flags(
            "\n".join([combined_output, *decoded_http_artifacts, *decoded_dns_hints, stream_payload_text, exported_object_text])
        )
        flag_candidates.extend(flags)

        finding = Finding(
            challenge_id=challenge_id,
            solver=self.name,
            finding="Analyzed packet capture traffic",
            evidence={
                "artifact": {"name": Path(pcap_path).name, "path": pcap_path},
                "tool_statuses": {label: result.status for label, result in labeled_results},
                "tool_samples": {label: _tool_sample(result) for label, result in labeled_results},
                "http_requests": _interesting_lines(str(dict(labeled_results)["tshark_http_requests"].raw.get("stdout", ""))),
                "decoded_http_artifacts": decoded_http_artifacts[:20],
                "http_object_exports": http_object_exports,
                "dns_summary": dns_summary,
                "tcp_streams": tcp_streams,
                "tcp_stream_payloads": tcp_stream_payloads,
                "protocol_streams": protocol_streams,
                "flag_candidates": list(flags),
            },
            hypothesis=_traffic_hypothesis(flags),
            confidence=0.82 if flags else 0.62,
            next_action=_next_action(flags),
        )
        context.notebook.add_finding(finding)
        return finding


def _looks_like_pcap_path(path: str) -> bool:
    return Path(path).suffix.lower() in {".pcap", ".pcapng", ".cap"}


def _looks_like_pcap_result(result) -> bool:
    stdout = str(result.raw.get("stdout", "")).lower()
    return "pcap" in stdout or "packet capture" in stdout


def _tool_sample(result) -> dict[str, str]:
    stdout = str(result.raw.get("stdout", ""))
    stderr = str(result.raw.get("stderr", ""))
    return {"stdout": stdout[:500], "stderr": stderr[:500]}


def _follow_tcp_stream_payloads(
    context: SolverContext,
    pcap_path: str,
    tcp_streams: list[dict[str, object]],
    limit: int = 3,
) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for stream in tcp_streams[:limit]:
        stream_id = str(stream.get("stream_id") or "")
        if not stream_id.isdigit():
            continue
        result = ctf.tshark_follow_tcp_stream(pcap_path, int(stream_id), scope=context.scope)
        context.notebook.add_tool_result(context.challenge.challenge_id, result)
        sample = _compact_text(str(result.raw.get("stdout", "")), limit=1200)
        flags = extract_flags(sample)
        payloads.append(
            {
                "stream_id": stream_id,
                "tool_status": result.status,
                "score": stream.get("score"),
                "hints": stream.get("hints", []),
                "sample": sample,
                "flags": list(flags),
            }
        )
    return payloads


def _export_http_objects(
    context: SolverContext,
    pcap_path: str,
    http_hint_output: str,
    limit: int = 20,
) -> list[dict[str, object]]:
    if "http" not in http_hint_output.lower():
        return []

    export_dir = _http_object_export_dir(context, pcap_path)
    if export_dir.exists():
        shutil.rmtree(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)

    result = ctf.tshark_http_object_export(pcap_path, str(export_dir), scope=context.scope)
    context.notebook.add_tool_result(context.challenge.challenge_id, result)
    candidate_paths = [Path(path) for path in result.artifacts] if result.artifacts else list(export_dir.rglob("*"))
    summaries: list[dict[str, object]] = []
    for path in sorted(candidate_paths):
        if not path.is_file():
            continue
        summaries.append(_exported_object_summary(path))
        if len(summaries) >= limit:
            break
    return summaries


def _protocol_stream_summaries(tcp_stream_payloads: list[dict[str, object]]) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for payload in tcp_stream_payloads:
        sample = str(payload.get("sample", ""))
        protocol = _classify_cleartext_protocol(sample)
        if not protocol:
            continue
        commands = _protocol_commands(protocol, sample)
        flags = extract_flags(sample)
        summaries.append(
            {
                "stream_id": str(payload.get("stream_id", "")),
                "protocol": protocol,
                "commands": commands[:12],
                "flags": list(flags),
                "sample": _compact_text(sample, limit=700),
            }
        )
    return summaries


def _classify_cleartext_protocol(sample: str) -> str | None:
    upper = sample.upper()
    if any(marker in upper for marker in ("EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:", "\nDATA", "\r\nDATA")):
        return "SMTP"
    if any(marker in upper for marker in ("USER ", "PASS ", "RETR ", "STOR ", "220 FTP", "230 ")):
        return "FTP"
    if any(marker in upper for marker in ("NICK ", "USER ", "JOIN #", "PRIVMSG ", "NOTICE ")):
        return "IRC"
    return None


def _protocol_commands(protocol: str, sample: str) -> list[str]:
    command_sets = {
        "SMTP": {"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN", "NOOP", "QUIT", "AUTH", "STARTTLS"},
        "FTP": {"USER", "PASS", "SYST", "PWD", "CWD", "TYPE", "PASV", "PORT", "LIST", "RETR", "STOR", "QUIT"},
        "IRC": {"NICK", "USER", "JOIN", "PART", "PRIVMSG", "NOTICE", "PING", "PONG", "QUIT", "MODE", "TOPIC"},
    }
    allowed = command_sets.get(protocol, set())
    commands: list[str] = []
    upper = sample.upper()
    for command in allowed:
        if re.search(rf"(?<![A-Z0-9]){re.escape(command)}(?:\s|:|$)", upper) and command not in commands:
            commands.append(command)
    return commands


def _http_object_export_dir(context: SolverContext, pcap_path: str) -> Path:
    artifacts_root = Path(context.notebook.path).parent / "artifacts"
    return artifacts_root / _safe_component(context.challenge.challenge_id) / "http-objects" / _safe_component(Path(pcap_path).stem)


def _exported_object_summary(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    preview = _compact_text(data[:4096].decode("utf-8", errors="replace"))
    return {
        "name": path.name,
        "path": str(path),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "text_preview": preview,
        "flags": list(extract_flags(preview)),
    }


def _decoded_http_artifacts(output: str) -> list[str]:
    decoded: list[str] = []
    for line in output.splitlines():
        parts = line.split("|")
        if not parts:
            continue
        payload = parts[-1].strip()
        if not payload:
            continue
        flag_snippets: list[str] = []
        other_snippets: list[str] = []
        for candidate in transform_candidates(payload):
            for flag in extract_flags(candidate.value):
                flag_snippets.append(flag)
            snippet = _compact_text(candidate.value)
            if snippet:
                other_snippets.append(snippet)
        for snippet in [*flag_snippets, *other_snippets]:
            if snippet not in decoded:
                decoded.append(snippet)
    return decoded


def _interesting_lines(output: str, limit: int = 40) -> list[str]:
    return [_compact_text(line) for line in output.splitlines()[:limit] if _compact_text(line)]


def _compact_text(value: str, limit: int = 500) -> str:
    text = " ".join(value.replace("\x00", " ").split())
    return text[:limit]


def _safe_component(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in ("-", "_", ".") else "_" for char in value.strip())
    cleaned = cleaned.strip("._")
    return cleaned or "artifact"


def _traffic_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "Packet payload output contains a flag-like token that should be verified."
    return "Traffic evidence is available; protocol-specific pivots can narrow the next step."


def _next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send candidates to Verifier and preserve the packet capture as reproduction evidence."
    return "Add DNS, HTTP, or TCP stream-specific analysis based on protocol hierarchy and conversations."
