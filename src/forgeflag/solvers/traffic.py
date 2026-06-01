from __future__ import annotations

from pathlib import Path

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
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
        flags = extract_flags("\n".join([combined_output, *decoded_http_artifacts]))
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


def _traffic_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "Packet payload output contains a flag-like token that should be verified."
    return "Traffic evidence is available; protocol-specific pivots can narrow the next step."


def _next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send candidates to Verifier and preserve the packet capture as reproduction evidence."
    return "Add DNS, HTTP, or TCP stream-specific analysis based on protocol hierarchy and conversations."
