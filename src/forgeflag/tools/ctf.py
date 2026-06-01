from __future__ import annotations

import os
from pathlib import Path
import tempfile
from urllib.parse import urlparse

from forgeflag.domain import ToolResult
from forgeflag.safety import ScopePolicy
from forgeflag.tools.runner import ToolRunner


def file_identify(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("file", [path])


def strings_extract(path: str, min_length: int = 4, scope: ScopePolicy | None = None) -> ToolResult:
    min_length = max(1, min(min_length, 64))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("strings", ["-n", str(min_length), path])


def checksec_binary(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("checksec", ["--file", path])


def ropgadget_scan(path: str, depth: int = 5, scope: ScopePolicy | None = None) -> ToolResult:
    depth = max(1, min(depth, 20))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("ROPgadget", ["--binary", path, "--depth", str(depth)])


def ropper_scan(path: str, search: str = "pop rdi; ret", scope: ScopePolicy | None = None) -> ToolResult:
    search = _tool_search_literal(search)
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("ropper", ["--file", path, "--search", search, "--nocolor"])


def binwalk_scan(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("binwalk", [path])


def exiftool_read(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("exiftool", [path])


def tshark_pcap_summary(path: str, packet_limit: int = 50, scope: ScopePolicy | None = None) -> ToolResult:
    packet_limit = max(1, min(packet_limit, 500))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("tshark", ["-r", path, "-c", str(packet_limit)])


def tshark_traffic_analysis(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("tshark", ["-r", path, "-q", "-z", "io,phs", "-z", "conv,tcp", "-z", "conv,udp"])


def tshark_dns_summary(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        [
            "-r",
            path,
            "-Y",
            "dns",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.a",
            "-e",
            "dns.txt",
            "-e",
            "dns.flags.rcode",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
        ],
    )


def tshark_tcp_streams(path: str, packet_limit: int = 500, scope: ScopePolicy | None = None) -> ToolResult:
    packet_limit = max(1, min(packet_limit, 500))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        [
            "-r",
            path,
            "-Y",
            "tcp",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.stream",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "_ws.col.Info",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
            "-c",
            str(packet_limit),
        ],
    )


def tshark_http_requests(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        [
            "-r",
            path,
            "-Y",
            "http.request",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.stream",
            "-e",
            "http.request.method",
            "-e",
            "http.host",
            "-e",
            "http.request.uri",
            "-e",
            "http.user_agent",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
        ],
    )


def tshark_http_artifact_scan(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        [
            "-r",
            path,
            "-Y",
            (
                'http.file_data contains "flag" || http.file_data contains "f1ag" || '
                'http.file_data contains "f1Ag" || http.file_data contains "flAg" || '
                'http.file_data contains "&#102;" || http.file_data contains "hnt.txt" || '
                'http.file_data contains "filename=\\"hnt" || http.request.uri contains "flag" || '
                'http.request.uri contains "hnt"'
            ),
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.stream",
            "-e",
            "http.request.method",
            "-e",
            "http.request.uri",
            "-e",
            "http.response.code",
            "-e",
            "http.file_data",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
        ],
    )


def tshark_flag_scan(
    path: str,
    needle: str = "flag{",
    packet_limit: int = 50,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    packet_limit = max(1, min(packet_limit, 200))
    needle = _tshark_contains_literal(needle)
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("tshark", ["-r", path, "-Y", f'frame contains "{needle}"', "-x", "-c", str(packet_limit)])


def nmap_tcp_basic(target: str, ports: str = "1-1024", scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("nmap_tcp_basic", ["-p", ports, target], target=target)


def ffuf_route_discovery(
    target: str,
    route_words: tuple[str, ...] = ("admin", "login", "flag", "robots.txt"),
    rate: int = 25,
    timeout_seconds: int = 15,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    scope = scope or ScopePolicy()
    target_url = _ffuf_target_url(target)
    words = _route_words(route_words)
    rate = max(1, min(rate, 100))
    timeout_seconds = max(3, min(timeout_seconds, 30))
    runner = ToolRunner(scope)
    wordlist_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as wordlist:
            wordlist_path = wordlist.name
            wordlist.write("\n".join(words) + "\n")
        return runner.run(
            "ffuf",
            [
                "-u",
                target_url,
                "-w",
                wordlist_path,
                "-of",
                "json",
                "-noninteractive",
                "-rate",
                str(rate),
                "-t",
                "5",
            ],
            target=target,
            timeout_seconds=timeout_seconds,
        )
    finally:
        if wordlist_path:
            try:
                os.unlink(wordlist_path)
            except OSError:
                pass


def ensure_existing_file(path: str) -> str:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"file not found: {resolved}")
    return str(resolved)


def _tshark_contains_literal(value: str) -> str:
    cleaned = "".join(char for char in value if char.isprintable() and char not in {'"', "\\"})
    return cleaned[:64] or "flag{"


def _tool_search_literal(value: str) -> str:
    cleaned = "".join(char for char in value if char.isprintable() and char not in {"\x00", "\n", "\r"})
    return cleaned[:80] or "pop rdi; ret"


def _ffuf_target_url(target: str) -> str:
    if "FUZZ" in target:
        return target
    parsed = urlparse(target)
    if not parsed.scheme:
        return target.rstrip("/") + "/FUZZ"
    return target.rstrip("/") + "/FUZZ"


def _route_words(words: tuple[str, ...], limit: int = 32) -> tuple[str, ...]:
    cleaned: list[str] = []
    for word in words:
        value = "".join(char for char in word.strip().lstrip("/") if char.isprintable() and char not in {"\x00", "\n", "\r"})
        if not value or value in cleaned:
            continue
        cleaned.append(value[:80])
    return tuple(cleaned[:limit]) or ("admin", "login", "flag", "robots.txt")
