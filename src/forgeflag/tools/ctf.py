from __future__ import annotations

from pathlib import Path

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
