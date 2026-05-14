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


def nmap_tcp_basic(target: str, ports: str = "1-1024", scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("nmap_tcp_basic", ["-p", ports, target], target=target)


def ensure_existing_file(path: str) -> str:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"file not found: {resolved}")
    return str(resolved)

