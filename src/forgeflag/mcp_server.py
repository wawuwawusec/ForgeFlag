from __future__ import annotations

import os
from typing import Any

from forgeflag.safety import ScopePolicy
from forgeflag.tools import ctf
from forgeflag.tools.runner import ToolRunner


def _scope_from_env(active_probe: bool = False) -> ScopePolicy:
    allowed_hosts = tuple(
        host.strip()
        for host in os.environ.get("FORGEFLAG_ALLOWED_HOSTS", "").split(",")
        if host.strip()
    )
    return ScopePolicy(allowed_hosts=allowed_hosts, active_probe=active_probe)


def _result_payload(result) -> dict[str, Any]:
    return {
        "tool": result.tool,
        "target": result.target,
        "status": result.status,
        "evidence": result.evidence,
        "artifacts": result.artifacts,
        "next_hints": result.next_hints,
        "raw": result.raw,
        "created_at": result.created_at,
    }


try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - exercised only without optional MCP extra.
    FastMCP = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


if FastMCP is not None:
    mcp = FastMCP("ForgeFlag CTF Tools", json_response=True)

    @mcp.tool()
    def tool_inventory() -> list[dict[str, object]]:
        """List ForgeFlag CTF tool wrappers and local executable availability."""
        return ToolRunner(_scope_from_env()).inventory()

    @mcp.tool()
    def file_identify(path: str) -> dict[str, Any]:
        """Identify a local challenge artifact with file(1)."""
        return _result_payload(ctf.file_identify(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def strings_extract(path: str, min_length: int = 4) -> dict[str, Any]:
        """Extract printable strings from a local challenge artifact."""
        return _result_payload(ctf.strings_extract(ctf.ensure_existing_file(path), min_length, _scope_from_env()))

    @mcp.tool()
    def checksec_binary(path: str) -> dict[str, Any]:
        """Inspect ELF hardening flags for a local binary challenge."""
        return _result_payload(ctf.checksec_binary(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def ropgadget_scan(path: str, depth: int = 5) -> dict[str, Any]:
        """Search ROP/JOP gadgets in a local binary challenge artifact."""
        return _result_payload(ctf.ropgadget_scan(ctf.ensure_existing_file(path), depth, _scope_from_env()))

    @mcp.tool()
    def ropper_scan(path: str, search: str = "pop rdi; ret") -> dict[str, Any]:
        """Search gadgets in a local binary challenge artifact with ropper."""
        return _result_payload(ctf.ropper_scan(ctf.ensure_existing_file(path), search, _scope_from_env()))

    @mcp.tool()
    def binwalk_scan(path: str) -> dict[str, Any]:
        """Scan a local artifact for embedded files and signatures."""
        return _result_payload(ctf.binwalk_scan(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def exiftool_read(path: str) -> dict[str, Any]:
        """Read metadata from a local image, document, or media artifact."""
        return _result_payload(ctf.exiftool_read(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def tshark_pcap_summary(path: str, packet_limit: int = 50) -> dict[str, Any]:
        """Summarize the first packets from a local PCAP artifact."""
        return _result_payload(ctf.tshark_pcap_summary(ctf.ensure_existing_file(path), packet_limit, _scope_from_env()))

    @mcp.tool()
    def tshark_traffic_analysis(path: str) -> dict[str, Any]:
        """Summarize PCAP protocol hierarchy and TCP/UDP conversations."""
        return _result_payload(ctf.tshark_traffic_analysis(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def tshark_http_requests(path: str) -> dict[str, Any]:
        """Extract HTTP request metadata from a local PCAP artifact."""
        return _result_payload(ctf.tshark_http_requests(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def tshark_http_artifact_scan(path: str) -> dict[str, Any]:
        """Scan HTTP file payloads in a local PCAP for CTF clues and encoded flags."""
        return _result_payload(ctf.tshark_http_artifact_scan(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def tshark_flag_scan(path: str, needle: str = "flag{", packet_limit: int = 50) -> dict[str, Any]:
        """Scan PCAP frames for a printable flag-like payload marker."""
        return _result_payload(ctf.tshark_flag_scan(ctf.ensure_existing_file(path), needle, packet_limit, _scope_from_env()))

    @mcp.tool()
    def nmap_tcp_basic(target: str, ports: str = "1-1024") -> dict[str, Any]:
        """Run a basic TCP scan against an explicitly allowlisted CTF target."""
        return _result_payload(ctf.nmap_tcp_basic(target, ports, _scope_from_env(active_probe=True)))


def main() -> None:
    if FastMCP is None:
        raise SystemExit(
            "ForgeFlag MCP server requires the optional MCP extra. Install with: pip install -e '.[mcp]'"
        ) from _IMPORT_ERROR
    mcp.run()


if __name__ == "__main__":
    main()
