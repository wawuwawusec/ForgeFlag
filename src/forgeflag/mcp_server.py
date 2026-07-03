from __future__ import annotations

import os
from typing import Any

from forgeflag.analysis_hints import recommended_analysis_hints
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
    def analysis_hints(category: str | None = None) -> list[dict[str, Any]]:
        """List ForgeFlag recommended CTF analysis hints from recent solve patterns."""
        return recommended_analysis_hints(category)

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
    def objdump_disassemble(path: str) -> dict[str, Any]:
        """Disassemble a local binary challenge artifact with bounded objdump output."""
        return _result_payload(ctf.objdump_disassemble(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def objdump_section_dump(path: str, section: str = ".rodata") -> dict[str, Any]:
        """Dump one local binary section with objdump."""
        return _result_payload(ctf.objdump_section_dump(ctf.ensure_existing_file(path), section, _scope_from_env()))

    @mcp.tool()
    def readelf_sections(path: str) -> dict[str, Any]:
        """List ELF sections for a local binary challenge artifact."""
        return _result_payload(ctf.readelf_sections(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def radare2_info(path: str) -> dict[str, Any]:
        """Run bounded radare2 metadata and string inspection for a local artifact."""
        return _result_payload(ctf.radare2_info(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def rsactftool_attack(public_key_path: str, cipher_path: str | None = None) -> dict[str, Any]:
        """Run RsaCtfTool against a local RSA public key and optional ciphertext artifact."""
        public_key = ctf.ensure_existing_file(public_key_path)
        cipher = ctf.ensure_existing_file(cipher_path) if cipher_path else None
        return _result_payload(ctf.rsactftool_attack(public_key, cipher, _scope_from_env()))

    @mcp.tool()
    def hashcat_dictionary_attack(hash_path: str, wordlist_path: str, hash_mode: int) -> dict[str, Any]:
        """Run a bounded hashcat dictionary attack against a local hash file."""
        return _result_payload(
            ctf.hashcat_dictionary_attack(
                ctf.ensure_existing_file(hash_path),
                ctf.ensure_existing_file(wordlist_path),
                hash_mode,
                _scope_from_env(),
            )
        )

    @mcp.tool()
    def john_dictionary_attack(hash_path: str, wordlist_path: str, hash_format: str | None = None) -> dict[str, Any]:
        """Run a bounded John the Ripper dictionary attack against a local hash file."""
        return _result_payload(
            ctf.john_dictionary_attack(
                ctf.ensure_existing_file(hash_path),
                ctf.ensure_existing_file(wordlist_path),
                hash_format,
                _scope_from_env(),
            )
        )

    @mcp.tool()
    def binwalk_scan(path: str) -> dict[str, Any]:
        """Scan a local artifact for embedded files and signatures."""
        return _result_payload(ctf.binwalk_scan(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def exiftool_read(path: str) -> dict[str, Any]:
        """Read metadata from a local image, document, or media artifact."""
        return _result_payload(ctf.exiftool_read(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def foremost_carve(path: str, output_dir: str) -> dict[str, Any]:
        """Carve embedded files from a local artifact into a caller-provided directory."""
        return _result_payload(ctf.foremost_carve(ctf.ensure_existing_file(path), output_dir, _scope_from_env()))

    @mcp.tool()
    def yara_scan(
        path: str,
        rules: dict[str, str] | None = None,
        output_dir: str | None = None,
    ) -> dict[str, Any]:
        """Run a bounded YARA scan against a local artifact using generated rules."""
        return _result_payload(ctf.yara_scan(ctf.ensure_existing_file(path), rules, output_dir, _scope_from_env()))

    @mcp.tool()
    def tshark_pcap_summary(path: str, packet_limit: int = 50) -> dict[str, Any]:
        """Summarize the first packets from a local PCAP artifact."""
        return _result_payload(ctf.tshark_pcap_summary(ctf.ensure_existing_file(path), packet_limit, _scope_from_env()))

    @mcp.tool()
    def tshark_traffic_analysis(path: str) -> dict[str, Any]:
        """Summarize PCAP protocol hierarchy and TCP/UDP conversations."""
        return _result_payload(ctf.tshark_traffic_analysis(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def tshark_dns_summary(path: str) -> dict[str, Any]:
        """Extract DNS query, answer, TXT, and response-code fields from a local PCAP artifact."""
        return _result_payload(ctf.tshark_dns_summary(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def tshark_tcp_streams(path: str, packet_limit: int = 500) -> dict[str, Any]:
        """Extract TCP stream metadata from a local PCAP artifact."""
        return _result_payload(ctf.tshark_tcp_streams(ctf.ensure_existing_file(path), packet_limit, _scope_from_env()))

    @mcp.tool()
    def tshark_follow_tcp_stream(path: str, stream_id: int) -> dict[str, Any]:
        """Follow one TCP stream from a local PCAP artifact as bounded ASCII text."""
        return _result_payload(ctf.tshark_follow_tcp_stream(ctf.ensure_existing_file(path), stream_id, _scope_from_env()))

    @mcp.tool()
    def tshark_http_requests(path: str) -> dict[str, Any]:
        """Extract HTTP request metadata from a local PCAP artifact."""
        return _result_payload(ctf.tshark_http_requests(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def tshark_http_artifact_scan(path: str) -> dict[str, Any]:
        """Scan HTTP file payloads in a local PCAP for CTF clues and encoded flags."""
        return _result_payload(ctf.tshark_http_artifact_scan(ctf.ensure_existing_file(path), _scope_from_env()))

    @mcp.tool()
    def tshark_http_object_export(path: str, output_dir: str) -> dict[str, Any]:
        """Export HTTP objects from a local PCAP artifact into a caller-provided directory."""
        return _result_payload(
            ctf.tshark_http_object_export(ctf.ensure_existing_file(path), output_dir, _scope_from_env())
        )

    @mcp.tool()
    def tshark_flag_scan(path: str, needle: str = "flag{", packet_limit: int = 50) -> dict[str, Any]:
        """Scan PCAP frames for a printable flag-like payload marker."""
        return _result_payload(ctf.tshark_flag_scan(ctf.ensure_existing_file(path), needle, packet_limit, _scope_from_env()))

    @mcp.tool()
    def nmap_tcp_basic(target: str, ports: str = "1-1024") -> dict[str, Any]:
        """Run a basic TCP scan against an explicitly allowlisted CTF target."""
        return _result_payload(ctf.nmap_tcp_basic(target, ports, _scope_from_env(active_probe=True)))

    @mcp.tool()
    def ffuf_route_discovery(target: str, route_words: list[str] | None = None) -> dict[str, Any]:
        """Run low-budget ffuf route discovery against an explicitly allowlisted CTF web target."""
        return _result_payload(
            ctf.ffuf_route_discovery(
                target,
                tuple(route_words or ("admin", "login", "flag", "robots.txt")),
                scope=_scope_from_env(active_probe=True),
            )
        )

    @mcp.tool()
    def tcp_interact(target: str, payload: str = "", receive_bytes: int = 4096) -> dict[str, Any]:
        """Open one scoped TCP service interaction and return a bounded transcript."""
        return _result_payload(
            ctf.tcp_interact(
                target,
                payload=payload,
                receive_bytes=receive_bytes,
                scope=_scope_from_env(active_probe=True),
            )
        )


def main() -> None:
    if FastMCP is None:
        raise SystemExit(
            "ForgeFlag MCP server requires the optional MCP extra. Install with: pip install -e '.[mcp]'"
        ) from _IMPORT_ERROR
    mcp.run()


if __name__ == "__main__":
    main()
