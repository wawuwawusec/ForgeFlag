from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import ToolResult
from forgeflag import mcp_server


@unittest.skipIf(mcp_server.FastMCP is None, "MCP optional dependency is not installed")
class McpToolTest(unittest.TestCase):
    def test_tshark_traffic_analysis_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "capture.pcap"
            pcap.write_bytes(b"not a real pcap for wrapper dispatch")
            with patch(
                "forgeflag.mcp_server.ctf.tshark_traffic_analysis",
                return_value=ToolResult(tool="tshark", target=None, status="success", evidence=["ok"]),
            ):
                payload = mcp_server.tshark_traffic_analysis(str(pcap))

        self.assertEqual(payload["tool"], "tshark")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["evidence"], ["ok"])

    def test_tshark_http_artifact_scan_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "capture.pcapng"
            pcap.write_bytes(b"not a real pcapng for wrapper dispatch")
            with patch(
                "forgeflag.mcp_server.ctf.tshark_http_artifact_scan",
                return_value=ToolResult(tool="tshark", target=None, status="success", evidence=["http clue"]),
            ):
                payload = mcp_server.tshark_http_artifact_scan(str(pcap))

        self.assertEqual(payload["tool"], "tshark")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["evidence"], ["http clue"])

    def test_tshark_dns_summary_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "capture.pcap"
            pcap.write_bytes(b"not a real pcap for wrapper dispatch")
            with patch(
                "forgeflag.mcp_server.ctf.tshark_dns_summary",
                return_value=ToolResult(tool="tshark", target=None, status="success", evidence=["dns clue"]),
            ):
                payload = mcp_server.tshark_dns_summary(str(pcap))

        self.assertEqual(payload["tool"], "tshark")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["evidence"], ["dns clue"])

    def test_ropgadget_scan_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "pwn"
            binary.write_bytes(b"fake")
            with patch(
                "forgeflag.mcp_server.ctf.ropgadget_scan",
                return_value=ToolResult(tool="ROPgadget", target=None, status="missing", evidence=["not installed"]),
            ):
                payload = mcp_server.ropgadget_scan(str(binary), depth=4)

        self.assertEqual(payload["tool"], "ROPgadget")
        self.assertEqual(payload["status"], "missing")
        self.assertEqual(payload["evidence"], ["not installed"])

    def test_rsactftool_attack_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            public_key = Path(tmp) / "pub.pem"
            public_key.write_text("public key", encoding="utf-8")
            with patch(
                "forgeflag.mcp_server.ctf.rsactftool_attack",
                return_value=ToolResult(tool="RsaCtfTool", target=None, status="missing", evidence=["not installed"]),
            ):
                payload = mcp_server.rsactftool_attack(str(public_key))

        self.assertEqual(payload["tool"], "RsaCtfTool")
        self.assertEqual(payload["status"], "missing")
        self.assertEqual(payload["evidence"], ["not installed"])

    def test_ffuf_route_discovery_mcp_tool_returns_structured_payload(self) -> None:
        with patch(
            "forgeflag.mcp_server.ctf.ffuf_route_discovery",
            return_value=ToolResult(tool="ffuf", target="http://127.0.0.1:8080/", status="missing", evidence=["not installed"]),
        ):
            payload = mcp_server.ffuf_route_discovery("http://127.0.0.1:8080/", ["admin"])

        self.assertEqual(payload["tool"], "ffuf")
        self.assertEqual(payload["status"], "missing")
        self.assertEqual(payload["evidence"], ["not installed"])


if __name__ == "__main__":
    unittest.main()
