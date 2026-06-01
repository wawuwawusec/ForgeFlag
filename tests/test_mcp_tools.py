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


if __name__ == "__main__":
    unittest.main()
