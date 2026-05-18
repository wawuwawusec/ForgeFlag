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


if __name__ == "__main__":
    unittest.main()
