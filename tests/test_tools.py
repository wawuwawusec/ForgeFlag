from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from forgeflag.domain import ToolResult
from forgeflag.safety import ScopePolicy
from forgeflag.tools.ctf import file_identify, strings_extract, tshark_flag_scan, tshark_traffic_analysis
from forgeflag.tools.runner import ToolRunner


class ToolRunnerTest(unittest.TestCase):
    def test_inventory_contains_scoped_network_tool(self) -> None:
        runner = ToolRunner(ScopePolicy())
        inventory = runner.inventory()

        nmap = next(row for row in inventory if row["name"] == "nmap_tcp_basic")
        self.assertEqual(nmap["category"], "recon")
        self.assertTrue(nmap["active_network"])

    def test_network_tool_refuses_without_active_scope(self) -> None:
        runner = ToolRunner(ScopePolicy(allowed_hosts=("127.0.0.1",), active_probe=False))

        result = runner.run("nmap_tcp_basic", ["-p", "80", "127.0.0.1"], target="127.0.0.1")

        self.assertEqual(result.status, "refused")
        self.assertIn("active probing is disabled", result.evidence[0])

    def test_unknown_tool_is_rejected(self) -> None:
        runner = ToolRunner(ScopePolicy())

        result = runner.run("shell")

        self.assertEqual(result.status, "error")
        self.assertIn("not in the ForgeFlag catalog", result.evidence[0])

    @unittest.skipUnless(shutil.which("file"), "file command is not available")
    def test_file_identify_local_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "note.txt"
            artifact.write_text("flag{local_artifact}\n", encoding="utf-8")

            result = file_identify(str(artifact))

        self.assertEqual(result.status, "success")
        self.assertIn("returncode=0", result.evidence)

    @unittest.skipUnless(shutil.which("strings"), "strings command is not available")
    def test_strings_extract_local_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "blob.bin"
            artifact.write_bytes(b"\x00\x01visible-ctf-string\x00")

            result = strings_extract(str(artifact), min_length=6)

        self.assertEqual(result.status, "success")
        self.assertIn("visible-ctf-string", result.raw["stdout"])

    def test_tshark_traffic_analysis_uses_protocol_and_conversation_stats(self) -> None:
        expected = ToolResult(tool="tshark", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = tshark_traffic_analysis("/tmp/capture.pcap")

        self.assertIs(result, expected)
        runner.run.assert_called_once_with(
            "tshark",
            ["-r", "/tmp/capture.pcap", "-q", "-z", "io,phs", "-z", "conv,tcp", "-z", "conv,udp"],
        )

    def test_tshark_flag_scan_limits_packet_count_and_searches_payload_bytes(self) -> None:
        expected = ToolResult(tool="tshark", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = tshark_flag_scan("/tmp/capture.pcap", needle="flag{", packet_limit=999)

        self.assertIs(result, expected)
        runner.run.assert_called_once_with(
            "tshark",
            ["-r", "/tmp/capture.pcap", "-Y", 'frame contains "flag{"', "-x", "-c", "200"],
        )


if __name__ == "__main__":
    unittest.main()
