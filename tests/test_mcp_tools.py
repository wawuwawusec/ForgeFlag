from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeflag.domain import ToolResult
from forgeflag import mcp_server


@unittest.skipIf(mcp_server.FastMCP is None, "MCP optional dependency is not installed")
class McpToolTest(unittest.TestCase):
    def test_analysis_hints_mcp_tool_returns_category_filtered_hints(self) -> None:
        payload = mcp_server.analysis_hints("traffic")

        self.assertTrue(payload)
        self.assertTrue(all(row["category"] == "traffic" for row in payload))
        self.assertIn("traffic-http-webshell-delimited-flag", {row["id"] for row in payload})
        self.assertIn("traffic-data-uri-image", {row["id"] for row in payload})

        crypto_payload = mcp_server.analysis_hints("crypto")
        self.assertTrue(all(row["category"] == "crypto" for row in crypto_payload))
        self.assertIn("crypto-python-random-prime-offset", {row["id"] for row in crypto_payload})

        reverse_payload = mcp_server.analysis_hints("reverse")
        self.assertTrue(all(row["category"] == "reverse" for row in reverse_payload))
        self.assertIn("reverse-pe-stack-xor-key-check", {row["id"] for row in reverse_payload})

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

    def test_tshark_http_object_export_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "capture.pcapng"
            output_dir = Path(tmp) / "objects"
            pcap.write_bytes(b"not a real pcapng for wrapper dispatch")
            with patch(
                "forgeflag.mcp_server.ctf.tshark_http_object_export",
                return_value=ToolResult(tool="tshark", target=None, status="success", evidence=["exported"]),
            ) as export:
                payload = mcp_server.tshark_http_object_export(str(pcap), str(output_dir))

        export.assert_called_once_with(str(pcap.resolve()), str(output_dir), mcp_server._scope_from_env())
        self.assertEqual(payload["tool"], "tshark")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["evidence"], ["exported"])

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

    def test_objdump_disassemble_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "rev"
            binary.write_bytes(b"fake")
            with patch(
                "forgeflag.mcp_server.ctf.objdump_disassemble",
                return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": "main:"}),
            ) as objdump:
                payload = mcp_server.objdump_disassemble(str(binary))

        objdump.assert_called_once_with(str(binary.resolve()), mcp_server._scope_from_env())
        self.assertEqual(payload["tool"], "objdump")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["raw"]["stdout"], "main:")

    def test_objdump_section_dump_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "rev"
            binary.write_bytes(b"fake")
            with patch(
                "forgeflag.mcp_server.ctf.objdump_section_dump",
                return_value=ToolResult(tool="objdump", target=None, status="success", raw={"stdout": "Contents"}),
            ) as objdump:
                payload = mcp_server.objdump_section_dump(str(binary), section=".data")

        objdump.assert_called_once_with(str(binary.resolve()), ".data", mcp_server._scope_from_env())
        self.assertEqual(payload["tool"], "objdump")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["raw"]["stdout"], "Contents")

    def test_readelf_sections_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "rev"
            binary.write_bytes(b"fake")
            with patch(
                "forgeflag.mcp_server.ctf.readelf_sections",
                return_value=ToolResult(tool="readelf", target=None, status="success", evidence=[".text"]),
            ) as readelf:
                payload = mcp_server.readelf_sections(str(binary))

        readelf.assert_called_once_with(str(binary.resolve()), mcp_server._scope_from_env())
        self.assertEqual(payload["tool"], "readelf")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["evidence"], [".text"])

    def test_radare2_info_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "rev"
            binary.write_bytes(b"fake")
            with patch(
                "forgeflag.mcp_server.ctf.radare2_info",
                return_value=ToolResult(tool="radare2", target=None, status="success", evidence=["izz"]),
            ) as radare2:
                payload = mcp_server.radare2_info(str(binary))

        radare2.assert_called_once_with(str(binary.resolve()), mcp_server._scope_from_env())
        self.assertEqual(payload["tool"], "radare2")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["evidence"], ["izz"])

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

    def test_hashcat_dictionary_attack_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hash_file = Path(tmp) / "hash.txt"
            words = Path(tmp) / "words.txt"
            hash_file.write_text("5d41402abc4b2a76b9719d911017c592", encoding="utf-8")
            words.write_text("hello\n", encoding="utf-8")
            with patch(
                "forgeflag.mcp_server.ctf.hashcat_dictionary_attack",
                return_value=ToolResult(tool="hashcat", target=None, status="missing", evidence=["not installed"]),
            ):
                payload = mcp_server.hashcat_dictionary_attack(str(hash_file), str(words), 0)

        self.assertEqual(payload["tool"], "hashcat")
        self.assertEqual(payload["status"], "missing")
        self.assertEqual(payload["evidence"], ["not installed"])

    def test_foremost_carve_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "blob.bin"
            output_dir = Path(tmp) / "carved"
            artifact.write_bytes(b"fake")
            with patch(
                "forgeflag.mcp_server.ctf.foremost_carve",
                return_value=ToolResult(tool="foremost", target=None, status="success", artifacts=[str(output_dir)]),
            ) as foremost:
                payload = mcp_server.foremost_carve(str(artifact), str(output_dir))

        foremost.assert_called_once_with(str(artifact.resolve()), str(output_dir), mcp_server._scope_from_env())
        self.assertEqual(payload["tool"], "foremost")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["artifacts"], [str(output_dir)])

    def test_yara_scan_mcp_tool_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "blob.bin"
            output_dir = Path(tmp) / "rules"
            artifact.write_bytes(b"fake")
            with patch(
                "forgeflag.mcp_server.ctf.yara_scan",
                return_value=ToolResult(tool="yara", target=None, status="success", evidence=["flag_text"]),
            ) as yara:
                payload = mcp_server.yara_scan(str(artifact), {"flag_text": "flag{"}, str(output_dir))

        yara.assert_called_once_with(
            str(artifact.resolve()),
            {"flag_text": "flag{"},
            str(output_dir),
            mcp_server._scope_from_env(),
        )
        self.assertEqual(payload["tool"], "yara")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["evidence"], ["flag_text"])

    def test_ffuf_route_discovery_mcp_tool_returns_structured_payload(self) -> None:
        with patch(
            "forgeflag.mcp_server.ctf.ffuf_route_discovery",
            return_value=ToolResult(tool="ffuf", target="http://127.0.0.1:8080/", status="missing", evidence=["not installed"]),
        ):
            payload = mcp_server.ffuf_route_discovery("http://127.0.0.1:8080/", ["admin"])

        self.assertEqual(payload["tool"], "ffuf")
        self.assertEqual(payload["status"], "missing")
        self.assertEqual(payload["evidence"], ["not installed"])

    def test_tcp_interact_mcp_tool_returns_structured_payload(self) -> None:
        with patch(
            "forgeflag.mcp_server.ctf.tcp_interact",
            return_value=ToolResult(
                tool="tcp_interact",
                target="127.0.0.1:31337",
                status="success",
                raw={"transcript": "ready"},
            ),
        ):
            payload = mcp_server.tcp_interact("127.0.0.1:31337", payload="hello")

        self.assertEqual(payload["tool"], "tcp_interact")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["raw"]["transcript"], "ready")


if __name__ == "__main__":
    unittest.main()
