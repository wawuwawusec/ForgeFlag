from __future__ import annotations

import shutil
import socketserver
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from forgeflag.domain import ToolResult
from forgeflag.safety import ScopePolicy
from forgeflag.tools.ctf import (
    file_identify,
    ffuf_route_discovery,
    hashcat_dictionary_attack,
    john_dictionary_attack,
    ropgadget_scan,
    ropper_scan,
    rsactftool_attack,
    strings_extract,
    tcp_interact,
    tshark_flag_scan,
    tshark_dns_summary,
    tshark_http_artifact_scan,
    tshark_http_requests,
    tshark_tcp_streams,
    tshark_traffic_analysis,
)
from forgeflag.tools.runner import ToolRunner, _docker_arg


class ToolRunnerTest(unittest.TestCase):
    def test_inventory_contains_scoped_network_tool(self) -> None:
        runner = ToolRunner(ScopePolicy())
        inventory = runner.inventory()

        nmap = next(row for row in inventory if row["name"] == "nmap_tcp_basic")
        self.assertEqual(nmap["category"], "recon")
        self.assertTrue(nmap["active_network"])

    def test_inventory_does_not_treat_missing_pyenv_shim_as_available(self) -> None:
        def fake_which(command: str) -> str | None:
            if command == "checksec":
                return "/Users/example/.pyenv/shims/checksec"
            return None

        completed = subprocess.CompletedProcess(
            args=["checksec"],
            returncode=127,
            stdout=b"",
            stderr=b"pyenv: checksec: command not found\n",
        )
        with patch("forgeflag.tools.runner.shutil.which", side_effect=fake_which):
            with patch("forgeflag.tools.runner.subprocess.run", return_value=completed):
                inventory = ToolRunner(ScopePolicy()).inventory()

        checksec = next(row for row in inventory if row["name"] == "checksec")
        self.assertFalse(checksec["available"])

    def test_inventory_marks_docker_fallback_as_available(self) -> None:
        def fake_which(command: str) -> str | None:
            if command == "docker":
                return "/usr/local/bin/docker"
            return None

        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout=b"[]", stderr=b"")
        with patch.dict("os.environ", {"FORGEFLAG_TOOL_DOCKER_IMAGE": "forgeflag-ctf:test"}):
            with patch("forgeflag.tools.runner.shutil.which", side_effect=fake_which):
                with patch("forgeflag.tools.runner.subprocess.run", return_value=completed):
                    inventory = ToolRunner(ScopePolicy()).inventory()

        ropper = next(row for row in inventory if row["name"] == "ropper")
        self.assertTrue(ropper["available"])
        self.assertFalse(ropper["host_available"])
        self.assertTrue(ropper["docker_available"])
        self.assertEqual(ropper["source"], "docker")

    def test_run_uses_docker_fallback_for_mount_paths(self) -> None:
        mount = Path("/tmp/forgeflag")
        artifact = mount / "artifact.bin"

        def fake_which(command: str) -> str | None:
            if command == "docker":
                return "/usr/local/bin/docker"
            return None

        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout=b"ok\n", stderr=b"")
        with patch.dict(
            "os.environ",
            {
                "FORGEFLAG_TOOL_DOCKER_IMAGE": "forgeflag-ctf:test",
                "FORGEFLAG_TOOL_DOCKER_MOUNT": str(mount),
            },
        ):
            with patch("forgeflag.tools.runner.shutil.which", side_effect=fake_which):
                with patch("forgeflag.tools.runner.subprocess.run", return_value=completed) as run:
                    result = ToolRunner(ScopePolicy()).run("ropper", ["--file", str(artifact), "--nocolor"])

        self.assertEqual(result.status, "success")
        argv = run.call_args.args[0]
        self.assertIn("forgeflag-ctf:test", argv)
        self.assertIn("/workspace/artifact.bin", argv)
        self.assertIn("--file", argv)

    def test_docker_arg_rewrites_key_value_mount_paths(self) -> None:
        rewritten = _docker_arg("--wordlist=/tmp/forgeflag/words.txt", Path("/tmp/forgeflag"))

        self.assertEqual(rewritten, "--wordlist=/workspace/words.txt")

    def test_network_tool_refuses_without_active_scope(self) -> None:
        runner = ToolRunner(ScopePolicy(allowed_hosts=("127.0.0.1",), active_probe=False))

        result = runner.run("nmap_tcp_basic", ["-p", "80", "127.0.0.1"], target="127.0.0.1")

        self.assertEqual(result.status, "refused")
        self.assertIn("active probing is disabled", result.evidence[0])

    def test_ffuf_route_discovery_refuses_without_active_scope(self) -> None:
        result = ffuf_route_discovery(
            "http://127.0.0.1:8080/",
            route_words=("admin",),
            scope=ScopePolicy(allowed_hosts=("127.0.0.1",), active_probe=False),
        )

        self.assertEqual(result.status, "refused")
        self.assertIn("active probing is disabled", result.evidence[0])

    def test_unknown_tool_is_rejected(self) -> None:
        runner = ToolRunner(ScopePolicy())

        result = runner.run("shell")

        self.assertEqual(result.status, "error")
        self.assertIn("not in the ForgeFlag catalog", result.evidence[0])

    def test_tcp_interact_reads_scoped_service_banner(self) -> None:
        class BannerHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.sendall(b"welcome flag{tcp_banner}\n")

        server = socketserver.TCPServer(("127.0.0.1", 0), BannerHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"127.0.0.1:{server.server_address[1]}"
            result = tcp_interact(
                target,
                scope=ScopePolicy(allowed_hosts=("127.0.0.1",), active_probe=True),
            )
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(result.status, "success")
        self.assertIn("welcome flag{tcp_banner}", result.raw["transcript"])
        self.assertIn("bytes_received=", result.evidence[1])

    def test_tcp_interact_refuses_when_active_probe_disabled(self) -> None:
        result = tcp_interact("127.0.0.1:31337", scope=ScopePolicy(allowed_hosts=("127.0.0.1",)))

        self.assertEqual(result.status, "refused")
        self.assertIn("active probing is disabled", result.evidence[0])

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

    def test_tshark_http_requests_extracts_request_fields(self) -> None:
        expected = ToolResult(tool="tshark", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = tshark_http_requests("/tmp/capture.pcap")

        self.assertIs(result, expected)
        args = runner.run.call_args.args[1]
        self.assertIn("http.request", args)
        self.assertIn("http.request.uri", args)
        self.assertIn("http.user_agent", args)

    def test_tshark_http_artifact_scan_searches_common_ctf_clues(self) -> None:
        expected = ToolResult(tool="tshark", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = tshark_http_artifact_scan("/tmp/capture.pcap")

        self.assertIs(result, expected)
        args = runner.run.call_args.args[1]
        display_filter = args[args.index("-Y") + 1]
        self.assertIn('http.file_data contains "f1ag"', display_filter)
        self.assertIn('http.file_data contains "&#102;"', display_filter)
        self.assertIn("http.file_data", args)

    def test_tshark_dns_summary_extracts_dns_fields(self) -> None:
        expected = ToolResult(tool="tshark", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = tshark_dns_summary("/tmp/capture.pcap")

        self.assertIs(result, expected)
        args = runner.run.call_args.args[1]
        self.assertIn("dns", args)
        self.assertIn("dns.qry.name", args)
        self.assertIn("dns.txt", args)

    def test_tshark_tcp_streams_extracts_stream_fields(self) -> None:
        expected = ToolResult(tool="tshark", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = tshark_tcp_streams("/tmp/capture.pcap", packet_limit=999)

        self.assertIs(result, expected)
        args = runner.run.call_args.args[1]
        self.assertIn("tcp", args)
        self.assertIn("tcp.stream", args)
        self.assertIn("-c", args)
        self.assertIn("500", args)

    def test_ropgadget_scan_uses_binary_argument_and_depth_limit(self) -> None:
        expected = ToolResult(tool="ROPgadget", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = ropgadget_scan("/tmp/pwn")

        self.assertIs(result, expected)
        runner.run.assert_called_once_with("ROPgadget", ["--binary", "/tmp/pwn", "--depth", "5"])

    def test_ropper_scan_uses_file_argument_and_search_budget(self) -> None:
        expected = ToolResult(tool="ropper", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = ropper_scan("/tmp/pwn", search="pop rdi; ret")

        self.assertIs(result, expected)
        runner.run.assert_called_once_with(
            "ropper",
            ["--file", "/tmp/pwn", "--search", "pop rdi; ret", "--nocolor"],
        )

    def test_ffuf_route_discovery_uses_target_scope_and_small_wordlist(self) -> None:
        expected = ToolResult(tool="ffuf", target="http://127.0.0.1:8080/", status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = ffuf_route_discovery(
                "http://127.0.0.1:8080/",
                route_words=("admin", "flag"),
                scope=ScopePolicy(allowed_hosts=("127.0.0.1",), active_probe=True),
            )

        self.assertIs(result, expected)
        call = runner.run.call_args
        self.assertEqual(call.args[0], "ffuf")
        args = call.args[1]
        self.assertIn("-u", args)
        self.assertIn("http://127.0.0.1:8080/FUZZ", args)
        self.assertIn("-rate", args)
        self.assertEqual(call.kwargs["target"], "http://127.0.0.1:8080/")
        self.assertEqual(call.kwargs["timeout_seconds"], 15)

    def test_rsactftool_attack_uses_public_key_and_ciphertext_paths(self) -> None:
        expected = ToolResult(tool="RsaCtfTool", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = rsactftool_attack("/tmp/pub.pem", cipher_path="/tmp/cipher.bin")

        self.assertIs(result, expected)
        runner.run.assert_called_once_with(
            "RsaCtfTool",
            ["--publickey", "/tmp/pub.pem", "--uncipherfile", "/tmp/cipher.bin"],
            timeout_seconds=30,
        )

    def test_hashcat_dictionary_attack_uses_mode_and_wordlist(self) -> None:
        expected = ToolResult(tool="hashcat", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = hashcat_dictionary_attack("/tmp/hash.txt", "/tmp/words.txt", hash_mode=0)

        self.assertIs(result, expected)
        runner.run.assert_called_once_with(
            "hashcat",
            ["-m", "0", "-a", "0", "--status", "--potfile-disable", "/tmp/hash.txt", "/tmp/words.txt"],
            timeout_seconds=60,
        )

    def test_john_dictionary_attack_uses_wordlist_and_optional_format(self) -> None:
        expected = ToolResult(tool="john", target=None, status="success")
        with patch("forgeflag.tools.ctf.ToolRunner") as runner_cls:
            runner = Mock()
            runner.run.return_value = expected
            runner_cls.return_value = runner

            result = john_dictionary_attack("/tmp/hash.txt", "/tmp/words.txt", hash_format="raw-md5")

        self.assertIs(result, expected)
        runner.run.assert_called_once_with(
            "john",
            ["--wordlist=/tmp/words.txt", "--format=raw-md5", "/tmp/hash.txt"],
            timeout_seconds=60,
        )


if __name__ == "__main__":
    unittest.main()
