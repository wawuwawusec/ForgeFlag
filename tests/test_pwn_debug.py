import unittest
from unittest import mock

from forgeflag.pwn_debug import (
    checksec_summary,
    crash_offset_from_registers,
    cyclic_find,
    debug_session,
    debruijn_pattern,
    parse_gdb_registers,
    probe_format_string,
)
from forgeflag.domain import ToolResult


class CyclicPatternTest(unittest.TestCase):
    def test_pattern_windows_are_unique(self) -> None:
        pattern = debruijn_pattern(512)
        self.assertEqual(len(pattern), 512)
        for start in range(0, 480, 3):
            value = int.from_bytes(pattern[start : start + 4], "little")
            self.assertEqual(cyclic_find(value, pattern), start)

    def test_cyclic_find_accepts_bytes(self) -> None:
        pattern = debruijn_pattern(256)
        self.assertEqual(cyclic_find(pattern[40:44], pattern), 40)
        self.assertIsNone(cyclic_find(b"zzzz", pattern))

    def test_crash_offset_maps_control_register(self) -> None:
        pattern = debruijn_pattern(512)
        value = int.from_bytes(pattern[88:92], "little")
        result = crash_offset_from_registers({"rbp": value, "rip": 0x400000}, pattern)
        self.assertEqual(result["control_register"], "rbp")
        self.assertEqual(result["offset"], 88)

    def test_parse_gdb_registers(self) -> None:
        text = "rax   0x1\nrbp   0x6161616c\nrip   0x41414141\nrdx 0xdeadbeef"
        self.assertEqual(parse_gdb_registers(text), {"rbp": 0x6161616C, "rip": 0x41414141})


class ChecksecSummaryTest(unittest.TestCase):
    def test_checksec_parses_hardening_matrix(self) -> None:
        file_result = ToolResult(tool="file", target="x", status="success", raw={"stdout": "ELF 64-bit pie executable, not stripped"})
        sections_result = ToolResult(tool="readelf", target="x", status="success", raw={
            "stdout": "Type: DYN\n  GNU_STACK      0x0 0x0 0x0 0x10 RW  0x10\n  GNU_RELRO      0x0 0x0 0x0 0x10 R   0x1"
        })
        symbols_result = ToolResult(tool="readelf", target="x", status="success", raw={
            "stdout": "123: __stack_chk_fail"
        })
        with mock.patch("forgeflag.pwn_debug.ctf.file_identify", return_value=file_result), \
             mock.patch("forgeflag.pwn_debug.ctf.readelf_sections", return_value=sections_result), \
             mock.patch("forgeflag.pwn_debug.ctf.readelf_symbols", return_value=symbols_result):
            summary = checksec_summary("/tmp/bin")
        self.assertTrue(summary["pie"])
        self.assertTrue(summary["nx"])
        self.assertTrue(summary["canary"])
        self.assertEqual(summary["relro"], "Partial RELRO")
        self.assertFalse(summary["stripped"])


class DebugSessionTest(unittest.TestCase):
    def test_debug_session_reports_missing_binary(self) -> None:
        result = debug_session("/nonexistent/binary", b"AAAA")
        self.assertEqual(result["status"], "missing")

    def test_debug_session_degrades_without_docker(self) -> None:
        with mock.patch("forgeflag.pwn_debug._docker_available", return_value=False):
            result = debug_session("/bin/ls", debruijn_pattern(64))
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("docker-build", result["error"])

    def test_format_string_probe_degrades_without_docker(self) -> None:
        with mock.patch("forgeflag.pwn_debug._docker_available", return_value=False):
            result = probe_format_string("/bin/ls")
        self.assertEqual(result["status"], "unavailable")

    def test_format_string_probe_detects_leaks(self) -> None:
        import tempfile
        from pathlib import Path

        completed = mock.Mock(returncode=0)
        completed.stdout = b"AAAA-0x7ffd1234-0x55d1abcd-0x1-(nil)\n"
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "fmt"
            binary.write_bytes(b"\x7fELF fake")
            with mock.patch("forgeflag.pwn_debug._docker_available", return_value=True), \
                 mock.patch("subprocess.run", return_value=completed) as run:
                result = probe_format_string(str(binary))
        run.assert_called()
        self.assertEqual(result["status"], "vulnerable")
        self.assertEqual(result["findings"][0]["leaked_addresses"], ["0x7ffd1234", "0x55d1abcd"])


if __name__ == "__main__":
    unittest.main()
