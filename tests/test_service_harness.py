import importlib.util
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_source = (ROOT / "scripts" / "forgeflag-service-harness").read_text()
harness = types.ModuleType("forgeflag_service_harness")
harness.__file__ = str(ROOT / "scripts" / "forgeflag-service-harness")
exec(compile(_source, "forgeflag-service-harness", "exec"), harness.__dict__)


def _write(src: Path, name: str, payload: bytes, mode: int = 0o644) -> None:
    target = src / name
    target.write_bytes(payload)
    target.chmod(mode)


class EntryDetectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.src = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _dockerfile(self, text: str) -> Path:
        df = self.src / "Dockerfile"
        df.write_text(text)
        return df

    def test_data_file_copy_is_not_the_entrypoint(self) -> None:
        _write(self.src, "flag.txt", b"DUCTF{real}\n")
        _write(self.src, "run.sh", b"#!/bin/sh\nqemu-aarch64 ./bin\n", 0o755)
        _write(self.src, "bin", b"\x7fELF" + b"\x00" * 60, 0o755)
        df = self._dockerfile(
            "FROM nsjail\n"
            "COPY ./flag.txt /home/ctf/chal\n"
            "COPY ./bin /home/ctf/chal\n"
            "COPY ./run.sh /home/ctf/chal/pwn\n"
        )
        info = harness.parse_dockerfile(df, self.src)
        self.assertEqual("./run.sh", info["entry"])

    def test_launchable_chal_copy_beats_data_file(self) -> None:
        _write(self.src, "flag.txt", b"DUCTF{real}\n")
        _write(self.src, "server", b"\x7fELF" + b"\x00" * 60, 0o755)
        df = self._dockerfile(
            "FROM nsjail\nCOPY ./flag.txt /home/ctf/chal\nCOPY ./server /home/ctf/chal\n"
        )
        info = harness.parse_dockerfile(df, self.src)
        self.assertEqual("./server", info["entry"])

    def test_fallback_prefers_run_sh_over_plain_binaries(self) -> None:
        _write(self.src, "run.sh", b"#!/bin/sh\ntrue\n", 0o755)
        _write(self.src, "helper", b"\x7fELF" + b"\x00" * 60, 0o755)
        df = self._dockerfile("FROM nsjail\nRUN true\n")
        info = harness.parse_dockerfile(df, self.src)
        self.assertEqual("run.sh", info["entry"])

    def test_entry_command_routes_by_type(self) -> None:
        self.assertEqual("python3 srv.py", harness._entry_command("srv.py"))
        self.assertEqual("sh ./run.sh", harness._entry_command("./run.sh"))
        self.assertEqual("./binary", harness._entry_command("binary"))

    def test_arch_detection_from_elf_header(self) -> None:
        def elf(machine: bytes) -> bytes:
            head = bytearray(b"\x7fELF" + b"\x00" * 16)
            head[18:20] = machine
            return bytes(head) + b"\x00" * 44

        _write(self.src, "aarch", elf(b"\xb7\x00"), 0o755)
        _write(self.src, "amd64", elf(b"\x3e\x00"), 0o755)
        self.assertEqual("aarch64", harness._detect_arch(self.src / "aarch"))
        self.assertEqual("x86_64", harness._detect_arch(self.src / "amd64"))


if __name__ == "__main__":
    unittest.main()
