"""Binary debugging primitives for pwn and reverse challenges.

Everything here is deterministic and bounded:

- ``checksec_summary`` parses existing readelf/file output into the standard
  hardening matrix (PIE / NX / RELRO / canary / stripped).
- ``debruijn_pattern`` / ``cyclic_find`` implement the classic pwntools-style
  cyclic pattern used to measure crash offsets.
- ``debug_session`` / ``probe_format_string`` execute the local challenge
  binary only inside the ForgeFlag Docker tool sandbox (network disabled,
  read-only filesystem, resource caps) with gdb batch commands, so host
  execution of untrusted challenge binaries stays out of scope.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

from forgeflag.tools import ctf
from forgeflag.tools.runner import _docker_host_mount

CYCLIC_ALPHABET = "abcdefghijklmnopqrstuvwxyz"
_DOCKER_IMAGE_FALLBACK = "forgeflag-ctf:latest"


def checksec_summary(path: str) -> dict[str, Any]:
    """Build a checksec-style hardening matrix from readelf/file evidence."""
    scope = None
    file_result = ctf.file_identify(path, scope)
    sections = ctf.readelf_sections(path, scope)
    symbols = ctf.readelf_symbols(path, scope) if hasattr(ctf, "readelf_symbols") else None

    file_text = str((file_result.raw or {}).get("stdout", ""))
    section_text = str((sections.raw or {}).get("stdout", "")) if sections is not None else ""
    symbol_text = str((symbols.raw or {}).get("stdout", "")) if symbols is not None else ""

    is_dyn = re.search(r"\bType:\s*DYN\b", section_text) or "pie executable" in file_text.lower()
    nx = "GNU_STACK" in section_text and not re.search(
        r"GNU_STACK\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+RWE",
        section_text,
    )
    canary = "__stack_chk_fail" in symbol_text or "__stack_chk_fail" in file_text
    relro = "No RELRO"
    if "GNU_RELRO" in section_text:
        relro = "Partial RELRO"
        if "BIND_NOW" in section_text or "FLAGS_1" in section_text and "NOW" in section_text:
            relro = "Full RELRO"
    stripped = "not stripped" not in file_text and ".symtab" not in section_text

    return {
        "artifact": path,
        "pie": bool(is_dyn),
        "nx": bool(nx),
        "canary": bool(canary),
        "relro": relro,
        "stripped": bool(stripped),
        "file_sample": file_text.strip().splitlines()[:1],
    }


def debruijn_pattern(length: int, alphabet: str = CYCLIC_ALPHABET, sublength: int = 4) -> bytes:
    """Deterministic de Bruijn pattern: every ``sublength`` window is unique."""
    length = max(16, min(int(length), 4096))
    k = len(alphabet)
    a = [0] * (k * sublength)
    sequence: list[int] = []

    def db(t: int, p: int) -> None:
        if t > sublength:
            if sublength % p == 0:
                sequence.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    text = "".join(alphabet[index] for index in sequence)
    while len(text) < length:
        text += text
    return text.encode("ascii")[:length]


def cyclic_find(value: int | str | bytes, pattern: bytes) -> int | None:
    """Offset of ``value`` inside ``pattern``; accepts int or 4-byte substring."""
    if isinstance(value, int):
        raw = value.to_bytes(8, "little").replace(b"\x00", b"")
        if len(raw) < 4:
            raw = raw.ljust(4, b"A")
        raw = raw[:4]
    elif isinstance(value, str):
        raw = value.encode("ascii", errors="ignore")[:4]
    else:
        raw = bytes(value)[:4]
    index = pattern.find(raw)
    return index if index >= 0 else None


def crash_offset_from_registers(registers: dict[str, int], pattern: bytes) -> dict[str, Any]:
    """Match register values against the cyclic pattern to find the offset."""
    for reg in ("rip", "eip", "rsp", "esp", "rbp", "ebp"):
        value = registers.get(reg)
        if value is None:
            continue
        offset = cyclic_find(value, pattern)
        if offset is not None:
            return {"control_register": reg, "value": hex(value), "offset": offset}
    return {}


def _docker_available(image: str | None) -> bool:
    try:
        import shutil as _shutil

        if not _shutil.which("docker"):
            return False
        probe = subprocess.run(
            ["docker", "image", "inspect", image or _DOCKER_IMAGE_FALLBACK],
            capture_output=True,
            timeout=20,
            check=False,
        )
        return probe.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def debug_session(
    path: str,
    payload: bytes,
    commands: Sequence[str] = ("info registers", "x/8gx $rsp", "bt"),
    image: str | None = None,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Run gdb -batch over the binary with ``payload`` on stdin, in the sandbox.

    Returns registers (parsed), raw gdb output, and the cyclic offset when the
    payload is a cyclic pattern and a control register points into it.
    """
    binary = Path(path)
    if not binary.is_file():
        return {"status": "missing", "error": f"binary not found: {path}"}
    image = image or _DOCKER_IMAGE_FALLBACK
    if not _docker_available(image):
        return {
            "status": "unavailable",
            "error": "ForgeFlag Docker tool image unavailable; install it with scripts/forgeflag-control docker-build",
        }

    with tempfile.TemporaryDirectory(prefix="forgeflag-gdb-") as tmp:
        work = Path(tmp)
        import shutil as _shutil

        target = work / "challenge"
        _shutil.copy2(binary, target)
        target.chmod(0o500)
        payload_file = work / "input.bin"
        payload_file.write_bytes(payload)
        payload_file.chmod(0o400)
        gdb_script = ["set pagination off", "set confirm off"]
        for command in commands:
            gdb_script.append(command)
        script_path = work / "gdb.cmd"
        script_path.write_text("\n".join(gdb_script) + "\n", encoding="utf-8")

        argv = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--pids-limit",
            "64",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "-v",
            f"{_docker_host_mount(work.resolve())}:/challenge:ro",
            "-w",
            "/challenge",
            image,
            "gdb",
            "-q",
            "-batch",
            "-x",
            "/challenge/gdb.cmd",
            "--args",
            "/challenge/challenge",
        ]
        try:
            completed = subprocess.run(
                argv,
                input=payload,
                capture_output=True,
                timeout=max(10, min(timeout_seconds, 120)),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout"}
        except OSError as exc:
            return {"status": "error", "error": str(exc)}

    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    registers = parse_gdb_registers(stdout)
    result: dict[str, Any] = {
        "status": "crashed" if _looks_like_crash(stdout, stderr, completed.returncode) else "exited",
        "returncode": completed.returncode,
        "registers": registers,
        "gdb_stdout": stdout[-8000:],
    }
    if registers and len(payload) >= 16:
        pattern = payload if payload == debruijn_pattern(len(payload)) else None
        if pattern:
            result["cyclic_offset"] = crash_offset_from_registers(registers, pattern)
    return result


def probe_format_string(
    path: str,
    probes: Sequence[str] = ("%p %p %p %p %p %p %p %p", "AAAA-%p-%p-%p-%p"),
    image: str | None = None,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Detect echo-back format-string primitives by feeding %p probes."""
    binary = Path(path)
    if not binary.is_file():
        return {"status": "missing"}
    image = image or _DOCKER_IMAGE_FALLBACK
    if not _docker_available(image):
        return {"status": "unavailable"}
    findings = []
    for probe in probes:
        with tempfile.TemporaryDirectory(prefix="forgeflag-fmt-") as tmp:
            work = Path(tmp)
            import shutil as _shutil

            target = work / "challenge"
            _shutil.copy2(binary, target)
            target.chmod(0o500)
            argv = [
                "docker",
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "--read-only",
                "--memory",
                "256m",
                "--cpus",
                "1",
                "--pids-limit",
                "64",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                "-v",
                f"{_docker_host_mount(work.resolve())}:/challenge:ro",
                "-w",
                "/challenge",
                image,
                "./challenge",
            ]
            try:
                completed = subprocess.run(
                    argv,
                    input=probe.encode() + b"\n",
                    capture_output=True,
                    timeout=max(5, min(timeout_seconds, 60)),
                    check=False,
                )
            except (subprocess.TimeoutExpired, OSError):
                continue
        stdout = completed.stdout.decode("utf-8", errors="replace")
        leaked = re.findall(r"0x[0-9a-f]{4,16}", stdout)
        probe_echoed = "0x" not in probe
        if len(leaked) >= 2 and probe_echoed:
            findings.append({"probe": probe, "leaked_addresses": leaked[:8]})
            break
    return {
        "status": "vulnerable" if findings else "not_detected",
        "findings": findings,
    }


def parse_gdb_registers(gdb_output: str) -> dict[str, int]:
    registers: dict[str, int] = {}
    for match in re.finditer(r"^\s*([er]?(?:ax|bx|cx|dx|si|di|bp|sp|ip|flags))\s+(0x[0-9a-f]+)", gdb_output, re.M):
        name = match.group(1)
        if name in {"rip", "eip", "rsp", "esp", "rbp", "ebp"}:
            registers[name] = int(match.group(2), 16)
    return registers


def _looks_like_crash(stdout: str, stderr: str, returncode: int) -> bool:
    if returncode in (0, 1):
        return False
    text = (stdout + stderr).lower()
    return "sigsegv" in text or "sigabrt" in text or "program received signal" in text or returncode < 0
