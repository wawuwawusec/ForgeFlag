from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from forgeflag.domain import ToolResult
from forgeflag.safety import ScopePolicy


@dataclass(frozen=True)
class ToolSpec:
    name: str
    command: tuple[str, ...]
    category: str
    description: str
    active_network: bool = False
    default_timeout_seconds: int = 20
    max_output_bytes: int = 16_384


TOOL_CATALOG: dict[str, ToolSpec] = {
    "file": ToolSpec("file", ("file",), "forensics", "Identify file type and metadata."),
    "strings": ToolSpec("strings", ("strings",), "reverse", "Extract printable strings from a file."),
    "checksec": ToolSpec("checksec", ("checksec",), "pwn", "Inspect ELF binary hardening flags."),
    "ROPgadget": ToolSpec("ROPgadget", ("ROPgadget",), "pwn", "Search ROP/JOP gadgets in a binary."),
    "ropper": ToolSpec("ropper", ("ropper",), "pwn", "Search gadgets and ROP chain helpers in a binary."),
    "RsaCtfTool": ToolSpec("RsaCtfTool", ("RsaCtfTool",), "crypto", "Run RSA CTF attack heuristics."),
    "hashcat": ToolSpec("hashcat", ("hashcat",), "crypto", "Run bounded dictionary hash cracking."),
    "john": ToolSpec("john", ("john",), "crypto", "Run bounded dictionary password/hash recovery."),
    "binwalk": ToolSpec("binwalk", ("binwalk",), "forensics", "Scan firmware and embedded file signatures."),
    "exiftool": ToolSpec("exiftool", ("exiftool",), "forensics", "Read metadata from images and documents."),
    "tshark": ToolSpec("tshark", ("tshark",), "forensics", "Summarize packet capture contents."),
    "ffuf": ToolSpec(
        "ffuf",
        ("ffuf",),
        "web",
        "Scoped route discovery for explicitly authorized CTF web targets.",
        active_network=True,
        default_timeout_seconds=15,
        max_output_bytes=32_768,
    ),
    "nmap_tcp_basic": ToolSpec(
        "nmap_tcp_basic",
        ("nmap", "-sT", "-Pn"),
        "recon",
        "Basic TCP scan for explicitly authorized CTF targets.",
        active_network=True,
        default_timeout_seconds=60,
        max_output_bytes=32_768,
    ),
}


class ToolRunner:
    def __init__(self, scope: ScopePolicy, cwd: str | Path | None = None) -> None:
        self.scope = scope
        self.cwd = Path(cwd) if cwd else None

    def inventory(self) -> list[dict[str, object]]:
        rows = []
        for spec in TOOL_CATALOG.values():
            executable = spec.command[0]
            rows.append(
                {
                    "name": spec.name,
                    "category": spec.category,
                    "description": spec.description,
                    "active_network": spec.active_network,
                    "available": _command_available(executable),
                    "command": list(spec.command),
                }
            )
        return rows

    def run(
        self,
        name: str,
        args: Iterable[str] = (),
        target: str | None = None,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        spec = TOOL_CATALOG.get(name)
        if spec is None:
            return ToolResult(tool=name, target=target, status="error", evidence=["tool is not in the ForgeFlag catalog"])

        if spec.active_network:
            try:
                self.scope.require_active_allowed(target)
            except ValueError as exc:
                return ToolResult(tool=name, target=target, status="refused", evidence=[str(exc)])

        executable = spec.command[0]
        if not _command_available(executable):
            return ToolResult(
                tool=name,
                target=target,
                status="missing",
                evidence=[f"executable not found on PATH: {executable}"],
            )

        argv = [*spec.command, *[str(arg) for arg in args]]
        try:
            completed = subprocess.run(
                argv,
                cwd=self.cwd,
                capture_output=True,
                timeout=timeout_seconds or spec.default_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                tool=name,
                target=target,
                status="timeout",
                evidence=[f"timed out after {exc.timeout} seconds", f"argv={shlex.join(argv)}"],
            )
        except OSError as exc:
            return ToolResult(tool=name, target=target, status="error", evidence=[str(exc)])

        stdout, stdout_truncated = _decode_limited(completed.stdout, spec.max_output_bytes)
        stderr, stderr_truncated = _decode_limited(completed.stderr, spec.max_output_bytes)
        status = "success" if completed.returncode == 0 else "error"
        return ToolResult(
            tool=name,
            target=target,
            status=status,
            evidence=[f"returncode={completed.returncode}", f"argv={shlex.join(argv)}"],
            raw={
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
            },
        )


def _decode_limited(data: bytes, max_bytes: int) -> tuple[str, bool]:
    truncated = len(data) > max_bytes
    clipped = data[:max_bytes]
    return clipped.decode("utf-8", errors="replace"), truncated


def _command_available(executable: str) -> bool:
    command_path = shutil.which(executable)
    if command_path is None:
        return False

    if not _looks_like_pyenv_shim(command_path):
        return True

    try:
        completed = subprocess.run(
            [executable],
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return True

    output = _decode_limited(completed.stdout + completed.stderr, 4096)[0]
    if completed.returncode == 127 and "pyenv:" in output and "command not found" in output:
        return False
    return True


def _looks_like_pyenv_shim(path: str) -> bool:
    parts = Path(path).parts
    return ".pyenv" in parts and "shims" in parts
