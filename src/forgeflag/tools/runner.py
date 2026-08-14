from __future__ import annotations

import shlex
import shutil
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from forgeflag.domain import ToolResult
from forgeflag.safety import ScopePolicy


DOCKER_TOOL_PATH = "/opt/forgeflag-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    command: tuple[str, ...]
    category: str
    description: str
    active_network: bool = False
    default_timeout_seconds: int = 20
    max_output_bytes: int = 16_384
    docker_supported: bool = True


TOOL_CATALOG: dict[str, ToolSpec] = {
    "file": ToolSpec("file", ("file",), "forensics", "Identify file type and metadata."),
    "strings": ToolSpec("strings", ("strings",), "reverse", "Extract printable strings from a file."),
    "checksec": ToolSpec("checksec", ("checksec",), "pwn", "Inspect ELF binary hardening flags.", default_timeout_seconds=60),
    "ROPgadget": ToolSpec("ROPgadget", ("ROPgadget",), "pwn", "Search ROP/JOP gadgets in a binary."),
    "ropper": ToolSpec("ropper", ("ropper",), "pwn", "Search gadgets and ROP chain helpers in a binary."),
    "RsaCtfTool": ToolSpec("RsaCtfTool", ("RsaCtfTool",), "crypto", "Run RSA CTF attack heuristics."),
    "objdump": ToolSpec(
        "objdump",
        ("objdump",),
        "reverse",
        "Disassemble binaries or dump sections for static reverse engineering.",
        default_timeout_seconds=30,
        max_output_bytes=32_768,
    ),
    "readelf": ToolSpec(
        "readelf",
        ("readelf",),
        "reverse",
        "Inspect ELF headers, sections, and symbols.",
        default_timeout_seconds=20,
    ),
    "radare2": ToolSpec(
        "radare2",
        ("r2",),
        "reverse",
        "Run bounded radare2 metadata and string analysis.",
        default_timeout_seconds=20,
        max_output_bytes=32_768,
    ),
    "hashcat": ToolSpec("hashcat", ("hashcat",), "crypto", "Run bounded dictionary hash cracking."),
    "john": ToolSpec("john", ("john",), "crypto", "Run bounded dictionary password/hash recovery."),
    "binwalk": ToolSpec("binwalk", ("binwalk",), "forensics", "Scan firmware and embedded file signatures."),
    "exiftool": ToolSpec("exiftool", ("exiftool",), "forensics", "Read metadata from images and documents."),
    "foremost": ToolSpec(
        "foremost",
        ("foremost",),
        "forensics",
        "Carve embedded files into a managed output directory.",
        default_timeout_seconds=30,
        max_output_bytes=32_768,
    ),
    "yara": ToolSpec(
        "yara",
        ("yara",),
        "forensics",
        "Run bounded YARA signature scans over local artifacts.",
        default_timeout_seconds=20,
    ),
    "steghide": ToolSpec(
        "steghide",
        ("steghide",),
        "forensics",
        "Inspect and extract steghide payloads from JPEG/BMP/WAV/AU artifacts with explicit hints.",
        default_timeout_seconds=20,
    ),
    "stegseek": ToolSpec(
        "stegseek",
        ("stegseek",),
        "forensics",
        "Run bounded steghide passphrase recovery with a challenge-scoped wordlist.",
        default_timeout_seconds=30,
    ),
    "tesseract": ToolSpec(
        "tesseract",
        ("tesseract",),
        "forensics",
        "Extract visible text from local challenge images with bounded OCR settings.",
        default_timeout_seconds=30,
        max_output_bytes=32_768,
    ),
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
        local_env = _load_project_tool_env(self.cwd or Path.cwd())
        self.docker_image = (
            os.environ.get("FORGEFLAG_TOOL_DOCKER_IMAGE")
            or local_env.get("FORGEFLAG_TOOL_DOCKER_IMAGE")
            or ""
        ).strip()
        docker_mount = os.environ.get("FORGEFLAG_TOOL_DOCKER_MOUNT") or local_env.get("FORGEFLAG_TOOL_DOCKER_MOUNT")
        self.docker_mount = Path(docker_mount or Path.cwd()).expanduser().resolve()

    def inventory(self) -> list[dict[str, object]]:
        rows = []
        docker_ready = _docker_image_available(self.docker_image)
        docker_commands = _docker_available_commands(
            self.docker_image,
            {spec.command[0] for spec in TOOL_CATALOG.values()},
        ) if docker_ready else set()
        for spec in TOOL_CATALOG.values():
            executable = spec.command[0]
            host_available = _command_available(executable)
            docker_available = bool(spec.docker_supported and executable in docker_commands)
            rows.append(
                {
                    "name": spec.name,
                    "category": spec.category,
                    "description": spec.description,
                    "active_network": spec.active_network,
                    "available": host_available or docker_available,
                    "host_available": host_available,
                    "docker_available": docker_available,
                    "source": "host" if host_available else ("docker" if docker_available else "missing"),
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
        host_available = _command_available(executable)
        docker_ready = bool(
            spec.docker_supported
            and _docker_image_available(self.docker_image)
            and _docker_command_available(self.docker_image, executable)
        )
        if not host_available and not docker_ready:
            return ToolResult(
                tool=name,
                target=target,
                status="missing",
                evidence=[f"executable not found on PATH: {executable}"],
            )

        argv = [*spec.command, *[str(arg) for arg in args]]
        if not host_available and docker_ready:
            return self._run_docker(spec, argv, target, timeout_seconds)

        return self._run_host(spec, argv, target, timeout_seconds)

    def run_local_binary(
        self,
        executable_path: str | Path,
        *,
        stdin: bytes | str = b"",
        fixture_files: dict[str, bytes | str] | None = None,
        timeout_seconds: int = 10,
    ) -> ToolResult:
        """Replay one local challenge binary in a resource-bounded, networkless container."""
        source = Path(executable_path).expanduser().resolve()
        if not source.is_file():
            return ToolResult(
                tool="local_binary_replay",
                target=str(source),
                status="missing",
                evidence=[f"local challenge binary not found: {source}"],
            )
        payload = stdin.encode("utf-8") if isinstance(stdin, str) else bytes(stdin)
        if len(payload) > 65_536:
            return ToolResult(
                tool="local_binary_replay",
                target=str(source),
                status="refused",
                evidence=["stdin exceeds the 65536-byte replay limit"],
            )
        fixtures = fixture_files or {}
        try:
            normalized_fixtures = _normalized_fixture_files(fixtures)
        except ValueError as exc:
            return ToolResult(
                tool="local_binary_replay",
                target=str(source),
                status="refused",
                evidence=[str(exc)],
            )
        timeout_seconds = max(1, min(int(timeout_seconds), 30))
        if not self.docker_image or not _docker_image_available(self.docker_image):
            return ToolResult(
                tool="local_binary_replay",
                target=str(source),
                status="missing",
                evidence=["configured ForgeFlag Docker tool image is unavailable"],
            )

        with tempfile.TemporaryDirectory(prefix="forgeflag-replay-") as tmp:
            replay_dir = Path(tmp)
            binary = replay_dir / "challenge"
            shutil.copy2(source, binary)
            binary.chmod(0o500)
            for name, content in normalized_fixtures.items():
                fixture = replay_dir / name
                fixture.write_bytes(content)
                fixture.chmod(0o400)

            argv = [
                "docker",
                "run",
                "--rm",
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
                "-i",
                "-v",
                f"{replay_dir}:/challenge:ro",
                "-w",
                "/challenge",
                self.docker_image,
                "./challenge",
            ]
            try:
                completed = subprocess.run(
                    argv,
                    input=payload,
                    capture_output=True,
                    timeout=timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                return ToolResult(
                    tool="local_binary_replay",
                    target=str(source),
                    status="timeout",
                    evidence=[f"timed out after {exc.timeout} seconds", "network=none"],
                )
            except OSError as exc:
                return ToolResult(
                    tool="local_binary_replay",
                    target=str(source),
                    status="error",
                    evidence=[str(exc)],
                )

        stdout, stdout_truncated = _decode_limited(completed.stdout, 32_768)
        stderr, stderr_truncated = _decode_limited(completed.stderr, 32_768)
        return ToolResult(
            tool="local_binary_replay",
            target=str(source),
            status="success" if completed.returncode == 0 else "error",
            evidence=[
                f"returncode={completed.returncode}",
                f"docker_image={self.docker_image}",
                "network=none",
                "filesystem=read_only",
                f"stdin_bytes={len(payload)}",
                f"fixture_files={','.join(sorted(normalized_fixtures)) or 'none'}",
            ],
            raw={
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
            },
        )

    def _run_host(
        self,
        spec: ToolSpec,
        argv: list[str],
        target: str | None,
        timeout_seconds: int | None,
    ) -> ToolResult:
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
                tool=spec.name,
                target=target,
                status="timeout",
                evidence=[f"timed out after {exc.timeout} seconds", f"argv={shlex.join(argv)}"],
            )
        except OSError as exc:
            return ToolResult(tool=spec.name, target=target, status="error", evidence=[str(exc)])

        stdout, stdout_truncated = _decode_limited(completed.stdout, spec.max_output_bytes)
        stderr, stderr_truncated = _decode_limited(completed.stderr, spec.max_output_bytes)
        status = "success" if completed.returncode == 0 else "error"
        return ToolResult(
            tool=spec.name,
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

    def _run_docker(
        self,
        spec: ToolSpec,
        argv: list[str],
        target: str | None,
        timeout_seconds: int | None,
    ) -> ToolResult:
        docker_argv = [
            "docker",
            "run",
            "--rm",
            "-e",
            "TERM=xterm",
            "-e",
            f"PATH={DOCKER_TOOL_PATH}",
            "-v",
            f"{self.docker_mount}:/workspace",
            "-w",
            "/workspace",
            self.docker_image,
            *[_docker_arg(arg, self.docker_mount) for arg in argv],
        ]
        try:
            completed = subprocess.run(
                docker_argv,
                cwd=self.cwd,
                capture_output=True,
                timeout=timeout_seconds or spec.default_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                tool=spec.name,
                target=target,
                status="timeout",
                evidence=[f"timed out after {exc.timeout} seconds", f"argv={shlex.join(docker_argv)}"],
            )
        except OSError as exc:
            return ToolResult(tool=spec.name, target=target, status="error", evidence=[str(exc)])

        stdout, stdout_truncated = _decode_limited(completed.stdout, spec.max_output_bytes)
        stderr, stderr_truncated = _decode_limited(completed.stderr, spec.max_output_bytes)
        status = "success" if completed.returncode == 0 else "error"
        return ToolResult(
            tool=spec.name,
            target=target,
            status=status,
            evidence=[
                f"returncode={completed.returncode}",
                f"docker_image={self.docker_image}",
                f"argv={shlex.join(docker_argv)}",
            ],
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


def _normalized_fixture_files(fixtures: dict[str, bytes | str]) -> dict[str, bytes]:
    normalized: dict[str, bytes] = {}
    total_bytes = 0
    for raw_name, raw_content in fixtures.items():
        name = str(raw_name)
        if not name or name in {".", ".."} or Path(name).name != name or "/" in name or "\\" in name:
            raise ValueError(f"fixture filename must be a simple basename: {name!r}")
        content = raw_content.encode("utf-8") if isinstance(raw_content, str) else bytes(raw_content)
        total_bytes += len(content)
        if len(content) > 65_536 or total_bytes > 131_072:
            raise ValueError("fixture files exceed the bounded replay size limit")
        normalized[name] = content
    return normalized


def _load_project_tool_env(start: Path) -> dict[str, str]:
    for directory in (start.expanduser().resolve(), *start.expanduser().resolve().parents):
        env_path = directory / ".forgeflag" / "docker.env"
        if env_path.is_file():
            return _read_simple_env(env_path)
    return {}


def _read_simple_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in {"FORGEFLAG_TOOL_DOCKER_IMAGE", "FORGEFLAG_TOOL_DOCKER_MOUNT"}:
            continue
        try:
            parts = shlex.split(value, posix=True)
        except ValueError:
            continue
        values[key] = parts[0] if parts else ""
    return values


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


def _docker_image_available(image: str) -> bool:
    if not image or shutil.which("docker") is None:
        return False
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _docker_available_commands(image: str, executables: set[str]) -> set[str]:
    if not executables or not image or shutil.which("docker") is None:
        return set()
    script = "for c in \"$@\"; do command -v \"$c\" >/dev/null 2>&1 && printf '%s\\n' \"$c\"; done"
    try:
        completed = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-e",
                f"PATH={DOCKER_TOOL_PATH}",
                image,
                "sh",
                "-c",
                script,
                "sh",
                *sorted(executables),
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if completed.returncode != 0:
        return set()
    return {line.strip() for line in completed.stdout.decode("utf-8", errors="replace").splitlines() if line.strip()}


def _docker_command_available(image: str, executable: str) -> bool:
    return executable in _docker_available_commands(image, {executable})


def _docker_arg(arg: str, mount: Path) -> str:
    resolved_mount = mount.expanduser().resolve()
    if "=" in arg:
        prefix, value = arg.split("=", 1)
        rewritten = _docker_arg(value, resolved_mount)
        if rewritten != value:
            return f"{prefix}={rewritten}"
    raw_path = Path(arg).expanduser()
    if not raw_path.is_absolute():
        return arg
    try:
        path = raw_path.resolve()
    except OSError:
        return arg
    try:
        relative = path.relative_to(resolved_mount)
    except ValueError:
        return arg
    return str(Path("/workspace") / relative)
