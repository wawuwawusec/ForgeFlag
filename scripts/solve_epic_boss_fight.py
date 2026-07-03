#!/usr/bin/env python3
"""Replay NUS Welcome CTF Epic Boss Fight as a local integer-overflow proof.

This helper is for local or explicitly authorized CTF challenge artifacts. It
runs the Linux challenge binary in a local container, repeatedly chooses
"Defend" until the signed 16-bit boss HP overflows below zero, then captures the
flag printed by the local service files.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:grey|flag|ctf)\{[^{}\r\n]{3,300}\}")
PLACEHOLDER_MARKERS = ("TEST_FLAG", "FLAG_FOR_TESTING", "DUMMY", "PLACEHOLDER")


def overflow_defend_count(initial_hp: int = 10000, heal_amount: int = 1000) -> int:
    hp = initial_hp
    count = 0
    while _to_int16(hp) > 0:
        hp += heal_amount
        count += 1
    return count


def build_defend_stream(count: int) -> bytes:
    return b"2\n" * count


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if any(marker in candidate.upper() for marker in PLACEHOLDER_MARKERS):
            continue
        if candidate not in flags:
            flags.append(candidate)
    return flags


def normalize_flag_prefix(flag: str, prefix: str | None) -> str:
    if not prefix:
        return flag
    open_brace = flag.find("{")
    if open_brace < 0:
        return flag
    return f"{prefix}{flag[open_brace:]}"


def solve_challenge_dir(
    challenge_dir: Path,
    image: str = "ubuntu:22.04",
    timeout: float = 20.0,
    emit_prefix: str | None = None,
) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker is required to replay the Linux challenge binary")
    binary = challenge_dir / "challenge"
    flag_file = challenge_dir / "flag.txt"
    if not binary.exists():
        raise FileNotFoundError(f"missing challenge binary: {binary}")
    if not flag_file.exists():
        raise FileNotFoundError(f"missing local flag file: {flag_file}")
    count = overflow_defend_count()
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
        input=build_defend_stream(count),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    text = completed.stdout.decode("utf-8", errors="replace")
    flags = extract_flags(text)
    if not flags:
        raise RuntimeError(f"no non-placeholder flag found in transcript: {text[-400:]!r}")
    service_flag = flags[0]
    normalized = normalize_flag_prefix(service_flag, emit_prefix)
    print(f"defend_count: {count}")
    print("method: signed 16-bit boss HP overflow via repeated defend actions")
    print(f"service_flag: {service_flag}")
    print(f"flag: {normalized}")
    return normalized


def _to_int16(value: int) -> int:
    value &= 0xFFFF
    if value & 0x8000:
        value -= 0x10000
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay NUS Epic Boss Fight from local CTF artifacts.")
    parser.add_argument("--challenge-dir", type=Path, required=True, help="directory containing challenge and flag.txt")
    parser.add_argument("--image", default="ubuntu:22.04", help="Linux container image used to run the ELF")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--emit-prefix", help="also emit the recovered body with this flag prefix")
    args = parser.parse_args()
    try:
        solve_challenge_dir(args.challenge_dir.resolve(), image=args.image, timeout=args.timeout, emit_prefix=args.emit_prefix)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
