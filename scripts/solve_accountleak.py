#!/usr/bin/env python3
"""Replay the TJCTF accountleak RSA proof against a local challenge service.

This helper is for local or explicitly authorized CTF services. It starts the
provided `server.py`, reads the public RSA values and shifted factor leak,
recovers the password offline, then submits it back to the same local process.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:tjctf|flag|ctf)\{[^{}\r\n]{3,160}\}")


def recover_password(ciphertext: int, modulus: int, shifted_product: int, max_shift: int = 1 << 20) -> tuple[int, int, int, int]:
    """Recover RSA plaintext from n=pq and leak=(p-s)(q-s), where s is small."""
    for shift in range(1, max_shift):
        numerator = modulus + shift * shift - shifted_product
        if numerator % shift:
            continue
        factor_sum = numerator // shift
        discriminant = factor_sum * factor_sum - 4 * modulus
        if discriminant < 0:
            continue
        root = math.isqrt(discriminant)
        if root * root != discriminant:
            continue
        p = (factor_sum + root) // 2
        q = (factor_sum - root) // 2
        if p <= 1 or q <= 1 or p * q != modulus:
            continue
        if (p - shift) * (q - shift) != shifted_product:
            continue
        phi = (p - 1) * (q - 1)
        private_exponent = pow(65537, -1, phi)
        password = pow(ciphertext, private_exponent, modulus)
        return password, p, q, shift
    raise ValueError("could not recover shifted RSA factors within bound")


def parse_public_values(line: str) -> tuple[int, int]:
    match = re.search(r"powerful numbers,\s*(\d+)\s+and\s+(\d+)", line)
    if not match:
        raise ValueError(f"could not parse ciphertext/modulus line: {line!r}")
    return int(match.group(1)), int(match.group(2))


def parse_shifted_product(transcript: str) -> int:
    match = re.search(r"i'll send coords\s*\n<Bobby>\s*(\d+)\s*\n<Bobby>\s*oop wasnt", transcript)
    if not match:
        raise ValueError("could not parse shifted factor leak")
    return int(match.group(1))


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_local_script(script: Path, cwd: Path, timeout: float = 8.0) -> str:
    proc = subprocess.Popen(
        [sys.executable, "-u", str(script)],
        cwd=str(cwd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    transcript = bytearray()
    try:
        _read_until(proc, transcript, "powerful numbers", timeout)
        ciphertext, modulus = parse_public_values(_decode(transcript))
        _read_until(proc, transcript, "diamond stash", timeout)
        _write_line(proc, "yea")
        _read_until(proc, transcript, "coords", timeout)
        _read_until(proc, transcript, "oop wasnt", timeout)
        shifted_product = parse_shifted_product(_decode(transcript))
        _read_until(proc, transcript, "crack my account", timeout)
        password, _, _, shift = recover_password(ciphertext, modulus, shifted_product)
        _write_line(proc, str(password))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _read_chunk(proc, max(0.1, deadline - time.monotonic()), transcript)
            flags = extract_flags(_decode(transcript))
            if flags:
                print(f"shift: {shift}")
                print(f"flag: {flags[0]}")
                return flags[0]
        raise RuntimeError("service transcript ended without a flag")
    finally:
        try:
            proc.kill()
        except OSError:
            pass


def _read_until(proc: subprocess.Popen[bytes], transcript: bytearray, needle: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    needle_bytes = needle.encode()
    while time.monotonic() < deadline:
        if needle_bytes in transcript:
            return
        _read_chunk(proc, max(0.1, deadline - time.monotonic()), transcript)
        if needle_bytes in transcript:
            return
    raise TimeoutError(f"timed out waiting for {needle!r}")


def _read_chunk(proc: subprocess.Popen[bytes], timeout: float, transcript: bytearray) -> None:
    if proc.stdout is None:
        raise RuntimeError("subprocess stdout is closed")
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        raise TimeoutError("timed out reading local challenge output")
    chunk = os.read(proc.stdout.fileno(), 4096)
    if chunk == b"":
        raise RuntimeError("local challenge exited before producing expected output")
    transcript.extend(chunk)


def _write_line(proc: subprocess.Popen[bytes], line: str) -> None:
    if proc.stdin is None:
        raise RuntimeError("subprocess stdin is closed")
    proc.stdin.write((line + "\n").encode())
    proc.stdin.flush()


def _decode(transcript: bytearray) -> str:
    return bytes(transcript).decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay TJCTF accountleak against a local/authorized CTF service.")
    parser.add_argument("--local-script", type=Path, required=True, help="path to the provided server.py")
    parser.add_argument("--cwd", type=Path, help="working directory containing flag.txt; defaults to script parent")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    script = args.local_script.resolve()
    cwd = (args.cwd or script.parent).resolve()
    try:
        solve_local_script(script, cwd, timeout=args.timeout)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
