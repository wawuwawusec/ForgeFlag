#!/usr/bin/env python3
"""Replay IrisCTF accessible-sesamum-indicum against a local challenge service.

This helper is for local or explicitly authorized CTF challenge artifacts. The
service consumes each submitted line from right to left, so the De Bruijn
sequence is reversed before submission while preserving complete 4-hex coverage.
"""

from __future__ import annotations

import argparse
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path


DEFAULT_ALPHABET = "0123456789abcdef"
FLAG_RE = re.compile(r"(?i)(?:irisctf|flag|ctf)\{[^{}\r\n]{3,200}\}")


def de_bruijn(alphabet: str, subsequence_length: int) -> str:
    """Return a cyclic De Bruijn sequence B(len(alphabet), subsequence_length)."""
    if not alphabet:
        raise ValueError("alphabet must not be empty")
    if subsequence_length <= 0:
        raise ValueError("subsequence length must be positive")

    symbols = list(alphabet)
    k = len(symbols)
    a = [0] * (k * subsequence_length)
    sequence: list[str] = []

    def db(t: int, p: int) -> None:
        if t > subsequence_length:
            if subsequence_length % p == 0:
                sequence.extend(symbols[a[index]] for index in range(1, p + 1))
            return
        a[t] = a[t - p]
        db(t + 1, p)
        for j in range(a[t - p] + 1, k):
            a[t] = j
            db(t + 1, t)

    db(1, 1)
    return "".join(sequence)


def build_attempt_stream(alphabet: str = DEFAULT_ALPHABET, pin_length: int = 4) -> str:
    """Build one line whose right-to-left consumption covers every PIN window."""
    cyclic = de_bruijn(alphabet, pin_length)
    linear = cyclic + cyclic[: pin_length - 1]
    return linear[::-1]


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_local_script(script: Path, cwd: Path, timeout: float = 20.0) -> str:
    proc = subprocess.Popen(
        [sys.executable, "-u", str(script)],
        cwd=str(cwd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    transcript = bytearray()
    attempt_stream = build_attempt_stream()
    try:
        for vault_index in range(16):
            _read_until(proc, transcript, "Attempt> ", timeout)
            _write_line(proc, attempt_stream)
            _read_until(proc, transcript, "You've defeated this vault.", timeout)
            print(f"vault {vault_index + 1}: covered {len(attempt_stream)} right-to-left digits")

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                _read_chunk(proc, max(0.1, deadline - time.monotonic()), transcript)
            except RuntimeError:
                break
            flags = extract_flags(_decode(transcript))
            if flags:
                print(f"flag: {flags[0]}")
                return flags[0]
        flags = extract_flags(_decode(transcript))
        if flags:
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
    parser = argparse.ArgumentParser(description="Replay IrisCTF accessible-sesamum-indicum against a local CTF service.")
    parser.add_argument("--local-script", type=Path, required=True, help="path to the provided chal.py")
    parser.add_argument("--cwd", type=Path, help="working directory containing flag.txt; defaults to script parent")
    parser.add_argument("--timeout", type=float, default=20.0)
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
