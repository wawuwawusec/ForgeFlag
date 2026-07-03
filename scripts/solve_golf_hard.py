#!/usr/bin/env python3
"""Replay TJCTF golf-hard against the local challenge service.

This helper is for local or explicitly authorized CTF challenge artifacts. It
starts the provided `golf.py`, supplies compact recursive PCRE/regex patterns,
and captures the flag from the service transcript. The helper injects a tiny
`tabulate` shim in a temporary working directory because the table formatting
dependency is irrelevant to the verifier logic.
"""

from __future__ import annotations

import argparse
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:tjctf|flag|ctf)\{[^{}\r\n]{3,200}\}")


def challenge_patterns() -> list[str]:
    return [
        "^a",
        r"^(x*)(x*)-\1=\2$",
        r"^(<(?1)*>)+$",
        r"^((.)(?1)\2|.?)$",
        r"^(x*).(x(?2)\1|=)$",
    ]


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_local_service(golf_script: Path, challenge_dir: Path, flag_path: Path, timeout: float = 20.0) -> str:
    with tempfile.TemporaryDirectory(prefix="forgeflag-golf-hard-") as tmpdir:
        workdir = Path(tmpdir)
        shutil.copytree(challenge_dir, workdir / "challenges")
        shutil.copy2(golf_script, workdir / "golf.py")
        shutil.copy2(flag_path, workdir / "flag.txt")
        (workdir / "tabulate.py").write_text(
            "def tabulate(rows, headers, disable_numparse=True, tablefmt='simple'):\n"
            "    return '\\n'.join(' | '.join('' if cell is None else str(cell) for cell in row) for row in rows)\n",
            encoding="utf-8",
        )

        proc = subprocess.Popen(
            [sys.executable, "-u", "golf.py"],
            cwd=str(workdir),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        transcript = bytearray()
        try:
            for pattern in challenge_patterns():
                _read_until(proc, transcript, "> ", timeout)
                _write_line(proc, pattern)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    _read_chunk(proc, max(0.1, deadline - time.monotonic()), transcript)
                except RuntimeError:
                    break
                flags = extract_flags(_decode(transcript))
                if flags:
                    print(f"patterns: {len(challenge_patterns())}")
                    print(f"flag: {flags[0]}")
                    return flags[0]
            flags = extract_flags(_decode(transcript))
            if flags:
                print(f"patterns: {len(challenge_patterns())}")
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
    start = len(transcript)
    while time.monotonic() < deadline:
        if needle_bytes in transcript[start:]:
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
    parser = argparse.ArgumentParser(description="Replay TJCTF golf-hard against a local CTF service.")
    parser.add_argument("--golf-script", type=Path, required=True, help="path to the provided golf.py")
    parser.add_argument("--challenge-dir", type=Path, required=True, help="path to the challenge levels directory")
    parser.add_argument("--flag", type=Path, required=True, help="path to the local challenge flag.txt read by golf.py")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    try:
        solve_local_service(
            args.golf_script.resolve(),
            args.challenge_dir.resolve(),
            args.flag.resolve(),
            timeout=args.timeout,
        )
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
