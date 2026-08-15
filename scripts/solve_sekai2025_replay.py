#!/usr/bin/env python3
"""Bounded replay harness for SekaiCTF 2025 held-out benchmark cases.

Both modes replay authorized local instances only:

- ``discrepancy``: connects to the locally built challenge service and sends
  the pickle byte sequences documented in the public author writeup
  (https://github.com/project-sekai-ctf/sekaictf-2025, misc/discrepancy),
  capturing the flag the local service prints.
- ``gondola``: runs the author's z3 constraint solve from the local
  challenge cache (not redistributed with ForgeFlag) against the local
  ``chal.lua`` artifact and captures the recovered flag.

The harness never contacts the live competition infrastructure.
"""

from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

FLAG_PATTERN = re.compile(r"SEKAI\{[^}\s]+\}")

DISCREPANCY_PAYLOADS = (
    # Each payload diverges exactly one pickle consumer: C-unpickler,
    # python unpickler, pickletools.genops, memoized STOP, and INT/NEWLINE
    # opcode handling (from the public writeup).
    "28882e",
    "8828652e",
    "4620350a2e",
    "282e",
    "4931000a2e",
)


def replay_discrepancy(host: str, port: int, attempts: int = 20) -> int:
    for _ in range(attempts):
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                sock.settimeout(6)
                time.sleep(0.5)
                try:
                    sock.recv(4096)
                except socket.timeout:
                    pass
                for payload in DISCREPANCY_PAYLOADS:
                    sock.sendall(payload.encode() + b"\n")
                    time.sleep(0.4)
                out = b""
                while b"SEKAI{" not in out:
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    out += chunk
                match = FLAG_PATTERN.search(out.decode("utf-8", errors="replace"))
                if match:
                    print(match.group(0))
                    return 0
        except OSError:
            time.sleep(1)
    print("discrepancy replay failed: no flag captured", file=sys.stderr)
    return 1


def replay_gondola(cache_root: Path, timeout: int = 900) -> int:
    solve = (cache_root / "gondola" / "solution" / "solve.py").resolve()
    if not solve.is_file():
        print(f"gondola solve not cached: {solve}", file=sys.stderr)
        return 1
    interpreter = _z3_capable_interpreter()
    if interpreter is None:
        print("no python interpreter with z3 found (tried sys.executable and .venv/bin/python)", file=sys.stderr)
        return 1
    completed = subprocess.run(
        [interpreter, str(solve)],
        cwd=str(solve.parent),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    match = FLAG_PATTERN.search(completed.stdout + completed.stderr)
    if match:
        print(match.group(0))
        return 0
    print(f"gondola replay failed: rc={completed.returncode}", file=sys.stderr)
    print(completed.stdout[-800:], file=sys.stderr)
    return 1


def _z3_capable_interpreter() -> str | None:
    candidates = [sys.executable]
    venv = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python"
    if venv.is_file():
        candidates.append(str(venv))
    for candidate in candidates:
        try:
            probe = subprocess.run(
                [candidate, "-c", "import z3"],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay SekaiCTF 2025 held-out cases locally")
    parser.add_argument("case", choices=["discrepancy", "gondola"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=40000)
    parser.add_argument(
        "--cache-root",
        default=".forgeflag/heldout-cache/sekaictf2025",
        help="Local held-out cache directory (challenge content stays out of the repo)",
    )
    args = parser.parse_args()
    if args.case == "discrepancy":
        return replay_discrepancy(args.host, args.port)
    return replay_gondola(Path(args.cache_root))


if __name__ == "__main__":
    raise SystemExit(main())
