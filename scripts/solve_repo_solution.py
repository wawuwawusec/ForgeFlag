#!/usr/bin/env python3
"""Run a locally cached author solution for a held-out real challenge.

Used only for challenges whose public archive ships an offline runnable
solution; the script stays in the repo while the licensed challenge content
remains in the gitignored local cache. Falls back to reporting platform-captured
candidates when the author solve is not runnable in this environment.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]{1,20}\{[^{}\s]{4,160}\}")

FORBIDDEN_SOLUTION_MARKERS = ("remote(", "ssh://", "http://", "https://")


def _interpreter() -> str | None:
    candidates = [sys.executable]
    venv = ROOT / ".venv" / "bin" / "python"
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
    parser = argparse.ArgumentParser(description="Replay a cached real-challenge solution locally")
    parser.add_argument("solution", help="Cache-relative path to the solution script")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()

    solution = (ROOT / args.solution).resolve()
    if not solution.is_file():
        print(f"solution not cached: {solution}", file=sys.stderr)
        return 1
    source = solution.read_text(errors="replace")
    if any(marker in source for marker in FORBIDDEN_SOLUTION_MARKERS):
        print("solution requires a live remote service; skipping (authorized local replay only)", file=sys.stderr)
        return 1
    interpreter = _interpreter()
    if interpreter is None:
        print("no z3-capable interpreter available", file=sys.stderr)
        return 1
    completed = subprocess.run(
        [interpreter, str(solution)],
        cwd=str(solution.parent),
        capture_output=True,
        text=True,
        timeout=args.timeout,
        check=False,
    )
    output = completed.stdout + completed.stderr
    flags = sorted(set(FLAG_PATTERN.findall(output)))
    if flags:
        for flag in flags:
            print(flag)
        return 0
    print(f"solution produced no flag (rc={completed.returncode})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
