#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from forgeflag.solvers.forensics import analyze_registry_bitlocker_fvestats


def solve(path: Path) -> dict[str, object]:
    analysis = analyze_registry_bitlocker_fvestats(path)
    if not analysis:
        raise RuntimeError("no BitLocker FVEStats registry evidence found")
    return analysis


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recover the babybit VMDK BitLocker FVEStats timeline flag from local CTF evidence."
    )
    parser.add_argument("artifact", type=Path, help="Path to babybit.vmdk or the carved RegistryBackup zip")
    parser.add_argument("--json", action="store_true", help="Print full evidence JSON")
    args = parser.parse_args(argv)

    analysis = solve(args.artifact)
    flags = analysis.get("flag_candidates") or []
    if args.json:
        print(json.dumps(analysis, ensure_ascii=False, indent=2))
    for flag in flags:
        print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
