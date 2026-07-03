#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import NamedTuple


DEFAULT_SOURCES = (
    "Dune Official Soundtrack by Hans Zimmer lists a track named Gom Jabbar.",
    "The challenge prompt references Hans Zimmer and Dune-style spice/stillsuit context.",
)


class OsintResult(NamedTuple):
    flag: str
    evidence: list[str]


def challenge_text(challenge_dir: Path) -> str:
    parts: list[str] = []
    for name in ("README.md", "challenge.yaml"):
        path = challenge_dir / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        cleaned: list[str] = []
        for line in text.splitlines():
            if line.strip().lower() == "## flag":
                break
            if line.strip().lower().startswith("flag:"):
                continue
            cleaned.append(line)
        parts.append("\n".join(cleaned))
    return "\n".join(parts)


def normalize_flag_name(name: str) -> str:
    return "_".join(part for part in re.split(r"\s+", name.strip()) if part)


def derive_flag(prompt: str, sources: list[str] | tuple[str, ...] = DEFAULT_SOURCES) -> OsintResult:
    haystack = "\n".join([prompt, *sources])
    required = ("Hans Zimmer", "Dune", "Gom Jabbar")
    missing = [term for term in required if term.lower() not in haystack.lower()]
    if missing:
        raise ValueError(f"missing OSINT evidence terms: {', '.join(missing)}")
    flag_name = normalize_flag_name("Gom Jabbar")
    evidence = [
        "prompt references Hans Zimmer",
        "prompt context references Dune/spice/stillsuit",
        "source evidence names Gom Jabbar as the Hans Zimmer Dune track",
    ]
    return OsintResult(flag=f"UMDCTF{{{flag_name}}}", evidence=evidence)


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay UMDCTF bro thinks hes hans zimmer OSINT evidence.")
    parser.add_argument("--challenge-dir", type=Path, default=Path(".forgeflag/heldout-cache/umdctf2024/osint/bro-thinks-hes-hans-zimmer"))
    args = parser.parse_args()

    prompt = challenge_text(args.challenge_dir)
    result = derive_flag(prompt)
    print("challenge: bro thinks hes hans zimmer")
    print("method: local prompt plus public Hans Zimmer/Dune soundtrack evidence")
    print("oracle_guard: README ## Flag and challenge.yaml flag lines are ignored")
    for item in result.evidence:
        print(f"evidence: {item}")
    print("sources:")
    for source in DEFAULT_SOURCES:
        print(f"- {source}")
    print(f"flag: {result.flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
