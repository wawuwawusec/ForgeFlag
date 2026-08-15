#!/usr/bin/env python3
"""Report captured flag candidates for an already-run benchmark challenge.

The capability benchmark replays this after the platform run to collect every
flag the product's own solvers surfaced (accepted candidates, findings
evidence, tool transcripts). Used as the replay step for real-challenge
manifests so the scorecard reflects genuine auto-solving.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request

sys.path.insert(0, "src")

from forgeflag.flags import extract_flags_generic  # noqa: E402


def get_json(base_url: str, path: str) -> dict | list:
    with urllib.request.urlopen(f"{base_url.rstrip('/')}{path}", timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit flag candidates captured by the ForgeFlag run")
    parser.add_argument("challenge_id")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    args = parser.parse_args()

    captured: list[str] = []
    try:
        report = get_json(args.url, f"/api/challenges/{args.challenge_id}/report")
    except Exception:
        report = {}
    try:
        findings = get_json(args.url, f"/api/challenges/{args.challenge_id}/findings")
    except Exception:
        findings = []
    try:
        summary = get_json(args.url, f"/api/challenges/{args.challenge_id}/summary")
    except Exception:
        summary = {}

    haystack = json.dumps({"report": report, "findings": findings, "summary": summary}, ensure_ascii=False)
    accepted = summary.get("accepted_flags") if isinstance(summary, dict) else None
    if isinstance(accepted, list):
        captured.extend(str(flag) for flag in accepted)
    captured.extend(extract_flags_generic(haystack))
    seen: set[str] = set()
    for flag in captured:
        if flag not in seen:
            seen.add(flag)
            print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
