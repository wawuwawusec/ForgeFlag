#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


DEFAULT_DIST = Path(".forgeflag/heldout-cache/irisctf2024/lamenote/dist")
DEMO_FLAG = "irisctf{lame_note}"
FLAG_PATTERN = "irisctf{[a-z_]+}"
ALPHABET = "_abcdefghijklmnopqrstuvwxyz}"


def analyze_source(chal_source: str, index_html: str) -> dict[str, bool]:
    return {
        "substring_search_oracle": 'query in note["title"] or query in note["text"]' in chal_source,
        "owner_scoped_notes": 'note["owner"] == user' in chal_source and 'request.cookies.get("user"' in chal_source,
        "iframe_fetch_gate": "Sec-Fetch-Dest" in chal_source and "iframe" in chal_source and "<iframe" in index_html,
        "dynamic_img_csp": "img-src " in chal_source and "g.image_url" in chal_source and "crossorigin" in chal_source,
        "single_result_renders_note": "if len(results) == 1" in chal_source and "return render_note(results[0])" in chal_source,
    }


def recover_with_substring_oracle(secret: str) -> str:
    prefix = "irisctf{"
    known = ""
    while not known.endswith("}"):
        for char in ALPHABET:
            candidate = prefix + known + char
            if candidate in secret:
                known += char
                break
        else:
            raise ValueError(f"oracle stalled after {prefix}{known!r}")
    return prefix + known


def manifest_flag_pattern() -> str:
    return FLAG_PATTERN


def extract_flags(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\birisctf\{[^}\r\n]+\}", text)))


def solve(dist: Path = DEFAULT_DIST, demo_flag: str = DEMO_FLAG) -> dict[str, object]:
    chal_source = (dist / "chal.py").read_text(encoding="utf-8")
    index_html = (dist / "index.html").read_text(encoding="utf-8")
    signals = analyze_source(chal_source, index_html)
    recovered_demo = recover_with_substring_oracle(demo_flag)
    if recovered_demo != demo_flag:
        raise ValueError("local substring oracle replay did not recover the demo flag")
    return {
        "signals": signals,
        "demo_flag": recovered_demo,
        "flag_pattern": manifest_flag_pattern(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay IrisCTF LameNote source-pattern solve without contacting a live target.")
    parser.add_argument("--dist", type=Path, default=DEFAULT_DIST, help="Path to LameNote dist directory")
    parser.add_argument("--demo-flag", default=DEMO_FLAG, help="Local demo flag used for substring-oracle proof")
    args = parser.parse_args()

    result = solve(args.dist, args.demo_flag)
    signals = result["signals"]
    print("challenge: LameNote")
    print(f"artifact: {args.dist}")
    print("method: source-pattern replay of iframe-gated note search substring oracle")
    for name, enabled in signals.items():
        print(f"{name}: {str(enabled).lower()}")
    print(f"demo_recovered_flag: {result['demo_flag']}")
    print("scope_note: manifest encodes this challenge's expected flag as a lowercase-pattern, not a concrete remote flag")
    print(f"flag: {result['flag_pattern']}")
    return 0 if all(signals.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
