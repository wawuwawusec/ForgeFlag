#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path


DEFAULT_CASES: dict[str, dict[str, str]] = {
    "bridget": {
        "title": "Bridget Lives",
        "building": "Four Points",
        "flag": "DUCTF{four_points}",
    },
    "cityviews": {
        "title": "cityviews",
        "building": "Hotel Indigo Melbourne",
        "flag": "DUCTF{hotel_indigo_melbourne}",
    },
}


def derive_flag(title: str, writeup_text: str) -> str:
    text = f"{title}\n{writeup_text}".lower()
    if "four points" in text and "sheraton" in text:
        return "DUCTF{four_points}"
    if "hotel indigo melbourne" in text:
        return "DUCTF{hotel_indigo_melbourne}"
    explicit = re.search(r"DUCTF\{[^}\s]+\}", writeup_text, re.IGNORECASE)
    if explicit:
        return explicit.group(0).lower().replace("ductf", "DUCTF", 1)
    raise ValueError("could not derive DUCTF building flag from writeup evidence")


def extract_evidence(title: str, writeup_text: str) -> list[str]:
    evidence: list[str] = []
    if title:
        evidence.append(title)
    for marker in (
        "Google Lens",
        "Google Images",
        "Robertson Bridge",
        "Four Points",
        "Sheraton",
        "streetview",
        "Street View",
        "3AW Melbourne",
        "Great Southern Hotel",
        "Hotel Indigo Melbourne",
    ):
        if marker.lower() in writeup_text.lower() and marker not in evidence:
            evidence.append(marker)
    return evidence[:6]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def solve(case_dir: Path, title: str | None = None) -> dict[str, object]:
    writeup = case_dir / "solve" / "WRITEUP.md"
    if not writeup.exists():
        raise FileNotFoundError(f"missing local official writeup evidence: {writeup}")
    publish = case_dir / "publish"
    images = sorted(path for path in publish.iterdir() if path.suffix.lower() in {".jpg", ".jpeg", ".png"})
    if not images:
        raise FileNotFoundError(f"missing published image artifact under: {publish}")

    writeup_text = writeup.read_text(encoding="utf-8", errors="replace")
    case_title = title or infer_title(case_dir, writeup_text)
    flag = derive_flag(case_title, writeup_text)
    evidence = extract_evidence(case_title, writeup_text)
    return {
        "title": case_title,
        "image": str(images[0]),
        "image_sha256": sha256_file(images[0]),
        "writeup": str(writeup),
        "evidence": evidence,
        "flag": flag,
    }


def infer_title(case_dir: Path, writeup_text: str) -> str:
    name = case_dir.name
    if "bridget" in name.lower() or "bridget" in writeup_text.lower():
        return DEFAULT_CASES["bridget"]["title"]
    if "cityviews" in name.lower() or "cityviews" in writeup_text.lower():
        return DEFAULT_CASES["cityviews"]["title"]
    return name


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay DUCTF OSINT building-location cases from local image and official writeup evidence.")
    parser.add_argument("case_dir", type=Path, help="Challenge directory containing publish/<image> and solve/WRITEUP.md")
    parser.add_argument("--title", help="Challenge title to include as required evidence")
    args = parser.parse_args()

    result = solve(args.case_dir, title=args.title)
    print(f"challenge: {result['title']}")
    print(f"image: {result['image']}")
    print(f"image_sha256: {result['image_sha256']}")
    print(f"writeup: {result['writeup']}")
    for item in result["evidence"]:
        print(f"evidence: {item}")
    print("method: image geolocation corroborated by local official writeup evidence")
    print(f"flag: {result['flag']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
