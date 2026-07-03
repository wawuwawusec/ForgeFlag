#!/usr/bin/env python3
"""Replay NUS Greyhats filefactory as a local archive/PNG repair proof.

This helper is for local or explicitly authorized CTF challenge artifacts. The
handout is named `flag.pdf` but is a ZIP archive containing `flag.png`; that PNG
starts with `JESS` instead of the normal PNG signature. After repairing the
magic bytes, the image shows a handwritten flag that still requires visual
transcription rather than pretending OCR is fully automatic.
"""

from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path


PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MANGLED_MAGIC = b"JESS\r\n\x1a\n"
DEFAULT_VISUAL_TRANSCRIPTION = "grey{these_files_are_kinda_weird_but_im_weirder}"
FLAG_RE = re.compile(r"(?i)(?:grey|flag|ctf)\{[^{}\r\n]{3,300}\}")
PLACEHOLDER_MARKERS = ("TEST_FLAG", "FLAG_FOR_TESTING", "DUMMY", "PLACEHOLDER")


def is_mangled_png(data: bytes) -> bool:
    return data.startswith(MANGLED_MAGIC) and data[12:16] == b"IHDR"


def repair_png_signature(data: bytes) -> bytes:
    if not is_mangled_png(data):
        raise ValueError("input does not look like JESS-mangled PNG data")
    return PNG_MAGIC + data[len(PNG_MAGIC) :]


def normalize_visual_transcription(text: str) -> str:
    text = text.strip()
    flags = extract_flags(text)
    if flags:
        return flags[0]
    body = re.sub(r"[^A-Za-z0-9]+", "_", text.lower()).strip("_")
    return f"grey{{{body}}}"


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if any(marker in candidate.upper() for marker in PLACEHOLDER_MARKERS):
            continue
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_archive(archive_path: Path, output_dir: Path, visual_transcription: str = DEFAULT_VISUAL_TRANSCRIPTION) -> str:
    if not archive_path.exists():
        raise FileNotFoundError(f"missing challenge archive: {archive_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as zf:
        names = zf.namelist()
        if "flag.png" not in names:
            raise RuntimeError(f"flag.png not found in archive entries: {names}")
        raw = zf.read("flag.png")
    repaired = repair_png_signature(raw)
    repaired_path = output_dir / "filefactory-repaired-flag.png"
    repaired_path.write_bytes(repaired)
    flag = normalize_visual_transcription(visual_transcription)
    print("challenge: filefactory")
    print("artifact: archive flag.pdf containing flag.png")
    print("archive_type: zip")
    print("mangled_magic: JESS...IHDR")
    print(f"repaired_png: {repaired_path}")
    print("method: repair PNG signature, then visually transcribe the handwritten flag")
    print(f"visual_transcription: {flag}")
    print(f"flag: {flag}")
    return flag


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay NUS filefactory from local CTF artifacts.")
    parser.add_argument("--archive", type=Path, required=True, help="challenge flag.pdf ZIP archive")
    parser.add_argument("--output-dir", type=Path, default=Path(".forgeflag/artifacts/filefactory"))
    parser.add_argument("--visual-transcription", default=DEFAULT_VISUAL_TRANSCRIPTION)
    args = parser.parse_args()
    try:
        solve_archive(args.archive.resolve(), args.output_dir.resolve(), visual_transcription=args.visual_transcription)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
