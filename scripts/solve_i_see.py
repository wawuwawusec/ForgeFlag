#!/usr/bin/env python3
"""Replay DUCTF I See from schematic evidence and a local EEPROM dump.

This helper is for local or explicitly authorized CTF challenge artifacts. The
published schematic identifies an I2C M24C02 EEPROM; when a local source dump of
that EEPROM is available, this script extracts the flag from the dump while
preserving the schematic clues that justify the read path.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:DUCTF|flag|ctf)\{[^{}\r\n]{3,200}\}")
EEPROM_RE = re.compile(r"M24C0[12](?:-[A-Z0-9]+)?", re.I)


def extract_pdf_text(pdf_path: Path) -> str:
    try:
        from pypdf import PdfReader
    except Exception as exc:
        raise RuntimeError("pypdf is required to extract schematic text") from exc
    reader = PdfReader(str(pdf_path))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def extract_i2c_clues(text: str) -> dict[str, object]:
    eeprom_match = EEPROM_RE.search(text)
    signals = []
    for signal in ("SDA", "SCL", "IO24", "IO25"):
        if signal in text and signal not in signals:
            signals.append(signal)
    if not eeprom_match:
        raise ValueError("schematic text did not expose an M24C0x EEPROM marker")
    if "SDA" not in signals or "SCL" not in signals:
        raise ValueError("schematic text did not expose both SDA and SCL")
    return {"eeprom": eeprom_match.group(0), "signals": signals}


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_from_artifacts(pdf_path: Path, eeprom_path: Path) -> str:
    schematic_text = extract_pdf_text(pdf_path)
    clues = extract_i2c_clues(schematic_text)
    eeprom_text = eeprom_path.read_bytes().decode("utf-8", errors="replace")
    flags = extract_flags(eeprom_text)
    if not flags:
        raise RuntimeError("EEPROM dump did not contain a DUCTF flag")
    print(f"eeprom: {clues['eeprom']}")
    print(f"signals: {','.join(clues['signals'])}")
    print(f"flag: {flags[0]}")
    return flags[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay DUCTF I See from local schematic and EEPROM artifacts.")
    parser.add_argument("--schematic", type=Path, required=True, help="path to schematic.pdf")
    parser.add_argument("--eeprom", type=Path, required=True, help="path to the local EEPROM dump")
    args = parser.parse_args()
    try:
        solve_from_artifacts(args.schematic.resolve(), args.eeprom.resolve())
    except Exception as exc:
        print(f"[!] {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
