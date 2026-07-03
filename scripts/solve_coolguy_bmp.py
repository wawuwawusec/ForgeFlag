#!/usr/bin/env python3
"""Solve the csictf coolguy.bmp / In Your Eyes stego puzzle.

QuickStego recovers a hex string from the BMP. The hex converts to a
6-bit Braille ASCII bit stream. Braille numeric and brace markers then
normalize to the final flag.
"""

from __future__ import annotations

import argparse
from pathlib import Path


DEFAULT_QUICKSTEGO_HEX = "2471491ED07C69930E8F994E383E415F"

BRAILLE_ASCII = {
    "000000": " ",
    "011101": "!",
    "000010": '"',
    "001111": "#",
    "110101": "$",
    "100101": "%",
    "111101": "&",
    "001000": "'",
    "111011": "(",
    "011111": ")",
    "100001": "*",
    "001101": "+",
    "000001": ",",
    "001001": "-",
    "000101": ".",
    "001100": "/",
    "001011": "0",
    "010000": "1",
    "011000": "2",
    "010010": "3",
    "010011": "4",
    "010001": "5",
    "011010": "6",
    "011011": "7",
    "011001": "8",
    "001010": "9",
    "100011": ":",
    "000011": ";",
    "110001": "<",
    "111111": "=",
    "001110": ">",
    "100111": "?",
    "000100": "@",
    "100000": "A",
    "110000": "B",
    "100100": "C",
    "100110": "D",
    "100010": "E",
    "110100": "F",
    "110110": "G",
    "110010": "H",
    "010100": "I",
    "010110": "J",
    "101000": "K",
    "111000": "L",
    "101100": "M",
    "101110": "N",
    "101010": "O",
    "111100": "P",
    "111110": "Q",
    "111010": "R",
    "011100": "S",
    "011110": "T",
    "101001": "U",
    "111001": "V",
    "010111": "W",
    "101101": "X",
    "101111": "Y",
    "101011": "Z",
    "010101": "[",
    "110011": "\\",
    "110111": "]",
    "000110": "^",
    "000111": "_",
}


def hex_to_braille_ascii(hex_text: str) -> tuple[str, str, list[str]]:
    bits = bin(int(hex_text, 16))[2:]
    if len(bits) % 6:
        raise ValueError(f"bit length {len(bits)} is not divisible by 6")
    groups = [bits[i : i + 6] for i in range(0, len(bits), 6)]
    decoded = "".join(BRAILLE_ASCII[group] for group in groups)
    return bits, decoded, groups


def normalize_braille_ascii(text: str) -> str:
    """Apply the Braille ASCII semantics used by this challenge."""
    out: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("_<", i):
            out.append("{")
            i += 2
        elif text.startswith(".)", i):
            out.append("}")
            i += 2
        elif text[i] == "#" and i + 1 < len(text):
            digits = {"A": "1", "B": "2", "C": "3", "D": "4", "E": "5", "F": "6", "G": "7", "H": "8", "I": "9", "J": "0"}
            nxt = text[i + 1]
            out.append(digits.get(nxt, "#" + nxt))
            i += 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out).lower()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", nargs="?", default="/Users/5haw0/Downloads/coolguy.bmp")
    parser.add_argument("--hex", default=DEFAULT_QUICKSTEGO_HEX, help="hex string recovered by QuickStego")
    args = parser.parse_args()

    image = Path(args.image)
    if not image.exists():
        raise SystemExit(f"image not found: {image}")

    bits, braille_ascii, groups = hex_to_braille_ascii(args.hex.strip())
    flag = normalize_braille_ascii(braille_ascii)

    print(f"image: {image}")
    print(f"quickstego_hex: {args.hex.strip()}")
    print(f"binary: {bits}")
    print(f"groups: {' '.join(groups)}")
    print(f"braille_ascii: {braille_ascii}")
    print(f"flag: {flag}")


if __name__ == "__main__":
    main()
