#!/usr/bin/env python3
"""Solve the Battle1/Battle2 visual-cipher challenge.

The two PNGs are 1-bit visual-cryptography shares. XORing their pixels reveals
the battle scene, the ciphertext, and the instruction line.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image


DEFAULT_CIPHERTEXT = "XFOK XKEK XKDK"
PLAINTEXT_QUOTE = "VENI VIDI VICI"
AUTHOR = "JULIUS CAESAR"


def xor_images(path1: Path, path2: Path, out_path: Path) -> None:
    img1 = Image.open(path1).convert("1")
    img2 = Image.open(path2).convert("1")
    if img1.size != img2.size:
        raise ValueError(f"image sizes differ: {img1.size} != {img2.size}")

    data1 = img1.tobytes()
    data2 = img2.tobytes()
    xored = bytes(a ^ b for a, b in zip(data1, data2))

    revealed = Image.frombytes("1", img1.size, xored)
    revealed.save(out_path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("battle1", nargs="?", default="/Users/5haw0/Downloads/Battle1.png")
    parser.add_argument("battle2", nargs="?", default="/Users/5haw0/Downloads/Battle2.png")
    parser.add_argument("--out", default="/tmp/battle_revealed.png")
    args = parser.parse_args()

    out_path = Path(args.out)
    xor_images(Path(args.battle1), Path(args.battle2), out_path)

    print(f"[+] revealed image: {out_path}")
    print(f"[+] visible ciphertext: {DEFAULT_CIPHERTEXT}")
    print(f"[+] deciphered quote: {PLAINTEXT_QUOTE}")
    print(f"[+] quotation author: {AUTHOR}")
    print(f"[+] flag: SVIUSCG{{{AUTHOR.replace(' ', '_')}}}")


if __name__ == "__main__":
    main()
