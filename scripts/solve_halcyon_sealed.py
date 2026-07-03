#!/usr/bin/env python3
"""Solve the Halcyon sealed build challenge.

Usage:
    python3 scripts/solve_halcyon_sealed.py \
        /Users/5haw0/Downloads/halcyon_ota_ledger.json \
        /Users/5haw0/Downloads/halcyon_release_signing.pub.pem \
        /Users/5haw0/Downloads/halcyon_eng_build_3.5.0-rc1.sealed
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


def inv(x: int) -> int:
    return pow(x % P256_ORDER, -1, P256_ORDER)


def recover_private_key(ledger: dict) -> int:
    seen: dict[int, dict] = {}
    for release in ledger["releases"]:
        r = int(release["signature"]["r"], 16)
        if r not in seen:
            seen[r] = release
            continue

        first = seen[r]
        second = release
        s1 = int(first["signature"]["s"], 16)
        s2 = int(second["signature"]["s"], 16)
        z1 = int(first["signed_sha256"], 16) % P256_ORDER
        z2 = int(second["signed_sha256"], 16) % P256_ORDER

        k = ((z1 - z2) * inv(s1 - s2)) % P256_ORDER
        d = ((s1 * k - z1) * inv(r)) % P256_ORDER
        print(f"[+] reused ECDSA r in versions {first['version']} and {second['version']}")
        print(f"[+] recovered nonce k = {k:064x}")
        print(f"[+] recovered private scalar d = {d:064x}")
        return d

    raise ValueError("no repeated ECDSA r value found")


def check_public_key(d: int, public_key_path: Path) -> None:
    recovered_pub = ec.derive_private_key(d, ec.SECP256R1()).public_key()
    expected_pub = serialization.load_pem_public_key(public_key_path.read_bytes())

    if recovered_pub.public_numbers() != expected_pub.public_numbers():
        raise ValueError("recovered private scalar does not match public key")
    print("[+] recovered scalar matches release public key")


def decrypt_sealed(d: int, sealed_path: Path) -> bytes:
    data = sealed_path.read_bytes()
    if len(data) < 12 + 16:
        raise ValueError("sealed file too short")

    # The challenge's seal format is deliberately bare: AES-256-GCM with
    # nonce || tag || ciphertext, keyed by SHA256(private_scalar_32_bytes).
    key = hashlib.sha256(d.to_bytes(32, "big")).digest()
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    return AESGCM(key).decrypt(nonce, ciphertext + tag, None)


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(f"usage: {argv[0]} ledger.json release.pub.pem build.sealed", file=sys.stderr)
        return 2

    ledger_path = Path(argv[1])
    public_key_path = Path(argv[2])
    sealed_path = Path(argv[3])

    ledger = json.loads(ledger_path.read_text())
    d = recover_private_key(ledger)
    check_public_key(d, public_key_path)
    plaintext = decrypt_sealed(d, sealed_path)
    print("[+] sealed plaintext:")
    print(plaintext.decode("utf-8", errors="replace"))

    match = re.search(rb"SVIUSCG\{[^}]+\}", plaintext)
    if match:
        print("[+] flag:", match.group(0).decode())
        return 0

    print("[-] no flag-like token found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
