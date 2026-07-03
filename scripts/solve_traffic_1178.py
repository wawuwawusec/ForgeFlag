#!/usr/bin/env python3
"""Solve the 1178 traffic-analysis PCAP.

The capture records a Laravel Ignition compromise, a webshell session that
recovers Cobalt Strike keys, and Beacon HTTP traffic containing the flag.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.Hash import HMAC, SHA256
    from Crypto.PublicKey import RSA
except ImportError as exc:  # pragma: no cover - environment guard
    raise SystemExit("pycryptodome is required: python3 -m pip install pycryptodome") from exc


UUID_FLAG_RE = re.compile(rb"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}")
ZIP_PASSWORD = b"P4Uk6qkh6Gvqwg3y"


def run_tshark(pcap: Path, *fields: str, display_filter: str = "") -> list[list[str]]:
    cmd = ["tshark", "-r", str(pcap)]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields", "-E", "separator=|"]
    for field in fields:
        cmd += ["-e", field]
    proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
    return [line.split("|") for line in proc.stdout.splitlines() if line]


def extract_pcap(input_path: Path, workdir: Path) -> Path:
    if input_path.suffix.lower() in {".pcap", ".pcapng"}:
        return input_path
    with zipfile.ZipFile(input_path) as zf:
        names = [name for name in zf.namelist() if name.lower().endswith((".pcap", ".pcapng"))]
        if not names:
            raise RuntimeError(f"no pcap/pcapng found in {input_path}")
        out = workdir / Path(names[0]).name
        out.write_bytes(zf.read(names[0]))
        return out


def http_file_data_blobs(pcap: Path) -> list[bytes]:
    blobs: list[bytes] = []
    for row in run_tshark(pcap, "http.file_data", display_filter="http.file_data"):
        if not row or not row[0]:
            continue
        try:
            blobs.append(bytes.fromhex(row[0].replace(":", "")))
        except ValueError:
            continue
    return blobs


def recover_beacon_keys(blobs: list[bytes]) -> bytes:
    for blob in blobs:
        pk_offset = blob.find(b"PK\x03\x04")
        if pk_offset < 0 or b"cobaltstrike.beacon_keys" not in blob:
            continue
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(blob[pk_offset:])
            tmp.flush()
            with zipfile.ZipFile(tmp.name) as zf:
                return zf.read(".cobaltstrike.beacon_keys", pwd=ZIP_PASSWORD)
    raise RuntimeError("could not recover .cobaltstrike.beacon_keys from HTTP objects")


def rsa_private_key_from_java_serialized_keys(data: bytes) -> RSA.RsaKey:
    # The Cobalt Strike key file is a Java serialized KeyPair. The private key is
    # embedded as a PKCS#8 DER blob after the 0x30820277 ASN.1 sequence header.
    marker = b"\x30\x82\x02\x77"
    offset = data.find(marker)
    if offset < 0:
        raise RuntimeError("PKCS#8 private key marker not found")
    der_len = int.from_bytes(data[offset + 2 : offset + 4], "big") + 4
    return RSA.import_key(data[offset : offset + der_len])


def first_beacon_cookie(pcap: Path) -> str:
    rows = run_tshark(
        pcap,
        "http.cookie",
        display_filter='http.request.uri contains "en_US/all.js" && http.cookie',
    )
    for row in rows:
        if row and row[0]:
            return row[0]
    raise RuntimeError("Beacon metadata cookie not found")


def decrypt_metadata(cookie: str, key: RSA.RsaKey) -> bytes:
    ciphertext = __import__("base64").b64decode(cookie)
    metadata = PKCS1_v1_5.new(key).decrypt(ciphertext, b"")
    if not metadata.startswith(b"\x00\x00\xbe\xef"):
        raise RuntimeError("decrypted metadata did not start with Beacon magic")
    return metadata


def derive_beacon_keys(raw_key: bytes) -> tuple[bytes, bytes]:
    digest = SHA256.new(raw_key).digest()
    return digest[:16], digest[16:]


def decrypt_beacon_packet(blob: bytes, aes_key: bytes, hmac_key: bytes) -> bytes | None:
    if len(blob) < 36:
        return None
    declared_len = int.from_bytes(blob[:4], "big")
    if declared_len == len(blob) - 4:
        blob = blob[4:]
    encrypted, expected_mac = blob[:-16], blob[-16:]
    if len(encrypted) % AES.block_size:
        return None
    actual_mac = HMAC.new(hmac_key, encrypted, SHA256).digest()[:16]
    if actual_mac != expected_mac:
        return None
    return AES.new(aes_key, AES.MODE_CBC, b"\x00" * 16).decrypt(encrypted)


def recover_flag_from_plaintext(plaintext: bytes) -> str | None:
    match = UUID_FLAG_RE.search(plaintext)
    if not match:
        return None
    uuid_part = match.group(0).decode()

    # The final callback output uses the same simple byte transform as the
    # tasking markers around the Beacon packet: the 4 bytes before "{uuid}" are
    # "flag" xor "mnop". Reconstruct the complete on-disk flag.txt content.
    prefix = plaintext[max(0, match.start() - 4) : match.start()]
    if len(prefix) == 4 and bytes(byte ^ key for byte, key in zip(prefix, b"mnop")) == b"flag":
        return "flag" + uuid_part
    return uuid_part


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="challenge zip, pcap, or pcapng")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="forgeflag-traffic-1178-") as tmp:
        pcap = extract_pcap(args.capture, Path(tmp))
        blobs = http_file_data_blobs(pcap)
        key_file = recover_beacon_keys(blobs)
        private_key = rsa_private_key_from_java_serialized_keys(key_file)

        metadata = decrypt_metadata(first_beacon_cookie(pcap), private_key)
        raw_key = metadata[8:24]
        aes_key, hmac_key = derive_beacon_keys(raw_key)
        text_offset = metadata.find(b"DESKTOP-")
        host_user_proc = metadata[text_offset:].split(b"\t")[:3] if text_offset >= 0 else []

        print(f"beacon_raw_key={raw_key.hex()}")
        if host_user_proc:
            print("metadata=" + " | ".join(part.decode("latin1", "replace") for part in host_user_proc))

        for blob in blobs:
            plaintext = decrypt_beacon_packet(blob, aes_key, hmac_key)
            if not plaintext:
                continue
            flag = recover_flag_from_plaintext(plaintext)
            if flag:
                print(f"flag={flag}")
                return 0

    raise RuntimeError("no flag found in decrypted Beacon traffic")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
