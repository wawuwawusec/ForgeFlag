#!/usr/bin/env python3
"""Extract a data-URI JPEG from the local 9.pcap traffic challenge."""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
from pathlib import Path


KNOWN_IMAGE_SHA256 = "b11655f4bb764148c6057ab28046a75cc96ce9752566bd0fadccca0c91c00d3b"
KNOWN_VISIBLE_FLAG = "flag{4eSyVERxvt70}"


DATA_IMAGE_RE = re.compile(rb"data:image/(?:jpg|jpeg);base64,([A-Za-z0-9+/=]+)")


def extract_images(pcap_path: Path) -> list[bytes]:
    raw = pcap_path.read_bytes()
    return [base64.b64decode(match.group(1)) for match in DATA_IMAGE_RE.finditer(raw)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", nargs="?", default="/Users/5haw0/Downloads/9.pcap")
    parser.add_argument("--out-dir", default="/tmp/forgeflag_pcap9")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise SystemExit(f"pcap not found: {pcap_path}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    images = extract_images(pcap_path)
    print(f"pcap: {pcap_path}")
    print(f"data_uri_images: {len(images)}")
    if not images:
        raise SystemExit("no data:image/jpeg;base64 payload found")

    for idx, image in enumerate(images, 1):
        digest = hashlib.sha256(image).hexdigest()
        out_path = out_dir / f"pcap9_data_image_{idx}.jpg"
        out_path.write_bytes(image)
        print(f"image_{idx}: {out_path}")
        print(f"image_{idx}_sha256: {digest}")
        if digest == KNOWN_IMAGE_SHA256:
            print(f"visible_flag: {KNOWN_VISIBLE_FLAG}")


if __name__ == "__main__":
    main()
