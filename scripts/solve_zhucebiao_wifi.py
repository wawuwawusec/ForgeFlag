#!/usr/bin/env python3
"""Recover the connected Wi-Fi SSID from a UTF-16LE Windows .reg export."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


WIRELESS_VALUE_RE = re.compile(
    r"\\NetworkList\\Nla\\Wireless\\[^\]]+\]\s+@=\"([0-9A-Fa-f]+)\"",
    re.MULTILINE,
)
PROFILE_NAME_RE = re.compile(r'"ProfileName"="([^"]+)"')


def read_reg(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or b"\x00" in raw[:128]:
        return raw.decode("utf-16le")
    return raw.decode("utf-8", errors="replace")


def decode_ssid_hex(hex_text: str) -> str:
    return bytes.fromhex(hex_text).decode("utf-8", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("reg", nargs="?", default="/Users/5haw0/Downloads/zhucebiao.reg")
    args = parser.parse_args()

    reg_path = Path(args.reg)
    if not reg_path.exists():
        raise SystemExit(f"registry export not found: {reg_path}")

    text = read_reg(reg_path)
    wireless = [decode_ssid_hex(match.group(1)) for match in WIRELESS_VALUE_RE.finditer(text)]
    profiles = PROFILE_NAME_RE.findall(text)
    wifi_names = [name for name in wireless if name in profiles]
    if not wifi_names:
        wifi_names = wireless
    if not wifi_names:
        raise SystemExit("no NetworkList\\Nla\\Wireless SSID found")

    ssid = wifi_names[0]
    print(f"wireless_ssid: {ssid}")
    print(f"profile_names: {', '.join(profiles)}")
    print(f"flag: flag{{{ssid.replace(' ', '')}}}")


if __name__ == "__main__":
    main()
