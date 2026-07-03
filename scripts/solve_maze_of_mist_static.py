#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import NamedTuple


DEFAULT_CHALLENGE_DIR = Path(".forgeflag/heldout-cache/htb2024/pwn/[Hard] Maze of Mist")
REQUIRED_ARTIFACTS = ("vmlinuz-linux", "initramfs.cpio.gz", "run.sh", "target")


class MazeStaticReport(NamedTuple):
    technique: str
    can_replay: bool
    missing_artifacts: tuple[str, ...]
    present_artifacts: tuple[str, ...]
    vdso_base: int | None
    gadgets: dict[str, int]
    proof_plan: tuple[str, ...]


def analyze_case_text(readme_text: str, exploit_text: str, present_files: set[str] | frozenset[str]) -> MazeStaticReport:
    present_artifacts = tuple(artifact for artifact in REQUIRED_ARTIFACTS if _artifact_present(artifact, present_files))
    missing_artifacts = tuple(artifact for artifact in REQUIRED_ARTIFACTS if artifact not in present_artifacts)
    vdso_base = _parse_vdso_base(exploit_text)
    gadgets = _parse_exploit_constants(exploit_text, vdso_base)
    technique = _detect_technique(readme_text, exploit_text, vdso_base)
    can_replay = not missing_artifacts
    proof_plan = _proof_plan(technique, missing_artifacts)
    return MazeStaticReport(
        technique=technique,
        can_replay=can_replay,
        missing_artifacts=missing_artifacts,
        present_artifacts=present_artifacts,
        vdso_base=vdso_base,
        gadgets=gadgets,
        proof_plan=proof_plan,
    )


def analyze_challenge_dir(challenge_dir: Path) -> MazeStaticReport:
    readme_text = _read_optional(challenge_dir / "README.md")
    exploit_text = _read_optional(challenge_dir / "htb" / "exploit.py") or _read_optional(challenge_dir / "exploit.py")
    present_files = {
        str(path.relative_to(challenge_dir))
        for path in challenge_dir.rglob("*")
        if path.is_file()
    }
    return analyze_case_text(readme_text, exploit_text, present_files=present_files)


def _artifact_present(artifact: str, present_files: set[str] | frozenset[str]) -> bool:
    return any(path == artifact or path.endswith(f"/{artifact}") for path in present_files)


def _read_optional(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _parse_vdso_base(exploit_text: str) -> int | None:
    match = re.search(r"\bVDSO_BASE_ADDR\s*=\s*(0x[0-9a-fA-F]+|\d+)", exploit_text)
    if not match:
        return None
    return int(match.group(1), 0)


def _parse_exploit_constants(exploit_text: str, vdso_base: int | None) -> dict[str, int]:
    constants: dict[str, int] = {}
    assignment_re = re.compile(r"^\s*([A-Z][A-Z0-9_]+)\s*=\s*(.+?)\s*$", re.MULTILINE)
    for name, expression in assignment_re.findall(exploit_text):
        if name == "VDSO_BASE_ADDR":
            continue
        value = _eval_constant_expression(expression, vdso_base)
        if value is not None:
            constants[name] = value
    return constants


def _eval_constant_expression(expression: str, vdso_base: int | None) -> int | None:
    expression = expression.split("#", 1)[0].strip()
    direct = re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)", expression)
    if direct:
        return int(direct.group(1), 0)
    vdso_offset = re.fullmatch(r"VDSO_BASE_ADDR\s*\+\s*(0x[0-9a-fA-F]+|\d+)", expression)
    if vdso_offset and vdso_base is not None:
        return vdso_base + int(vdso_offset.group(1), 0)
    return None


def _detect_technique(readme_text: str, exploit_text: str, vdso_base: int | None) -> str:
    haystack = f"{readme_text}\n{exploit_text}".lower()
    if "ret2vdso" in haystack or (vdso_base is not None and "syscall" in haystack):
        return "ret2vdso"
    if "vdso" in haystack:
        return "vdso"
    return "unknown"


def _proof_plan(technique: str, missing_artifacts: tuple[str, ...]) -> tuple[str, ...]:
    if missing_artifacts:
        return (
            "recover the original QEMU handout artifacts before accepting a flag",
            "boot the provided rootfs with the provided run.sh instead of trusting writeup/oracle text",
            "extract /target from the rootfs and verify protections, stack layout, and syscall path",
            f"replay the {technique} payload against the local authorized VM and capture /root/flag.txt",
        )
    return (
        "boot the local authorized VM with run.sh",
        "verify /target and VDSO addresses match the exploit evidence",
        f"replay the {technique} payload and capture service-returned flag evidence",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize HTB Maze of Mist ret2vdso evidence and VM handout completeness.")
    parser.add_argument("--challenge-dir", type=Path, default=DEFAULT_CHALLENGE_DIR)
    args = parser.parse_args()

    report = analyze_challenge_dir(args.challenge_dir)
    print("challenge: [Hard] Maze of Mist")
    print(f"artifact_dir: {args.challenge_dir}")
    print(f"technique: {report.technique}")
    print(f"can_replay: {str(report.can_replay).lower()}")
    print(f"present_artifacts: {', '.join(report.present_artifacts) if report.present_artifacts else '(none)'}")
    print(f"missing_artifacts: {', '.join(report.missing_artifacts) if report.missing_artifacts else '(none)'}")
    if report.vdso_base is not None:
        print(f"vdso_base: 0x{report.vdso_base:x}")
    for name, value in sorted(report.gadgets.items()):
        print(f"constant: {name}=0x{value:x}")
    for step in report.proof_plan:
        print(f"proof_plan: {step}")
    return 0 if report.can_replay else 2


if __name__ == "__main__":
    raise SystemExit(main())
