from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from forgeflag import __version__
from forgeflag.domain import LLMConfig
from forgeflag.safety import ScopePolicy
from forgeflag.tools.runner import ToolRunner
from forgeflag.platform_utils import script_invocation


DOCKER_PROFILES = (
    {
        "name": "forgeflag-volatility",
        "target": "forgeflag-volatility",
        "image": "forgeflag-ctf:volatility",
        "purpose": "Memory forensics and dump triage without bloating the default tool image.",
    },
    {
        "name": "forgeflag-sagemath",
        "target": "forgeflag-sagemath",
        "image": "forgeflag-ctf:sagemath",
        "purpose": "Math-heavy crypto work such as lattices, finite fields, and elliptic curves.",
    },
    {
        "name": "forgeflag-ghidra-headless",
        "target": "forgeflag-ghidra-headless",
        "image": "forgeflag-ctf:ghidra-headless",
        "purpose": "Scripted reverse-engineering exports and headless analysis jobs.",
    },
)

PYTHON_DEPENDENCIES = (
    ("capstone", "capstone"),
    ("cryptography", "cryptography"),
    ("PIL", "Pillow"),
    ("Registry", "python-registry"),
    ("z3", "z3-solver"),
)

CORE_TOOL_WRAPPERS = frozenset({"file", "strings", "tshark"})


def format_system_health(payload: dict[str, Any]) -> str:
    """Render a stable, terminal-friendly health summary without ANSI styling."""
    core = payload.get("core_readiness") if isinstance(payload.get("core_readiness"), dict) else {}
    commercial = (
        payload.get("commercial_readiness")
        if isinstance(payload.get("commercial_readiness"), dict)
        else {}
    )
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    lines = [
        "ForgeFlag doctor",
        f"Core solving readiness: {str(core.get('status') or 'unknown').upper()}",
        f"Commercial readiness: {str(commercial.get('status') or payload.get('status') or 'unknown').upper()}",
        (
            "Checks: "
            f"{counts.get('ok', 0)} ok, "
            f"{counts.get('warnings', 0)} warning, "
            f"{counts.get('errors', 0)} error"
        ),
        "",
    ]
    status_labels = {"ok": "OK", "warning": "WARN", "error": "BLOCK"}
    for check in payload.get("checks", []):
        if not isinstance(check, dict):
            continue
        status = str(check.get("status") or "unknown")
        label = str(check.get("label") or check.get("id") or "Unknown check")
        summary = str(check.get("summary") or "No summary")
        lines.append(f"[{status_labels.get(status, status.upper())}] {label}: {summary}")

    actions = [str(action) for action in payload.get("next_actions", []) if str(action).strip()]
    if actions:
        lines.extend(["", "Next actions:"])
        lines.extend(f"{index}. {action}" for index, action in enumerate(actions, start=1))
    return "\n".join(lines)


def docker_profile_inventory() -> list[dict[str, Any]]:
    docker = shutil.which("docker")
    rows: list[dict[str, Any]] = []
    for profile in DOCKER_PROFILES:
        image = str(profile["image"])
        available = False
        if docker:
            try:
                result = subprocess.run(
                    [docker, "image", "inspect", image],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
                available = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                available = False
        rows.append(
            {
                **profile,
                "available": available,
                "source": "docker" if available else "missing",
                "category": "heavyweight-profile",
                "build_command": (
                    "docker build -f docker/Dockerfile.ctf "
                    f"--target {profile['target']} -t {image} ."
                ),
                "verify_command": f"docker image inspect {image}",
            }
        )
    return rows


def capability_benchmark_path(db_path: Path) -> Path:
    return db_path.parent / "capability-benchmark-latest.json"


def capability_benchmark_history_path(db_path: Path) -> Path:
    return db_path.parent / "capability-benchmark-history.jsonl"


def read_capability_benchmark_history(history_path: Path, limit: int = 20) -> list[dict[str, Any]]:
    if not history_path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in history_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records[-limit:]


def system_health(db_path: Path) -> dict[str, Any]:
    checks = [
        _notebook_health(db_path),
        _python_dependency_health(),
        _tool_health(),
        _docker_profile_health(),
        _benchmark_health(db_path),
        _llm_health(),
    ]
    errors = sum(1 for check in checks if check["status"] == "error")
    warnings = sum(1 for check in checks if check["status"] == "warning")
    status = "blocked" if errors else "limited" if warnings else "ready"
    core_readiness = _core_readiness(checks)
    next_actions = _deduped_health_actions(checks)
    diagnostic_bundle = _diagnostic_bundle(
        db_path=db_path,
        status=status,
        core_readiness=core_readiness,
        checks=checks,
        next_actions=next_actions,
    )
    return {
        "status": status,
        "summary": _commercial_health_summary(status),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "core_readiness": core_readiness,
        "commercial_readiness": {
            "status": status,
            "label": "Commercial readiness",
            "blocking_checks": [check["id"] for check in checks if check["status"] == "error"],
            "warning_checks": [check["id"] for check in checks if check["status"] == "warning"],
        },
        "counts": {
            "checks": len(checks),
            "ok": sum(1 for check in checks if check["status"] == "ok"),
            "warnings": warnings,
            "errors": errors,
        },
        "checks": checks,
        "next_actions": next_actions,
        "diagnostic_bundle": diagnostic_bundle,
    }


def _diagnostic_bundle(
    db_path: Path,
    status: str,
    core_readiness: dict[str, Any],
    checks: list[dict[str, Any]],
    next_actions: list[str],
) -> dict[str, Any]:
    config = LLMConfig.from_env()
    blocking_checks = [str(check["id"]) for check in checks if check.get("status") == "error"]
    warning_checks = [str(check["id"]) for check in checks if check.get("status") == "warning"]
    counts = {
        "checks": len(checks),
        "ok": sum(1 for check in checks if check.get("status") == "ok"),
        "warnings": len(warning_checks),
        "errors": len(blocking_checks),
    }
    support_summary = [
        f"ForgeFlag {__version__} status={status}",
        f"checks ok={counts['ok']} warnings={counts['warnings']} errors={counts['errors']}",
        f"db={db_path}",
        f"llm={config.provider}/{config.model} enabled={config.enabled}",
        f"next_actions={len(next_actions)}",
    ]
    return {
        "bundle_version": 1,
        "service": {
            "name": "ForgeFlag",
            "version": __version__,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "pid": os.getpid(),
            "cwd": str(Path.cwd()),
            "db_path": str(db_path),
        },
        "readiness": {
            "status": status,
            "counts": counts,
            "blocking_checks": blocking_checks,
            "warning_checks": warning_checks,
        },
        "core_readiness": core_readiness,
        "llm": {
            "enabled": config.enabled,
            "provider": config.provider,
            "model": config.model,
            "base_url": config.base_url,
            "api_key_configured": bool(config.api_key),
        },
        "checks": [
            {
                "id": str(check.get("id") or "unknown"),
                "status": str(check.get("status") or "unknown"),
                "summary": str(check.get("summary") or ""),
            }
            for check in checks
        ],
        "next_actions": list(next_actions),
        "support_summary": support_summary,
    }


def _core_readiness(checks: list[dict[str, Any]]) -> dict[str, Any]:
    core_ids = {"notebook", "python_dependencies", "tools", "benchmark"}
    core_checks = [check for check in checks if check.get("id") in core_ids]
    blocking = [str(check["id"]) for check in core_checks if check.get("status") == "error"]
    warnings = [
        str(check["id"])
        for check in core_checks
        if check.get("status") == "warning" and _core_warning_applies(check)
    ]
    status = "blocked" if blocking else "limited" if warnings else "ready"
    return {
        "status": status,
        "label": "Core solving readiness",
        "summary": _core_health_summary(status),
        "blocking_checks": blocking,
        "warning_checks": warnings,
        "check_ids": [str(check.get("id") or "unknown") for check in core_checks],
    }


def _core_warning_applies(check: dict[str, Any]) -> bool:
    if check.get("id") != "tools":
        return True
    details = check.get("details") if isinstance(check.get("details"), dict) else {}
    return bool(details.get("core_missing"))


def _notebook_health(db_path: Path) -> dict[str, Any]:
    exists = db_path.exists()
    return {
        "id": "notebook",
        "label": "Notebook",
        "status": "ok",
        "summary": f"SQLite notebook {'exists' if exists else 'will be initialized'} at {db_path}",
        "next_actions": [],
    }


def _python_dependency_health() -> dict[str, Any]:
    missing = [
        package_name
        for import_name, package_name in PYTHON_DEPENDENCIES
        if importlib.util.find_spec(import_name) is None
    ]
    return {
        "id": "python_dependencies",
        "label": "Python dependencies",
        "status": "error" if missing else "ok",
        "summary": (
            "Python runtime can import all package dependencies"
            if not missing
            else f"Missing Python packages: {', '.join(missing)}"
        ),
        "next_actions": ["python -m pip install -e ."] if missing else [],
        "details": {
            "checked_imports": [import_name for import_name, _ in PYTHON_DEPENDENCIES],
            "missing_packages": missing,
        },
    }


def _tool_health() -> dict[str, Any]:
    wrappers = ToolRunner(ScopePolicy()).inventory()
    missing = [row for row in wrappers if row.get("source") == "missing" or row.get("available") is False]
    missing_names = [str(row.get("name") or "unknown") for row in missing]
    core_missing = [name for name in missing_names if name in CORE_TOOL_WRAPPERS]
    optional_missing = [name for name in missing_names if name not in CORE_TOOL_WRAPPERS]
    status = "error" if core_missing else "warning" if optional_missing else "ok"
    next_actions = []
    if core_missing:
        next_actions.append(script_invocation("forgeflag-tool-smoke"))
        next_actions.append(f"Install missing core host tools or run {script_invocation('forgeflag-control', 'docker-build')}")
    elif optional_missing:
        next_actions.append(script_invocation("forgeflag-control", "docker-build"))
    return {
        "id": "tools",
        "label": "Tool wrappers",
        "status": status,
        "summary": (
            f"{len(wrappers) - len(missing)} available wrappers; "
            f"missing wrappers: {len(missing)}; "
            f"core missing: {len(core_missing)}; optional missing: {len(optional_missing)}"
        ),
        "next_actions": next_actions,
        "details": {
            "total": len(wrappers),
            "core_required": sorted(CORE_TOOL_WRAPPERS),
            "core_missing": core_missing,
            "optional_missing": optional_missing[:12],
            "missing": missing_names[:12],
        },
    }


def _docker_profile_health() -> dict[str, Any]:
    profiles = docker_profile_inventory()
    missing = [row for row in profiles if not row.get("available")]
    return {
        "id": "docker_profiles",
        "label": "Heavyweight Docker profiles",
        "status": "warning" if missing else "ok",
        "summary": f"{len(profiles) - len(missing)} / {len(profiles)} optional heavyweight profiles built",
        "next_actions": [str(row.get("build_command")) for row in missing[:3] if row.get("build_command")],
        "details": {
            "missing": [str(row.get("name") or "unknown") for row in missing],
        },
    }


def _benchmark_health(db_path: Path) -> dict[str, Any]:
    latest = capability_benchmark_path(db_path)
    refresh_command = f"{script_invocation('forgeflag-capability-benchmark', '--output', str(latest), '--history', str(capability_benchmark_history_path(db_path)))}"
    if not latest.exists():
        return {
            "id": "benchmark",
            "label": "Capability benchmark",
            "status": "warning",
            "summary": "No saved capability benchmark scorecard yet",
            "next_actions": [refresh_command],
        }
    try:
        scorecard = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "id": "benchmark",
            "label": "Capability benchmark",
            "status": "error",
            "summary": f"Saved capability benchmark is unreadable: {exc}",
            "next_actions": [refresh_command],
        }
    readiness = scorecard.get("readiness") if isinstance(scorecard, dict) else {}
    readiness_status = str((readiness or {}).get("status") or "unknown")
    status = "ok" if readiness_status == "ready" else "error" if readiness_status == "blocked" else "warning"
    totals = scorecard.get("totals", {}) if isinstance(scorecard, dict) else {}
    return {
        "id": "benchmark",
        "label": "Capability benchmark",
        "status": status,
        "summary": f"readiness={readiness_status}; passed={totals.get('passed', 0)} / {totals.get('cases', 0)}; failed={totals.get('failed', 0)}",
        "next_actions": (readiness or {}).get("next_actions") or ([] if status == "ok" else [refresh_command]),
        "details": {"readiness": readiness, "path": str(latest)},
    }


def _llm_health() -> dict[str, Any]:
    config = LLMConfig.from_env()
    if config.enabled:
        return {
            "id": "llm",
            "label": "LLM runtime",
            "status": "ok",
            "summary": f"{config.provider} {config.model} configured",
            "next_actions": [],
        }
    return {
        "id": "llm",
        "label": "LLM runtime",
        "status": "warning",
        "summary": "LLM runtime is not configured; deterministic solvers still run",
        "next_actions": ["Set FORGEFLAG_LLM_PROVIDER and provider API key or configure it in the Web UI"],
    }


def _commercial_health_summary(status: str) -> str:
    if status == "ready":
        return "commercial-ready: core runtime, tools, benchmark gate, and optional LLM are green"
    if status == "limited":
        return "commercial-limited: core runtime works but release evidence or optional integrations need attention"
    return "commercial-blocked: fix blocking checks before treating this platform as production-ready"


def _core_health_summary(status: str) -> str:
    if status == "ready":
        return "core-ready: notebook, tool wrappers, and capability benchmark are green for CTF solving"
    if status == "limited":
        return "core-limited: refresh the capability benchmark or resolve core warnings before trusting solves"
    return "core-blocked: fix notebook, tool wrapper, or benchmark errors before running challenge work"


def _deduped_health_actions(checks: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()
    for check in checks:
        for action in check.get("next_actions", []):
            if not isinstance(action, str):
                continue
            cleaned = action.strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            actions.append(cleaned)
    return actions[:12]
