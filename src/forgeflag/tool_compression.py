from __future__ import annotations

from dataclasses import replace
import json
import re
from typing import Any

from forgeflag.domain import ToolResult
from forgeflag.flags import extract_flags


_INTERESTING_PATTERNS = (
    "flag",
    "ctf{",
    "f1ag",
    "error",
    "warning",
    "password",
    "secret",
    "key",
    "token",
    "admin",
    "login",
    "http/",
    "get ",
    "post ",
    "dns",
    "tcp",
    "stream",
    "nx ",
    "canary",
    "pie ",
    "relro",
    "gadget",
    "rsa",
)


def compressed_tool_summary(result: ToolResult, max_lines: int = 20, max_chars: int = 4096) -> dict[str, Any]:
    stdout = _text(result.raw.get("stdout") or result.raw.get("sample"))
    stderr = _text(result.raw.get("stderr"))
    combined = "\n".join(part for part in (stdout, stderr, "\n".join(result.evidence)) if part)
    flags = list(extract_flags(combined))[:10]
    interesting = _interesting_lines(combined, max_lines=max_lines)
    errors = _error_lines(stderr or combined, max_lines=8)
    summary: dict[str, Any] = {
        "tool": result.tool,
        "target": result.target,
        "status": result.status,
        "flags": flags,
        "interesting_lines": interesting,
        "errors": errors,
        "next_hints": list(result.next_hints)[:10],
        "truncated": bool(result.raw.get("stdout_truncated") or result.raw.get("stderr_truncated")),
    }
    return _fit_summary(summary, max_chars=max_chars)


def with_compressed_summary(result: ToolResult) -> ToolResult:
    if "compressed_summary" in result.raw:
        return result
    raw = dict(result.raw)
    raw["compressed_summary"] = compressed_tool_summary(result)
    return replace(result, raw=raw)


def _interesting_lines(text: str, max_lines: int) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = _clean_line(raw_line)
        if not line or line in seen:
            continue
        lower = line.lower()
        if _looks_interesting(lower):
            seen.add(line)
            lines.append(line[:300])
            if len(lines) >= max_lines:
                break
    return lines


def _error_lines(text: str, max_lines: int) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = _clean_line(raw_line)
        if not line or line in seen:
            continue
        lower = line.lower()
        if "error" in lower or "warning" in lower or "not found" in lower or "failed" in lower or "timeout" in lower:
            seen.add(line)
            lines.append(line[:300])
            if len(lines) >= max_lines:
                break
    return lines


def _looks_interesting(lower_line: str) -> bool:
    if any(pattern in lower_line for pattern in _INTERESTING_PATTERNS):
        return True
    if re.search(r"\b(?:get|post|put|delete|head|options)\s+/\S*", lower_line):
        return True
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lower_line):
        return True
    return False


def _fit_summary(summary: dict[str, Any], max_chars: int) -> dict[str, Any]:
    fitted = dict(summary)
    while len(json.dumps(fitted, ensure_ascii=False)) > max_chars and fitted.get("interesting_lines"):
        fitted["interesting_lines"] = fitted["interesting_lines"][:-1]
    while len(json.dumps(fitted, ensure_ascii=False)) > max_chars and fitted.get("errors"):
        fitted["errors"] = fitted["errors"][:-1]
    return fitted


def _clean_line(value: str) -> str:
    return " ".join(value.replace("\x00", " ").split())


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""
