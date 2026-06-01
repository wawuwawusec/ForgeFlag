from __future__ import annotations

import re
from typing import Any


HASH_PATTERNS: tuple[tuple[str, re.Pattern[str], int | None, str | None, float], ...] = (
    ("bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{40,60}"), 3200, "bcrypt", 0.9),
    ("sha512crypt", re.compile(r"\$6\$[^\s:]{1,32}\$[./A-Za-z0-9]{40,100}"), 1800, "sha512crypt", 0.9),
    ("sha256", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])"), 1400, "raw-sha256", 0.78),
    ("sha1", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])"), 100, "raw-sha1", 0.78),
    ("md5_or_ntlm", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])"), 0, "raw-md5", 0.68),
)


def hash_summary_from_text(text: str, limit: int = 40) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for hash_type, pattern, hashcat_mode, john_format, confidence in HASH_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            key = (hash_type, value)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "type": hash_type,
                    "value": value,
                    "hashcat_mode": hashcat_mode,
                    "john_format": john_format,
                    "confidence": confidence,
                }
            )
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break

    hashcat_modes = [
        candidate["hashcat_mode"]
        for candidate in candidates
        if candidate["hashcat_mode"] is not None
    ]
    john_formats = [
        candidate["john_format"]
        for candidate in candidates
        if candidate["john_format"]
    ]
    return {
        "candidates": candidates,
        "hashcat_modes": list(dict.fromkeys(hashcat_modes)),
        "john_formats": list(dict.fromkeys(john_formats)),
        "recommended_tools": ["hashcat", "john"] if candidates else [],
    }
