from __future__ import annotations

import os
import re


FLAG_PATTERN = re.compile(
    r"(?i)(?:^|(?<![A-Za-z0-9_])|(?<=\\n)|(?<=\\r))"
    r"(?:[A-Za-z0-9_]{0,20}ctf|flag|f1ag|htb|ductf|svibrg|grey|spirit|pcl|sekai|dice|cor|csaw|wctf|actf|bctf)\{[^{}\r\n]{3,160}\}"
)

# Generic fallback: any short word-like prefix with a non-trivial body catches
# competitions whose flag prefix has not been seen yet — new events mint fresh
# prefixes every season and a commercial client must not need a code change
# for each one.
GENERIC_FLAG_PATTERN = re.compile(
    r"(?i)(?:^|(?<![A-Za-z0-9_>])|(?<=\\n)|(?<=\\r))"
    r"([a-z][a-z0-9_]{1,15})\{([^{}\r\n]*[a-z0-9][^{}\r\n]*[a-z0-9][^{}\r\n]*)\}"
)

EMBEDDED_GENERIC_FLAG_PATTERN = re.compile(r"(?i)(?:flag|f1ag)\{[^{}\r\n]{3,160}\}")

# Code-like braces that must not be reported as flags.
_GENERIC_EXCLUDED_PREFIXES = frozenset(
    {
        "background",
        "border",
        "bottom",
        "case",
        "class",
        "color",
        "def",
        "display",
        "font",
        "for",
        "function",
        "height",
        "if",
        "key",
        "label",
        "left",
        "margin",
        "name",
        "padding",
        "right",
        "size",
        "style",
        "switch",
        "top",
        "type",
        "url",
        "value",
        "while",
        "width",
    }
)


def _extra_prefixes() -> frozenset[str]:
    raw = os.environ.get("FORGEFLAG_FLAG_PREFIXES", "")
    return frozenset(prefix.strip().lower() for prefix in raw.split(",") if prefix.strip())


def extract_flags(text: str) -> tuple[str, ...]:
    """Conservative extraction used inside solver candidate scoring."""
    seen: set[str] = set()
    flags: list[str] = []
    for pattern in (FLAG_PATTERN, EMBEDDED_GENERIC_FLAG_PATTERN):
        for match in pattern.finditer(text):
            candidate = match.group(0)
            if candidate not in seen:
                seen.add(candidate)
                flags.append(candidate)
    return tuple(flags)


def extract_flags_generic(text: str) -> tuple[str, ...]:
    """Broad extraction for replay transcripts and raw tool output.

    Adds unknown competition prefixes (any short word-like prefix with a
    non-trivial body) on top of the conservative set, because a commercial
    client must capture flags from events whose prefix it has never seen.
    """
    flags = list(extract_flags(text))
    seen = set(flags)
    extra = _extra_prefixes()
    for match in GENERIC_FLAG_PATTERN.finditer(text):
        prefix = match.group(1).lower()
        if prefix in _GENERIC_EXCLUDED_PREFIXES and prefix not in extra:
            continue
        if "flag" in prefix or "f1ag" in prefix:
            # mangled variants of the canonical flag prefix are already
            # captured by FLAG_PATTERN / EMBEDDED_GENERIC_FLAG_PATTERN
            continue
        candidate = match.group(0)
        if candidate not in seen:
            seen.add(candidate)
            flags.append(candidate)
    return tuple(flags)
