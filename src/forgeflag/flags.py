from __future__ import annotations

import re


FLAG_PATTERN = re.compile(
    r"(?i)(?:^|(?<![A-Za-z0-9_])|(?<=\\n)|(?<=\\r))"
    r"(?:[A-Za-z0-9_]{0,20}ctf|flag|f1ag|htb|ductf|svibrg)\{[^{}\s]{3,128}\}"
)


def extract_flags(text: str) -> tuple[str, ...]:
    seen: set[str] = set()
    flags: list[str] = []
    for match in FLAG_PATTERN.finditer(text):
        candidate = match.group(0)
        if candidate not in seen:
            seen.add(candidate)
            flags.append(candidate)
    return tuple(flags)
