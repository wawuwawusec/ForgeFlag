from __future__ import annotations

import re


FLAG_PATTERN = re.compile(
    r"(?i)(?:^|(?<![A-Za-z0-9_])|(?<=\\n)|(?<=\\r))"
    r"(?:[A-Za-z0-9_]{0,20}ctf|flag|f1ag|htb|ductf|svibrg|grey|spirit|pcl)\{[^{}\r\n]{3,160}\}"
)

EMBEDDED_GENERIC_FLAG_PATTERN = re.compile(r"(?i)(?:flag|f1ag)\{[^{}\r\n]{3,160}\}")


def extract_flags(text: str) -> tuple[str, ...]:
    seen: set[str] = set()
    flags: list[str] = []
    for pattern in (FLAG_PATTERN, EMBEDDED_GENERIC_FLAG_PATTERN):
        for match in pattern.finditer(text):
            candidate = match.group(0)
            if candidate not in seen:
                seen.add(candidate)
                flags.append(candidate)
    return tuple(flags)
