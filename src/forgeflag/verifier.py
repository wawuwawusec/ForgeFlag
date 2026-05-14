from __future__ import annotations

import re
from dataclasses import dataclass

from forgeflag.domain import Finding


FLAG_PATTERN = re.compile(r"(?i)\b(?:flag|ctf)\{[^{}\s]{3,128}\}")


@dataclass(frozen=True)
class VerificationResult:
    accepted: tuple[str, ...]
    rejected: tuple[str, ...]


class Verifier:
    def verify(self, findings: list[Finding], candidates: tuple[str, ...]) -> VerificationResult:
        accepted: list[str] = []
        rejected: list[str] = []
        evidence_text = " ".join(str(f.evidence) for f in findings)
        for candidate in candidates:
            if FLAG_PATTERN.search(candidate) and candidate in evidence_text:
                accepted.append(candidate)
            else:
                rejected.append(candidate)
        return VerificationResult(tuple(accepted), tuple(rejected))

