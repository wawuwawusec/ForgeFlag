from __future__ import annotations

from dataclasses import dataclass
import re

from forgeflag.domain import Finding
from forgeflag.flags import FLAG_PATTERN


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
            if _is_template_or_placeholder_flag(candidate):
                rejected.append(candidate)
            elif FLAG_PATTERN.search(candidate) and candidate in evidence_text:
                accepted.append(candidate)
            elif _is_evidence_marked_recovered_input(findings, candidate):
                accepted.append(candidate)
            else:
                rejected.append(candidate)
        return VerificationResult(tuple(accepted), tuple(rejected))


def _is_template_or_placeholder_flag(candidate: str) -> bool:
    inner_match = re.search(r"\{(?P<body>.*)\}", candidate)
    if not inner_match:
        return False
    inner = inner_match.group("body").lower()
    markers = (
        "name_of_",
        "building_name",
        "name_of_building",
        "name_of_structure",
        "password123",
        "answer1",
        "dummy_flag",
        "dummy flag",
        "testflag",
        "testingflag",
        "testing flag",
        "test_flag",
        "test flag",
        "placeholder",
        "fake_flag",
        "fake flag",
        "fakeflag",
        "not_the_real_flag",
        "not_the_real_thing",
        "not-a-real-flag",
        "real_flag_on_instance",
        "flag_goes_here",
        "flaggoeshere",
        "flag goes here",
        "censored",
        "example",
    )
    if any(marker in inner for marker in markers):
        return True
    if inner in {"flag", "test", "fake", "xyz", "todo", "flaggoeshere", "...", "…"}:
        return True
    if "redacted" in inner:
        return True
    # handout template bodies; exact matches only, because real flags may
    # legitimately end in _flag (e.g. raw_pcap_payload_flag)
    if inner in {
        "decoded_flag",
        "decrypted_flag",
        "recovered_flag",
        "real_flag",
        "redacted_flag",
        "the_flag",
        "original_flag",
        "this_is_the_flag",
        "this_is_the_original_flag",
        "thisistheflag",
        "sample_flag",
        "your_flag",
    }:
        return True
    if "xxxx" in inner:
        return True
    if re.fullmatch(r"(?:\[\d+\]_?)+", inner):
        return True
    if re.fullmatch(r"\[[^\]]{2,40}\](?:\+|\{[\d,]+\}|\*)?", inner):
        # handout regex templates like CTF{[0-9a-zA-Z_@!?-]+}
        return True
    if re.search(r"\bchr\s*\(", inner):
        return True
    return False


def _is_evidence_marked_recovered_input(findings: list[Finding], candidate: str) -> bool:
    if not candidate or FLAG_PATTERN.search(candidate):
        return False
    for finding in findings:
        if finding.solver != "ReverseSolver":
            continue
        if _evidence_contains_recovered_value(finding.evidence, candidate):
            return True
    return False


def _evidence_contains_recovered_value(value: object, candidate: str) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in {"recovered_input", "accepted_input"} and nested == candidate:
                return True
            if key == "accepted_inputs" and isinstance(nested, list) and candidate in nested:
                return True
            if _evidence_contains_recovered_value(nested, candidate):
                return True
    elif isinstance(value, list):
        return any(_evidence_contains_recovered_value(item, candidate) for item in value)
    return False
