from __future__ import annotations

from forgeflag.ctf_scope import ctf_scope_evidence
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.solvers.base import SolverContext
from forgeflag.tools.http_probe import HttpProbeTool


class ReconSolver:
    name = "ReconSolver"
    supported_categories = set(ChallengeCategory)

    def solve(self, context: SolverContext) -> SolverResult:
        challenge = context.challenge
        findings: list[Finding] = []
        flag_candidates: list[str] = []

        category_hint = challenge.category.value
        if challenge.category == ChallengeCategory.UNKNOWN:
            category_hint = infer_category(challenge.tags, challenge.description or "", challenge.target)

        finding = Finding(
            challenge_id=challenge.challenge_id,
            solver=self.name,
            finding=f"Initial triage suggests category={category_hint}",
            evidence={
                "tags": list(challenge.tags),
                "target": challenge.target,
                "ctf_scope": ctf_scope_evidence(ChallengeCategory.RECON),
            },
            hypothesis=f"Dispatch specialist solver for {category_hint}",
            confidence=0.55 if category_hint == "unknown" else 0.75,
            next_action="Run the matching specialist solver and collect evidence.",
        )
        context.notebook.add_finding(finding)
        findings.append(finding)

        text_flags = extract_flags(_challenge_text(challenge))
        if text_flags:
            flag_candidates.extend(text_flags)
            text_finding = Finding(
                challenge_id=challenge.challenge_id,
                solver=self.name,
                finding="Found flag-like token in challenge text",
                evidence={
                    "flag_candidates": list(text_flags),
                    "source": "title/description/tags/target",
                    "matching_lines": _matching_flag_lines(_challenge_text(challenge)),
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.RECON),
                },
                hypothesis="The challenge text itself contains a complete flag-like token or proof candidate.",
                confidence=0.86,
                next_action="Verify whether the text candidate is the intended flag, then record the shortest reproduction path.",
            )
            context.notebook.add_finding(text_finding)
            findings.append(text_finding)

        if challenge.target and challenge.target.startswith(("http://", "https://")) and context.scope.active_probe:
            tool_result = HttpProbeTool(context.scope).run(challenge.target)
            context.notebook.add_tool_result(challenge.challenge_id, tool_result)
            probe_finding = Finding(
                challenge_id=challenge.challenge_id,
                solver=self.name,
                finding="HTTP target probe completed",
                evidence={
                    "tool": tool_result.tool,
                    "status": tool_result.status,
                    "evidence": tool_result.evidence,
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.RECON),
                },
                hypothesis="HTTP metadata can guide web challenge strategy.",
                confidence=0.7 if tool_result.status == "success" else 0.35,
                next_action="Inspect routes, forms, and application-specific behavior.",
            )
            context.notebook.add_finding(probe_finding)
            findings.append(probe_finding)

        return SolverResult(
            solver=self.name,
            challenge_id=challenge.challenge_id,
            status="flag_candidate" if flag_candidates else "ok",
            findings=tuple(findings),
            flag_candidates=tuple(dict.fromkeys(flag_candidates)),
        )


def infer_category(tags: tuple[str, ...], description: str, target: str | None) -> str:
    haystack = " ".join([*tags, description, target or ""]).lower()
    if any(token in haystack for token in ("http", "web", "login", "xss", "sqli", "ssti")):
        return ChallengeCategory.WEB.value
    if any(token in haystack for token in ("elf", "libc", "rop", "pwn")):
        return ChallengeCategory.PWN.value
    if any(token in haystack for token in ("apk", "reverse", "reversing", "ghidra")):
        return ChallengeCategory.REVERSE.value
    if any(token in haystack for token in ("rsa", "aes", "crypto", "cipher")):
        return ChallengeCategory.CRYPTO.value
    if any(token in haystack for token in ("pcap", "forensic", "memory", "stego")):
        return ChallengeCategory.FORENSICS.value
    return ChallengeCategory.UNKNOWN.value


def _challenge_text(challenge) -> str:
    return "\n".join(
        value
        for value in (
            challenge.title or "",
            challenge.description or "",
            " ".join(challenge.tags),
            challenge.target or "",
        )
        if value.strip()
    )


def _matching_flag_lines(text: str, limit: int = 6) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines():
        if extract_flags(line):
            lines.append(line.strip()[:220])
        if len(lines) >= limit:
            break
    return lines
