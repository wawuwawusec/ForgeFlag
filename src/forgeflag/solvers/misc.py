from __future__ import annotations

from pathlib import Path

from forgeflag.archive_analysis import analyze_archive
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.hash_analysis import hash_summary_from_text
from forgeflag.image import analyze_png_ihdr
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
from forgeflag.transforms import candidates_to_payload, transform_candidates


class MiscSolver:
    name = "MiscSolver"
    supported_categories = {ChallengeCategory.MISC}

    def solve(self, context: SolverContext) -> SolverResult:
        image_findings = self._analyze_image_attachments(context)
        if image_findings:
            return SolverResult(self.name, context.challenge.challenge_id, "ok", tuple(image_findings))

        archive_findings = self._analyze_archive_attachments(context)
        if archive_findings:
            return SolverResult(self.name, context.challenge.challenge_id, "ok", tuple(archive_findings))

        text = "\n".join(_text_inputs(context))
        hash_summary = hash_summary_from_text(text)
        if hash_summary["candidates"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed misc hash candidates",
                evidence={"hashes": hash_summary},
                hypothesis="Misc text or attachment content contains hash-like values that should be triaged before generic transforms.",
                confidence=0.64,
                next_action="Choose a likely mode, prepare a challenge-scoped wordlist, then run hashcat or John only when requested.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        candidates = transform_candidates(text)
        flags = extract_flags("\n".join(candidate.value for candidate in candidates))
        if candidates:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Decoded misc transform candidates",
                evidence={"transform_candidates": candidates_to_payload(candidates)},
                hypothesis=_transform_hypothesis(flags),
                confidence=0.8 if flags else 0.54,
                next_action=_transform_next_action(flags),
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if flags else "ok",
                (finding,),
                flags,
            )

        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Misc solver placeholder registered",
            evidence={"planned_adapters": ["archive triage", "encoding detection", "osint-style CTF artifact parsing"]},
            hypothesis="Future implementation should route unusual artifacts into the closest specialist workflow.",
            confidence=0.35,
            next_action="Implement archive, encoding, and puzzle triage.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))

    def _analyze_image_attachments(self, context: SolverContext) -> list[Finding]:
        findings: list[Finding] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = Path(ctf.ensure_existing_file(attachment_path))
            except FileNotFoundError:
                continue
            png_ihdr = analyze_png_ihdr(resolved)
            if not png_ihdr:
                continue
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed misc image artifact",
                evidence={
                    "artifact": {"name": resolved.name, "path": str(resolved)},
                    "png_ihdr": png_ihdr,
                },
                hypothesis="Misc image puzzle has PNG structure evidence that should be inspected before broader puzzle triage.",
                confidence=0.72,
                next_action="Open the repaired PNG, then inspect visible hints, channels, and bit planes.",
            )
            context.notebook.add_finding(finding)
            findings.append(finding)
        return findings

    def _analyze_archive_attachments(self, context: SolverContext) -> list[Finding]:
        findings: list[Finding] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = Path(ctf.ensure_existing_file(attachment_path))
            except FileNotFoundError:
                continue
            archive = analyze_archive(resolved)
            if not archive:
                continue
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed misc archive artifact",
                evidence={
                    "artifact": {"name": resolved.name, "path": str(resolved)},
                    "archive": archive,
                },
                hypothesis="Misc archive puzzle has structured entries that should be inspected before broader puzzle triage.",
                confidence=0.66,
                next_action=_archive_next_action(archive),
            )
            context.notebook.add_finding(finding)
            findings.append(finding)
        return findings


def _text_inputs(context: SolverContext) -> list[str]:
    challenge = context.challenge
    values = [
        challenge.title or "",
        challenge.description or "",
        " ".join(challenge.tags),
    ]
    for attachment_path in challenge.attachment_paths:
        try:
            resolved = ctf.ensure_existing_file(attachment_path)
        except FileNotFoundError:
            continue
        try:
            raw = Path(resolved).read_bytes()[:64_000]
        except OSError:
            continue
        values.append(raw.decode("utf-8", errors="ignore"))
    return [value for value in values if value.strip()]


def _transform_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "A reversible transform chain produced a flag-like token."
    return "Misc challenge text contains encoded data that should guide the next puzzle step."


def _transform_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send decoded candidates to Verifier and preserve the transform recipe."
    return "Inspect transform candidates, then route to crypto, archive, or stego follow-up."


def _archive_next_action(archive: dict[str, object]) -> str:
    if archive.get("encrypted"):
        return "Collect password hints before attempting archive extraction."
    return "Inspect interesting archive entries and extract only into a managed artifact workspace."
