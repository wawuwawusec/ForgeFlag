from __future__ import annotations

from pathlib import Path

from forgeflag.archive_analysis import analyze_archive, preview_archive_text
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.hash_analysis import hash_summary_from_text
from forgeflag.image import analyze_image_stego_hints, analyze_png_ihdr
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
from forgeflag.transforms import candidates_to_payload, transform_candidates


class MiscSolver:
    name = "MiscSolver"
    supported_categories = {ChallengeCategory.MISC}

    def solve(self, context: SolverContext) -> SolverResult:
        flag_candidates: list[str] = []
        image_findings = self._analyze_image_attachments(context, flag_candidates)
        if image_findings:
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if flag_candidates else "ok",
                tuple(image_findings),
                tuple(dict.fromkeys(flag_candidates)),
            )

        archive_findings = self._analyze_archive_attachments(context, flag_candidates)
        if archive_findings:
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if flag_candidates else "ok",
                tuple(archive_findings),
                tuple(dict.fromkeys(flag_candidates)),
            )

        text = "\n".join(_text_inputs(context))
        sandbox_finding = _sandbox_serialization_finding(context, text)
        if sandbox_finding:
            context.notebook.add_finding(sandbox_finding)
            return SolverResult(self.name, context.challenge.challenge_id, "ok", (sandbox_finding,))

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

    def _analyze_image_attachments(self, context: SolverContext, flag_candidates: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = Path(ctf.ensure_existing_file(attachment_path))
            except FileNotFoundError:
                continue
            png_ihdr = analyze_png_ihdr(resolved)
            image_stego = analyze_image_stego_hints(resolved)
            flags = extract_flags(_image_text(image_stego))
            if not png_ihdr and not image_stego:
                continue
            flag_candidates.extend(flags)
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed misc image artifact",
                evidence={
                    "artifact": {"name": resolved.name, "path": str(resolved)},
                    "flag_candidates": list(flags),
                    **({"png_ihdr": png_ihdr} if png_ihdr else {}),
                    **({"image_stego": image_stego} if image_stego else {}),
                },
                hypothesis=_image_hypothesis(flags, png_ihdr, image_stego),
                confidence=0.78 if flags else 0.68,
                next_action=_image_next_action(flags, png_ihdr, image_stego),
            )
            context.notebook.add_finding(finding)
            findings.append(finding)
        return findings

    def _analyze_archive_attachments(self, context: SolverContext, flag_candidates: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = Path(ctf.ensure_existing_file(attachment_path))
            except FileNotFoundError:
                continue
            archive = analyze_archive(resolved)
            if not archive:
                continue
            previews = preview_archive_text(resolved)
            flags = extract_flags("\n".join(str(item.get("text_preview", "")) for item in previews))
            flag_candidates.extend(flags)
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed misc archive artifact",
                evidence={
                    "artifact": {"name": resolved.name, "path": str(resolved)},
                    "archive": archive,
                    "archive_text_previews": previews,
                    "flag_candidates": list(flags),
                },
                hypothesis=_archive_hypothesis(flags),
                confidence=0.8 if flags else 0.66,
                next_action=_archive_next_action(archive, flags),
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


def _sandbox_serialization_finding(context: SolverContext, text: str) -> Finding | None:
    lowered = text.lower()
    if "pickle.loads" not in lowered and "pickle.load" not in lowered:
        return None
    if "blacklist" not in lowered and "sandbox" not in lowered:
        return None
    return Finding(
        challenge_id=context.challenge.challenge_id,
        solver=MiscSolver.name,
        finding="Identified misc sandbox serialization pattern",
        evidence={
            "pattern": "pickle blacklist sandbox",
            "evidence_terms": _matched_terms(lowered, ("pickle", "blacklist", "sandbox", "loads")),
            "source_lines": _matching_lines(text, ("pickle", "blacklist", "sandbox", "loads")),
        },
        hypothesis="The attachment uses pickle deserialization inside a blacklist-style sandbox, a common CTF object-chain escape pattern.",
        confidence=0.72,
        next_action="Treat the blacklist as bypassable evidence: inspect allowed globals/opcodes, then build a safe local pickle payload reproduction path.",
    )


def _matched_terms(lowered: str, terms: tuple[str, ...]) -> list[str]:
    return [term for term in terms if term.lower() in lowered]


def _matching_lines(text: str, terms: tuple[str, ...], limit: int = 8) -> list[str]:
    lowered_terms = tuple(term.lower() for term in terms)
    lines: list[str] = []
    for line in text.splitlines():
        if any(term in line.lower() for term in lowered_terms):
            lines.append(line.strip()[:220])
        if len(lines) >= limit:
            break
    return lines


def _transform_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "A reversible transform chain produced a flag-like token."
    return "Misc challenge text contains encoded data that should guide the next puzzle step."


def _transform_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send decoded candidates to Verifier and preserve the transform recipe."
    return "Inspect transform candidates, then route to crypto, archive, or stego follow-up."


def _archive_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "Archive preview content contains a flag-like token."
    return "Misc archive puzzle has structured entries that should be inspected before broader puzzle triage."


def _archive_next_action(archive: dict[str, object], flags: tuple[str, ...] = ()) -> str:
    if flags:
        return "Send archive-derived candidates to Verifier and preserve the archive preview evidence."
    if archive.get("encrypted"):
        return "Collect password hints before attempting archive extraction."
    return "Inspect interesting archive entries and extract only into a managed artifact workspace."


def _image_hypothesis(
    flags: tuple[str, ...],
    png_ihdr: dict[str, object] | None,
    image_stego: dict[str, object] | None,
) -> str:
    if flags:
        return "Image metadata or appended bytes contain a flag-like token."
    if png_ihdr:
        return "Misc image puzzle has PNG structure evidence that should be inspected before broader puzzle triage."
    if image_stego:
        return "Image metadata or structure contains stego-style hints worth inspecting before generic puzzle triage."
    return "Image artifact should be routed to visual and stego follow-up."


def _image_next_action(
    flags: tuple[str, ...],
    png_ihdr: dict[str, object] | None,
    image_stego: dict[str, object] | None,
) -> str:
    if flags:
        return "Send image-derived flag candidates to Verifier and preserve the image evidence path."
    if png_ihdr and png_ihdr.get("repaired_path"):
        return "Open the repaired PNG, then inspect visible hints, channels, and bit planes."
    if image_stego:
        return "Review image text chunks, comments, and trailing bytes before trying low-bit-plane tools."
    return "Inspect transform candidates, then route to crypto, archive, or stego follow-up."


def _image_text(image_stego: dict[str, object] | None) -> str:
    if not image_stego:
        return ""
    values: list[str] = []
    for item in image_stego.get("text_chunks", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
    for item in image_stego.get("comments", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
    for item in image_stego.get("idat_payloads", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
            values.extend(str(flag) for flag in item.get("flag_like_strings", []) if isinstance(flag, str))
    trailing = image_stego.get("trailing_data")
    if isinstance(trailing, dict):
        values.append(str(trailing.get("ascii_preview", "")))
    return "\n".join(values)
