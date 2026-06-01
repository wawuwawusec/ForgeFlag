from __future__ import annotations

from pathlib import Path
from typing import Any

from forgeflag.archive_analysis import analyze_archive
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.image import analyze_image_stego_hints, analyze_png_ihdr
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf


class ForensicsSolver:
    name = "ForensicsSolver"
    supported_categories = {ChallengeCategory.FORENSICS}

    def solve(self, context: SolverContext) -> SolverResult:
        challenge = context.challenge
        findings: list[Finding] = []
        flag_candidates: list[str] = []

        if not challenge.attachment_paths:
            finding = Finding(
                challenge_id=challenge.challenge_id,
                solver=self.name,
                finding="Forensics solver awaiting challenge attachments",
                evidence={"planned_adapters": ["file", "strings", "binwalk", "exiftool"]},
                hypothesis="Forensics challenges usually need one or more local artifacts to triage.",
                confidence=0.45,
                next_action="Register challenge attachments under .forgeflag/artifacts and rerun.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(self.name, challenge.challenge_id, "no_attachments", (finding,))

        for attachment_path in challenge.attachment_paths:
            findings.append(self._triage_attachment(context, attachment_path, flag_candidates))

        return SolverResult(
            self.name,
            challenge.challenge_id,
            "flag_candidate" if flag_candidates else "ok",
            tuple(findings),
            tuple(dict.fromkeys(flag_candidates)),
        )

    def _triage_attachment(
        self,
        context: SolverContext,
        attachment_path: str,
        flag_candidates: list[str],
    ) -> Finding:
        challenge_id = context.challenge.challenge_id
        try:
            resolved = ctf.ensure_existing_file(attachment_path)
        except FileNotFoundError as exc:
            finding = Finding(
                challenge_id=challenge_id,
                solver=self.name,
                finding="Forensics attachment unavailable",
                evidence={"attachment_path": attachment_path, "error": str(exc)},
                hypothesis="The attachment path must be registered before local triage can run.",
                confidence=0.2,
                next_action="Check the attachment path and rerun the challenge.",
            )
            context.notebook.add_finding(finding)
            return finding

        labeled_results = [
            ("file", ctf.file_identify(resolved, context.scope)),
            ("strings", ctf.strings_extract(resolved, min_length=4, scope=context.scope)),
            ("binwalk", ctf.binwalk_scan(resolved, context.scope)),
            ("exiftool", ctf.exiftool_read(resolved, context.scope)),
        ]
        for _, result in labeled_results:
            context.notebook.add_tool_result(challenge_id, result)

        combined_output = "\n".join(
            str(result.raw.get("stdout", "")) + "\n" + str(result.raw.get("stderr", ""))
            for _, result in labeled_results
        )
        png_ihdr = analyze_png_ihdr(Path(resolved))
        image_stego = analyze_image_stego_hints(Path(resolved))
        flags = tuple(dict.fromkeys((*extract_flags(combined_output), *extract_flags(_image_text(image_stego)))))
        flag_candidates.extend(flags)
        archive = analyze_archive(resolved)

        finding = Finding(
            challenge_id=challenge_id,
            solver=self.name,
            finding="Triaged forensic attachment",
            evidence={
                "artifact": {
                    "name": Path(resolved).name,
                    "path": resolved,
                },
                "tool_statuses": {label: result.status for label, result in labeled_results},
                "tool_samples": {label: _tool_sample(result) for label, result in labeled_results},
                "flag_candidates": list(flags),
                **({"png_ihdr": png_ihdr} if png_ihdr else {}),
                **({"image_stego": image_stego} if image_stego else {}),
                **({"archive": archive} if archive else {}),
            },
            hypothesis=_forensics_hypothesis(
                flags,
                labeled_results[0][1].status,
                labeled_results[1][1].status,
                png_ihdr,
                archive,
                image_stego,
            ),
            confidence=0.78 if flags else 0.58,
            next_action=_next_action(flags, png_ihdr, archive, image_stego),
        )
        context.notebook.add_finding(finding)
        return finding


def _tool_sample(result) -> dict[str, str]:
    stdout = str(result.raw.get("stdout", ""))
    stderr = str(result.raw.get("stderr", ""))
    return {
        "stdout": stdout[:500],
        "stderr": stderr[:500],
    }


def _forensics_hypothesis(
    flags: tuple[str, ...],
    file_status: str,
    strings_status: str,
    png_ihdr: dict[str, Any] | None = None,
    archive: dict[str, Any] | None = None,
    image_stego: dict[str, Any] | None = None,
) -> str:
    if flags:
        return "Printable artifact content contains a flag-like token that should be verified."
    if png_ihdr and png_ihdr.get("suspected_height_mismatch"):
        return "PNG IHDR height appears inconsistent with IDAT scanline data; the repaired artifact is likely the next image to inspect."
    if archive:
        return "Archive structure was detected; interesting entry names should guide extraction and password-hint checks."
    if image_stego:
        return "Image metadata or structure contains stego-style hints that should be inspected before heavier extraction."
    if file_status == "success" and strings_status == "success":
        return "The artifact is readable; metadata or embedded payload analysis is the next likely path."
    return "Initial triage ran, but one or more local tools could not inspect the artifact."


def _next_action(
    flags: tuple[str, ...],
    png_ihdr: dict[str, Any] | None = None,
    archive: dict[str, Any] | None = None,
    image_stego: dict[str, Any] | None = None,
) -> str:
    if flags:
        return "Send candidates to Verifier and preserve the attachment path as reproduction evidence."
    if png_ihdr and png_ihdr.get("repaired_path"):
        return "Open the repaired PNG, then continue with visual, channel, and low-bit-plane stego analysis."
    if archive:
        if archive.get("encrypted"):
            return "Collect password hints before attempting archive extraction."
        return "Inspect interesting archive entries and extract only into a managed artifact workspace."
    if image_stego:
        return "Review image text chunks, comments, and trailing bytes before trying channel or low-bit-plane stego tools."
    return "Inspect tool output for embedded archives, metadata hints, or alternate encodings."


def _image_text(image_stego: dict[str, Any] | None) -> str:
    if not image_stego:
        return ""
    values: list[str] = []
    for item in image_stego.get("text_chunks", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
    for item in image_stego.get("comments", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
    trailing = image_stego.get("trailing_data")
    if isinstance(trailing, dict):
        values.append(str(trailing.get("ascii_preview", "")))
    return "\n".join(values)
