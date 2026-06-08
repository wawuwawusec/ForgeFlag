from __future__ import annotations

from pathlib import Path
import re

from forgeflag.archive_analysis import analyze_archive, preview_archive_text
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.hash_analysis import hash_summary_from_text
from forgeflag.image import analyze_image_stego_hints, analyze_magic_extension_mismatch, analyze_png_ihdr
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
            magic_mismatch = analyze_magic_extension_mismatch(resolved)
            png_ihdr = analyze_png_ihdr(resolved)
            image_stego = analyze_image_stego_hints(resolved)
            jpeg_tools, jpeg_flags = _analyze_jpeg_stego_tools(context, resolved, image_stego)
            image_text = _image_text(image_stego)
            decoded_image_candidates = tuple(transform_candidates(image_text)) if image_text else ()
            decoded_image_flags = extract_flags("\n".join(candidate.value for candidate in decoded_image_candidates))
            flags = tuple(dict.fromkeys((*extract_flags(image_text), *decoded_image_flags, *jpeg_flags)))
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
                    **({"magic_extension_mismatch": magic_mismatch} if magic_mismatch else {}),
                    **({"png_ihdr": png_ihdr} if png_ihdr else {}),
                    **({"image_stego": image_stego} if image_stego else {}),
                    **(
                        {"decoded_image_text_candidates": candidates_to_payload(decoded_image_candidates)}
                        if decoded_image_candidates
                        else {}
                    ),
                    **({"jpeg_stego_tools": jpeg_tools} if jpeg_tools else {}),
                },
                hypothesis=_image_hypothesis(flags, magic_mismatch, png_ihdr, image_stego, jpeg_tools),
                confidence=0.78 if flags else 0.68,
                next_action=_image_next_action(flags, magic_mismatch, png_ihdr, image_stego, jpeg_tools),
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


def _analyze_jpeg_stego_tools(
    context: SolverContext,
    image_path: Path,
    image_stego: dict[str, object] | None,
) -> tuple[dict[str, object], tuple[str, ...]]:
    if not image_stego or image_stego.get("format") != "jpeg":
        return {}, ()

    evidence: dict[str, object] = {}
    flags: list[str] = []
    info = ctf.steghide_info(str(image_path), scope=context.scope)
    evidence["steghide_info"] = _tool_result_payload(info)

    attempts: list[dict[str, object]] = []
    output_dir = image_path.parent / ".forgeflag-stego"
    output_dir.mkdir(parents=True, exist_ok=True)
    passphrases = _jpeg_hint_passphrases(context, image_path)
    for passphrase in passphrases:
        result = ctf.steghide_extract(str(image_path), passphrase, str(output_dir), scope=context.scope)
        payload = _tool_result_payload(result)
        payload["passphrase_hint"] = _mask_passphrase_hint(passphrase)
        attempts.append(payload)
        flags.extend(extract_flags(_tool_text(result)))
        for artifact in result.artifacts:
            try:
                artifact_text = Path(artifact).read_bytes()[:64_000].decode("utf-8", errors="ignore")
            except OSError:
                continue
            flags.extend(extract_flags(artifact_text))
        if result.status == "success":
            break

    if attempts:
        best = next((attempt for attempt in attempts if attempt.get("status") == "success"), attempts[-1])
        evidence["steghide_extract"] = best
        evidence["steghide_attempts"] = attempts[:8]
    if not any(attempt.get("status") == "success" for attempt in attempts) and hasattr(ctf, "stegseek_crack"):
        stegseek = ctf.stegseek_crack(str(image_path), passphrases, str(output_dir), scope=context.scope)
        evidence["stegseek_crack"] = _tool_result_payload(stegseek)
        evidence["stegseek_crack"]["wordlist_size"] = len(passphrases)
        flags.extend(extract_flags(_tool_text(stegseek)))
        for artifact in stegseek.artifacts:
            try:
                artifact_text = Path(artifact).read_bytes()[:64_000].decode("utf-8", errors="ignore")
            except OSError:
                continue
            flags.extend(extract_flags(artifact_text))
    return evidence, tuple(dict.fromkeys(flags))


def _jpeg_hint_passphrases(context: SolverContext, image_path: Path, limit: int = 24) -> tuple[str, ...]:
    challenge = context.challenge
    sources = [
        image_path.stem,
        challenge.title or "",
        challenge.description or "",
        " ".join(challenge.tags),
    ]
    values: list[str] = ["", image_path.stem]
    for source in sources:
        cleaned = " ".join(source.replace("_", " ").replace("-", " ").split())
        if cleaned:
            values.append(cleaned)
        for token in re.findall(r"[A-Za-z0-9]{2,32}", source):
            values.append(token)
            values.append(token.lower())
            if token.lower().endswith("s") and len(token) > 3:
                values.append(token[:-1])
                values.append(token[:-1].lower())
    deduped: list[str] = []
    for value in values:
        if len(value) > 64 or value in deduped:
            continue
        deduped.append(value)
        if len(deduped) >= limit:
            break
    return tuple(deduped)


def _tool_result_payload(result: object) -> dict[str, object]:
    status = str(getattr(result, "status", "unknown"))
    raw = getattr(result, "raw", {})
    stdout = str(raw.get("stdout", "")) if isinstance(raw, dict) else ""
    stderr = str(raw.get("stderr", "")) if isinstance(raw, dict) else ""
    payload: dict[str, object] = {
        "status": status,
        "evidence": list(getattr(result, "evidence", []))[:6],
        "artifacts": list(getattr(result, "artifacts", []))[:4],
    }
    if stdout:
        payload["stdout_preview"] = stdout[:500]
    if stderr:
        payload["stderr_preview"] = stderr[:500]
    return payload


def _tool_text(result: object) -> str:
    raw = getattr(result, "raw", {})
    if not isinstance(raw, dict):
        return ""
    return "\n".join(str(raw.get(key, "")) for key in ("stdout", "stderr"))


def _mask_passphrase_hint(passphrase: str) -> str:
    if not passphrase:
        return "<empty>"
    if len(passphrase) <= 2:
        return passphrase[0] + "*"
    return f"{passphrase[0]}{'*' * min(len(passphrase) - 2, 10)}{passphrase[-1]}"


def _image_hypothesis(
    flags: tuple[str, ...],
    magic_mismatch: dict[str, object] | None,
    png_ihdr: dict[str, object] | None,
    image_stego: dict[str, object] | None,
    jpeg_tools: dict[str, object] | None = None,
) -> str:
    if flags:
        return "Image metadata or appended bytes contain a flag-like token."
    if magic_mismatch:
        return "The filename extension is misleading; image puzzle triage should follow the magic-byte format."
    if png_ihdr:
        return "Misc image puzzle has PNG structure evidence that should be inspected before broader puzzle triage."
    if jpeg_tools:
        return "JPEG structure and bounded stego-tool evidence were collected; hidden data may require a stronger passphrase/tool path."
    if image_stego:
        return "Image metadata or structure contains stego-style hints worth inspecting before generic puzzle triage."
    return "Image artifact should be routed to visual and stego follow-up."


def _image_next_action(
    flags: tuple[str, ...],
    magic_mismatch: dict[str, object] | None,
    png_ihdr: dict[str, object] | None,
    image_stego: dict[str, object] | None,
    jpeg_tools: dict[str, object] | None = None,
) -> str:
    if flags:
        return "Send image-derived flag candidates to Verifier and preserve the image evidence path."
    if magic_mismatch:
        actual = magic_mismatch.get("actual_format")
        return f"Ignore the misleading extension and continue image/stego checks as {actual}."
    if png_ihdr and png_ihdr.get("repaired_path"):
        return "Open the repaired PNG, then inspect visible hints, channels, and bit planes."
    if jpeg_tools:
        extract = jpeg_tools.get("steghide_extract") if isinstance(jpeg_tools, dict) else None
        if isinstance(extract, dict) and extract.get("status") == "success":
            return "Inspect the extracted steghide artifact manually if no flag pattern was detected."
        return "Try a challenge-scoped steghide/stegseek wordlist, then move to outguess/F5/JPEG DCT stego checks if passphrases fail."
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
    for item in image_stego.get("lsb_candidates", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
            values.extend(str(flag) for flag in item.get("flag_like_strings", []) if isinstance(flag, str))
    trailing = image_stego.get("trailing_data")
    if isinstance(trailing, dict):
        values.append(str(trailing.get("ascii_preview", "")))
    return "\n".join(values)
