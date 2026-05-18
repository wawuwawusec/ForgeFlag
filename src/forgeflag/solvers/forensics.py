from __future__ import annotations

import binascii
import struct
import zlib
from pathlib import Path
from typing import Any

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
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
        flags = extract_flags(combined_output)
        flag_candidates.extend(flags)
        png_ihdr = _analyze_png_ihdr(Path(resolved))

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
            },
            hypothesis=_forensics_hypothesis(flags, labeled_results[0][1].status, labeled_results[1][1].status, png_ihdr),
            confidence=0.78 if flags else 0.58,
            next_action=_next_action(flags, png_ihdr),
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
) -> str:
    if flags:
        return "Printable artifact content contains a flag-like token that should be verified."
    if png_ihdr and png_ihdr.get("suspected_height_mismatch"):
        return "PNG IHDR height appears inconsistent with IDAT scanline data; the repaired artifact is likely the next image to inspect."
    if file_status == "success" and strings_status == "success":
        return "The artifact is readable; metadata or embedded payload analysis is the next likely path."
    return "Initial triage ran, but one or more local tools could not inspect the artifact."


def _next_action(flags: tuple[str, ...], png_ihdr: dict[str, Any] | None = None) -> str:
    if flags:
        return "Send candidates to Verifier and preserve the attachment path as reproduction evidence."
    if png_ihdr and png_ihdr.get("repaired_path"):
        return "Open the repaired PNG, then continue with visual, channel, and low-bit-plane stego analysis."
    return "Inspect tool output for embedded archives, metadata hints, or alternate encodings."


def _analyze_png_ihdr(path: Path) -> dict[str, Any] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None

    pos = 8
    idat = bytearray()
    ihdr_body = None
    ihdr_crc = None
    while pos + 12 <= len(data):
        size = struct.unpack(">I", data[pos : pos + 4])[0]
        kind = data[pos + 4 : pos + 8]
        body_start = pos + 8
        body_end = body_start + size
        crc_end = body_end + 4
        if crc_end > len(data):
            break
        body = data[body_start:body_end]
        crc = struct.unpack(">I", data[body_end:crc_end])[0]
        if kind == b"IHDR":
            ihdr_body = body
            ihdr_crc = crc
        elif kind == b"IDAT":
            idat.extend(body)
        pos = crc_end
        if kind == b"IEND":
            break

    if ihdr_body is None or ihdr_crc is None or len(ihdr_body) != 13:
        return None

    width, height, bit_depth, color_type, compression, filter_method, interlace = struct.unpack(">IIBBBBB", ihdr_body)
    ihdr_crc_calc = binascii.crc32(b"IHDR" + ihdr_body) & 0xFFFFFFFF
    evidence: dict[str, Any] = {
        "width": width,
        "declared_height": height,
        "bit_depth": bit_depth,
        "color_type": color_type,
        "ihdr_crc_ok": ihdr_crc == ihdr_crc_calc,
        "ihdr_crc": f"{ihdr_crc:08x}",
        "ihdr_crc_calculated": f"{ihdr_crc_calc:08x}",
    }

    derived_height = _derive_png_height_from_idat(
        bytes(idat),
        width=width,
        bit_depth=bit_depth,
        color_type=color_type,
        compression=compression,
        filter_method=filter_method,
        interlace=interlace,
    )
    if derived_height:
        evidence["derived_height"] = derived_height
        evidence["suspected_height_mismatch"] = derived_height != height
        if derived_height != height:
            repaired = _write_repaired_png_height(path, data, derived_height)
            if repaired:
                evidence["repaired_path"] = str(repaired)
    else:
        evidence["suspected_height_mismatch"] = False

    return evidence if not evidence["ihdr_crc_ok"] or evidence.get("suspected_height_mismatch") else None


def _derive_png_height_from_idat(
    idat: bytes,
    *,
    width: int,
    bit_depth: int,
    color_type: int,
    compression: int,
    filter_method: int,
    interlace: int,
) -> int | None:
    if not idat or width <= 0 or bit_depth != 8 or compression != 0 or filter_method != 0 or interlace != 0:
        return None
    channels_by_color_type = {0: 1, 2: 3, 4: 2, 6: 4}
    channels = channels_by_color_type.get(color_type)
    if channels is None:
        return None
    try:
        raw = zlib.decompress(idat)
    except zlib.error:
        return None
    row_size = 1 + width * channels
    if row_size <= 1 or len(raw) % row_size != 0:
        return None
    return len(raw) // row_size


def _write_repaired_png_height(path: Path, data: bytes, height: int) -> Path | None:
    if height <= 0 or len(data) < 33:
        return None
    repaired = bytearray(data)
    repaired[20:24] = struct.pack(">I", height)
    repaired_crc = binascii.crc32(repaired[12:29]) & 0xFFFFFFFF
    repaired[29:33] = struct.pack(">I", repaired_crc)
    target = path.with_name(f"{path.stem}-ihdr-height-{height}{path.suffix}")
    try:
        target.write_bytes(repaired)
    except OSError:
        return None
    return target
