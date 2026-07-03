from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import gzip
from io import BytesIO
import json
from pathlib import Path
import re
import tempfile
from typing import Any
import zipfile
import zlib

from forgeflag.archive_analysis import analyze_archive, preview_archive_text
from forgeflag.ctf_scope import ctf_scope_evidence
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.image import analyze_image_stego_hints, analyze_magic_extension_mismatch, analyze_png_ihdr
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
from forgeflag.transforms import TransformCandidate, candidates_to_payload, transform_candidates


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
                evidence={
                    "planned_adapters": ["file", "strings", "binwalk", "exiftool"],
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.FORENSICS),
                },
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
                evidence={
                    "attachment_path": attachment_path,
                    "error": str(exc),
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.FORENSICS),
                },
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
        decoded_candidates = _forensic_transform_candidates(combined_output)
        decoded_flags = extract_flags("\n".join(candidate.value for candidate in decoded_candidates))
        magic_mismatch = analyze_magic_extension_mismatch(Path(resolved))
        png_ihdr = analyze_png_ihdr(Path(resolved))
        image_stego = analyze_image_stego_hints(Path(resolved))
        image_text = _image_text(image_stego)
        decoded_image_candidates = tuple(transform_candidates(image_text)) if image_text else ()
        decoded_image_flags = extract_flags("\n".join(candidate.value for candidate in decoded_image_candidates))
        flags = tuple(
            dict.fromkeys((*extract_flags(combined_output), *decoded_flags, *extract_flags(image_text), *decoded_image_flags))
        )
        if not flags:
            extension_results = [
                ("foremost", ctf.foremost_carve(resolved, str(Path(resolved).parent / "foremost-output"), context.scope)),
                ("yara", ctf.yara_scan(resolved, output_dir=str(Path(resolved).parent), scope=context.scope)),
            ]
            for _, result in extension_results:
                context.notebook.add_tool_result(challenge_id, result)
            labeled_results.extend(extension_results)
            extension_output = "\n".join(
                str(result.raw.get("stdout", "")) + "\n" + str(result.raw.get("stderr", ""))
                for _, result in extension_results
            )
            flags = tuple(dict.fromkeys((*flags, *extract_flags(extension_output))))
        archive = analyze_archive(resolved)
        archive_text_previews = preview_archive_text(resolved) if archive else []
        archive_flags = extract_flags("\n".join(str(item.get("text_preview", "")) for item in archive_text_previews))
        archive_image_recoveries = (
            _recover_archive_image_entries(context, Path(resolved), flag_candidates) if archive else []
        )
        archive_image_flags = tuple(
            flag for recovery in archive_image_recoveries for flag in recovery.get("flag_candidates", [])
        )
        gpp_cpasswords = analyze_gpp_cpasswords(archive_text_previews)
        gpp_flags = extract_flags("\n".join(str(item.get("password", "")) for item in gpp_cpasswords))
        registry_wifi = analyze_registry_wifi(Path(resolved))
        registry_wifi_flags = tuple(registry_wifi.get("flag_candidates", ())) if registry_wifi else ()
        registry_bitlocker = analyze_registry_bitlocker_fvestats(Path(resolved))
        registry_bitlocker_flags = tuple(registry_bitlocker.get("flag_candidates", ())) if registry_bitlocker else ()
        minecraft_region = analyze_minecraft_region(Path(resolved))
        minecraft_flags = tuple(minecraft_region.get("flag_candidates", ())) if minecraft_region else ()
        flags = tuple(
            dict.fromkeys(
                (
                    *flags,
                    *archive_flags,
                    *archive_image_flags,
                    *gpp_flags,
                    *registry_wifi_flags,
                    *registry_bitlocker_flags,
                    *minecraft_flags,
                )
            )
        )
        flag_candidates.extend(flags)

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
                "ctf_scope": ctf_scope_evidence(ChallengeCategory.FORENSICS),
                **(
                    {"decoded_transform_candidates": candidates_to_payload(decoded_candidates)}
                    if decoded_candidates
                    else {}
                ),
                **({"magic_extension_mismatch": magic_mismatch} if magic_mismatch else {}),
                **({"png_ihdr": png_ihdr} if png_ihdr else {}),
                **({"image_stego": image_stego} if image_stego else {}),
                **(
                    {"decoded_image_text_candidates": candidates_to_payload(decoded_image_candidates)}
                    if decoded_image_candidates
                    else {}
                ),
                **({"archive": archive} if archive else {}),
                **({"archive_text_previews": archive_text_previews} if archive_text_previews else {}),
                **({"archive_image_recoveries": archive_image_recoveries} if archive_image_recoveries else {}),
                **({"gpp_cpasswords": gpp_cpasswords} if gpp_cpasswords else {}),
                **({"registry_wifi": registry_wifi} if registry_wifi else {}),
                **({"registry_bitlocker_fvestats": registry_bitlocker} if registry_bitlocker else {}),
                **({"minecraft_region": minecraft_region} if minecraft_region else {}),
            },
            hypothesis=_forensics_hypothesis(
                flags,
                labeled_results[0][1].status,
                labeled_results[1][1].status,
                magic_mismatch,
                png_ihdr,
                archive,
                image_stego,
                gpp_cpasswords,
                registry_wifi,
                registry_bitlocker,
                minecraft_region,
            ),
            confidence=0.78 if flags else 0.58,
            next_action=_next_action(
                flags,
                magic_mismatch,
                png_ihdr,
                archive,
                image_stego,
                gpp_cpasswords,
                registry_wifi,
                registry_bitlocker,
                minecraft_region,
            ),
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


def _forensic_transform_candidates(text: str) -> tuple[TransformCandidate, ...]:
    candidates = list(transform_candidates(text))
    seen = {(candidate.value, candidate.recipe, candidate.source) for candidate in candidates}
    for candidate in candidates[:40]:
        for nested in transform_candidates(candidate.value, max_depth=2, max_candidates=30):
            combined = TransformCandidate(
                value=nested.value,
                recipe=(*candidate.recipe, *nested.recipe),
                source=candidate.source,
            )
            key = (combined.value, combined.recipe, combined.source)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(combined)
    return tuple(candidates)


def _recover_archive_image_entries(
    context: SolverContext,
    archive_path: Path,
    flag_candidates: list[str],
    limit: int = 10,
    max_bytes: int = 2_000_000,
) -> list[dict[str, Any]]:
    if not zipfile.is_zipfile(archive_path):
        return []
    output_dir = (
        Path(context.notebook.path).parent
        / "artifacts"
        / _safe_component(context.challenge.challenge_id)
        / "archive-images"
        / _safe_component(archive_path.stem)
    )
    recoveries: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(archive_path) as zf:
            entries = sorted(zf.infolist(), key=lambda info: ("flag" not in info.filename.lower(), info.filename))
            for info in entries:
                if len(recoveries) >= limit:
                    break
                if info.is_dir() or info.file_size > max_bytes or info.flag_bits & 0x1:
                    continue
                try:
                    raw = zf.read(info)
                except (RuntimeError, zipfile.BadZipFile):
                    continue
                repaired = _repair_mangled_png_signature(raw)
                if not repaired:
                    continue
                output_dir.mkdir(parents=True, exist_ok=True)
                repaired_path = output_dir / (_safe_component(Path(info.filename).stem) + ".png")
                repaired_path.write_bytes(repaired)
                image_stego = analyze_image_stego_hints(repaired_path)
                image_text = _image_text(image_stego)
                decoded_candidates = tuple(transform_candidates(image_text)) if image_text else ()
                flags = tuple(
                    dict.fromkeys(
                        (
                            *extract_flags(image_text),
                            *extract_flags("\n".join(candidate.value for candidate in decoded_candidates)),
                        )
                    )
                )
                flag_candidates.extend(flags)
                recoveries.append(
                    {
                        "entry_name": info.filename,
                        "repair": "png_signature",
                        "original_signature": raw[:4].decode("latin1", errors="replace"),
                        "repaired_path": str(repaired_path),
                        "image_stego": image_stego or {},
                        "decoded_image_text_candidates": candidates_to_payload(decoded_candidates)
                        if decoded_candidates
                        else [],
                        "flag_candidates": list(flags),
                    }
                )
    except zipfile.BadZipFile:
        return []
    return recoveries


def _repair_mangled_png_signature(data: bytes) -> bytes | None:
    png_tail = b"\r\n\x1a\n\x00\x00\x00\rIHDR"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    if len(data) > 16 and data[4:16] == png_tail:
        return b"\x89PNG" + data[4:]
    return None


def _safe_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return cleaned or "artifact"


def _forensics_hypothesis(
    flags: tuple[str, ...],
    file_status: str,
    strings_status: str,
    magic_mismatch: dict[str, Any] | None = None,
    png_ihdr: dict[str, Any] | None = None,
    archive: dict[str, Any] | None = None,
    image_stego: dict[str, Any] | None = None,
    gpp_cpasswords: list[dict[str, str]] | None = None,
    registry_wifi: dict[str, Any] | None = None,
    registry_bitlocker: dict[str, Any] | None = None,
    minecraft_region: dict[str, Any] | None = None,
) -> str:
    if flags:
        return "Printable artifact content contains a flag-like token that should be verified."
    if gpp_cpasswords:
        return "Group Policy Preferences cpassword material was decrypted from local challenge evidence."
    if registry_wifi:
        return "Windows registry NetworkList entries contain Wi-Fi profile evidence."
    if registry_bitlocker:
        return "Windows registry BitLocker FVEStats timestamps were recovered from local challenge hive evidence."
    if minecraft_region:
        return "Minecraft Anvil region chunks were decompressed; orphan sector strings may preserve deleted container contents."
    if magic_mismatch:
        return "The file extension does not match the magic bytes; triage should follow the actual container format."
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
    magic_mismatch: dict[str, Any] | None = None,
    png_ihdr: dict[str, Any] | None = None,
    archive: dict[str, Any] | None = None,
    image_stego: dict[str, Any] | None = None,
    gpp_cpasswords: list[dict[str, str]] | None = None,
    registry_wifi: dict[str, Any] | None = None,
    registry_bitlocker: dict[str, Any] | None = None,
    minecraft_region: dict[str, Any] | None = None,
) -> str:
    if flags:
        return "Send candidates to Verifier and preserve the attachment path as reproduction evidence."
    if gpp_cpasswords:
        return "Verify the recovered Group Policy Preferences password against the challenge flag format."
    if registry_wifi:
        return "Verify the decoded Wi-Fi SSID against challenge flag formatting rules."
    if registry_bitlocker:
        return "Verify the BitLocker encryption start/end timeline against the challenge flag formatting rules."
    if minecraft_region:
        return "Inspect decompressed Minecraft chunk strings, especially orphan sectors and container item lore."
    if magic_mismatch:
        actual = magic_mismatch.get("actual_format")
        return f"Ignore the misleading extension and rerun analysis as {actual} based on magic bytes."
    if png_ihdr and png_ihdr.get("repaired_path"):
        return "Open the repaired PNG, then continue with visual, channel, and low-bit-plane stego analysis."
    if archive:
        if archive.get("encrypted"):
            return "Collect password hints before attempting archive extraction."
        return "Inspect interesting archive entries and extract only into a managed artifact workspace."
    if image_stego:
        return "Review image text chunks, comments, and trailing bytes before trying channel or low-bit-plane stego tools."
    return "Inspect tool output for embedded archives, metadata hints, or alternate encodings."


WIRELESS_VALUE_RE = re.compile(
    r"\\NetworkList\\Nla\\Wireless\\[^\]]+\]\s+@=\"([0-9A-Fa-f]+)\"",
    re.MULTILINE,
)
PROFILE_NAME_RE = re.compile(r'"ProfileName"="([^"]+)"')
GPP_CPASSWORD_RE = re.compile(r'cpassword="([^"]+)"', re.IGNORECASE)
GPP_USERNAME_RE = re.compile(r'(?:userName|name)="([^"]+)"', re.IGNORECASE)
GPP_AES_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")


def analyze_gpp_cpasswords(archive_text_previews: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for preview in archive_text_previews:
        name = str(preview.get("name", ""))
        text = str(preview.get("text_preview", ""))
        if "cpassword" not in text.lower():
            continue
        username_match = GPP_USERNAME_RE.search(text)
        username = username_match.group(1) if username_match else ""
        for match in GPP_CPASSWORD_RE.finditer(text):
            password = _decrypt_gpp_cpassword(match.group(1))
            if not password:
                continue
            findings.append(
                {
                    "entry": name,
                    "username": username,
                    "cpassword": match.group(1),
                    "password": password,
                }
            )
    return findings


def _decrypt_gpp_cpassword(cpassword: str) -> str:
    try:
        padded = cpassword + ("=" * (-len(cpassword) % 4))
        ciphertext = base64.b64decode(padded)
    except ValueError:
        return ""
    if not ciphertext or len(ciphertext) % 16:
        return ""
    plaintext = _aes_cbc_decrypt(ciphertext, GPP_AES_KEY, b"\0" * 16)
    if not plaintext:
        return ""
    decoded = _decode_gpp_plaintext(plaintext)
    flags = extract_flags(decoded)
    return flags[0] if flags else decoded


def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        pass
    try:
        from Crypto.Cipher import AES

        return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)
    except Exception:
        return b""


def _decode_gpp_plaintext(plaintext: bytes) -> str:
    if not plaintext:
        return ""
    pad_len = plaintext[-1]
    candidate_lengths = [0]
    if 0 < pad_len <= 16:
        candidate_lengths.extend([pad_len, pad_len - 1, pad_len + 1])
    for trim in candidate_lengths:
        if trim < 0 or trim >= len(plaintext):
            continue
        candidate = plaintext[:-trim] if trim else plaintext
        if trim == pad_len and not plaintext.endswith(bytes([pad_len]) * pad_len):
            continue
        try:
            decoded = candidate.rstrip(b"\0").decode("utf-16le")
        except UnicodeDecodeError:
            continue
        cleaned = decoded.strip()
        if cleaned and "\ufffd" not in cleaned:
            return cleaned
    return plaintext.rstrip(b"\0").decode("utf-16le", errors="replace").strip()


def analyze_registry_wifi(path: Path) -> dict[str, Any] | None:
    if path.suffix.lower() != ".reg":
        return None
    try:
        text = _read_registry_export(path)
    except UnicodeError:
        return None
    wireless_ssids = [
        _decode_registry_ssid_hex(match.group(1)) for match in WIRELESS_VALUE_RE.finditer(text)
    ]
    wireless_ssids = [ssid for ssid in wireless_ssids if ssid]
    if not wireless_ssids:
        return None
    profile_names = PROFILE_NAME_RE.findall(text)
    matched_ssids = [ssid for ssid in wireless_ssids if ssid in profile_names] or wireless_ssids
    flag_candidates = [f"flag{{{ssid.replace(' ', '')}}}" for ssid in matched_ssids]
    return {
        "wireless_ssids": matched_ssids,
        "profile_names": profile_names,
        "flag_candidates": flag_candidates,
        "source": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Wireless",
    }


def _read_registry_export(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or b"\x00" in raw[:128]:
        return raw.decode("utf-16le")
    return raw.decode("utf-8", errors="replace")


def _decode_registry_ssid_hex(hex_text: str) -> str:
    try:
        return bytes.fromhex(hex_text).decode("utf-8", errors="replace")
    except ValueError:
        return ""


def analyze_registry_bitlocker_fvestats(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    for archive in _registry_archive_candidates(path):
        analysis = _analyze_registry_archive_bitlocker_fvestats(archive)
        if analysis:
            return analysis
    return None


def _registry_archive_candidates(path: Path, limit: int = 8) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if zipfile.is_zipfile(path):
        candidates.append({"source": str(path), "kind": "zip_file", "data": path.read_bytes()})
    foremost_zip_dir = path.parent / "foremost-output" / "zip"
    if foremost_zip_dir.is_dir():
        for zip_path in sorted(foremost_zip_dir.glob("*.zip"))[:limit]:
            try:
                candidates.append({"source": str(zip_path), "kind": "foremost_zip", "data": zip_path.read_bytes()})
            except OSError:
                continue
    if len(candidates) < limit:
        for offset, data in _carve_zip_archives(path, limit=limit - len(candidates)):
            candidates.append({"source": str(path), "kind": "embedded_zip", "offset": offset, "data": data})
    return candidates[:limit]


def _carve_zip_archives(path: Path, limit: int = 4, max_bytes: int = 128_000_000) -> list[tuple[int, bytes]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) > max_bytes:
        return []
    results: list[tuple[int, bytes]] = []
    start = 0
    while len(results) < limit:
        offset = data.find(b"PK\x03\x04", start)
        if offset < 0:
            break
        end = _zip_eocd_end(data, offset)
        if end and end > offset:
            archive = data[offset:end]
            if _is_readable_zip_bytes(archive):
                results.append((offset, archive))
                start = end
                continue
        start = offset + 4
    return results


def _zip_eocd_end(data: bytes, start: int) -> int | None:
    marker = b"PK\x05\x06"
    search_from = start
    while True:
        offset = data.find(marker, search_from)
        if offset < 0:
            return None
        if offset + 22 <= len(data):
            comment_len = int.from_bytes(data[offset + 20 : offset + 22], "little")
            end = offset + 22 + comment_len
            if end <= len(data):
                return end
        search_from = offset + 4


def _is_readable_zip_bytes(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            return bool(zf.infolist())
    except zipfile.BadZipFile:
        return False


def _analyze_registry_archive_bitlocker_fvestats(archive: dict[str, Any]) -> dict[str, Any] | None:
    try:
        with zipfile.ZipFile(BytesIO(archive["data"])) as zf:
            system_entries = [
                info
                for info in zf.infolist()
                if not info.is_dir()
                and Path(info.filename).name.upper() == "SYSTEM"
                and info.file_size <= 64_000_000
            ]
            for info in system_entries:
                try:
                    hive_bytes = zf.read(info)
                except (RuntimeError, zipfile.BadZipFile):
                    continue
                parsed = _parse_system_hive_bitlocker_fvestats(hive_bytes)
                if not parsed:
                    continue
                parsed.update(
                    {
                        "archive_source": archive["source"],
                        "archive_kind": archive["kind"],
                        "archive_offset": archive.get("offset"),
                        "entry_name": info.filename,
                    }
                )
                return parsed
    except (KeyError, zipfile.BadZipFile):
        return None
    return None


def _parse_system_hive_bitlocker_fvestats(hive_bytes: bytes) -> dict[str, Any] | None:
    try:
        from Registry import Registry
    except ImportError:
        return None
    with tempfile.NamedTemporaryFile(prefix="forgeflag-system-", suffix=".hive") as handle:
        handle.write(hive_bytes)
        handle.flush()
        try:
            registry = Registry.Registry(handle.name)
            key = registry.open("ControlSet001\\Control\\FVEStats")
        except Exception:
            return None
        raw_values: dict[str, int] = {}
        for name in ("OsvEncryptInit", "OsvEncryptComplete"):
            try:
                value = key.value(name).value()
            except Exception:
                return None
            if not isinstance(value, int):
                return None
            raw_values[name] = value
    init = _format_windows_filetime(raw_values["OsvEncryptInit"])
    complete = _format_windows_filetime(raw_values["OsvEncryptComplete"])
    flag = f"PCL{{{init['local']}_{complete['local']}}}"
    return {
        "source": "SYSTEM\\ControlSet001\\Control\\FVEStats",
        "raw_filetime": raw_values,
        "timestamps": {
            "OsvEncryptInit": init,
            "OsvEncryptComplete": complete,
        },
        "flag_candidates": [flag],
    }


def _format_windows_filetime(value: int) -> dict[str, str]:
    utc = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
    local = utc.astimezone(timezone(timedelta(hours=8)))
    return {
        "utc": utc.strftime("%Y-%m-%d_%H:%M:%S"),
        "local": f"{local.year}/{local.month}/{local.day}_{local:%H:%M:%S}",
        "timezone": "UTC+08:00",
    }


def analyze_minecraft_region(path: Path, max_chunks: int = 128) -> dict[str, Any] | None:
    if path.suffix.lower() not in {".mca", ".mcr"}:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 8192 or len(data) % 4096:
        return None

    used_sectors = _minecraft_region_used_sectors(data)
    chunk_summaries: list[dict[str, Any]] = []
    text_corpus: list[str] = []
    seen_sectors: set[int] = set()
    matched_chunk_count = 0
    matched_orphan_count = 0
    for sector in range(2, len(data) // 4096):
        decoded = _decode_minecraft_region_sector(data, sector)
        if not decoded or sector in seen_sectors:
            continue
        seen_sectors.add(sector)
        strings = _extract_nbt_len_prefixed_strings(decoded["payload"])
        if not strings:
            continue
        json_texts = _extract_minecraft_json_texts(strings)
        interesting = _interesting_minecraft_strings(strings)
        if not json_texts and not interesting:
            continue
        matched_chunk_count += 1
        orphan_sector = sector not in used_sectors
        if orphan_sector:
            matched_orphan_count += 1
        text_corpus.extend(strings)
        text_corpus.extend(json_texts)
        joined_json_text = "".join(json_texts)
        joined_lore_text = _join_minecraft_lore_fragments(json_texts)
        if joined_lore_text:
            text_corpus.append(joined_lore_text)
        chunk_flags = extract_flags("\n".join((*json_texts, joined_lore_text, *interesting)))
        summary = {
            "sector": sector,
            "orphan_sector": orphan_sector,
            "compression": decoded["compression"],
            "decompressed_size": len(decoded["payload"]),
            "json_texts": json_texts[:40],
            "interesting_strings": interesting[:40],
            "flag_candidates": list(chunk_flags),
        }
        if len(chunk_summaries) < max_chunks or chunk_flags:
            chunk_summaries.append(summary)

    flags = extract_flags("\n".join(text_corpus))
    if not chunk_summaries and not flags:
        return None
    retained_chunks = _retained_minecraft_chunk_summaries(chunk_summaries, limit=20)
    return {
        "format": "minecraft_anvil_region",
        "path": str(path),
        "chunks": retained_chunks,
        "chunk_count": matched_chunk_count,
        "orphan_chunk_count": matched_orphan_count,
        "flag_candidates": list(flags),
    }


def _minecraft_region_used_sectors(data: bytes) -> set[int]:
    used: set[int] = set()
    for index in range(1024):
        offset = int.from_bytes(data[index * 4 : index * 4 + 3], "big")
        count = data[index * 4 + 3]
        if offset <= 1 or count == 0:
            continue
        used.update(range(offset, min(offset + count, len(data) // 4096)))
    return used


def _decode_minecraft_region_sector(data: bytes, sector: int) -> dict[str, Any] | None:
    start = sector * 4096
    if start + 5 > len(data):
        return None
    length = int.from_bytes(data[start : start + 4], "big")
    if length <= 1 or length > 4096 * 255 or start + 4 + length > len(data):
        return None
    compression_type = data[start + 4]
    payload = data[start + 5 : start + 4 + length]
    try:
        if compression_type == 1:
            decompressed = gzip.decompress(payload)
            compression = "gzip"
        elif compression_type == 2:
            decompressed = zlib.decompress(payload)
            compression = "zlib"
        elif compression_type == 3:
            decompressed = payload
            compression = "none"
        else:
            return None
    except (OSError, zlib.error, EOFError):
        return None
    return {"payload": decompressed, "compression": compression}


def _extract_nbt_len_prefixed_strings(data: bytes, limit: int = 2000) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(rb"[\x20-\x7e]{2,256}", data):
        raw = match.group(0)
        text = raw.decode("utf-8", errors="ignore")
        if text in seen:
            continue
        seen.add(text)
        strings.append(text)
        if len(strings) >= limit:
            break
    return strings


def _extract_minecraft_json_texts(strings: list[str]) -> list[str]:
    texts: list[str] = []
    for value in strings:
        if not value.startswith("{") and '{"text"' in value:
            value = value[value.find("{") :]
        if not value.startswith("{") or '"text"' not in value:
            continue
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            continue
        text = decoded.get("text") if isinstance(decoded, dict) else None
        if isinstance(text, str):
            texts.append(text)
    return texts


def _join_minecraft_lore_fragments(texts: list[str]) -> str:
    fragments = [text for text in texts if 0 < len(text) <= 4 or "{" in text or "}" in text]
    return "".join(fragments)


def _interesting_minecraft_strings(strings: list[str]) -> list[str]:
    keywords = (
        "minecraft:",
        "Items",
        "CustomName",
        "LootTable",
        "display",
        "Lore",
        "flag",
        "ctf{",
    )
    return [value for value in strings if any(keyword.lower() in value.lower() for keyword in keywords)]


def _retained_minecraft_chunk_summaries(chunks: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    retained: list[dict[str, Any]] = []
    seen: set[int] = set()
    for chunk in chunks:
        if chunk.get("flag_candidates"):
            retained.append(chunk)
            seen.add(int(chunk["sector"]))
    for chunk in chunks:
        if len(retained) >= limit:
            break
        sector = int(chunk["sector"])
        if sector in seen:
            continue
        retained.append(chunk)
        seen.add(sector)
    return sorted(retained, key=lambda item: int(item["sector"]))


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
