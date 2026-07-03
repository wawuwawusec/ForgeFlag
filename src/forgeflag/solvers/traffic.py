from __future__ import annotations

import codecs
import base64
import hashlib
from pathlib import Path
import re
import shutil
import struct

from forgeflag.ctf_scope import ctf_scope_evidence
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
from forgeflag.traffic_analysis import dns_summary_from_tshark, tcp_stream_shortlist
from forgeflag.transforms import transform_candidates


class TrafficSolver:
    name = "TrafficSolver"
    supported_categories = {ChallengeCategory.FORENSICS, ChallengeCategory.TRAFFIC}

    def solve(self, context: SolverContext) -> SolverResult:
        challenge = context.challenge
        findings: list[Finding] = []
        flag_candidates: list[str] = []
        pcap_paths = self._pcap_paths(context)
        image_waveform_paths = self._image_waveform_paths(context)

        if not pcap_paths and not image_waveform_paths:
            finding = Finding(
                challenge_id=challenge.challenge_id,
                solver=self.name,
                finding="Traffic solver found no packet captures",
                evidence={
                    "attachment_paths": list(challenge.attachment_paths),
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.TRAFFIC),
                },
                hypothesis="Traffic analysis applies only when a registered attachment is a packet capture.",
                confidence=0.35,
                next_action="Register a .pcap, .pcapng, or .cap artifact if this challenge includes traffic data.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(self.name, challenge.challenge_id, "not_applicable", (finding,))

        for pcap_path in pcap_paths:
            findings.append(self._analyze_pcap(context, pcap_path, flag_candidates))
        for image_path in image_waveform_paths:
            findings.append(self._analyze_image_waveform(context, image_path, flag_candidates))

        return SolverResult(
            self.name,
            challenge.challenge_id,
            "flag_candidate" if flag_candidates else "ok",
            tuple(findings),
            tuple(dict.fromkeys(flag_candidates)),
        )

    def _pcap_paths(self, context: SolverContext) -> list[str]:
        paths: list[str] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = ctf.ensure_existing_file(attachment_path)
            except FileNotFoundError:
                continue
            if _looks_like_pcap_path(resolved):
                paths.append(resolved)
                continue
            result = ctf.file_identify(resolved, context.scope)
            context.notebook.add_tool_result(context.challenge.challenge_id, result)
            if _looks_like_pcap_result(result):
                paths.append(resolved)
        return paths

    def _image_waveform_paths(self, context: SolverContext) -> list[str]:
        paths: list[str] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = ctf.ensure_existing_file(attachment_path)
            except FileNotFoundError:
                continue
            if _looks_like_rf_image_context(context, resolved):
                paths.append(resolved)
        return paths

    def _analyze_pcap(
        self,
        context: SolverContext,
        pcap_path: str,
        flag_candidates: list[str],
    ) -> Finding:
        challenge_id = context.challenge.challenge_id
        labeled_results = [
            ("tshark_pcap_summary", ctf.tshark_pcap_summary(pcap_path, packet_limit=50, scope=context.scope)),
            ("tshark_traffic_analysis", ctf.tshark_traffic_analysis(pcap_path, context.scope)),
            ("tshark_flag_scan", ctf.tshark_flag_scan(pcap_path, scope=context.scope)),
            ("tshark_dns_summary", ctf.tshark_dns_summary(pcap_path, context.scope)),
            ("tshark_tcp_streams", ctf.tshark_tcp_streams(pcap_path, scope=context.scope)),
            ("tshark_http_requests", ctf.tshark_http_requests(pcap_path, context.scope)),
            ("tshark_http_artifact_scan", ctf.tshark_http_artifact_scan(pcap_path, context.scope)),
        ]
        for _, result in labeled_results:
            context.notebook.add_tool_result(challenge_id, result)

        combined_output = "\n".join(
            str(result.raw.get("stdout", "")) + "\n" + str(result.raw.get("stderr", ""))
            for _, result in labeled_results
        )
        decoded_http_artifacts = _decoded_http_artifacts(
            str(dict(labeled_results)["tshark_http_artifact_scan"].raw.get("stdout", ""))
        )
        http_object_exports = _export_http_objects(
            context,
            pcap_path,
            "\n".join(
                [
                    str(dict(labeled_results)["tshark_pcap_summary"].raw.get("stdout", "")),
                    str(dict(labeled_results)["tshark_traffic_analysis"].raw.get("stdout", "")),
                    str(dict(labeled_results)["tshark_tcp_streams"].raw.get("stdout", "")),
                    str(dict(labeled_results)["tshark_http_requests"].raw.get("stdout", "")),
                    str(dict(labeled_results)["tshark_http_artifact_scan"].raw.get("stdout", "")),
                ]
            ),
        )
        dns_summary = dns_summary_from_tshark(str(dict(labeled_results)["tshark_dns_summary"].raw.get("stdout", "")))
        tcp_streams = tcp_stream_shortlist(
            str(dict(labeled_results)["tshark_tcp_streams"].raw.get("stdout", "")),
            http_requests_output=str(dict(labeled_results)["tshark_http_requests"].raw.get("stdout", "")),
            decoded_payloads=decoded_http_artifacts,
        )
        tcp_stream_payloads = _follow_tcp_stream_payloads(context, pcap_path, tcp_streams)
        data_uri_artifacts = _extract_data_uri_artifacts(context, pcap_path, tcp_stream_payloads)
        tcp_stream_payloads = _sanitized_tcp_stream_payloads(tcp_stream_payloads)
        protocol_streams = _protocol_stream_summaries(tcp_stream_payloads)
        decoded_dns_hints = [str(value) for value in dns_summary.get("decoded_query_hints", [])]
        stream_payload_text = "\n".join(str(item.get("sample", "")) for item in tcp_stream_payloads)
        data_uri_text = "\n".join(
            "\n".join([str(item.get("text_preview", "")), *[str(flag) for flag in item.get("flags", [])]])
            for item in data_uri_artifacts
        )
        exported_object_text = "\n".join(
            "\n".join([str(item.get("text_preview", "")), *[str(flag) for flag in item.get("flags", [])]])
            for item in http_object_exports
        )
        antsword_recovery = _recover_antsword_cut_flags(http_object_exports)
        antsword_flags = tuple(antsword_recovery.get("flag_candidates", ())) if antsword_recovery else ()
        tool_version_flags = _tool_version_flags(candidate_text_seed(context, combined_output, stream_payload_text))
        raw_capture_scan = _raw_capture_flag_scan(pcap_path)
        pcap_record_resync = _pcap_record_resync_repair(pcap_path, _pcap_repair_dir(context, pcap_path))
        ip_id_stego = _ip_id_stego_recovery(pcap_path)
        if pcap_record_resync:
            repaired_ip_id_stego = _ip_id_stego_recovery(str(pcap_record_resync["path"]))
            if repaired_ip_id_stego.get("flag_candidates") or repaired_ip_id_stego.get("decoded_text"):
                ip_id_stego = repaired_ip_id_stego
            pcap_record_resync["recovered_flags"] = list(ip_id_stego.get("flag_candidates", []))
        candidate_text = "\n".join(
            [
                combined_output,
                *decoded_http_artifacts,
                *decoded_dns_hints,
                stream_payload_text,
                data_uri_text,
                exported_object_text,
                raw_capture_scan.get("text_preview", ""),
                "\n".join(str(flag) for flag in raw_capture_scan.get("flags", [])),
                str(ip_id_stego.get("decoded_text", "")),
                "\n".join(str(flag) for flag in ip_id_stego.get("flag_candidates", [])),
                "\n".join(str(item.get("flag", "")) for item in tool_version_flags),
            ]
        )
        flags = tuple(
            dict.fromkeys(
                [
                    *extract_flags(candidate_text),
                    *antsword_flags,
                ]
            )
        )
        flag_candidates.extend(flags)

        evidence = {
            "artifact": {"name": Path(pcap_path).name, "path": pcap_path},
            "tool_statuses": {label: result.status for label, result in labeled_results},
            "tool_samples": {label: _tool_sample(result) for label, result in labeled_results},
            "http_requests": _interesting_lines(str(dict(labeled_results)["tshark_http_requests"].raw.get("stdout", ""))),
            "decoded_http_artifacts": decoded_http_artifacts[:20],
            "http_object_exports": http_object_exports,
            "dns_summary": dns_summary,
            "tcp_streams": tcp_streams,
            "tcp_stream_payloads": tcp_stream_payloads,
            "data_uri_artifacts": data_uri_artifacts,
            "protocol_streams": protocol_streams,
            "flag_candidates": list(flags),
            **({"raw_capture_flag_scan": raw_capture_scan} if raw_capture_scan.get("flags") else {}),
            **({"pcap_record_resync": pcap_record_resync} if pcap_record_resync else {}),
            **({"ip_id_stego": ip_id_stego} if ip_id_stego.get("flag_candidates") else {}),
            **({"tool_version_flags": tool_version_flags} if tool_version_flags else {}),
            "ctf_scope": ctf_scope_evidence(ChallengeCategory.TRAFFIC),
        }
        if antsword_recovery:
            evidence["antsword_recovery"] = antsword_recovery

        finding = Finding(
            challenge_id=challenge_id,
            solver=self.name,
            finding="Analyzed packet capture traffic",
            evidence=evidence,
            hypothesis=_traffic_hypothesis(flags),
            confidence=0.82 if flags else 0.62,
            next_action=_next_action(flags),
        )
        context.notebook.add_finding(finding)
        return finding

    def _analyze_image_waveform(
        self,
        context: SolverContext,
        image_path: str,
        flag_candidates: list[str],
    ) -> Finding:
        recovery = _recover_ask_manchester_from_image(image_path)
        flags = tuple(recovery.get("flag_candidates", ())) if recovery else ()
        flag_candidates.extend(flags)
        evidence = {
            "artifact": {"name": Path(image_path).name, "path": image_path},
            "rf_image_waveform": recovery or {"encoding": "ask_ook_manchester", "flag_candidates": []},
            "flag_candidates": list(flags),
            "ctf_scope": ctf_scope_evidence(ChallengeCategory.TRAFFIC),
        }
        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Decoded RF image waveform" if flags else "Analyzed RF image waveform",
            evidence=evidence,
            hypothesis=(
                "Image waveform appears to carry ASK/OOK Manchester-encoded data with a flag-like token."
                if flags
                else "Image waveform evidence is available; refine ASK/OOK timing or modulation assumptions."
            ),
            confidence=0.82 if flags else 0.48,
            next_action=(
                "Send recovered RF waveform candidates to Verifier and preserve timing evidence."
                if flags
                else "Inspect the waveform crop and tune half-bit width, start offset, or Manchester polarity."
            ),
        )
        context.notebook.add_finding(finding)
        return finding


def _looks_like_pcap_path(path: str) -> bool:
    return Path(path).suffix.lower() in {".pcap", ".pcapng", ".cap"}


def _looks_like_image_path(path: str) -> bool:
    return Path(path).suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp"}


def _looks_like_rf_image_context(context: SolverContext, path: str) -> bool:
    if not _looks_like_image_path(path):
        return False
    challenge = context.challenge
    if challenge.category == ChallengeCategory.TRAFFIC:
        return True
    text = " ".join(
        [
            challenge.title or "",
            challenge.description or "",
            " ".join(challenge.tags),
            Path(path).name,
        ]
    ).lower()
    return any(marker in text for marker in ("rf", "radio", "ask", "ook", "manchester", "sine", "waveform", "signal"))


def _looks_like_pcap_result(result) -> bool:
    stdout = str(result.raw.get("stdout", "")).lower()
    return "pcap" in stdout or "packet capture" in stdout


def _tool_sample(result) -> dict[str, str]:
    stdout = str(result.raw.get("stdout", ""))
    stderr = str(result.raw.get("stderr", ""))
    return {"stdout": stdout[:500], "stderr": stderr[:500]}


def _raw_capture_flag_scan(path: str, max_bytes: int = 4_000_000) -> dict[str, object]:
    artifact = Path(path)
    try:
        size = artifact.stat().st_size
        with artifact.open("rb") as handle:
            data = handle.read(max_bytes)
    except OSError:
        return {"flags": [], "bytes_scanned": 0, "truncated": False, "text_preview": ""}
    text = data.decode("latin1", errors="ignore")
    printable = re.sub(r"[^\x09\x0a\x0d\x20-\x7e]", " ", text)
    flags = list(extract_flags(printable))
    preview = _compact_text(printable, limit=1200) if flags else ""
    return {
        "flags": flags,
        "bytes_scanned": len(data),
        "truncated": size > max_bytes,
        "text_preview": preview,
    }


def _pcap_record_resync_repair(path: str, output_dir: Path, max_packet_size: int = 262_144) -> dict[str, object] | None:
    artifact = Path(path)
    try:
        data = artifact.read_bytes()
    except OSError:
        return None
    endian = _pcap_endian(data)
    if not endian or len(data) < 24:
        return None

    def plausible_header(offset: int) -> bool:
        if offset + 16 > len(data):
            return False
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + "IIII", data, offset)
        return (
            946_684_800 <= ts_sec <= 2_052_460_800
            and ts_usec < 1_000_000
            and 0 < incl_len <= max_packet_size
            and incl_len <= orig_len <= max_packet_size
            and offset + 16 + incl_len <= len(data)
        )

    records: list[tuple[int, int, int, int, int, int]] = []
    repairs: list[dict[str, int]] = []
    offset = 24
    record_index = 0
    while offset + 16 <= len(data):
        if not plausible_header(offset):
            found = _find_next_pcap_header(plausible_header, offset + 1, min(len(data) - 16, offset + max_packet_size))
            if found is None:
                break
            repairs.append(
                {
                    "record": record_index + 1,
                    "bad_header_offset": offset,
                    "resynced_header_offset": found,
                    "skipped_bytes": found - offset,
                }
            )
            offset = found

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + "IIII", data, offset)
        data_start = offset + 16
        expected_next = data_start + incl_len
        found_next = None
        if expected_next < len(data) and not plausible_header(expected_next):
            found_next = _find_next_pcap_header(plausible_header, data_start, min(len(data) - 16, data_start + max_packet_size))
        if found_next is not None and found_next != expected_next:
            fixed_incl_len = found_next - data_start
            if 0 < fixed_incl_len <= max_packet_size:
                repairs.append(
                    {
                        "record": record_index + 1,
                        "header_offset": offset,
                        "old_incl_len": incl_len,
                        "fixed_incl_len": fixed_incl_len,
                        "next_header_offset": found_next,
                    }
                )
                incl_len = fixed_incl_len
                orig_len = min(orig_len, incl_len)
                expected_next = found_next

        records.append((ts_sec, ts_usec, incl_len, orig_len, data_start, data_start + incl_len))
        record_index += 1
        offset = expected_next
        if offset >= len(data):
            break

    if not repairs or not records:
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    repaired_path = output_dir / f"{artifact.stem}-resync{artifact.suffix or '.pcap'}"
    repaired = bytearray(data[:24])
    for ts_sec, ts_usec, incl_len, orig_len, start, end in records:
        repaired += struct.pack(endian + "IIII", ts_sec, ts_usec, incl_len, max(orig_len, incl_len))
        repaired += data[start:end]
    repaired_path.write_bytes(repaired)

    return {
        "method": "pcap_record_header_resync",
        "path": str(repaired_path),
        "original_sha256": hashlib.sha256(data).hexdigest(),
        "repaired_sha256": hashlib.sha256(repaired).hexdigest(),
        "records_recovered": len(records),
        "repair_count": len(repairs),
        "repairs": repairs[:50],
    }


def _find_next_pcap_header(plausible_header, start: int, stop: int) -> int | None:
    for candidate in range(max(24, start), max(24, stop)):
        if plausible_header(candidate):
            return candidate
    return None


def _pcap_endian(data: bytes) -> str | None:
    if data.startswith(b"\xd4\xc3\xb2\xa1") or data.startswith(b"\x4d\x3c\xb2\xa1"):
        return "<"
    if data.startswith(b"\xa1\xb2\xc3\xd4") or data.startswith(b"\xa1\xb2\x3c\x4d"):
        return ">"
    return None


def _ip_id_stego_recovery(path: str, marker: bytes = b"where is the flag?") -> dict[str, object]:
    try:
        data = Path(path).read_bytes()
    except OSError:
        return {"flag_candidates": [], "decoded_text": "", "packet_count": 0}
    endian = _pcap_endian(data)
    if not endian or len(data) < 24:
        return {"flag_candidates": [], "decoded_text": "", "packet_count": 0}

    ip_ids: list[int] = []
    marker_lower = marker.lower()
    offset = 24
    while offset + 16 <= len(data):
        try:
            _, _, incl_len, _ = struct.unpack_from(endian + "IIII", data, offset)
        except struct.error:
            break
        if incl_len <= 0 or incl_len > 262_144 or offset + 16 + incl_len > len(data):
            break
        packet = data[offset + 16 : offset + 16 + incl_len]
        parsed = _ethernet_ipv4_tcp_payload(packet)
        if parsed:
            payload = bytes(parsed["payload"])
            if payload and (marker_lower in payload.lower() or int(parsed["dst_port"]) == 2222):
                ip_ids.append(int(parsed["ip_id"]))
        offset += 16 + incl_len

    candidates = _decode_ip_id_candidates(ip_ids)
    deduped_ip_ids = _dedupe_adjacent_values(ip_ids)
    if deduped_ip_ids != ip_ids:
        candidates.extend(_decode_ip_id_candidates(deduped_ip_ids))
    decoded_text = "\n".join(item["decoded_text"] for item in candidates)
    flags = list(dict.fromkeys(flag for item in candidates for flag in item["flags"]))
    return {
        "method": "ipv4_identification_little_endian_pairs",
        "marker": marker.decode("ascii", errors="replace"),
        "packet_count": len(ip_ids),
        "ip_ids_hex": [f"0x{value:04x}" for value in ip_ids[:80]],
        "adjacent_deduped_ip_ids_hex": [f"0x{value:04x}" for value in deduped_ip_ids[:80]],
        "decoded_text": _compact_text(decoded_text, limit=1000),
        "flag_candidates": flags,
    }


def _ethernet_ipv4_tcp_payload(packet: bytes) -> dict[str, object] | None:
    if len(packet) < 14:
        return None
    ether_type = int.from_bytes(packet[12:14], "big")
    ip_offset = 14
    if ether_type == 0x8100 and len(packet) >= 18:
        ether_type = int.from_bytes(packet[16:18], "big")
        ip_offset = 18
    if ether_type != 0x0800 or len(packet) < ip_offset + 20:
        return None
    version_ihl = packet[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(packet) < ip_offset + ihl:
        return None
    total_length = int.from_bytes(packet[ip_offset + 2 : ip_offset + 4], "big")
    if total_length < ihl or ip_offset + total_length > len(packet):
        total_length = min(len(packet) - ip_offset, max(total_length, ihl))
    protocol = packet[ip_offset + 9]
    if protocol != 6:
        return None
    ip_id = int.from_bytes(packet[ip_offset + 4 : ip_offset + 6], "big")
    tcp_offset = ip_offset + ihl
    if len(packet) < tcp_offset + 20:
        return None
    src_port = int.from_bytes(packet[tcp_offset : tcp_offset + 2], "big")
    dst_port = int.from_bytes(packet[tcp_offset + 2 : tcp_offset + 4], "big")
    data_offset = (packet[tcp_offset + 12] >> 4) * 4
    if data_offset < 20:
        return None
    payload_offset = tcp_offset + data_offset
    payload_end = ip_offset + total_length
    if payload_offset > payload_end:
        return None
    return {"ip_id": ip_id, "src_port": src_port, "dst_port": dst_port, "payload": packet[payload_offset:payload_end]}


def _decode_ip_id_candidates(ip_ids: list[int]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for byte_order in ("little", "big"):
        raw = b"".join(value.to_bytes(2, byte_order) for value in ip_ids)
        text = raw.split(b"\x00", 1)[0].decode("latin1", errors="ignore")
        flags = list(extract_flags(text))
        if flags or _printable_ratio(text) >= 0.8:
            candidates.append({"byte_order": byte_order, "decoded_text": text, "flags": flags})
    return candidates


def _dedupe_adjacent_values(values: list[int]) -> list[int]:
    deduped: list[int] = []
    for value in values:
        if deduped and value == deduped[-1]:
            continue
        deduped.append(value)
    return deduped


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for char in text if char in "\t\r\n" or 32 <= ord(char) <= 126) / len(text)


def _recover_ask_manchester_from_image(path: str) -> dict[str, object] | None:
    try:
        from PIL import Image
    except ImportError:
        return None

    try:
        image = Image.open(path).convert("RGB")
    except OSError:
        return None

    width, height = image.size
    pixels = image.load()
    y_trace: list[float | None] = []
    mask_columns = 0
    for x in range(width):
        ys: list[int] = []
        for y in range(height):
            red, green, blue = pixels[x, y]
            if blue - max(red, green) > 24:
                ys.append(y)
        if ys:
            mask_columns += 1
            y_trace.append(sum(ys) / len(ys))
        else:
            y_trace.append(None)

    if mask_columns < max(40, width // 20):
        return None

    trace = _interpolate_missing_trace(y_trace)
    if len(trace) < 240:
        return None

    center = sum(trace) / len(trace)
    centered = [value - center for value in trace]
    carrier_period = _estimate_carrier_period(centered)
    envelope_window = max(4, min(32, int(round(carrier_period or 12.0))))
    energy = _moving_average([value * value for value in centered], envelope_window)
    match = _decode_manchester_energy(
        energy,
        approximate_half_bit_width=(carrier_period * 2.0 if carrier_period else None),
    )
    if not match:
        return None

    return {
        "encoding": "ask_ook_manchester",
        "flag_candidates": match["flag_candidates"],
        "decoded_text_preview": _compact_text(str(match["decoded_text"]), limit=500),
        "image_size": {"width": width, "height": height},
        "blue_signal_columns": mask_columns,
        "carrier_period_pixels": round(carrier_period, 3) if carrier_period else None,
        "envelope_window": envelope_window,
        "start_offset": match["start_offset"],
        "byte_aligned_start_offset": round(
            float(match["start_offset"]) + float(match["byte_offset"]) * 2.0 * float(match["half_bit_width"]),
            2,
        ),
        "half_bit_width": match["half_bit_width"],
        "byte_offset": match["byte_offset"],
        "manchester_mapping": match["manchester_mapping"],
        "printable_ratio": round(float(match["printable_ratio"]), 3),
    }


def _interpolate_missing_trace(trace: list[float | None]) -> list[float]:
    known = [(index, value) for index, value in enumerate(trace) if value is not None]
    if not known:
        return []
    output = [0.0] * len(trace)
    first_index, first_value = known[0]
    for index in range(first_index + 1):
        output[index] = float(first_value)
    previous_index, previous_value = first_index, float(first_value)
    for current_index, current_value_raw in known[1:]:
        current_value = float(current_value_raw)
        span = current_index - previous_index
        for offset in range(span):
            ratio = offset / span if span else 0.0
            output[previous_index + offset] = previous_value + (current_value - previous_value) * ratio
        previous_index, previous_value = current_index, current_value
    for index in range(previous_index, len(trace)):
        output[index] = previous_value
    return output


def _estimate_carrier_period(trace: list[float], min_period: int = 4, max_period: int = 40) -> float | None:
    if len(trace) < max_period * 4:
        return None
    max_samples = min(len(trace), 6000)
    sample = trace[:max_samples]
    best_period = None
    best_score = float("-inf")
    for period in range(min_period, max_period + 1):
        score = 0.0
        count = 0
        for index in range(max_samples - period):
            score += sample[index] * sample[index + period]
            count += 1
        if count:
            score /= count
        if score > best_score:
            best_score = score
            best_period = period
    return float(best_period) if best_period else None


def _moving_average(values: list[float], window: int) -> list[float]:
    if window <= 1:
        return list(values)
    prefix = [0.0]
    for value in values:
        prefix.append(prefix[-1] + value)
    radius = window // 2
    output: list[float] = []
    for index in range(len(values)):
        start = max(0, index - radius)
        end = min(len(values), index + radius + 1)
        output.append((prefix[end] - prefix[start]) / max(1, end - start))
    return output


def _decode_manchester_energy(energy: list[float], approximate_half_bit_width: float | None = None) -> dict[str, object] | None:
    prefix = [0.0]
    for value in energy:
        prefix.append(prefix[-1] + value)

    best_match: dict[str, object] | None = None
    for half_bit_width in _half_bit_width_candidates(approximate_half_bit_width):
        max_start = min(len(energy) - 160, 1400)
        if max_start <= 0:
            continue
        start_step = max(2, int(half_bit_width // 6))
        for start_offset in range(0, max_start + 1, start_step):
            half_energies = _sample_half_bit_energies(prefix, start_offset, half_bit_width)
            if len(half_energies) < 80:
                continue
            for first_half_offset in (0, 1):
                pair_energies = half_energies[first_half_offset:]
                if len(pair_energies) < 80:
                    continue
                pair_count = len(pair_energies) // 2
                data_bits_low_high_one: list[int] = []
                for pair_index in range(pair_count):
                    first = pair_energies[pair_index * 2]
                    second = pair_energies[pair_index * 2 + 1]
                    data_bits_low_high_one.append(1 if second > first else 0)
                for mapping, bits in (
                    ("low_high_is_one", data_bits_low_high_one),
                    ("high_low_is_one", [1 - bit for bit in data_bits_low_high_one]),
                ):
                    decoded = _best_ascii_decode(bits)
                    flags = list(extract_flags(decoded["text"]))
                    if not flags:
                        continue
                    match = {
                        "flag_candidates": flags,
                        "decoded_text": decoded["text"],
                        "printable_ratio": decoded["printable_ratio"],
                        "byte_offset": decoded["byte_offset"],
                        "start_offset": start_offset + int(round(first_half_offset * half_bit_width)),
                        "half_bit_width": round(half_bit_width, 2),
                        "manchester_mapping": mapping,
                    }
                    if not best_match or _rf_match_score(match) > _rf_match_score(best_match):
                        best_match = match
                    if decoded["printable_ratio"] >= 0.98:
                        return match
    return best_match


def _half_bit_width_candidates(approximate_half_bit_width: float | None = None) -> list[float]:
    candidates: list[float] = []
    if approximate_half_bit_width:
        center = max(8.0, min(64.0, approximate_half_bit_width))
        for offset in range(-10, 11):
            candidates.append(round(center + offset * 0.05, 2))
    for value in range(48, 145, 2):
        candidates.append(value / 4)
    deduped: list[float] = []
    seen: set[float] = set()
    for value in candidates:
        if value < 8.0 or value > 64.0 or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _sample_half_bit_energies(prefix: list[float], start_offset: int, half_bit_width: float, limit: int = 2200) -> list[float]:
    energies: list[float] = []
    index = 0
    while index < limit:
        start = int(round(start_offset + index * half_bit_width))
        end = int(round(start_offset + (index + 1) * half_bit_width))
        if end >= len(prefix) or end <= start:
            break
        energies.append((prefix[end] - prefix[start]) / max(1, end - start))
        index += 1
    return energies


def _best_ascii_decode(bits: list[int]) -> dict[str, object]:
    best = {"text": "", "printable_ratio": 0.0, "byte_offset": 0}
    for byte_offset in range(8):
        chars: list[str] = []
        printable = 0
        total = 0
        for index in range(byte_offset, len(bits) - 7, 8):
            value = 0
            for bit in bits[index : index + 8]:
                value = (value << 1) | bit
            total += 1
            if value in (9, 10, 13) or 32 <= value <= 126:
                printable += 1
                chars.append(chr(value))
            else:
                chars.append(" ")
        text = "".join(chars)
        ratio = printable / total if total else 0.0
        flag_bonus = 1.0 if extract_flags(text) else 0.0
        score = ratio + flag_bonus
        best_score = float(best["printable_ratio"]) + (1.0 if extract_flags(str(best["text"])) else 0.0)
        if score > best_score:
            best = {"text": text, "printable_ratio": ratio, "byte_offset": byte_offset}
    return best


def _rf_match_score(match: dict[str, object]) -> float:
    text = str(match.get("decoded_text", ""))
    flags = match.get("flag_candidates", [])
    printable_ratio = float(match.get("printable_ratio", 0.0))
    return len(flags) * 10.0 + printable_ratio + min(len(text), 200) / 1000.0


def candidate_text_seed(context: SolverContext, combined_output: str, stream_payload_text: str) -> str:
    return "\n".join(
        [
            context.challenge.title or "",
            context.challenge.description or "",
            " ".join(context.challenge.tags),
            combined_output,
            stream_payload_text,
        ]
    )


def _tool_version_flags(text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    wrapper = "DUCTF" if "ductf" in text.lower() else "flag"
    for tool, version in re.findall(r"\b(Nikto)/([0-9]+(?:\.[0-9A-Za-z_-]+)+)", text, flags=re.IGNORECASE):
        normalized_tool = tool.lower()
        normalized_version = version.strip().strip(").,;")
        flag = f"{wrapper}{{{normalized_tool}_{normalized_version}}}"
        findings.append(
            {
                "tool": normalized_tool,
                "version": normalized_version,
                "flag": flag,
                "source": "http_user_agent_or_stream_text",
            }
        )
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding["tool"], finding["version"], finding["flag"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _follow_tcp_stream_payloads(
    context: SolverContext,
    pcap_path: str,
    tcp_streams: list[dict[str, object]],
    limit: int = 3,
) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for stream in tcp_streams[:limit]:
        stream_id = str(stream.get("stream_id") or "")
        if not stream_id.isdigit():
            continue
        result = ctf.tshark_follow_tcp_stream(pcap_path, int(stream_id), scope=context.scope)
        context.notebook.add_tool_result(context.challenge.challenge_id, result)
        raw_text = str(result.raw.get("stdout", ""))
        sample = _compact_text(raw_text, limit=1200)
        flags = extract_flags(sample)
        payloads.append(
            {
                "stream_id": stream_id,
                "tool_status": result.status,
                "score": stream.get("score"),
                "hints": stream.get("hints", []),
                "sample": sample,
                "flags": list(flags),
                "_raw_text_for_extract": raw_text,
            }
        )
    return payloads


def _sanitized_tcp_stream_payloads(tcp_stream_payloads: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{key: value for key, value in payload.items() if not key.startswith("_")} for payload in tcp_stream_payloads]


def _export_http_objects(
    context: SolverContext,
    pcap_path: str,
    http_hint_output: str,
    limit: int = 20,
) -> list[dict[str, object]]:
    if "http" not in http_hint_output.lower():
        return []

    export_dir = _http_object_export_dir(context, pcap_path)
    if export_dir.exists():
        shutil.rmtree(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)

    result = ctf.tshark_http_object_export(pcap_path, str(export_dir), scope=context.scope)
    context.notebook.add_tool_result(context.challenge.challenge_id, result)
    candidate_paths = [Path(path) for path in result.artifacts] if result.artifacts else list(export_dir.rglob("*"))
    summaries: list[dict[str, object]] = []
    for path in sorted(candidate_paths):
        if not path.is_file():
            continue
        summaries.append(_exported_object_summary(path))
        if len(summaries) >= limit:
            break
    return summaries


def _protocol_stream_summaries(tcp_stream_payloads: list[dict[str, object]]) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for payload in tcp_stream_payloads:
        sample = str(payload.get("sample", ""))
        protocol = _classify_cleartext_protocol(sample)
        if not protocol:
            continue
        commands = _protocol_commands(protocol, sample)
        flags = extract_flags(sample)
        summaries.append(
            {
                "stream_id": str(payload.get("stream_id", "")),
                "protocol": protocol,
                "commands": commands[:12],
                "flags": list(flags),
                "sample": _compact_text(sample, limit=700),
            }
        )
    return summaries


DATA_URI_RE = re.compile(r"data:(image/[a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/=\r\n]+)")


def _extract_data_uri_artifacts(
    context: SolverContext,
    pcap_path: str,
    tcp_stream_payloads: list[dict[str, object]],
    limit: int = 10,
) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    output_dir = _data_uri_export_dir(context, pcap_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    for payload in tcp_stream_payloads:
        source_text = str(payload.get("_raw_text_for_extract", payload.get("sample", "")))
        for match in DATA_URI_RE.finditer(source_text):
            media_type = match.group(1).lower()
            encoded = "".join(match.group(2).split())
            try:
                data = base64.b64decode(encoded, validate=True)
            except ValueError:
                continue
            suffix = _data_uri_suffix(media_type)
            index = len(artifacts) + 1
            path = output_dir / f"stream-{payload.get('stream_id', 'unknown')}-data-uri-{index}{suffix}"
            path.write_bytes(data)
            decoded_text = data[:1_000_000].decode("utf-8", errors="replace")
            text_preview = _compact_text(decoded_text)
            flags = list(extract_flags(decoded_text))
            artifacts.append(
                {
                    "stream_id": str(payload.get("stream_id", "")),
                    "media_type": media_type,
                    "path": str(path),
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "text_preview": text_preview,
                    "flags": flags,
                }
            )
            if len(artifacts) >= limit:
                return artifacts
    return artifacts


def _classify_cleartext_protocol(sample: str) -> str | None:
    upper = sample.upper()
    if any(marker in upper for marker in ("EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:", "\nDATA", "\r\nDATA")):
        return "SMTP"
    if any(marker in upper for marker in ("USER ", "PASS ", "RETR ", "STOR ", "220 FTP", "230 ")):
        return "FTP"
    if any(marker in upper for marker in ("NICK ", "USER ", "JOIN #", "PRIVMSG ", "NOTICE ")):
        return "IRC"
    return None


def _protocol_commands(protocol: str, sample: str) -> list[str]:
    command_sets = {
        "SMTP": {"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN", "NOOP", "QUIT", "AUTH", "STARTTLS"},
        "FTP": {"USER", "PASS", "SYST", "PWD", "CWD", "TYPE", "PASV", "PORT", "LIST", "RETR", "STOR", "QUIT"},
        "IRC": {"NICK", "USER", "JOIN", "PART", "PRIVMSG", "NOTICE", "PING", "PONG", "QUIT", "MODE", "TOPIC"},
    }
    allowed = command_sets.get(protocol, set())
    commands: list[str] = []
    upper = sample.upper()
    for command in allowed:
        if re.search(rf"(?<![A-Z0-9]){re.escape(command)}(?:\s|:|$)", upper) and command not in commands:
            commands.append(command)
    return commands


def _http_object_export_dir(context: SolverContext, pcap_path: str) -> Path:
    artifacts_root = Path(context.notebook.path).parent / "artifacts"
    return artifacts_root / _safe_component(context.challenge.challenge_id) / "http-objects" / _safe_component(Path(pcap_path).stem)


def _data_uri_export_dir(context: SolverContext, pcap_path: str) -> Path:
    artifacts_root = Path(context.notebook.path).parent / "artifacts"
    return artifacts_root / _safe_component(context.challenge.challenge_id) / "data-uris" / _safe_component(Path(pcap_path).stem)


def _pcap_repair_dir(context: SolverContext, pcap_path: str) -> Path:
    artifacts_root = Path(context.notebook.path).parent / "artifacts"
    return artifacts_root / _safe_component(context.challenge.challenge_id) / "pcap-repairs" / _safe_component(Path(pcap_path).stem)


def _data_uri_suffix(media_type: str) -> str:
    suffixes = {
        "image/jpeg": ".jpg",
        "image/jpg": ".jpg",
        "image/png": ".png",
        "image/gif": ".gif",
        "image/bmp": ".bmp",
        "image/webp": ".webp",
        "image/svg+xml": ".svg",
    }
    return suffixes.get(media_type, ".bin")


def _exported_object_summary(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    preview = _compact_text(data[:4096].decode("utf-8", errors="replace"))
    return {
        "name": path.name,
        "path": str(path),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "text_preview": preview,
        "flags": list(extract_flags(preview)),
    }


def _recover_antsword_cut_flags(http_object_exports: list[dict[str, object]]) -> dict[str, object] | None:
    objects = _export_text_objects(http_object_exports)
    for command_object in objects:
        reversed_text = command_object["text"][::-1]
        positions = [int(value) for value in re.findall(r"cut\s+-c\s+(\d+)\s+/flag", reversed_text)]
        if len(positions) < 8:
            continue
        for output_object in objects:
            if output_object["name"] == command_object["name"]:
                continue
            recovery = _recover_antsword_output(
                positions=positions,
                output_text=output_object["text"],
                command_object=command_object["name"],
                output_object=output_object["name"],
            )
            if recovery:
                return recovery
    return None


def _export_text_objects(http_object_exports: list[dict[str, object]]) -> list[dict[str, str]]:
    objects: list[dict[str, str]] = []
    for item in http_object_exports:
        name = str(item.get("name") or item.get("path") or "http_object")
        path = Path(str(item.get("path") or ""))
        text = ""
        if path.is_file():
            text = path.read_bytes().decode("utf-8", errors="replace")
        if not text:
            text = str(item.get("text_preview") or "")
        if text:
            objects.append({"name": name, "text": text})
    return objects


def _recover_antsword_output(
    *,
    positions: list[int],
    output_text: str,
    command_object: str,
    output_object: str,
) -> dict[str, object] | None:
    for raw_chars in _antsword_output_char_sequences(output_text, expected_length=len(positions)):
        for transform_name, decoded_chars in (
            ("rot13", [_rot13_char(char) for char in raw_chars]),
            ("raw", raw_chars),
        ):
            flag_text = _chars_by_cut_positions(positions, decoded_chars)
            flags = list(extract_flags(flag_text))
            if not flags:
                continue
            return {
                "method": f"antsword_{transform_name}_reverse_cut",
                "command_object": command_object,
                "output_object": output_object,
                "positions": positions[:80],
                "decoded_chars": "".join(decoded_chars),
                "reconstructed_text": flag_text,
                "flag_candidates": flags,
                "reproduction": [
                    f"reverse {command_object} and extract cut -c N /flag positions",
                    f"read one-character command output from {output_object}",
                    f"apply {transform_name} to output characters and place each character at its cut position",
                ],
            }
    return None


def _antsword_output_char_sequences(output_text: str, expected_length: int) -> list[list[str]]:
    lines = [line.strip() for line in output_text.splitlines() if line.strip()]
    single_chars = [line for line in lines if len(line) == 1]
    candidates: list[list[str]] = [single_chars]
    for line in lines:
        if len(line) <= 1:
            continue
        candidates.extend(
            [
                [line[-1], *single_chars],
                [*single_chars, line[0]],
                [line[-1], *single_chars, line[0]],
            ]
        )
    deduped: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for chars in candidates:
        if len(chars) != expected_length or not all(len(char) == 1 for char in chars):
            continue
        key = tuple(chars)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(chars)
    return deduped


def _chars_by_cut_positions(positions: list[int], chars: list[str]) -> str:
    if not positions or len(positions) != len(chars):
        return ""
    output = ["?"] * max(positions)
    for position, char in zip(positions, chars):
        if position <= 0:
            return ""
        output[position - 1] = char
    return "".join(output)


def _rot13_char(char: str) -> str:
    return codecs.decode(char, "rot_13")


def _decoded_http_artifacts(output: str) -> list[str]:
    decoded: list[str] = []
    for line in output.splitlines():
        parts = line.split("|")
        if not parts:
            continue
        payload = parts[-1].strip()
        if not payload:
            continue
        flag_snippets: list[str] = []
        other_snippets: list[str] = []
        for candidate in transform_candidates(payload):
            for flag in extract_flags(candidate.value):
                flag_snippets.append(flag)
            snippet = _compact_text(candidate.value)
            if snippet:
                other_snippets.append(snippet)
        for snippet in [*flag_snippets, *other_snippets]:
            if snippet not in decoded:
                decoded.append(snippet)
    return decoded


def _interesting_lines(output: str, limit: int = 40) -> list[str]:
    return [_compact_text(line) for line in output.splitlines()[:limit] if _compact_text(line)]


def _compact_text(value: str, limit: int = 500) -> str:
    text = " ".join(value.replace("\x00", " ").split())
    return text[:limit]


def _safe_component(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in ("-", "_", ".") else "_" for char in value.strip())
    cleaned = cleaned.strip("._")
    return cleaned or "artifact"


def _traffic_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "Packet payload output contains a flag-like token that should be verified."
    return "Traffic evidence is available; protocol-specific pivots can narrow the next step."


def _next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send candidates to Verifier and preserve the packet capture as reproduction evidence."
    return "Add DNS, HTTP, or TCP stream-specific analysis based on protocol hierarchy and conversations."
