from __future__ import annotations

import binascii
import html
import re
import struct
import zlib
from pathlib import Path
from typing import Any

from forgeflag.flags import extract_flags


def analyze_png_ihdr(path: Path) -> dict[str, Any] | None:
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


def analyze_image_stego_hints(path: Path) -> dict[str, Any] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return _analyze_png_stego_hints(data)
    if data.startswith(b"\xff\xd8"):
        return _analyze_jpeg_stego_hints(data)
    return None


def _analyze_png_stego_hints(data: bytes) -> dict[str, Any] | None:
    chunks: list[dict[str, Any]] = []
    text_chunks: list[dict[str, str]] = []
    idat_payloads: list[dict[str, Any]] = []
    idat = bytearray()
    ihdr_body: bytes | None = None
    trailing_data: dict[str, Any] | None = None
    pos = 8
    while pos + 12 <= len(data):
        size = struct.unpack(">I", data[pos : pos + 4])[0]
        kind = data[pos + 4 : pos + 8]
        body_start = pos + 8
        body_end = body_start + size
        crc_end = body_end + 4
        if crc_end > len(data):
            kind_text = kind.decode("ascii", errors="replace")
            chunks.append({"type": kind_text, "size": size, "truncated": True})
            if kind == b"IDAT":
                idat_payload = _decode_independent_idat_payload(data[body_start:])
                if idat_payload:
                    idat_payload["chunk_index"] = len([chunk for chunk in chunks if chunk["type"] == "IDAT"]) - 1
                    idat_payload["truncated_chunk"] = True
                    idat_payloads.append(idat_payload)
            break
        kind_text = kind.decode("ascii", errors="replace")
        chunks.append({"type": kind_text, "size": size})
        body = data[body_start:body_end]
        if kind == b"IHDR":
            ihdr_body = body
        text_chunk = _decode_png_text_chunk(kind, body)
        if text_chunk:
            text_chunks.append(text_chunk)
        if kind == b"IDAT":
            idat.extend(body)
            idat_payload = _decode_independent_idat_payload(body)
            if idat_payload:
                idat_payload["chunk_index"] = len([chunk for chunk in chunks if chunk["type"] == "IDAT"]) - 1
                idat_payloads.append(idat_payload)
        pos = crc_end
        if kind == b"IEND":
            tail = data[crc_end:]
            if tail:
                trailing_data = _byte_preview(tail)
            break

    lsb_candidates = _extract_png_lsb_candidates(ihdr_body, bytes(idat))
    if not text_chunks and not idat_payloads and not trailing_data and not lsb_candidates:
        return None
    return {
        "format": "png",
        "chunks": chunks[:80],
        "text_chunks": text_chunks,
        **({"idat_payloads": idat_payloads} if idat_payloads else {}),
        **({"lsb_candidates": lsb_candidates} if lsb_candidates else {}),
        **({"trailing_data": trailing_data} if trailing_data else {}),
    }


def _decode_png_text_chunk(kind: bytes, body: bytes) -> dict[str, str] | None:
    if kind == b"tEXt" and b"\x00" in body:
        keyword, text = body.split(b"\x00", 1)
        return {
            "type": "tEXt",
            "keyword": _decode_preview(keyword, limit=80),
            "text_preview": _decode_preview(text, limit=500),
        }
    if kind == b"zTXt" and body.count(b"\x00") >= 1:
        keyword, rest = body.split(b"\x00", 1)
        if rest[:1] != b"\x00":
            return None
        try:
            text = zlib.decompress(rest[1:])
        except zlib.error:
            return None
        return {
            "type": "zTXt",
            "keyword": _decode_preview(keyword, limit=80),
            "text_preview": _decode_preview(text, limit=500),
        }
    if kind == b"iTXt" and b"\x00" in body:
        parts = body.split(b"\x00", 5)
        if len(parts) < 6:
            return None
        keyword, compression_flag, compression_method, _language, _translated, text = parts
        if compression_flag == b"\x01" and compression_method == b"\x00":
            try:
                text = zlib.decompress(text)
            except zlib.error:
                return None
        return {
            "type": "iTXt",
            "keyword": _decode_preview(keyword, limit=80),
            "text_preview": _decode_preview(text, limit=500),
        }
    return None


def _analyze_jpeg_stego_hints(data: bytes) -> dict[str, Any] | None:
    pos = 2
    comments: list[dict[str, str]] = []
    app_markers: list[str] = []
    markers: list[dict[str, Any]] = [{"type": "SOI", "offset": 0}]
    trailing_data: dict[str, Any] | None = None
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker_offset = pos
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            break
        marker = data[pos]
        pos += 1
        if marker == 0x00:
            continue
        marker_type = _jpeg_marker_name(marker)
        if marker == 0xD9:
            markers.append({"type": marker_type, "offset": marker_offset})
            tail = data[pos:]
            if tail:
                trailing_data = _byte_preview(tail)
            break
        if pos + 2 > len(data):
            break
        size = struct.unpack(">H", data[pos : pos + 2])[0]
        if size < 2 or pos + size > len(data):
            break
        body = data[pos + 2 : pos + size]
        markers.append({"type": marker_type, "offset": marker_offset, "size": size})
        if marker == 0xFE:
            comments.append({"text_preview": _decode_preview(body, limit=500)})
        if 0xE0 <= marker <= 0xEF:
            app_markers.append(f"APP{marker - 0xE0}")
        if marker == 0xDA:
            eoi_offset = _find_jpeg_eoi(data, pos + size)
            if eoi_offset is not None:
                markers.append({"type": "EOI", "offset": eoi_offset})
                tail = data[eoi_offset + 2 :]
                if tail:
                    trailing_data = _byte_preview(tail)
            break
        pos += size

    if not comments and not app_markers and not trailing_data:
        return None
    return {
        "format": "jpeg",
        "comments": comments,
        "app_markers": list(dict.fromkeys(app_markers)),
        "markers": markers[:120],
        **({"trailing_data": trailing_data} if trailing_data else {}),
    }


def _jpeg_marker_name(marker: int) -> str:
    if 0xE0 <= marker <= 0xEF:
        return f"APP{marker - 0xE0}"
    names = {
        0xC0: "SOF0",
        0xC2: "SOF2",
        0xC4: "DHT",
        0xD8: "SOI",
        0xD9: "EOI",
        0xDA: "SOS",
        0xDB: "DQT",
        0xDD: "DRI",
        0xFE: "COM",
    }
    if 0xD0 <= marker <= 0xD7:
        return f"RST{marker - 0xD0}"
    return names.get(marker, f"0xFF{marker:02X}")


def _find_jpeg_eoi(data: bytes, start: int) -> int | None:
    pos = start
    while pos + 1 < len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker_offset = pos
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            return None
        marker = data[pos]
        if marker == 0x00 or 0xD0 <= marker <= 0xD7:
            pos += 1
            continue
        if marker == 0xD9:
            return marker_offset
        pos += 1
    return None


def _byte_preview(data: bytes) -> dict[str, Any]:
    return {
        "length": len(data),
        "ascii_preview": _decode_preview(data, limit=500),
        "hex_preview": data[:64].hex(),
    }


def _decode_independent_idat_payload(body: bytes) -> dict[str, Any] | None:
    if not body.startswith((b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")):
        return None
    try:
        decompressed = zlib.decompress(body)
    except zlib.error:
        return None
    strings = _printable_strings(decompressed)
    flags = [item.decode("ascii", errors="replace") for item in strings if b"{" in item and b"}" in item]
    if not flags and not _looks_like_text_payload(decompressed):
        return None
    return {
        "decompressed_size": len(decompressed),
        "text_preview": _decode_preview(decompressed, limit=500),
        **({"flag_like_strings": flags[:10]} if flags else {}),
    }


def _extract_png_lsb_candidates(ihdr_body: bytes | None, idat: bytes) -> list[dict[str, Any]]:
    decoded = _decode_png_scanlines(ihdr_body, idat)
    if not decoded:
        return []
    _width, _height, channels, raw = decoded
    channel_orders = ("rgb", "bgr", "rgba", "abgr", "r", "g", "b", "a")
    channel_map = {"r": 0, "g": 1, "b": 2, "a": 3}
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for bit_index in range(4):
        for channel_order in channel_orders:
            indexes = [channel_map[channel] for channel in channel_order]
            if any(index >= channels for index in indexes):
                continue
            bits = []
            for pixel_offset in range(0, len(raw), channels):
                for index in indexes:
                    bits.append((raw[pixel_offset + index] >> bit_index) & 1)
            for bit_order in ("lsb", "msb"):
                payload = _pack_bits(bits, bit_order)
                for text, decoders, flags in _lsb_text_hits(payload):
                    key = f"{bit_index}:{channel_order}:{bit_order}:{text}"
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append(
                        {
                            "recipe": f"b{bit_index + 1},{channel_order},{bit_order},xy",
                            "bit_plane": bit_index + 1,
                            "channel_order": channel_order,
                            "bit_order": bit_order,
                            "coordinate_order": "xy",
                            "text_preview": text[:500],
                            **({"decoders": decoders} if decoders else {}),
                            **({"flag_like_strings": list(flags)} if flags else {}),
                        }
                    )
                    if len(candidates) >= 12:
                        return candidates
    return candidates


def _decode_png_scanlines(ihdr_body: bytes | None, idat: bytes) -> tuple[int, int, int, bytes] | None:
    if ihdr_body is None or len(ihdr_body) != 13 or not idat:
        return None
    width, height, bit_depth, color_type, compression, filter_method, interlace = struct.unpack(">IIBBBBB", ihdr_body)
    if width <= 0 or height <= 0 or bit_depth != 8 or compression != 0 or filter_method != 0 or interlace != 0:
        return None
    channels_by_color_type = {2: 3, 6: 4}
    channels = channels_by_color_type.get(color_type)
    if channels is None:
        return None
    try:
        scanlines = zlib.decompress(idat)
    except zlib.error:
        return None
    row_size = width * channels
    stride = row_size + 1
    if len(scanlines) < height * stride:
        return None
    rows: list[bytes] = []
    previous = bytes(row_size)
    for y in range(height):
        start = y * stride
        filter_type = scanlines[start]
        row = scanlines[start + 1 : start + stride]
        if len(row) != row_size:
            return None
        unfiltered = _unfilter_png_row(filter_type, row, previous, channels)
        if unfiltered is None:
            return None
        rows.append(unfiltered)
        previous = unfiltered
    return width, height, channels, b"".join(rows)


def _unfilter_png_row(filter_type: int, row: bytes, previous: bytes, bytes_per_pixel: int) -> bytes | None:
    out = bytearray(row)
    for index, value in enumerate(row):
        left = out[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
        up = previous[index] if index < len(previous) else 0
        up_left = previous[index - bytes_per_pixel] if index >= bytes_per_pixel and index < len(previous) else 0
        if filter_type == 0:
            restored = value
        elif filter_type == 1:
            restored = value + left
        elif filter_type == 2:
            restored = value + up
        elif filter_type == 3:
            restored = value + ((left + up) // 2)
        elif filter_type == 4:
            restored = value + _paeth_predictor(left, up, up_left)
        else:
            return None
        out[index] = restored & 0xFF
    return bytes(out)


def _paeth_predictor(left: int, up: int, up_left: int) -> int:
    estimate = left + up - up_left
    distances = (abs(estimate - left), abs(estimate - up), abs(estimate - up_left))
    if distances[0] <= distances[1] and distances[0] <= distances[2]:
        return left
    if distances[1] <= distances[2]:
        return up
    return up_left


def _pack_bits(bits: list[int], bit_order: str) -> bytes:
    out = bytearray()
    for offset in range(0, len(bits) - 7, 8):
        chunk = bits[offset : offset + 8]
        if bit_order == "lsb":
            out.append(sum(bit << index for index, bit in enumerate(chunk)))
        else:
            out.append(sum(bit << (7 - index) for index, bit in enumerate(chunk)))
    return bytes(out)


def _lsb_text_hits(payload: bytes) -> list[tuple[str, list[str], tuple[str, ...]]]:
    hits: list[tuple[str, list[str], tuple[str, ...]]] = []
    for raw in _printable_strings(payload[:512_000]):
        if len(raw) < 8:
            continue
        text = raw.decode("latin-1", errors="replace")
        variants: list[tuple[str, list[str]]] = []
        unescaped = html.unescape(text)
        if unescaped != text:
            variants.append((unescaped, ["html_unescape"]))
        variants.append((text, []))
        for candidate, decoders in variants:
            flags = extract_flags(candidate)
            if not flags and not _looks_like_lsb_text(candidate):
                continue
            hits.append((candidate, decoders, flags))
            if len(hits) >= 4:
                return hits
    return hits


def _looks_like_lsb_text(text: str) -> bool:
    lowered = text.lower()
    if "flag" in lowered or "ctf{" in lowered or re.search(r"&#x[0-9a-f]{2};", lowered):
        return True
    if re.search(r"\b(secret|password|passphrase|hint|decode|base64|xor|key)\b", lowered):
        return True
    return False


def _looks_like_text_payload(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for byte in data if 32 <= byte <= 126 or byte in {9, 10, 13})
    return printable / len(data) >= 0.85


def _printable_strings(data: bytes) -> list[bytes]:
    return re.findall(rb"[ -~]{4,}", data)


def _decode_preview(data: bytes, limit: int) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 or byte in {9, 10, 13} else "." for byte in data[:limit])


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
