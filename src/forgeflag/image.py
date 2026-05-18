from __future__ import annotations

import binascii
import struct
import zlib
from pathlib import Path
from typing import Any


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
