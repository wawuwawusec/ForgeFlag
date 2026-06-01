from __future__ import annotations

import binascii
import struct
import zlib


def png_with_wrong_declared_height(width: int, actual_height: int, declared_height: int) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", binascii.crc32(kind + body) & 0xFFFFFFFF)

    rows = []
    for y in range(actual_height):
        rgba = bytes([255, 255 - y, 0, 255]) * width
        rows.append(b"\x00" + rgba)
    idat = zlib.compress(b"".join(rows))
    correct_ihdr = struct.pack(">IIBBBBB", width, actual_height, 8, 6, 0, 0, 0)
    wrong_ihdr = struct.pack(">IIBBBBB", width, declared_height, 8, 6, 0, 0, 0)
    correct_crc = struct.pack(">I", binascii.crc32(b"IHDR" + correct_ihdr) & 0xFFFFFFFF)
    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", len(wrong_ihdr))
        + b"IHDR"
        + wrong_ihdr
        + correct_crc
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def png_with_text_and_trailing_data(text: str, trailing: bytes = b"") -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", binascii.crc32(kind + body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    row = b"\x00" + bytes([255, 255, 255, 255])
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"tEXt", b"Comment\x00" + text.encode("latin-1", errors="replace"))
        + chunk(b"IDAT", zlib.compress(row))
        + chunk(b"IEND", b"")
        + trailing
    )
