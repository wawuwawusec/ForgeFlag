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


def png_with_extra_compressed_idat(secret: str, *, truncated_length: bool = False) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", binascii.crc32(kind + body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    row = b"\x00" + bytes([255, 255, 255])
    extra_idat = zlib.compress(secret.encode("ascii"))
    extra_chunk = (
        (struct.pack(">I", len(extra_idat) + 32) if truncated_length else struct.pack(">I", len(extra_idat)))
        + b"IDAT"
        + extra_idat
        + (b"" if truncated_length else struct.pack(">I", binascii.crc32(b"IDAT" + extra_idat) & 0xFFFFFFFF))
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(row))
        + extra_chunk
        + chunk(b"IEND", b"")
    )


def png_with_rgb_lsb_payload(payload: str, *, width: int = 64, height: int = 8) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", binascii.crc32(kind + body) & 0xFFFFFFFF)

    data = bytearray(bytes([254, 254, 254, 255]) * width * height)
    bits = []
    for byte in payload.encode("ascii") + b"\x00":
        bits.extend((byte >> bit) & 1 for bit in range(8))
    if len(bits) > width * height * 3:
        raise ValueError("payload does not fit in RGB LSB capacity")
    for offset, bit in enumerate(bits):
        pixel = offset // 3
        channel = offset % 3
        index = pixel * 4 + channel
        data[index] = (data[index] & 0xFE) | bit

    rows = []
    row_size = width * 4
    for y in range(height):
        rows.append(b"\x00" + bytes(data[y * row_size : (y + 1) * row_size]))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"".join(rows)))
        + chunk(b"IEND", b"")
    )
