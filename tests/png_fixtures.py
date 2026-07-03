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


def bmp_with_bgr_lsb_payload(payload: str, *, width: int = 64, height: int = 8) -> bytes:
    return _bmp_with_lsb_payload(payload, width=width, height=height, include_padding=False)


def bmp_with_full_row_lsb_payload(payload: str, *, width: int = 63, height: int = 8) -> bytes:
    return _bmp_with_lsb_payload(payload, width=width, height=height, include_padding=True)


def _bmp_with_lsb_payload(payload: str, *, width: int, height: int, include_padding: bool) -> bytes:
    bits = []
    for byte in payload.encode("ascii") + b"\x00":
        bits.extend((byte >> bit) & 1 for bit in range(8))
    row_stride = ((width * 24 + 31) // 32) * 4
    pixel_bytes = bytearray(row_stride * height)
    capacity = len(pixel_bytes) if include_padding else width * height * 3
    if len(bits) > capacity:
        raise ValueError("payload does not fit in BMP LSB capacity")
    write_indexes = []
    for row in range(height):
        row_start = row * row_stride
        row_width = row_stride if include_padding else width * 3
        write_indexes.extend(range(row_start, row_start + row_width))
    for offset, bit in enumerate(bits):
        pixel_bytes[write_indexes[offset]] = 0xFE | bit
    for offset in range(len(pixel_bytes)):
        if pixel_bytes[offset] == 0:
            pixel_bytes[offset] = 0xFE
    for offset in write_indexes[len(bits) :]:
        pixel_bytes[offset] = 0xFE

    pixel_offset = 54
    file_size = pixel_offset + len(pixel_bytes)
    file_header = b"BM" + struct.pack("<IHHI", file_size, 0, 0, pixel_offset)
    dib_header = struct.pack(
        "<IiiHHIIiiII",
        40,
        width,
        height,
        1,
        24,
        0,
        len(pixel_bytes),
        2835,
        2835,
        0,
        0,
    )
    return file_header + dib_header + bytes(pixel_bytes)
