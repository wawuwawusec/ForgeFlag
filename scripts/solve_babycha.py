#!/usr/bin/env python3
"""Replay IrisCTF babycha against a local challenge service.

This helper is for local or explicitly authorized CTF challenge artifacts. The
challenge mistakenly emits serialized ChaCha state as keystream before updating
the state, so one known-plaintext block reveals the current state and lets us
predict the next block used for the flag.
"""

from __future__ import annotations

import argparse
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:irisctf|flag|ctf)\{[^{}\r\n]{3,200}\}")
HEX_TOKEN_RE = re.compile(r"\b([0-9a-fA-F]{16,})\b")
KNOWN_PLAINTEXT = b"A" * 64
ROUNDS = 20


def rotl(value: int, shift: int) -> int:
    return (((value) << shift) | ((value % 2**32) >> (32 - shift))) % 2**32


def quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] += x[b]
    x[d] ^= x[a]
    x[d] = rotl(x[d], 16)
    x[c] += x[d]
    x[b] ^= x[c]
    x[b] = rotl(x[b], 12)
    x[a] += x[b]
    x[d] ^= x[a]
    x[d] = rotl(x[d], 8)
    x[c] += x[d]
    x[b] ^= x[c]
    x[b] = rotl(x[b], 7)


def chacha_block(inp: list[int]) -> list[int]:
    x = list(inp)
    for _ in range(0, ROUNDS, 2):
        quarter_round(x, 0, 4, 8, 12)
        quarter_round(x, 1, 5, 9, 13)
        quarter_round(x, 2, 6, 10, 14)
        quarter_round(x, 3, 7, 11, 15)

        quarter_round(x, 0, 5, 10, 15)
        quarter_round(x, 1, 6, 11, 12)
        quarter_round(x, 2, 7, 8, 13)
        quarter_round(x, 3, 4, 9, 14)

    return [(a + b) % 2**32 for a, b in zip(x, inp)]


def state_to_bytes(state: list[int]) -> bytes:
    if len(state) != 16:
        raise ValueError("ChaCha state must contain 16 words")
    return b"".join(word.to_bytes(4, "big") for word in state)


def bytes_to_state(data: bytes) -> list[int]:
    if len(data) != 64:
        raise ValueError("serialized ChaCha state leak must be 64 bytes")
    return [int.from_bytes(data[index : index + 4], "big") for index in range(0, 64, 4)]


def recover_state_from_known_plaintext(ciphertext_hex: str, plaintext: bytes = KNOWN_PLAINTEXT) -> list[int]:
    ciphertext = bytes.fromhex(ciphertext_hex.strip())
    if len(ciphertext) < 64:
        raise ValueError("known-plaintext ciphertext must contain at least one full state block")
    leaked = bytes(a ^ b for a, b in zip(ciphertext[:64], plaintext[:64]))
    return bytes_to_state(leaked)


def decrypt_after_state_leak(leaked_state_hex: str, flag_ciphertext_hex: str) -> str:
    leaked_state = bytes_to_state(bytes.fromhex(leaked_state_hex.strip()))
    next_keystream = state_to_bytes(chacha_block(leaked_state))
    flag_ciphertext = bytes.fromhex(flag_ciphertext_hex.strip())
    plaintext = bytes(a ^ b for a, b in zip(flag_ciphertext, next_keystream))
    return plaintext.decode("utf-8", errors="replace")


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if candidate not in flags:
            flags.append(candidate)
    return flags


def solve_local_script(script: Path, cwd: Path, timeout: float = 8.0) -> str:
    proc = subprocess.Popen(
        [sys.executable, "-u", str(script)],
        cwd=str(cwd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    transcript = bytearray()
    try:
        _read_until(proc, transcript, "> ", timeout)
        _write_line(proc, "1")
        _read_until(proc, transcript, "? ", timeout)
        _write_line(proc, KNOWN_PLAINTEXT.decode())
        known_start = len(transcript)
        _read_until(proc, transcript, "> ", timeout, start_at=known_start)
        known_ciphertext_hex = _last_hex_line(_decode(transcript))

        leaked_state = recover_state_from_known_plaintext(known_ciphertext_hex)
        _write_line(proc, "2")
        flag_start = len(transcript)
        _read_until(proc, transcript, "> ", timeout, start_at=flag_start)
        flag_ciphertext_hex = _last_hex_line(_decode(transcript), exclude=known_ciphertext_hex)

        flag = decrypt_after_state_leak(state_to_bytes(leaked_state).hex(), flag_ciphertext_hex)
        flags = extract_flags(flag)
        if not flags:
            raise RuntimeError(f"decrypted text did not contain a flag: {flag!r}")
        print(f"state_words: {len(leaked_state)}")
        print(f"flag: {flags[0]}")
        return flags[0]
    finally:
        try:
            proc.kill()
        except OSError:
            pass


def _last_hex_line(text: str, exclude: str | None = None) -> str:
    values = [match.group(1) for match in HEX_TOKEN_RE.finditer(text)]
    if exclude is not None:
        values = [value for value in values if value.lower() != exclude.lower()]
    if not values:
        raise ValueError("could not parse hex ciphertext from service transcript")
    return values[-1]


def _read_until(
    proc: subprocess.Popen[bytes],
    transcript: bytearray,
    needle: str,
    timeout: float,
    start_at: int = 0,
) -> None:
    deadline = time.monotonic() + timeout
    needle_bytes = needle.encode()
    while time.monotonic() < deadline:
        if needle_bytes in transcript[start_at:]:
            return
        _read_chunk(proc, max(0.1, deadline - time.monotonic()), transcript)
    raise TimeoutError(f"timed out waiting for {needle!r}")


def _read_chunk(proc: subprocess.Popen[bytes], timeout: float, transcript: bytearray) -> None:
    if proc.stdout is None:
        raise RuntimeError("subprocess stdout is closed")
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        raise TimeoutError("timed out reading local challenge output")
    chunk = os.read(proc.stdout.fileno(), 4096)
    if chunk == b"":
        raise RuntimeError("local challenge exited before producing expected output")
    transcript.extend(chunk)


def _write_line(proc: subprocess.Popen[bytes], line: str) -> None:
    if proc.stdin is None:
        raise RuntimeError("subprocess stdin is closed")
    proc.stdin.write((line + "\n").encode())
    proc.stdin.flush()


def _decode(transcript: bytearray) -> str:
    return bytes(transcript).decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay IrisCTF babycha against a local CTF service.")
    parser.add_argument("--local-script", type=Path, required=True, help="path to the provided chal.py")
    parser.add_argument("--cwd", type=Path, help="working directory containing the challenge script; defaults to script parent")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    script = args.local_script.resolve()
    cwd = (args.cwd or script.parent).resolve()
    try:
        solve_local_script(script, cwd, timeout=args.timeout)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
