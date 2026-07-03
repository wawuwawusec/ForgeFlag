#!/usr/bin/env python3
"""Replay UMDCTF giedi-composite from chal.sage and output.txt.

This helper is for local or explicitly authorized CTF challenge artifacts. It
does not read the challenge flag file; it parses the public key and ciphertext,
then runs a Sage lattice replay that recovers the NTRU-style private key.
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path


FLAG_RE = re.compile(r"(?i)(?:UMDCTF|flag|ctf)\{[^{}\r\n]{3,200}\}")


def parse_output_lists(text: str) -> tuple[list[int], list[int]]:
    public_match = re.search(r"Public key:\s*\n(\[[^\]]+\])", text, flags=re.S)
    ct_match = re.search(r"Ct:\s*\n(\[[^\]]+\])", text, flags=re.S)
    if not public_match or not ct_match:
        raise ValueError("could not parse public key and ciphertext lists")
    pub = ast.literal_eval(public_match.group(1))
    ct = ast.literal_eval(ct_match.group(1))
    if not isinstance(pub, list) or not isinstance(ct, list):
        raise ValueError("parsed public key and ciphertext must be lists")
    if len(pub) != len(ct):
        raise ValueError("public key and ciphertext lengths differ")
    if not all(isinstance(value, int) for value in pub + ct):
        raise ValueError("public key and ciphertext entries must be integers")
    return pub, ct


def extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for match in FLAG_RE.finditer(text):
        candidate = match.group(0)
        if candidate not in flags:
            flags.append(candidate)
    return flags


def build_sage_replay(pub: list[int], ct: list[int]) -> str:
    return textwrap.dedent(
        f"""
        N = {len(pub)}
        q = 2003
        p = 3
        pub = {pub!r}
        ct = {ct!r}

        def int_to_bytes(n):
            n = ZZ(n)
            if n == 0:
                return bytes([0])
            out = []
            while n:
                out.append(int(n % 256))
                n //= 256
            return bytes(reversed(out))

        def decode_msg(m):
            n = ZZ(0)
            for bit in m:
                n *= 2
                n += ZZ(bit)
            return int_to_bytes(n)

        Fq = Zmod(q)
        Fp = Zmod(p)
        Rq = PolynomialRing(Fq, 'x').quotient(x^N - 1)
        Rp = PolynomialRing(Fp, 'x').quotient(x^N - 1)
        Rx.<x> = PolynomialRing(ZZ, 'x')

        reduced_lattices = []
        p1 = Rx(x^70 - x^35 + 1)
        p2 = Rx(x^70 + x^35 + 1)
        p3 = Rx(x^70 - 1)

        crt_basis = [
            1/6*x^175 - 1/6*x^140 - 1/3*x^105 - 1/6*x^70 + 1/6*x^35 + 1/3,
            -1/6*x^175 - 1/6*x^140 + 1/3*x^105 - 1/6*x^70 - 1/6*x^35 + 1/3,
            1/3*x^140 + 1/3*x^70 + 1/3,
        ]

        rings = []
        for c in [p1, p2, p3]:
            R = Rx.quotient(c)
            rings.append(R)
            deg = c.degree()
            conv_matrix = matrix(ZZ, deg, deg, [list(map(ZZ, (R(pub) * x^i).list())) for i in range(0, deg)])
            ntru_lattice = block_matrix([[identity_matrix(ZZ, deg), conv_matrix], [zero_matrix(ZZ, deg, deg), q * identity_matrix(ZZ, deg)]])
            reduced_lattices.append(ntru_lattice.BKZ(delta=0.99, block_size=35))

        f1 = rings[0](list(reduced_lattices[0].rows()[2][:70]))
        f2 = rings[1](list(reduced_lattices[1].rows()[2][:70]))
        f3 = rings[2](list(reduced_lattices[2].rows()[2][:70]))

        def find_key():
            for i in range(N):
                for j in range(N):
                    candidate = crt_basis[0] * f1.lift() + crt_basis[1] * f2.lift() * x^i + crt_basis[2] * f3.lift() * x^j
                    candidate = candidate % (x^N - 1)
                    coeffs = list(candidate)
                    if len(set(coeffs)) <= 5:
                        return candidate
            raise ValueError("could not combine CRT key residues")

        fk = find_key()
        for i in range(N):
            shifted = (fk * x^i) % (x^N - 1)
            try:
                v = Rq(shifted) * Rq(ct)
                centered = [c.lift_centered() for c in v.list()]
                vp = Rp(centered) * Rp(shifted).inverse()
                plaintext = [c.lift_centered() for c in vp.list()]
                if all(bit in [0, 1] for bit in plaintext):
                    print(decode_msg(plaintext))
                    break
                if all(bit in [0, -1] for bit in plaintext):
                    print(decode_msg([-bit for bit in plaintext]))
                    break
            except Exception:
                pass
        """
    ).strip() + "\n"


def solve_with_sage(output_path: Path, timeout: float = 120.0) -> str:
    sage = shutil.which("sage")
    if not sage:
        raise RuntimeError("sage executable not found; install SageMath or use the ForgeFlag CTF tool image")
    pub, ct = parse_output_lists(output_path.read_text(encoding="utf-8"))
    replay = build_sage_replay(pub, ct)
    with tempfile.TemporaryDirectory(prefix="forgeflag-giedi-") as tmpdir:
        replay_path = Path(tmpdir) / "solve_giedi_composite.sage"
        replay_path.write_text(replay, encoding="utf-8")
        completed = subprocess.run(
            [sage, str(replay_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    flags = extract_flags(completed.stdout)
    if not flags:
        raise RuntimeError(f"Sage replay did not recover a flag; returncode={completed.returncode}\n{completed.stdout[-2000:]}")
    print(f"n: {len(pub)}")
    print("method: composite-ring NTRU lattice CRT replay")
    print(f"flag: {flags[0]}")
    return flags[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay UMDCTF giedi-composite from local CTF artifacts.")
    parser.add_argument("--output", type=Path, required=True, help="path to output.txt containing public key and ciphertext")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()
    try:
        solve_with_sage(args.output.resolve(), timeout=args.timeout)
    except Exception as exc:
        print(f"[!] {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
