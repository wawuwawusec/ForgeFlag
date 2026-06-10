#!/usr/bin/env python3
"""Solve the SVIUSCG buddy reverse challenge.

Usage:
    python3 scripts/solve_buddy.py /Users/5haw0/Downloads/buddy

The binary is a tiny bytecode VM.  The early VM phase fixes many flag bytes and
rolls a state byte through the S-box.  Later self-decrypted bytecode becomes a
small CSP over 4-byte S-box relations; this script compiles a tiny C helper for
that CSP because it is much faster than generic SMT for this specific shape.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


CHECKS = [
    (39, 27, 8, 10, 0x27),
    (13, 21, 35, 29, 0x7A),
    (0, 17, 23, 25, 0x7D),
    (31, 15, 40, 20, 0x69),
    (30, 36, 33, 37, 0x57),
    (35, 36, 33, 17, 0x08),
    (21, 29, 20, 13, 0xC5),
    (37, 0, 27, 15, 0x71),
    (39, 30, 10, 40, 0x91),
    (8, 31, 23, 25, 0xAB),
    (27, 40, 39, 15, 0xC1),
    (8, 20, 29, 31, 0x88),
    (33, 17, 0, 23, 0x97),
    (13, 30, 10, 25, 0xEF),
    (37, 21, 36, 35, 0xC3),
    (30, 20, 37, 40, 0x9F),
    (13, 23, 21, 36, 0x9F),
    (29, 27, 31, 39, 0x34),
    (33, 25, 17, 10, 0x75),
    (35, 8, 0, 15, 0xD0),
]

KNOWN = {
    0: ord("S"),
    1: ord("V"),
    2: ord("I"),
    3: ord("U"),
    4: ord("S"),
    5: ord("C"),
    6: ord("G"),
    7: ord("{"),
    9: ord("y"),
    11: ord("_"),
    12: ord("b"),
    14: ord("d"),
    16: ord("y"),
    18: ord("h"),
    19: ord("0"),
    22: ord("_"),
    24: ord("u"),
    26: ord("_"),
    28: ord("1"),
    32: ord("y"),
    34: ord("u"),
    38: ord("4"),
    40: ord("}"),
    41: 0,
}


def extract_sbox(blob: bytes) -> list[int]:
    return list(blob[0x2000 + 0x78 : 0x2000 + 0x178])


def c_array(values: list[int]) -> str:
    return ",".join(f"0x{x:02x}" for x in values)


def solve_csp_with_c(sbox: list[int]) -> str:
    checks = ",".join("{" + ",".join(map(str, row)) + "}" for row in CHECKS)
    known = ",".join("{" + f"{k},{v}" + "}" for k, v in KNOWN.items())
    source = f"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned char S[256] = {{{c_array(sbox)}}};
typedef struct {{ int idx, a, b, c, val; }} Check;
static Check checks[] = {{{checks}}};
static int known[][2] = {{{known}}};
static unsigned char val_at[64];
static uint64_t bit_for[256];
static int nv, solutions;

static inline uint8_t f4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {{
    uint8_t t = a, xs[3] = {{b, c, d}};
    for (int i = 0; i < 3; i++) {{
        uint8_t old = t;
        uint8_t doubled = (uint8_t)(t << 1);
        if (old & 0x80) doubled ^= 0x4b;
        t = S[doubled ^ old ^ xs[i]];
    }}
    return t;
}}

static int propagate(uint64_t dom[42]) {{
    int changed = 1;
    while (changed) {{
        changed = 0;
        for (unsigned ci = 0; ci < sizeof(checks) / sizeof(checks[0]); ci++) {{
            Check ch = checks[ci];
            int vars[4] = {{ch.idx, ch.a, ch.b, ch.c}};
            uint64_t supp[4] = {{0, 0, 0, 0}};
            int count = 0;
            for (int i0 = 0; i0 < nv; i0++) if (dom[vars[0]] & (1ULL << i0))
            for (int i1 = 0; i1 < nv; i1++) if (dom[vars[1]] & (1ULL << i1))
            for (int i2 = 0; i2 < nv; i2++) if (dom[vars[2]] & (1ULL << i2))
            for (int i3 = 0; i3 < nv; i3++) if (dom[vars[3]] & (1ULL << i3)) {{
                if (f4(val_at[i0], val_at[i1], val_at[i2], val_at[i3]) == ch.val) {{
                    count++;
                    supp[0] |= 1ULL << i0; supp[1] |= 1ULL << i1;
                    supp[2] |= 1ULL << i2; supp[3] |= 1ULL << i3;
                }}
            }}
            if (!count) return 0;
            for (int k = 0; k < 4; k++) {{
                uint64_t nd = dom[vars[k]] & supp[k];
                if (!nd) return 0;
                if (nd != dom[vars[k]]) {{ dom[vars[k]] = nd; changed = 1; }}
            }}
        }}
    }}
    return 1;
}}

static int popc(uint64_t x) {{ return __builtin_popcountll(x); }}

static void print_solution(uint64_t dom[42]) {{
    for (int i = 0; i < 42; i++) {{
        int bit = __builtin_ctzll(dom[i]);
        char c = val_at[bit];
        if (!c || c == '\\n') break;
        putchar(c);
    }}
    putchar('\\n');
}}

static void search(uint64_t dom[42]) {{
    if (solutions) return;
    if (!propagate(dom)) return;
    int best = -1, bestn = 99;
    for (unsigned ci = 0; ci < sizeof(checks) / sizeof(checks[0]); ci++) {{
        int vars[4] = {{checks[ci].idx, checks[ci].a, checks[ci].b, checks[ci].c}};
        for (int k = 0; k < 4; k++) {{
            int n = popc(dom[vars[k]]);
            if (n > 1 && n < bestn) {{ best = vars[k]; bestn = n; }}
        }}
    }}
    if (best < 0) {{ solutions++; print_solution(dom); return; }}
    uint64_t d = dom[best];
    for (int i = 0; i < nv; i++) if (d & (1ULL << i)) {{
        uint64_t next[42];
        memcpy(next, dom, sizeof(next));
        next[best] = 1ULL << i;
        search(next);
    }}
}}

int main(void) {{
    const char *allowed = "SVIUSCGabcdefghijklmnopqrstuvwxyz0123456789_{{}}";
    for (const char *p = allowed; *p; p++) {{
        if (bit_for[(unsigned char)*p]) continue;
        val_at[nv] = *p;
        bit_for[(unsigned char)*p] = 1ULL << nv++;
    }}
    val_at[nv] = 0; bit_for[0] = 1ULL << nv++;
    uint64_t all = (1ULL << nv) - 1, dom[42];
    for (int i = 0; i < 42; i++) dom[i] = all;
    for (unsigned i = 0; i < sizeof(known) / sizeof(known[0]); i++)
        dom[known[i][0]] = bit_for[(unsigned char)known[i][1]];
    search(dom);
    return solutions ? 0 : 1;
}}
"""
    with tempfile.TemporaryDirectory() as tmp:
        c_path = Path(tmp) / "buddy_csp.c"
        exe = Path(tmp) / "buddy_csp"
        c_path.write_text(source)
        subprocess.run(["cc", "-O3", str(c_path), "-o", str(exe)], check=True)
        return subprocess.check_output([str(exe)], text=True).strip()


def vm_accepts(blob: bytes, candidate: bytes) -> bool:
    rodata = blob[0x2000 : 0x2000 + 0x17F]
    data = bytearray(blob[0x2180 : 0x2180 + 0x226])
    sbox = list(rodata[0x78 : 0x178])
    buf = bytearray(128)
    buf[: len(candidate)] = candidate[:128]
    if len(candidate) < 128:
        buf[len(candidate)] = 0
    pc = idx = tmp = state = 0
    for _ in range(5000):
        op = data[pc]
        pc += 1
        if op == 0 or op > 14:
            return False
        if op == 1:
            idx = data[pc]
            pc += 1
        elif op == 2:
            tmp = buf[idx]
        elif op == 3:
            tmp ^= data[pc]
            pc += 1
        elif op == 4:
            tmp = (tmp + data[pc]) & 0xFF
            pc += 1
        elif op == 5:
            if tmp != data[pc]:
                return False
            pc += 1
        elif op == 6:
            i = data[pc]
            pc += 1
            if buf[i] not in (0, 10):
                return False
        elif op == 7:
            return True
        elif op == 8:
            tmp ^= state
        elif op == 9:
            state = sbox[state ^ buf[idx]]
        elif op == 10:
            tmp = sbox[tmp]
        elif op == 11:
            length = data[pc] | (data[pc + 1] << 8)
            pc += 2
            for i in range(length):
                data[pc + i] ^= state
        elif op == 12:
            a, b, v = data[pc], data[pc + 1], data[pc + 2]
            pc += 3
            if (buf[a] ^ buf[b]) != v:
                return False
        elif op == 13:
            pc += 1
        elif op == 14:
            a = data[pc]
            pc += 1
            old = tmp
            doubled = ((tmp << 1) & 0xFF) ^ (0x4B if old & 0x80 else 0)
            tmp = sbox[doubled ^ old ^ buf[a]]
    return False


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} /path/to/buddy")
    blob = Path(sys.argv[1]).read_bytes()
    flag = solve_csp_with_c(extract_sbox(blob))
    print(flag)
    if not vm_accepts(blob, flag.encode() + b"\n"):
        raise SystemExit("candidate did not satisfy VM")


if __name__ == "__main__":
    main()
