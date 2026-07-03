from __future__ import annotations

from forgeflag.domain import ChallengeCategory


_UNIVERSAL_PLAYBOOK = (
    "route the challenge by category, artifact type, target shape, tags, and existing observations; "
    "run cheap evidence first before expensive or active actions; preserve exact reproduction evidence."
)

_SCOPE_CONTEXT = (
    "scope_context: ForgeFlag is for local or authorized CTF/lab research. "
    "Default to passive artifact analysis and reproducible replay evidence. "
    "Active network actions require explicit active-probe intent and allowlisted hosts. "
    "Do not suggest unscoped activity or real-world unauthorized use."
)


_CATEGORY_PLAYBOOKS: dict[ChallengeCategory, tuple[str, ...]] = {
    ChallengeCategory.WEB: (
        "Scope wording: authorized CTF web challenge or local fixture; use scoped request, challenge route, response evidence, authorized target.",
        "Start with response capture: status, headers, title, visible links, forms, scripts, cookies, redirects.",
        "Check obvious routes only when scoped: /robots.txt, /sitemap.xml, /admin, /login, /api, /flag, static JS bundles, source maps.",
        "Classify bug class before payloads: SQL/NoSQL injection, command/code injection, SSTI, path traversal/LFI/RFI, upload, IDOR, SSRF, JWT/session, GraphQL, XXE.",
        "suggested_solvers: WebSolver",
        "tool_hints: http_probe, ffuf",
    ),
    ChallengeCategory.CRYPTO: (
        "Classify the primitive: encoding, encryption, hash, signature/MAC, oracle, or math.",
        "Peel reversible layers: hex, Base32/Base64, URL/HTML, binary/octal/decimal ASCII, ROT/Caesar, separators.",
        "For XOR/AES/RSA/hash cases, collect parameters, IV/nonce, reused keystream clues, factors, exponent, ciphertext, and hash mode evidence.",
        "For PRNG/stream-cipher source tasks, inspect Python random seeds, LCG consecutive outputs, LFSR taps/seed leaks, MT19937 output counts, and missing sidecar key/output files before guessing.",
        "If deterministic solvers stall on PRNG tasks, propose replay steps: derive LCG a/b/n or rewind state, clone MT19937 from 624 full outputs or partial-bit matrix evidence, and verify against flag grammar.",
        "suggested_solvers: CryptoSolver",
        "tool_hints: transform_candidates, rsa_summary_from_text, hash_summary_from_text, recover_prng_stream_flags_from_text, RsaCtfTool",
    ),
    ChallengeCategory.FORENSICS: (
        "Identify the real container first; extensions lie in CTFs.",
        "Run file, strings, metadata, archive listing, magic-byte checks before extraction.",
        "For images inspect PNG chunks/IHDR/CRC/trailing data, JPEG comments/APP markers, palettes, alpha channel, bit planes, dimensions.",
        "If broad triage stalls, use bounded carving and YARA scans such as foremost and yara before escalating to heavyweight memory/disk tooling.",
        "For archives/documents inspect comments, embedded files, relationship graphs, encryption state, macros, object streams, suspicious filenames.",
        "suggested_solvers: ForensicsSolver",
        "tool_hints: file, strings, binwalk, exiftool, foremost, yara, image_stego_hints, archive_analysis",
    ),
    ChallengeCategory.TRAFFIC: (
        "Start with capture type, packet counts, protocol hierarchy, endpoints, conversations, and time range.",
        "Search for direct flag markers, then protocol carriers: DNS queries/TXT, HTTP requests/objects, TCP streams, SMTP/FTP payloads, TLS SNI/certs, ICMP payloads.",
        "For DNS exfiltration, group by base domain, preserve label order, and try Base32/Base64/hex on labels.",
        "For HTTP, extract URLs, hosts, cookies, auth headers, uploaded/downloaded objects, forms, compressed or encoded bodies.",
        "suggested_solvers: TrafficSolver",
        "tool_hints: tshark_flag_scan, tshark_dns_summary, tshark_tcp_streams, tshark_http_requests, tshark_http_artifact_scan, tshark_http_object_export",
    ),
    ChallengeCategory.REVERSE: (
        "Scope wording: local artifact analysis of provided challenge binaries, firmware, ROMs, or attachments; use validation logic, local binary, static evidence, solve script.",
        "Start with file, strings, imports, symbols, section names, packer indicators, architecture, and endianness.",
        "If strings expose a flag, preserve that shortest path; otherwise identify validation functions, input reads, compare loops, decode routines.",
        "Use bounded local wrappers for section listings, disassembly, section dumps, and r2 metadata before heavier decompiler routes.",
        "Use IDA/Ghidra/r2 pivots when available; watch encoded strings, little-endian constants, XOR loops, custom VMs, anti-debug, UPX.",
        "suggested_solvers: ReverseSolver",
        "tool_hints: file, strings, objdump, readelf, radare2, ROPgadget, ropper, ida_mcp",
    ),
    ChallengeCategory.PWN: (
        "Scope wording: local vulnerable binary or explicitly authorized CTF service; use proof-of-solve harness, local crash reproduction, offset evidence, challenge service.",
        "Start with file, checksec, dangerous functions, strings, imports, symbols, expected I/O.",
        "Reproduce locally before exploit generation; capture crash input, cyclic offset, registers, protections.",
        "Classify primitive: ret2win, stack overflow, off-by-one, format string, integer overflow, ret2libc, ret2csu, shellcode, UAF, tcache poisoning, partial overwrite.",
        "Generate pwntools scripts only after evidence identifies primitive and target.",
        "suggested_solvers: PwnSolver",
        "tool_hints: checksec, strings, ROPgadget, ropper, pwntools",
    ),
    ChallengeCategory.MISC: (
        "Route misc early: encoding, archive, image/stego, scripting, game/pathfinding, sandbox, OSINT, esolang/polyglot, QR/barcode, audio, AI/prompt.",
        "For programming/pathfinding puzzles, parse examples into a deterministic solver before guessing.",
        "For sandbox tasks, inspect blacklists, exposed builtins/imports, serialization boundaries, object traversal, exception leakage.",
        "For audio/QR/barcode/image tasks, inspect metadata and cheap transforms before specialized extraction.",
        "suggested_solvers: MiscSolver",
        "tool_hints: transform_candidates, archive_analysis, image_stego_hints",
    ),
    ChallengeCategory.INFRA: (
        "Classify the target as service config, cloud/container, credentials, logs, or deployment surface.",
        "Prefer read-only evidence: banners, config snippets, exposed metadata, version fingerprints, and provided files.",
        "Avoid active scanning unless scope explicitly allows it.",
        "suggested_solvers: InfraSolver",
        "tool_hints: nmap_tcp_basic",
    ),
    ChallengeCategory.RECON: (
        "Collect only scoped passive facts first: category hints, target shape, artifact metadata, obvious service identity.",
        "Escalate to specialist solvers rather than broad probing.",
        "suggested_solvers: ReconSolver",
        "tool_hints: file, http_probe",
    ),
    ChallengeCategory.UNKNOWN: (
        "route the challenge by artifact type, text clues, target presence, tags, and cheap evidence first.",
        "If there is a URL, consider WebSolver; if there is a PCAP, consider TrafficSolver; if binary, consider ReverseSolver/PwnSolver.",
        "If text looks encoded or mathematical, consider CryptoSolver; if image/archive/document, consider MiscSolver or ForensicsSolver.",
        "suggested_solvers: WebSolver, TrafficSolver, CryptoSolver, ForensicsSolver, MiscSolver, ReverseSolver, PwnSolver",
        "tool_hints: file, strings, transform_candidates, http_probe",
    ),
}


def category_playbook(category: ChallengeCategory) -> str:
    lines = ["category_playbook:", f"- {_SCOPE_CONTEXT}", f"- universal: {_UNIVERSAL_PLAYBOOK}"]
    for item in _CATEGORY_PLAYBOOKS.get(category, _CATEGORY_PLAYBOOKS[ChallengeCategory.UNKNOWN]):
        lines.append(f"- {item}")
    return "\n".join(lines)


def prior_failure_patterns(category: ChallengeCategory, context_text: str = "") -> str:
    lowered = context_text.lower()
    lines = [
        "prior_failure_patterns:",
        "- Do not accept source literal flags without replay evidence; treat them as clues until a solver or transcript verifies the path.",
        "- Prefer artifact-backed proof-of-solve: exact file, extracted value, command/tool route, and candidate verification evidence.",
    ]
    if category == ChallengeCategory.CRYPTO or _has_any(
        lowered,
        ("random.seed", "getrandbits", "lcg", "lfsr", "mt19937", "stream cipher", "prng", "xor keystream"),
    ):
        lines.extend(
            [
                "- Crypto PRNG/stream tasks: inspect head and tail of source plus output/key sidecar files before guessing from comments.",
                "- LCG: try known a/b/n recovery, modular inverse from consecutive outputs, residue lifting, and verify generated flag grammar.",
                "- MT19937: look for 624 full outputs, partial-bit getrandbits leakage, or matrix reconstruction evidence.",
                "- LFSR/BM: recover taps/state from bitstreams with Berlekamp-Massey or source-defined feedback, then replay bytes.",
                "- Missing sidecar files such as key, output, data, enc, or cipher should be reported as blockers instead of hallucinated.",
            ]
        )
    if category == ChallengeCategory.TRAFFIC or _has_any(lowered, (".pcap", ".pcapng", "tshark", "wireshark", "tcp stream")):
        lines.extend(
            [
                "- Traffic: if tshark parsing fails, try raw byte flag scan, capture resync, TCP stream extraction, HTTP object export, DNS label decode, and IP-ID/payload stego.",
                "- Preserve endpoint, stream number, packet/time evidence for every recovered candidate.",
            ]
        )
    if category == ChallengeCategory.FORENSICS or _has_any(lowered, (".bmp", ".png", "quickstego", "zsteg", ".reg", "registry")):
        lines.extend(
            [
                "- Forensics/stego: try obvious extractors such as QuickStego/zsteg strings before generic low-bit guessing; for BMP braille puzzles, convert extracted text to binary/braille only after proving the extraction.",
                "- Registry WiFi tasks usually pivot through WLAN profile keys and SSID names; remove spaces only when the challenge format says so.",
            ]
        )
    if category == ChallengeCategory.REVERSE or _has_any(lowered, (".exe", "elf", "objdump", "ghidra", "ida", "validation")):
        lines.extend(
            [
                "- Reverse: start with local artifact triage, strings, section dumps, imports, and validation constants before assuming dynamic exploitation is needed.",
                "- If a literal flag appears in strings or rodata, still record the file/section evidence and replay command.",
            ]
        )
    if category == ChallengeCategory.PWN or _has_any(lowered, ("checksec", "ret2win", "cyclic", "canary", "got", "plt")):
        lines.extend(
            [
                "- Pwn: require local crash or I/O transcript, protection summary, offset evidence, and a bounded harness before proposing an exploit route.",
                "- Flag retrieval from a service must stay within explicitly authorized CTF scope and should include replay steps.",
            ]
        )
    if category == ChallengeCategory.WEB or _has_any(lowered, ("http://", "https://", "jwt", "ssti", "sql", "upload", "cookie")):
        lines.extend(
            [
                "- Web: classify the challenge bug class from scoped request/response evidence; do not suggest broad scanning without allowlisted target scope.",
                "- Source disclosure, static JS, cookies, headers, and route-specific evidence should come before payload-heavy attempts.",
            ]
        )
    if len(lines) == 3:
        lines.append("- No category-specific prior failures matched; route by artifact type and keep a replayable evidence trail.")
    return "\n".join(lines)


def _has_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)
