from __future__ import annotations

from forgeflag.domain import ChallengeCategory


_UNIVERSAL_PLAYBOOK = (
    "route the challenge by category, artifact type, target shape, tags, and existing observations; "
    "run cheap evidence first before expensive or active actions; preserve exact reproduction evidence."
)


_CATEGORY_PLAYBOOKS: dict[ChallengeCategory, tuple[str, ...]] = {
    ChallengeCategory.WEB: (
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
        "suggested_solvers: CryptoSolver",
        "tool_hints: transform_candidates, rsa_summary_from_text, hash_summary_from_text, RsaCtfTool",
    ),
    ChallengeCategory.FORENSICS: (
        "Identify the real container first; extensions lie in CTFs.",
        "Run file, strings, metadata, archive listing, magic-byte checks before extraction.",
        "For images inspect PNG chunks/IHDR/CRC/trailing data, JPEG comments/APP markers, palettes, alpha channel, bit planes, dimensions.",
        "For archives/documents inspect comments, embedded files, relationship graphs, encryption state, macros, object streams, suspicious filenames.",
        "suggested_solvers: ForensicsSolver",
        "tool_hints: file, strings, binwalk, exiftool, image_stego_hints, archive_analysis",
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
        "Start with file, strings, imports, symbols, section names, packer indicators, architecture, and endianness.",
        "If strings expose a flag, preserve that shortest path; otherwise identify validation functions, input reads, compare loops, decode routines.",
        "Use IDA/Ghidra/r2 pivots when available; watch encoded strings, little-endian constants, XOR loops, custom VMs, anti-debug, UPX.",
        "suggested_solvers: ReverseSolver",
        "tool_hints: file, strings, ROPgadget, ropper, ida_mcp",
    ),
    ChallengeCategory.PWN: (
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
    lines = ["category_playbook:", f"- universal: {_UNIVERSAL_PLAYBOOK}"]
    for item in _CATEGORY_PLAYBOOKS.get(category, _CATEGORY_PLAYBOOKS[ChallengeCategory.UNKNOWN]):
        lines.append(f"- {item}")
    return "\n".join(lines)
