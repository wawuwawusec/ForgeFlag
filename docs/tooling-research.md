# Tooling Research Notes

ForgeFlag's curated project catalog is intentionally selective. It favors established CTF tools that are already common in public CTF lists or official project repositories, then maps them into ForgeFlag integration types instead of installing everything.

The catalog lives in `src/forgeflag/project_catalog.py` and is exposed through:

```bash
forgeflag catalog
forgeflag catalog --category traffic
```

The same data is available from the Web UI Catalog tab and `/api/project-catalog`.

## Selection Sources

- `apsdehal/awesome-ctf` lists common CTF platforms and tools, including CTFd, CyberChef, Pwntools, ROPgadget, Wireshark, Ghidra, ExifTool, Volatility, Binwalk, sqlmap, and many category-specific references.
- `zardus/ctf-tools` is a broad install-script collection for security research and CTF tools. It is useful as a coverage reference, but ForgeFlag should port only selected tools behind typed wrappers.
- Official project repositories document the role of core tools:
  - `pwntools`: CTF framework and exploit-development library.
  - `CyberChef`: browser workbench for encoding, encryption, compression, and data analysis.
  - `Ghidra`: reverse engineering framework with disassembly, decompilation, graphing, and scripting.
  - `Wireshark`: packet capture and protocol analysis project; ForgeFlag currently uses its `tshark` CLI.
  - `CTFd`: customizable Capture The Flag framework for running events.

GitHub API star queries can be rate-limited in unauthenticated local runs, so the checked-in catalog does not depend on live star counts. Treat popularity as a heuristic from official pages and public curated lists, not as a hard ranking.

## Integration Policy

- `existing_wrapper`: already exposed through `forgeflag.tools.ctf` and safe to use from solvers.
- `wrapper_candidate`: good candidate for a typed `ToolRunner` wrapper and deterministic tests.
- `scoped_active_wrapper_candidate`: network-capable; must require `ScopePolicy.active_probe` and allowlisted targets.
- `docker_candidate`: useful but heavyweight, OS-sensitive, or dependency-heavy; keep outside the base venv.
- `library_dependency`: can be used from Python solvers when dependency cost is acceptable.
- `solver_workspace`: useful for generating per-challenge scripts or workspaces rather than a direct one-shot wrapper.
- `external_gui_or_mcp`: best used through explicit exports, headless mode, or read-only MCP-style adapters.
- `reference_only`: use for roadmap coverage, not direct execution.

## Current Catalog Focus

- Pwn/reverse: pwntools, pwndbg, GEF, ROPgadget, Ropper, Ghidra, radare2, Rizin, angr.
- Crypto/misc: CyberChef, RsaCtfTool, Z3, SageMath, hashcat, John the Ripper. ForgeFlag fingerprints common hashes and exposes bounded dictionary wrappers, but does not automatically start cracking.
- Forensics/misc: Binwalk, ExifTool, Volatility 3, Didier Stevens Suite. ForgeFlag now does lightweight PNG/JPEG stego hint triage before heavier carving or channel tools.
- Archive/puzzle triage: Python stdlib archive parsers first, then optional 7z/binwalk/carving wrappers when structure evidence justifies extraction.
- Traffic: Wireshark/tshark, Scapy.
- Web/infra: sqlmap, ffuf, nuclei, CTFd.
- Reference collection: zardus/ctf-tools.

## External Corpus-Inspired Regression Policy

Public CTF archives are useful as a coverage guide, but ForgeFlag should not vendor large challenge archives or copyrighted writeups into the repository. Instead, use them to extract small deterministic patterns that reproduce common solver failures:

- Platform flag prefixes: preserve full prefixes such as `picoCTF{...}` and `HTB{...}` instead of matching a shorter inner `CTF{...}` token.
- Encoding warmups: keep dependency-light transforms for Base32, Base64, hex, URL encoding, HTML entities, binary ASCII, and ROT13 before reaching for heavier tooling.
- Traffic puzzles: treat DNS query labels as possible encoded payload carriers, not only as suspicious long domain names.
- PCAP triage: prioritize DNS/TXT answers, HTTP artifacts, and TCP streams that contain or decode into flag-like evidence.

The current regression tests synthesize tiny fixtures from these patterns so they remain fast, deterministic, and safe to run offline.

`scripts/forgeflag-corpus-smoke` now turns the same policy into a Web-run smoke corpus for web, crypto, misc, forensics, traffic, reverse, and pwn. It generates small local fixtures, submits them through the Web API, runs each challenge, and fails if the expected flag is not accepted.

`docs/ctf-playbook.md` records the broader community-derived method library. It summarizes sources such as CTFtime, picoCTF indexes, HackTheBox official writeups, Root-Me writeups, HackTricks, CTF Support, CryptoHack, pwn.college, ir0nstone, CTF Base, and Cyber Writeups, then distills them into category-specific method cards.

## Heavyweight Tool Policy

SageMath, Volatility, and Ghidra/headless are intentionally treated as Docker profile tools instead of local venv dependencies:

- `forgeflag-volatility`: memory dump analysis and forensic plugins.
- `forgeflag-sagemath`: math-heavy crypto solving.
- `forgeflag-ghidra-headless`: scripted reverse-engineering exports.

Build commands and invocation boundaries are documented in `docs/tool-containers.md`. Future adapters for these tools should mirror the IDA MCP approach: disabled by default, read-only by default, registered-attachment input only, typed operation surface, and structured evidence output.

## Design Choices Adopted

- Package heavyweight security tools in Docker instead of assuming they exist on every host.
- Expose executable tools through a small allowlisted catalog, not arbitrary shell execution.
- Treat network-capable tools as active probes that require explicit scope.
- Return structured `ToolResult` payloads so solvers can record evidence in the shared notebook.
- Prefer category-specific solvers that extract concise findings over dumping raw tool output.
- Inspect archive structure before extraction; do not unpack untrusted archives into the project root.
- Treat password cracking as an explicit operator action with a chosen wordlist, hash mode, and bounded runtime.
- Prefer bounded metadata and structure summaries for image puzzles before invoking heavier stego tools.

## References

- https://github.com/apsdehal/awesome-ctf
- https://github.com/zardus/ctf-tools
- https://pwn.college/ctf-archive/
- https://github.com/cryptohack/ctf_archive
- https://archive.ooo/
- https://ctftime.org/writeup/31040
- https://7rocky.github.io/en/ctf/picoctf/forensics/
- https://github.com/Gallopsled/pwntools
- https://github.com/gchq/CyberChef
- https://github.com/NationalSecurityAgency/ghidra
- https://gitlab.com/wireshark/wireshark
- https://github.com/CTFd/CTFd
