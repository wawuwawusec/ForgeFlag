# CTF Playbook Notes

This note summarizes public CTF challenge patterns that ForgeFlag should keep testing against. It is a pattern guide, not a vendored challenge archive.

## Sources Reviewed

- picoCTF solution indexes show broad beginner-to-medium coverage across Web Exploitation, Cryptography, Reverse Engineering, Forensics, General Skills, Binary Exploitation, and Blockchain.
- picoCTF writeup indexes are especially useful for repeatable tags: pcap/Wireshark, metadata, base64, zip/tar/binwalk, steganography, RSA, ROT13, Morse, Vigenere, strings, grep, and binary encodings.
- HackTheBox Cyber Apocalypse official repositories provide a modern multi-category taxonomy: crypto weaknesses, forensic log/traffic/malware analysis, misc scripting/sandbox tasks, pwn bug classes, reverse strings/packers/file formats, and web API/injection patterns.
- CTFtime task pages and writeup indexes are useful for checking whether a pattern is common across events rather than tied to one platform.
- Root-Me writeups and code-snippet series are useful for web/security bug classes such as SQL-like injection, SSRF/header behavior, integer overflow, stack overflow, and login bypasses.

## Category Playbooks

### Web

Common first moves:

- Fetch the declared target only when the host is explicitly allowlisted.
- Record the first response, visible links, forms, title, and content type.
- Look for obvious flags in the response before fuzzing.
- If active probing is enabled, run a small route wordlist such as `robots.txt`, `admin`, `login`, `flag`, and routes discovered from links/forms.
- For deeper work, classify the bug class before acting: SQL injection, command injection, SSTI, JWT/session confusion, SSRF, path traversal, upload handling, or API option leakage.

ForgeFlag coverage today:

- `WebSolver` runs scoped HTTP probing and low-budget route discovery.
- The corpus smoke includes a visible-response flag case.

### Crypto

Common first moves:

- Normalize text and try reversible encodings before assuming a hard cryptosystem: hex, Base32/Base64, URL, HTML entities, binary ASCII, ROT13/Caesar-style rotations, Morse, and simple transpositions.
- If parameters are present, identify the primitive: RSA, DH/DLP, AES mode, stream cipher, substitution, Vigenere, or custom arithmetic.
- For RSA, extract `n/e/c/p/q/d/phi`, check known factors, prime `n`, low exponent, shared factors, and public/private key markers.
- For hashes, classify candidate hash types and choose a bounded wordlist before cracking.

ForgeFlag coverage today:

- Transform chaining handles common reversible encodings.
- RSA and hash triage are structured.
- The corpus smoke includes Base32 decoding and verifies the replay report.

### Misc

Common first moves:

- Treat misc as routing: decide whether the artifact is really crypto, archive, image/stego, scripting, OSINT, programming, or puzzle logic.
- For text-like puzzles, try binary/octal/hex/Base encodings and simple transforms.
- For scripting tasks, preserve input/output examples and produce a small deterministic solver.
- For sandbox/eval/pickle-style tasks, identify import/builtin exposure and dangerous object paths before exploitation.

ForgeFlag coverage today:

- Misc image, archive, hash, and transform triage are ordered before placeholder output.
- The corpus smoke found and fixed a binary ASCII seed-extraction bug when challenge metadata surrounds the attachment content.

### Forensics

Common first moves:

- Run file identification, strings, metadata, and archive/carving checks.
- Check image-specific structures before heavy tools: PNG chunks/IHDR/CRC/trailing data, JPEG comments/APP markers, visible metadata.
- For archive puzzles, inspect names/comments/encryption state before extraction.
- For disk/memory/log cases, build a timeline and preserve evidence paths.

ForgeFlag coverage today:

- `ForensicsSolver` records file/strings/binwalk/exiftool results, image hints, archive summaries, and flag candidates.
- The corpus smoke includes a strings-based artifact.

### Traffic

Common first moves:

- Confirm the capture type and protocol hierarchy.
- Search payload bytes for direct markers, then pivot to DNS, HTTP, TCP streams, SMTP/FTP/object export, and suspicious long labels.
- Treat DNS labels, TXT answers, HTTP objects, and TCP streams as possible encoded carriers.
- Preserve stream IDs and tool commands for replay.

ForgeFlag coverage today:

- `TrafficSolver` runs tshark summaries, DNS summary, TCP shortlist, HTTP request/artifact scans, and flag scans.
- The corpus smoke generates a real PCAP with an HTTP payload flag and runs it through the Web service.

### Reverse

Common first moves:

- Run `file` and `strings` first; many warmups are direct strings or simple transformations.
- Check packers and format hints before decompilation.
- Move into IDA/Ghidra/r2 only after preserving basic static evidence.
- For validation binaries, recover input constraints and produce a small solver script.

ForgeFlag coverage today:

- Local reverse triage uses file/strings/ROPgadget/ropper and optional IDA MCP.
- The corpus smoke compiles a small binary and verifies strings-based recovery.

### Pwn

Common first moves:

- Run `file`, `checksec`, and strings.
- Identify the bug class: stack overflow, off-by-one, format string, integer overflow, UAF, heap/tcache, ret2win, ret2csu, ret2libc, or sandbox escape.
- Reproduce the crash locally before exploit generation.
- Generate pwntools workspaces only after offsets, protections, and I/O shape are understood.

ForgeFlag coverage today:

- Local pwn triage uses file/strings/checksec/ROPgadget/ropper and optional IDA MCP.
- The corpus smoke compiles a small pwn-style binary and verifies strings/checksec baseline behavior.

## Web Corpus Smoke

Run while the Web UI is active:

```bash
scripts/forgeflag-control start
scripts/forgeflag-corpus-smoke --url http://127.0.0.1:8080
```

Current smoke cases:

| ID | Category | Pattern | Expected |
| --- | --- | --- | --- |
| `corpus-web` | web | scoped first response | `flag{corpus_web}` |
| `corpus-crypto` | crypto | Base32 transform | `flag{corpus_crypto}` |
| `corpus-misc` | misc | binary ASCII with metadata noise | `flag{corpus_misc}` |
| `corpus-forensics` | forensics | file/strings triage | `flag{corpus_forensics}` |
| `corpus-traffic` | traffic | real PCAP HTTP payload | `flag{corpus_traffic}` |
| `corpus-reverse` | reverse | compiled binary strings | `flag{corpus_reverse}` |
| `corpus-pwn` | pwn | compiled binary triage | `flag{corpus_pwn}` |

The smoke should exit non-zero if any expected flag is not accepted by the Web run path.

## Gaps To Add Next

- Web: API option leakage, robots.txt discovery, simple form capture, and SSRF/path traversal evidence.
- Crypto: Caesar all-rotation search, Morse, Vigenere/substitution hints, XOR cribbing, and RSA solve-script generation.
- Misc: small scripting puzzle harnesses and sandbox/pickle blackbox notes.
- Forensics: zip-with-comment/password hint, PNG/JPEG visual preview, and disk image timeline fixtures.
- Traffic: DNS label reconstruction across multiple packets, TXT extraction, HTTP object export, SMTP/FTP exfil, and stream reassembly.
- Reverse/Pwn: crash reproduction, offset discovery, ret2win sample, and generated pwntools workspace.
