# CTF Playbook Notes

This note summarizes public CTF challenge patterns that ForgeFlag should keep testing against. It is a pattern guide, not a vendored challenge archive.

## Sources Reviewed

- picoCTF solution indexes show broad beginner-to-medium coverage across Web Exploitation, Cryptography, Reverse Engineering, Forensics, General Skills, Binary Exploitation, and Blockchain.
- picoCTF writeup indexes are especially useful for repeatable tags: pcap/Wireshark, metadata, base64, zip/tar/binwalk, steganography, RSA, ROT13, Morse, Vigenere, strings, grep, and binary encodings.
- HackTheBox Cyber Apocalypse official repositories provide a modern multi-category taxonomy: crypto weaknesses, forensic log/traffic/malware analysis, misc scripting/sandbox tasks, pwn bug classes, reverse strings/packers/file formats, and web API/injection patterns.
- CTFtime task pages and writeup indexes are useful for checking whether a pattern is common across events rather than tied to one platform.
- Root-Me writeups and code-snippet series are useful for web/security bug classes such as SQL-like injection, SSRF/header behavior, integer overflow, stack overflow, and login bypasses.
- HackTricks provides practical triage workflows for crypto, forensics, stego, and many web exploitation classes.
- CTF Support groups Web CTF techniques into reconnaissance, injections, logic/access flaws, client-side attacks, and file/inclusion vulnerabilities.
- CTF Base and Cyber Writeups are useful searchable indexes for seeing how often a technique appears across events and platforms.
- CryptoHack is useful for mapping crypto challenges from encoding/XOR basics toward AES, RSA, Diffie-Hellman, ECC, hashes, lattices, and crypto-on-the-web.
- pwn.college and ir0nstone notes are useful for pwn progression: shellcoding, memory corruption, ret2win, padding discovery, endian issues, and pwntools-based exploits.

## Community Knowledge Sources

Use these sources as research input for future solver work. Do not copy full writeups into ForgeFlag; extract stable patterns, commands, decision points, and small synthetic fixtures.

| Source | Best Use | Notes |
| --- | --- | --- |
| CTFtime task/writeup pages | Cross-event pattern validation | Good for confirming whether a technique is common across many CTFs. |
| picoCTF Solutions / picoCTF writeup indexes | Beginner and medium category coverage | Strong source for encoding, metadata, file, pcap, simple web, reverse, and binary warmups. |
| HackTheBox Cyber Apocalypse official writeups | Modern multi-category challenge taxonomy | Useful for realistic web/API, malware/traffic forensics, heap/pwn, reverse, and misc scripting examples. |
| Root-Me Blog / Root-Me challenge ecosystem | Web and applied vulnerability classes | Useful for injection, auth, SSRF/header, login bypass, and service-level writeups. |
| HackTricks | Checklist-style methodology | Useful for building first-pass solver decision trees. |
| CTF Support | Web technique taxonomy | Good for mapping WebSolver output into bug-class hints. |
| CryptoHack | Crypto learning path | Useful for deciding when to escalate from transforms to XOR/AES/RSA/DH/ECC/lattice tooling. |
| pwn.college | Binary exploitation curriculum | Useful for pwn solver milestones such as crash reproduction, shellcoding, and memory corruption. |
| ir0nstone notes | Practical pwn walkthroughs | Useful for ret2win/ROP/pwntools workflow details. |
| CTF Base / Cyber Writeups | Searchable writeup libraries | Useful as a corpus source for future MCP/search-backed recommendation features. |
| Reddit r/securityCTF / r/hackthebox / r/CTFlearn | Community learning patterns | Useful for meta-advice: read writeups after solving, compare approaches, and practice by category. |

## Method Cards

These cards are the distilled "what to try next" logic ForgeFlag should gradually surface in the Web UI and LLM prompts.

### Universal Triage

- Preserve the original files and record hashes before transformation.
- Identify category, artifact types, network scope, flag format, provided source code, and expected interaction mode.
- Run cheap evidence collection first: `file`, `strings`, metadata, protocol summary, HTML summary, challenge text transforms.
- Prefer hypotheses with a reproduction path: exact command, stream ID, route, attachment, decoded source, or solver script.
- Stop automatic escalation at safety boundaries: network probing, password cracking, archive extraction, and exploit execution require explicit operator intent.

### Web Method Card

- Start with response capture: status, headers, title, visible links, forms, scripts, cookies, and redirects.
- Check obvious routes: `/robots.txt`, `/sitemap.xml`, `/admin`, `/login`, `/api`, `/flag`, static JS bundles, source maps.
- Classify bug class before payloads: SQL/NoSQL injection, command/code injection, SSTI, path traversal/LFI/RFI, file upload, IDOR, auth logic, SSRF, XXE, GraphQL, JWT/session, XSS/prototype pollution.
- If source code is provided, inspect routes, middleware, template rendering, deserialization, upload paths, and environment variable reads.
- If an API returns option lists or commands, treat hidden command discovery as a high-priority branch.

ForgeFlag next additions:

- Record response headers and cookies in WebSolver evidence.
- Add robots/source-map/static-JS discovery behind active-probe scope.
- Add bug-class hint extraction from forms and technologies.

### Crypto Method Card

- Decide whether the input is encoding, encryption, hash, signature/MAC, oracle, or math problem.
- Peel reversible layers safely: Base encodings, hex, URL/HTML, compression markers, binary/octal/decimal ASCII, ROT/Caesar, Morse, and common separators.
- For XOR, check known plaintext from flag format, repeated-key clues, equal-length ciphertexts, and nonce/keystream reuse.
- For AES/stream modes, collect IV/nonce/counter and look for CTR reuse, CBC padding oracles, ECB block repetition, and GCM nonce misuse.
- For RSA, extract all integers and test prime `n`, known factors, shared factors, small exponent, bad padding, broadcast, partial key leakage, and Coppersmith-style hints.
- For hashes, fingerprint first, then decide whether lookup or bounded cracking is justified.

ForgeFlag next additions:

- Add Caesar all-rotation, Morse, octal/decimal ASCII, and simple XOR cribbing.
- Emit crypto primitive hints even when no flag is decoded.
- Generate a reproducible Python/Sage solve workspace for RSA parameter cases.

### Forensics And Stego Method Card

- Identify the real container first; extensions lie often in CTFs.
- Run file, strings, metadata, archive listing, and magic-byte checks before extraction.
- For images, inspect PNG chunks/IHDR/CRC/trailing data, JPEG comments/APP markers, palettes, alpha channel, bit planes, dimensions, and visual anomalies.
- For archives and documents, inspect comments, embedded files, relationship graphs, encryption state, macros, object streams, and suspicious filenames.
- For disk/memory/log cases, build a timeline and search for deleted files, credentials, shell history, process/network artifacts, and malware staging.
- Treat stego as forensics first: metadata, appended data, embedded files, then content-level extraction such as LSB/spectrogram/DTMF/zero-width text.

ForgeFlag next additions:

- Add magic-extension mismatch evidence.
- Add safe archive listing for nested archives and comments.
- Add PNG/JPEG preview generation and a stego checklist in Findings.

### Traffic Method Card

- Start with capture type, packet counts, protocol hierarchy, endpoints, conversations, and time range.
- Search for direct flag markers and then protocol-specific carriers: DNS queries/TXT, HTTP requests/objects, TCP streams, SMTP/FTP payloads, TLS SNI/certs, ICMP payloads, and unusual ports.
- For DNS exfiltration, group by base domain, preserve label order, try Base32/Base64/hex on labels, and reconstruct split payloads.
- For HTTP, extract URLs, hosts, cookies, auth headers, uploaded/downloaded objects, forms, and compressed/encoded bodies.
- For encrypted or custom protocols, look for keys in attachments, reused IV/nonces, predictable headers, and cleartext control channels.

ForgeFlag next additions:

- Reconstruct DNS label payloads across multiple packets.
- Export HTTP objects into managed artifacts.
- Add stream-follow summaries with stream IDs and decoded candidates.

### Reverse Method Card

- Start with `file`, `strings`, imports, symbols, section names, packer indicators, architecture, and endianness.
- If strings expose a candidate, preserve it as the shortest path; otherwise identify validation functions, input reads, compare loops, and decode routines.
- Use Ghidra/IDA/r2 for decompilation and control-flow pivots; rename variables and functions as constraints become clear.
- Watch for encoded strings, little-endian constants, table lookups, XOR loops, custom VMs, anti-debug checks, and packers such as UPX.
- Convert recovered checks into a small solver script rather than hand-solving inside the UI.

ForgeFlag next additions:

- Add packer and architecture hints.
- Add encoded-string transform passes over `strings` output.
- Add a reverse solve-script workspace for constraint recovery.

### Pwn Method Card

- Start with `file`, `checksec`, dangerous functions, strings, imports, symbols, and expected I/O.
- Reproduce locally before exploit generation; capture crash input, offset, registers, and protections.
- Classify the primitive: ret2win, stack overflow, off-by-one, format string, integer overflow, ret2libc, ret2csu, shellcode, UAF, tcache poisoning, partial overwrite, or sandbox escape.
- For stack bugs, find offset, target address, endianness, calling convention, stack alignment, and required arguments.
- For format strings, identify stack offset, leak target, write target, and whether GOT/return address writes are possible.
- Generate pwntools scripts only after evidence identifies the primitive and target.

ForgeFlag next additions:

- Add pwntools workspace generation with checksec-derived comments.

### Misc / Programming Method Card

- Route misc tasks early: encoding, archive, image/stego, scripting, game/pathfinding, sandbox, OSINT, esolang/polyglot, QR/barcode, audio, or AI/prompt.
- Preserve examples and derive a deterministic solver for input-output tasks.
- For pathfinding/game puzzles, parse the map, identify graph state, and choose BFS/Dijkstra/A* or dynamic programming.
- For sandbox tasks, inspect blacklists, exposed builtins/imports, serialization boundaries, object traversal, and exception leakage.
- For audio, inspect waveform, spectrogram, DTMF tones, Morse, sample LSB, and metadata.

ForgeFlag next additions:

- Add QR/barcode and audio metadata hooks.
- Add programming-puzzle scaffold generation.
- Add sandbox-pattern hints for Python eval/pickle/jail tasks.

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
- `WebSolver` analyzes source attachments for Flask/FastAPI/Express/Django/Laravel-style routes and promotes source-derived API option leakage, JWT/session, SSRF, and path traversal hints.
- The corpus smoke includes a visible-response flag case.

### Crypto

Common first moves:

- Normalize text and try reversible encodings before assuming a hard cryptosystem: hex, Base32/Base64, URL, HTML entities, binary ASCII, ROT13/Caesar-style rotations, Morse, and simple transpositions.
- If parameters are present, identify the primitive: RSA, DH/DLP, AES mode, stream cipher, substitution, Vigenere, or custom arithmetic.
- For RSA, extract `n/e/c/p/q/d/phi`, check known factors, prime `n`, low exponent, shared factors, and public/private key markers.
- For hashes, classify candidate hash types and choose a bounded wordlist before cracking.

ForgeFlag coverage today:

- Transform chaining handles common reversible encodings.
- Transform chaining now includes Caesar all-rotation search, Morse, and decimal/octal ASCII in addition to hex, Base32/Base64, binary ASCII, ROT13, URL, and HTML entity decoding.
- CryptoSolver recovers single-byte XOR, supplied-key repeating XOR, and supplied-key Vigenere flags when ciphertext/key evidence is present.
- RSA and hash triage are structured; known-factor RSA recovery preserves parameters, and low-exponent exact-root RSA now recovers flags and emits a reproducible Python solve script in the Write-up.
- AES-CTR nonce reuse now emits a Python crib/keystream helper script in the Write-up so the player can fill ciphertexts and known plaintext snippets.
- Poly1305 one-time key reuse now emits a Sage-oriented algebra helper that builds message/tag equations and enumerates the small tag carry window.
- The corpus smoke includes Base32 decoding and verifies the generated CTF write-up.
- PNG misc/stego triage should inspect abnormal extra IDAT chunks as possible independent zlib payloads; truncated length fields can still carry recoverable flag text.

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
- Source-level format-string patterns now produce a pwntools harness for `%p` offset probing, offset replay, and optional `fmtstr_payload` target writes.
- Source-level ret2win patterns now produce a crash harness, cyclic offset instruction, and a configurable pwntools exploit script with `--find-offset`, `--offset`, local binary mode, and remote host/port mode.
- Binary triage can infer ret2win workflow hints when tool output exposes win-like symbols and unsafe input symbols, then pass the win symbol into the generated exploit script.
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

## Expanded Web Benchmark

Run while the Web UI is active:

```bash
scripts/forgeflag-control start
scripts/forgeflag-expanded-corpus --url http://127.0.0.1:8080 --keep --strict
```

The expanded benchmark generates safe local fixtures from public CTF writeup patterns instead of vendoring original challenge archives. It currently covers 74 cases: Web has 11 cases, Crypto has 13 cases, and Forensics, Traffic, Reverse, Pwn, and Misc each have 10 cases. The current strict result is 74/74 through the Web API.

## Gaps To Add Next

- Web: API option leakage, robots.txt discovery, simple form capture, and SSRF/path traversal evidence.
- Crypto: unknown-key Vigenere/substitution hints, automated crib extraction, and Sage/LLL solve-script generation for harder RSA/lattice cases.
- Misc: small scripting puzzle harnesses and sandbox/pickle blackbox notes.
- Forensics: zip-with-comment/password hint, PNG/JPEG visual preview, and disk image timeline fixtures.
- Traffic: DNS label reconstruction across multiple packets, TXT extraction, HTTP object export, SMTP/FTP exfil, and stream reassembly.
- Reverse/Pwn: crash reproduction, offset discovery, ret2win sample, and generated pwntools workspace.
