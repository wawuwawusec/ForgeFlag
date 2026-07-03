# CTF Playbook Notes

This note summarizes public CTF challenge patterns that ForgeFlag should keep testing against. It is a pattern guide, not a vendored challenge archive.

For concrete recent hands-on examples and replay snippets, see [ForgeFlag CTF Casebook](ctf-casebook.md). For local proof-of-solve helper alignment, see [ForgeFlag Solve Scripts](solve-scripts.md).

## Sources Reviewed

- picoCTF solution indexes show broad beginner-to-medium coverage across Web Exploitation, Cryptography, Reverse Engineering, Forensics, General Skills, Binary Exploitation, and Blockchain.
- picoCTF writeup indexes are especially useful for repeatable tags: pcap/Wireshark, metadata, base64, zip/tar/binwalk, steganography, RSA, ROT13, Morse, Vigenere, strings, grep, and binary encodings.
- HackTheBox Cyber Apocalypse official repositories provide a modern multi-category taxonomy: crypto weaknesses, forensic log/traffic/malware analysis, misc scripting/sandbox tasks, pwn bug classes, reverse strings/packers/file formats, and web API/injection patterns.
- CTFtime task pages and writeup indexes are useful for checking whether a pattern is common across events rather than tied to one platform; its now-running/upcoming event pages are also a good first pass for current online competitions, but not enough for domestic China coverage.
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
| Domestic China CTF portals and official event sites | Current competitions and practice targets | Necessary when the player asks for Chinese events; many are absent from CTFtime or hidden behind dynamic frontends. |
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

### CTF Research Scope Method Card

- Frame ForgeFlag work as local or authorized CTF/lab research: challenge artifacts, owned fixtures, practice platforms, and explicit competition targets.
- Prefer passive analysis and reproducible replay evidence before active probing.
- When using an LLM for planning, include the scope context and ask for bounded CTF next steps, expected evidence, solver ordering, and explicit `flag_candidates` only when the candidate is derived from local challenge evidence. Long source attachments should expose both head and tail excerpts because CTF outputs often sit in final comments.
- Active network work must be gated by `ScopePolicy`, `--active-probe`, and an allowlisted host.
- Write reports as challenge solve notes with evidence, constraints, and replay commands; avoid language that implies use against systems outside the challenge scope.
- For Web, Reverse, and Pwn work, restate the category-specific CTF boundary before giving payloads, scripts, exploit harnesses, or active probing steps.

### Competition Discovery Method Card

- Start current-event searches with CTFtime `now=true` and `upcoming=true`, then verify each candidate against the official event page before calling it running.
- Record the local time used for the decision. For China-based players, convert schedules to Beijing time and call out whether an event is running now, registration-open, upcoming, or always-on practice.
- For China/domestic requests, search beyond CTFtime: official event sites, XCTF/攻防世界, BUUCTF, CTFHub, NSSCTF, CISCN-style portals, and university or vendor challenge pages.
- Treat Nuxt/Vue/React event sites as dynamic until proven otherwise. If plain HTML is sparse, inspect embedded scripts, XHR/API data, or a rendered page before deciding the schedule is unavailable.
- Return a short action list: direct entry URL, time window, status, and quick fit label such as beginner-friendly, Jeopardy, AI/security attack-defense, qualifier, or practice platform.

### Web Method Card

- Scope wording: treat Web tasks as authorized CTF web challenges or local fixtures. Prefer "scoped request", "challenge route", "response evidence", and "authorized target" over generic attack language.
- Start with response capture: status, headers, title, visible links, forms, scripts, cookies, and redirects.
- Check obvious routes: `/robots.txt`, `/sitemap.xml`, `/admin`, `/login`, `/api`, `/flag`, static JS bundles, source maps.
- Classify bug class before payloads: SQL/NoSQL injection, command/code injection, SSTI, path traversal/LFI/RFI, file upload, IDOR, auth logic, SSRF, XXE, GraphQL, JWT/session, XSS/prototype pollution.
- If source code is provided, inspect routes, middleware, template rendering, deserialization, upload paths, and environment variable reads.
- If the app uses wrapper dependencies around routers, loggers, auth, or diagnostics, inspect downloaded package source too. Supply-chain CTF bugs often hide pre-auth middleware in module cache rather than in the submitted application files.
- For signed cookies or URL parameters, classify the MAC construction. `MD5(secret || data)` and `SHA1(secret || data)` are prefix MACs: if the secret leaks in source, directly re-sign forged data; otherwise try hash length extension and append an overriding parameter such as `&role=admin`.
- For URL-to-PDF or URL-to-screenshot renderers, inspect both the preflight URL validation and the renderer's actual fetch behavior. A guard that resolves DNS before passing the URL to WeasyPrint, Chromium, wkhtmltopdf, or a similar renderer can be bypassed with DNS rebinding if the renderer resolves again.
- If an API returns option lists or commands, treat hidden command discovery as a high-priority branch.

ForgeFlag next additions:

- Record response headers and cookies in WebSolver evidence.
- Add robots/source-map/static-JS discovery behind active-probe scope.
- Add bug-class hint extraction from forms and technologies.

### Crypto Method Card

- Decide whether the input is encoding, encryption, hash, signature/MAC, oracle, or math problem.
- Peel reversible layers safely: Base encodings, hex, URL/HTML, compression markers, binary/octal/decimal ASCII, ROT/Caesar, Morse, and common separators.
- For XOR, check known plaintext from flag format, repeated-key clues, equal-length ciphertexts, and nonce/keystream reuse.
- For self-synchronizing XOR scripts where the key slot depends on previous plaintext, use the flag wrapper as a crib and verify repeated key-slot consistency before attempting slow full-text language search.
- For integer transforms that repeatedly apply `x ^= x >> k`, treat the script as a reversible linear map over GF(2). If the shift sequence comes from a deterministic seed, invert the shifts in reverse order over the fixed plaintext bit length.
- For LCG tasks, replay before guessing: known `a/b/n` plus ciphertext may be forward or inverse; two consecutive outputs can reveal an unknown increment; six consecutive outputs can recover `n` from `gcd(d[i+2]*d[i]-d[i+1]^2)`. If the recovered plaintext is only a residue modulo `n`, lift `residue + k*n` with flag grammar.
- For MT19937, count generated words exactly. Full 624 32-bit outputs are enough for untemper + twist cloning; mixed `getrandbits(32/64/96/128)` values usually split into little-endian 32-bit chunks; small-bit outputs require a partial-bit symbolic/matrix clone and should be documented as an external-helper path.
- For LFSR tasks with a leaked bitstream, run Berlekamp-Massey or explicit GF(2) linear equations before guessing. If the stream is slightly short, enumerate the remaining free variables and use flag/hash constraints such as a known SHA256 prefix to select the key.
- For simple LFSR stream files, preserve taps, leaked seed or seed high bits, output length, and ciphertext. If the source writes a `key` file but the file is absent, mark the case as missing sidecar evidence rather than accepting a guessed flag.
- For Python `random` scripts that print `gift = key ^ seed`, recover the byte seed first, seed `random` with `bytes_to_long(seed)`, regenerate any `next_prime(random.randint(...))` offsets, and remove those offsets from the output integer before converting back to bytes.
- For custom toy block ciphers with tiny keys, write exact encrypt/decrypt functions before guessing: use known flag prefixes to recover or brute-force the key, then invert each round. If the round function is not one-to-one, keep candidate sets and resolve collisions with flag grammar plus re-encryption.
- For simple position-dependent alphabet shifts, test Trithemius-style decryption before treating the text as Vigenere. Many challenge outputs preserve punctuation and count the shift by absolute character index.
- For fixed-position shuffles with example mappings, recover the permutation from known plaintext/ciphertext pairs, then invert the censored row. Two crafted examples can identify every source index in a 16-byte shufflebox-style puzzle.
- For AES/stream modes, collect IV/nonce/counter and look for CTR reuse, CBC padding oracles, ECB block repetition, and GCM nonce misuse.
- For ECDSA/DSA-style signatures, scan all signatures for repeated `r`. If found, recover the nonce and private scalar from the two message hashes, then verify the recovered private key against the public key before using it for any follow-on decryption.
- For RSA, extract all integers and test prime `n`, known factors, shared factors, small exponent, bad padding, broadcast, related messages, partial key leakage, and Coppersmith-style hints. If two low-exponent ciphertexts encrypt affine-related plaintexts such as `m` and `m + 1` under the same modulus, run Franklin-Reiter by taking `gcd(x^e - c1, (x + a)^e - c2)` in `Z_N[x]`. If the high bits of a 1024-bit prime are known and the unknown low bits are below roughly `N^1/4`, recover the low bits with a univariate Coppersmith lattice and then factor with `gcd(p_high + x, n)`.
- For service-backed RSA leaks such as `(p-s)(q-s)` with small `s`, prefer a local/authorized replay helper: parse the transcript, enumerate the shift to recover `p+q`, decrypt the password, and submit it back to the same service.
- For matrix or linear-algebra ciphers, turn the stated transform into equations over unknown matrix entries. If modular inversion fails under `mod n`, compute `gcd(bad_pivot, n)` before abandoning the route; CTF authors often hide a useful factor in composite moduli.
- For hashes, fingerprint first, then decide whether lookup or bounded cracking is justified. If the scheme is custom and intentionally expensive, use the stated password grammar to generate a precise candidate set and verify it with compiled/native code instead of a slow scripting loop.
- For custom hash wrappers with a known candidate grammar, strip the wrapper to the raw digest and generate the bounded Cartesian product yourself before reaching for cracking rigs. Preserve tricky normalization variants for domain terms with punctuation, spaces, symbols, or gender markers.
- For "sealed to a signing key" CTF artifacts, do not assume a full ECIES container first. After recovering the signer private scalar, test simple wrappers such as AES-GCM `nonce || tag || ciphertext` with `SHA256(private_scalar)` as the key, then escalate to structured KEM/DEM parsing only if that fails.

ForgeFlag next additions:

- Add Caesar all-rotation, Morse, octal/decimal ASCII, and simple XOR cribbing.
- Emit crypto primitive hints even when no flag is decoded.
- Generate a reproducible Python/Sage solve workspace for RSA parameter cases.

### Forensics And Stego Method Card

- Identify the real container first; extensions lie often in CTFs.
- Run file, strings, metadata, archive listing, and magic-byte checks before extraction.
- For images, inspect PNG chunks/IHDR/CRC/trailing data, JPEG comments/APP markers, embedded thumbnails, palettes, alpha channel, bit planes, dimensions, and visual anomalies. If two 1-bit or noise-like images are provided together, try XOR/equality/difference composites early because they may be visual-cryptography shares. If a BMP is clean but the prompt hints at Windows tooling, try QuickStego before overfitting generic LSB output. If appended data starts with a console/firmware/game header, pivot into light reverse engineering instead of treating it as generic stego.
- For archives and documents, inspect comments, embedded files, relationship graphs, encryption state, macros, object streams, and suspicious filenames.
- For Windows Group Policy Preference archives, prioritize `Machine/Preferences/Groups/Groups.xml`, extract `cpassword`, and decrypt it with the published GPP AES key before heavier forensics. Treat `Groups.xml`, `Preferences`, and `cpassword` as archive-preview priority markers.
- For Windows registry exports, detect UTF-16LE first; for Wi-Fi questions, inspect `NetworkList\\Nla\\Wireless` and cross-check `NetworkList\\Profiles` before accepting generic network profile names.
- For Minecraft `.mca` / `.mcr` region files, parse the Anvil location table but also scan unreferenced sectors. Crash or deleted-container challenges can leave old chest `Items` and JSON `Lore` in orphan zlib/gzip chunks; join short `{"text": ...}` lore fragments separately from long item names and titles.
- If a ZIP is missing the end-of-central-directory record, parse local file headers (`PK\x03\x04`) and recover each stored/deflated stream by filename, compressed size, and CRC before attempting heavier repair.
- For disk/memory/log cases, build a timeline and search for deleted files, credentials, shell history, process/network artifacts, malware staging, and browser profile databases such as Chrome History/Cookies/Downloads; scan suspicious URL query parameters with reversible transforms. For Linux memory snapshots, if ps/env/lsof/sockets are clean but a named process is suspicious, enumerate its VMAs and dump anonymous, heap, stack, and especially `rwx` mappings.
- Treat stego as forensics first: metadata, appended data, embedded files, then content-level extraction such as LSB/spectrogram/DTMF/zero-width text.

ForgeFlag next additions:

- Add safe archive listing for nested archives and comments.
- Add PNG/JPEG preview generation and a stego checklist in Findings.

### Traffic Method Card

- Start with capture type, packet counts, protocol hierarchy, endpoints, conversations, and time range.
- Search for direct flag markers and then protocol-specific carriers: DNS queries/TXT, HTTP requests/objects, TCP streams, SMTP/FTP payloads, TLS SNI/certs, ICMP payloads, and unusual ports.
- For DNS exfiltration, group by base domain, preserve label order, try Base32/Base64/hex on labels, and reconstruct split payloads.
- For HTTP, extract URLs, hosts, cookies, auth headers, uploaded/downloaded objects, forms, and compressed/encoded bodies.
- For webshell-style HTTP responses, treat delimiters such as `X@Y`, `[S]`, `[E]`, and cwd lines as wrapper text; extract embedded `flag{...}` / `f1ag{...}` even when the marker is adjacent to wrapper bytes.
- If the question asks for the scanning tool and version, inspect HTTP user-agents and wrap evidence like `Nikto/2.1.6` as the requested CTF flag format, for example `DUCTF{nikto_2.1.6}`.
- If tshark stops early with a damaged classic PCAP record length, try record-header resynchronization before giving up; preserve repair offsets and the repaired capture path.
- For repeated tiny marker packets, inspect header fields as possible carriers. IPv4 Identification values can encode two bytes per packet and may need adjacent de-duplication before little-endian decoding.
- For raw TCP streams, search printable payloads for data URIs such as `data:image/*;base64,`; decode and render them even when there is no valid HTTP framing.
- For RF/radio challenges where the attachment is a waveform image rather than a PCAP, extract the colored trace, estimate the carrier period, try ASK/OOK Manchester half-bit timing near twice the carrier period, and decode both Manchester polarities before heavier DSP.
- For beacon-like HTTP, separate browser noise from scripted traffic by User-Agent, interval, repeated paths, and form fields. If Base64-decoded payloads share a long prefix, crib likely JSON headers to recover reused XOR keystreams before trying heavier crypto.
- For Cobalt Strike style HTTP, look for `.cobaltstrike.beacon_keys`, Java serialized `KeyPair` blobs, encrypted metadata cookies, and periodic `GET` tasking paths. Decrypt the RSA metadata first, then derive `AES = SHA256(raw_key)[:16]` and `HMAC = SHA256(raw_key)[16:]` for Beacon task/result packets.
- For "wrong place" or Around-the-World clues, compare the claimed host/CDN naming with the actual destination IP, ASN, WHOIS, and GeoIP country/city. Preserve both the protocol evidence and the geolocation source.
- For encrypted or custom protocols, look for keys in attachments, reused IV/nonces, predictable headers, and cleartext control channels.

ForgeFlag next additions:

- Reconstruct DNS label payloads across multiple packets.
- Export HTTP objects into managed artifacts.
- Add stream-follow summaries with stream IDs and decoded candidates.

### Reverse Method Card

- Scope wording: treat reverse tasks as local artifact analysis of provided challenge binaries, firmware, ROMs, or attachments. Prefer "validation logic", "local binary", "static evidence", and "solve script" over generic malware/offensive language unless the challenge explicitly supplies malware-analysis context.
- Start with `file`, `strings`, imports, symbols, section names, packer indicators, architecture, and endianness.
- If strings expose a candidate, preserve it as the shortest path; otherwise identify validation functions, input reads, compare loops, and decode routines.
- Use Ghidra/IDA/r2 for decompilation and control-flow pivots; rename variables and functions as constraints become clear.
- Watch for encoded strings, little-endian constants, table lookups, XOR loops, custom VMs, anti-debug checks, and packers such as UPX.
- For stripped prompt binaries, pair prompt/success/failure strings with nearby `strlen`, `fgets`, and byte-compare loops. Invert simple byte formulas such as `(input[i] ^ key) + i == table[i]` directly from `.rodata`.
- For ELF argv-key checks, do not stop at anti-debug noise such as `ptrace`. If `main` initializes a short stack byte string, XORs `argv[1]` with that key modulo key length, and calls `strcmp` against a `.rodata` string, recover the little-endian key bytes and decode `ciphertext[i] ^ key[i % len(key)]` as the submission input.
- For small embedded ROMs or firmware carved from another file, parse the container header, carve the executable segment, and look for repeated memory-write instruction patterns. Graphics challenges often draw the flag directly into framebuffer/VRAM with fixed-width bitmap glyphs.
- For stripped static binaries with tiny `.text` and large `.data`, check for bytecode VMs: a jump table in `.rodata`, an instruction stream in `.data`, and a read buffer in `.bss`. If a VM opcode self-decrypts later bytecode using runtime state, emulate the VM and solve constraints in phases instead of linear-disassembling the encrypted bytes.
- For dense dispatch binaries with fixed-size blocks, avoid trusting truncated text disassembly alone. Disassemble the block window from bytes, extract immediate dependency masks, and try popcount or rank ordering to reconstruct validation order.
- For compiled byte-equality chains, scan around input helper calls such as `read_byte` for tagged immediate comparisons, then fallback to raw binary bytes when wrapper disassembly truncates before the validation entry point.
- For PE32 key-check warmups, pair prompt/success/failure strings with nearby stack-byte initializers. If the function writes encrypted bytes to `[esp+offset]`, pushes a small seed and length, then calls a local decoder before comparing user input, regenerate the XOR stream from the seed and decrypt the stack byte array.
- For custom VM paint programs, look for repeated validation helper calls over canvas memory. Invert the memory transform first, render the recovered image as evidence, and only then classify the visual object.
- Convert recovered checks into a small solver script rather than hand-solving inside the UI.

ForgeFlag next additions:

- Add packer and architecture hints.
- Add encoded-string transform passes over `strings` output.
- Add a reverse solve-script workspace for constraint recovery.

### Pwn Method Card

- Scope wording: treat pwn tasks as local vulnerable binaries or explicitly authorized CTF services. Prefer "proof-of-solve harness", "local crash reproduction", "offset evidence", and "challenge service" over generic intrusion language.
- Start with `file`, `checksec`, dangerous functions, strings, imports, symbols, and expected I/O.
- Reproduce locally before exploit generation; capture crash input, offset, registers, and protections.
- Classify the primitive: ret2win, stack overflow, off-by-one, format string, integer overflow, ret2libc, ret2csu, shellcode, UAF, tcache poisoning, partial overwrite, or sandbox escape.
- For stack bugs, find offset, target address, endianness, calling convention, stack alignment, and required arguments.
- For format strings, identify stack offset, leak target, write target, and whether GOT/return address writes are possible.
- Generate pwntools scripts only after evidence identifies the primitive and target.
- Use `/Users/5haw0/学习/CTF/pwn/堆基本结构及利用讲义-例题/lesson-after/level6-64/freenote_x64.py` as the house reference style for Pwn exploit scripts: pwntools first, local debug mode by default, explicit remote mode, top-level `process` / `remote` plus `ELF` / `libc` setup, prompt-synchronized menu helpers, separated leak and exploit phases, optional `debugf()` breakpoints, `log.success` for derived addresses, and a deterministic proof mode or final `interactive()` handoff.
- Do not mark a Pwn challenge solved from an exploit idea alone. If the official service or flag is unavailable, create a local test `flag` in the challenge working directory, run the exploit against the local binary/container/service, execute `cat flag` or an equivalent command through the gained primitive, and preserve the transcript as `exploit_verified` proof.
- For menu binaries, prefer helper functions that mirror challenge actions and synchronize on prompts. If the exploit overwrites a prompt-producing function such as `printf` with `system`, switch from prompt waits to timeout or raw reads after the overwrite because the original prompt contract may disappear.

ForgeFlag next additions:

- Add pwntools workspace generation with checksec-derived comments.

### Misc / Programming Method Card

- Route misc tasks early: encoding, archive, image/stego, scripting, game/pathfinding, sandbox, OSINT, esolang/polyglot, QR/barcode, audio, or AI/prompt.
- Preserve examples and derive a deterministic solver for input-output tasks.
- For pathfinding/game puzzles, parse the map, identify graph state, and choose BFS/Dijkstra/A* or dynamic programming.
- For sandbox tasks, inspect blacklists, exposed builtins/imports, serialization boundaries, object traversal, and exception leakage.
- For Python `eval(user_input + suffix)` blacklists, test whether a safe-looking expression plus `#` can comment out the appended suffix before escalating to object traversal. Source-only replays should inject an explicit local `flag.txt` fixture when the remote flag file was not shipped.
- For audio, inspect waveform, spectrogram, DTMF tones, Morse, sample LSB, and metadata. For melody/notation prompts, segment events after calibration. If events are monophonic, test note letters, scale degrees, staff positions, and tiny binary alphabets; if events are chords, score simultaneous natural notes and try note-set bitmasks as 7-bit ASCII.
- For recipe/cooking esolangs, model bowls, ingredients, and serving operations as state updates. If quantities and ingredients are tiny, brute force the domain against the final dish evidence before investing in a full interpreter.
- For corrupted esolang or visual-code source, recover structure before execution. DoubleHelix-style Ruby can be decoded by matching the DNA-art row cycle, enumerating missing `AT/CG/GC/TA` pairs, and packing bits in little-endian byte order.
- For Vivado hardware handouts, treat `.dcp` checkpoints as ZIP containers first. Extract `main.edf`, parse LUT `INIT` values and net joins, then simulate small combinational switch/LED/seven-segment designs before falling back to GUI schematic reconstruction.
- For ML/adversarial-image tasks, match the service's exact model mode and preprocessing before optimizing. A ResNet left in train mode can score a single image differently from `eval()` mode, and BatchNorm makes batched candidate scoring differ from the single-image service path, so preserve baseline score, pixel budget, and server-returned proof separately from model-only experiments.

ForgeFlag next additions:

- Add QR/barcode and audio metadata hooks.
- Add programming-puzzle scaffold generation.
- `scripts/solve_unbreakable.py` replays Python eval blacklist bypasses where `#` can truncate an appended call suffix and `print(open(...).read())` remains filter-safe.
- `scripts/solve_ee2026.py` replays Vivado DCP/EDIF LUT-netlist puzzles by extracting the checkpoint, evaluating switch conditions, and mapping active-low display outputs through the assignment table.
- `scripts/solve_attack_of_the_worm.py` wraps a local CPU PyTorch replay path for sparse adversarial pixel challenges, including `--score-only`, `--payload-file`, parameterized `--search-unstable`, `--search-seeds`, and `--search-output` / `--payload-output` modes for exact single-image server scoring, bounded seed-sweep unstable-pixel search, and cached candidate replay, but the current UMDCTF case still needs a verified 30-pixel payload before it can become a scorecard pass.
- Add broader sandbox-pattern hints for pickle/jail tasks.

## Category Playbooks

### Web

Common first moves:

- Fetch the declared target only when the host is explicitly allowlisted.
- Record the first response, visible links, forms, title, and content type.
- Look for obvious flags in the response before fuzzing.
- If active probing is enabled, run a small route wordlist such as `robots.txt`, `admin`, `login`, `flag`, and routes discovered from links/forms.
- For deeper work, classify the bug class before acting: SQL injection, command injection, SSTI, JWT/session confusion, SSRF, path traversal, upload handling, or API option leakage.
- For source-attached Go apps, inspect `go.mod`, dependency graph, and module cache. Suspicious organization-local packages may install hidden middleware or diagnostic headers before the application's auth layer.
- For homegrown session signatures, inspect whether the code uses HMAC. Raw `hash(secret || data)` means either direct re-signing if the secret leaked, or length extension if only a valid signed guest token is available.
- For source-attached Bun/Hono YAML converters, inspect signed-field extraction and output-file construction together. `signed.__proto__`, null-byte path truncation, `/proc/self/fd/*`, and YAML-shaped JavaScript/TypeScript can combine into a source overwrite chain.
- Treat obvious handout placeholders such as `test_flag_real_flag_on_instance` as rejected candidates, not final flags. Preserve them as evidence that a local/live proof harness is still required.
- Prefer bounded proof replay for Web RCE-style CTF cases: overwrite or patch the local challenge service to return `getflag` output over HTTP instead of using reverse-shell callbacks, then tear the container down after verification.
- For C-backed HTTP services with manual auth parsing, audit prefix comparisons such as `strncmp(user_input, secret, strlen(user_input))`; a one-character Basic Auth replay can prove the bug without broad network probing.
- For PHP token challenges, inspect `pack()` / `unpack()` format strings and signed serialized data together. User-controlled `X` rewind operators can reshape a signed token before later permission checks, and fixed roots such as `/pro` can sometimes be joined into `/proc/self/root/...`.
- For SSRF filters that blacklist `localhost` or `127.0.0.1` by substring, test loopback aliases inside the authorized local service only. Addresses such as `127.0.0.2` can bypass naive host checks while still reaching routes guarded by loopback `req.ip`.
- For Python recursive merge helpers, check whether user JSON can traverse magic attributes such as `__class__`, `__init__`, and `__globals__`. A module global used by a protected route can become writable through class pollution.
- For protocol translation proxies, compare front-door policy with the backend bytes. Preserving `Transfer-Encoding: chunked` across HTTP/3 or HTTP/2 to HTTP/1.1 conversion can enable a zero-length chunk followed by a smuggled backend request.
- For iframe-gated note apps, inspect owner-scoped search routes for substring tests over note titles or text. If admin-only note content is reachable only through an authorized browser/adminbot context, model prefix queries locally and preserve source-pattern evidence when the concrete live flag is absent.

ForgeFlag coverage today:

- `WebSolver` runs scoped HTTP probing and low-budget route discovery.
- `WebSolver` analyzes source attachments for Flask/FastAPI/Express/Django/Laravel-style routes and promotes source-derived API option leakage, JWT/session, SSRF, and path traversal hints.
- Source archives are unpacked for full source-file review, including Hono/Bun/Express routes and YAML parse/stringify sinks, even when no live target is configured.
- Web source analysis rejects placeholder/test flags and records exploit-chain hints such as prototype pollution, Bun null-byte paths, `/proc/self/fd` overwrite pivots, YAML-to-TypeScript shaping, and SUID `getflag` targets.
- `scripts/solve_prisoner_processor.py` is the current manual replay helper for local/authorized Prisoner Processor services.
- `scripts/solve_cecure_cerver.py` replays one-character Basic Auth prefix bypasses locally by compiling the provided C source, sending bounded HTTP requests, and preserving the returned flag response.
- `scripts/solve_private_hidden_paths.py` replays PHP `pack()` format-string token shaping locally by starting the provided Docker service, minting a pro token, and preserving the `/proc/self/root/flag.txt` HTTP response.
- `scripts/solve_fetcher.py` replays loopback-alias SSRF locally by starting the provided Bun/Express service and posting `url=http://127.0.0.2:3000/flag` through `/fetch`.
- `scripts/solve_co2.py` replays Python class pollution locally by registering a throwaway account, submitting a nested feedback JSON payload, and preserving the `/get_flag` response.
- `scripts/solve_http_fanatics.py` replays HTTP/3-to-H1 request smuggling locally by reconstructing proxy-emitted HTTP/1.1 bytes and smuggling `POST /admin/register` into the backend stream.
- `scripts/solve_lamenote.py` replays iframe-gated owner-scoped substring search oracles by identifying the source signals, demonstrating prefix recovery against a local synthetic note, and emitting the manifest flag pattern when no concrete remote admin note is shipped.
- The corpus smoke includes a visible-response flag case.

### Crypto

Common first moves:

- Normalize text and try reversible encodings before assuming a hard cryptosystem: hex, Base32/Base64, URL, HTML entities, binary ASCII, ROT13/Caesar-style rotations, Morse, and simple transpositions.
- If parameters are present, identify the primitive: RSA, DH/DLP, AES mode, stream cipher, substitution, Vigenere, or custom arithmetic.
- For RSA, extract `n/e/c/p/q/d/phi`, check known factors, prime `n`, low exponent, shared factors, and public/private key markers. If source code loops over `iroot(c+n*i,e)` or `iroot(c+i*n,e)`, infer `e` from the call and search the bounded `c + k*n` exact-root window.
- For hashes, classify candidate hash types and choose a bounded wordlist before cracking.

ForgeFlag coverage today:

- Transform chaining handles common reversible encodings.
- Transform chaining now includes Caesar all-rotation search, Morse, decimal/octal ASCII, and QuickStego-style hex-to-Braille ASCII in addition to hex, Base32/Base64, binary ASCII, ROT13, URL, and HTML entity decoding.
- CryptoSolver recovers single-byte XOR, supplied-key repeating XOR, and supplied-key Vigenere flags when ciphertext/key evidence is present.
- CryptoSolver detects DUCTF three-line-style `q[y % 16] ^ x; y = x` self-synchronizing XOR scripts and can recover bounded CTF-idiom flag candidates from raw ciphertext by key-slot consistency.
- CryptoSolver recovers deterministic right-shift XOR linear scripts that assert `enc(flag) == b"..."` by reconstructing the seeded shift sequence and applying the inverse transform without Sage.
- CryptoSolver recovers source-backed 256-bit LFSR/Berlekamp-Massey tasks when a long bitstream and hash-prefix flag constraint are present, preserving recovered key, mask, free-variable count, and replay explanation.
- CryptoSolver recovers local PRNG/stream samples for Python random seed brute force, Python random prime-offset replay, LCG forward/inverse/two-output/consecutive-output patterns, simple LFSR seed and seed-high-bit leaks, and full-output MT19937 clone cases. `scripts/solve_prng_stream_cipher_cases.py` preserves the broader local sample pack, including MT2 digest replay, MT3 partial 8-bit matrix clone, streamgame key-observation brute force, and lfsr3 artifact drift.
- `scripts/solve_accountleak.py` replays shifted RSA factor-leak services locally by parsing `c`, `n`, and `(p-s)(q-s)`, enumerating the bounded shift, and submitting the recovered password for a transcript-backed flag.
- `scripts/solve_accessible_sesamum.py` replays short-PIN sliding-window services locally with a De Bruijn attempt stream, reversing the stream when the challenge consumes each submitted line from right to left.
- `scripts/solve_babycha.py` replays state-as-keystream ChaCha mistakes locally by recovering one serialized state block from chosen plaintext, computing the next block, and decrypting the service flag ciphertext.
- `scripts/solve_giedi_composite.py` replays composite-ring NTRU-style challenges with Sage by splitting `x^N - 1` into CRT components, reducing each component lattice, recombining key residues, and decrypting the message polynomial from `output.txt`.
- RSA and hash triage are structured; known-factor, low-exponent exact-root, source-loop modular low-exponent root, prime-modulus, close-prime Fermat, common-modulus, shared-prime, and broadcast RSA now preserve parameters, recover flags when directly solvable, and emit reproducible Python solve scripts in the Write-up.
- AES-CTR nonce reuse now emits a Python crib/keystream helper script in the Write-up so the player can fill ciphertexts and known plaintext snippets; AES-GCM nonce reuse now emits a GHASH/forbidden-attack analysis scaffold for nonce, AAD, ciphertext, and tag collection.
- Poly1305 one-time key reuse now emits a Sage-oriented algebra helper that builds message/tag equations and enumerates the small tag carry window.
- The corpus smoke includes Base32 decoding and verifies the generated CTF write-up.
- PNG misc/stego triage should inspect abnormal extra IDAT chunks as possible independent zlib payloads; truncated length fields can still carry recoverable flag text.
- Forensics/Misc now record magic-byte versus filename extension mismatches and continue image/stego analysis using the detected container type, such as PNG content uploaded as `.jpg`.
- BMP stego triage now extracts QuickStego-style LSB text candidates from uncompressed 24/32-bit images, including full-row streams where row padding carries part of the bitstream. BMP/QuickStego hex can feed a second-stage Braille ASCII transform: convert recovered hex to binary without left-zero padding, split into 6-bit cells, then normalize Braille numeric and punctuation markers. Reports now preserve that two-stage path as explicit replay steps.

### Misc

Common first moves:

- Treat misc as routing: decide whether the artifact is really crypto, archive, image/stego, scripting, OSINT, programming, or puzzle logic.
- For text-like puzzles, try binary/octal/hex/Base encodings and simple transforms.
- For scripting tasks, preserve input/output examples and produce a small deterministic solver.
- For sandbox/eval/pickle-style tasks, identify import/builtin exposure and dangerous object paths before exploitation.

ForgeFlag coverage today:

- Misc image, archive, hash, and transform triage are ordered before placeholder output.
- The corpus smoke found and fixed a binary ASCII seed-extraction bug when challenge metadata surrounds the attachment content.
- CCIR476/SITOR 7-bit binary streams are decoded with LTRS/FIGS state tracking; keep wrapped message flags in explicit evidence because official CTF flags can contain spaces and punctuation.
- Decayed mame/doublehelix Ruby sources are reconstructed statically from the DNA-art format, with fully blank rows preserved as ambiguous pair positions and leetspeak-readable flag candidates ranked before verification.
- `scripts/solve_golf_hard.py` replays recursive regex golf services locally by submitting compact patterns for starts-with, unary subtraction, balanced brackets, palindromes, and unary multiplication under per-level length limits.
- `scripts/solve_i_see.py` handles schematic-backed hardware-source replays by extracting M24C0x/I2C clues from a PDF schematic and reading a local EEPROM dump for printable flag text.

### Forensics

Common first moves:

- Run file identification, strings, metadata, and archive/carving checks.
- Check image-specific structures before heavy tools: PNG chunks/IHDR/CRC/trailing data, JPEG comments/APP markers, visible metadata.
- For OSINT building-location prompts, distinguish visible landmark from camera location. Preserve image hash, visible clues, search/street-view corroboration, and final building-name normalization.
- For OSINT music/media prompts, separate image-location evidence from the answer format. If the prompt asks for a musician, composer, soundtrack, or track name, strip local oracle metadata and cross-reference the prompt's media vocabulary against public source evidence before normalizing the flag name.
- For archive puzzles, inspect names/comments/encryption state before extraction.
- For disk/memory/log cases, build a timeline and preserve evidence paths.
- For Windows disk images that carve `RegistryBackup` zip files, inspect binary hives rather than stopping at `foremost`: `SYSTEM\ControlSet001\Control\FVEStats` can preserve BitLocker `OsvEncryptInit` and `OsvEncryptComplete` FILETIME values; convert to the challenge timezone before formatting the flag.

ForgeFlag coverage today:

- `ForensicsSolver` records file/strings/binwalk/exiftool results, image hints, archive summaries, optional `foremost` carving and YARA scans, and flag candidates.
- ForensicsSolver can carve embedded zip archives from VMDK-style local artifacts, inspect RegistryBackup `SYSTEM` hives, recover BitLocker FVEStats start/end timestamps, and emit `PCL{start_end}` style timeline flags.
- ForensicsSolver repairs archive-contained PNG entries when the first four signature bytes are mangled but the PNG chunk tail and `IHDR` are intact, then reruns image text/stego analysis on the repaired artifact.
- `scripts/solve_filefactory.py` is the current replay helper for archive-contained mangled PNG flags: it writes the repaired PNG artifact and preserves the visual transcription used to recover the flag.
- `scripts/solve_babybit_vmdk.py` replays the babybit VMDK path by carving the embedded RegistryBackup zip, reading `SYSTEM\ControlSet001\Control\FVEStats`, and preserving the UTC+8 BitLocker timeline flag.
- `scripts/solve_hans_zimmer_osint.py` replays a music/media OSINT prompt by stripping local oracle metadata, preserving Hans Zimmer/Dune clue evidence, and normalizing the source-derived `Gom Jabbar` answer.
- `scripts/solve_ductf_osint_building.py` replays DUCTF image-geolocation building cases by preserving the published image hash, local official writeup clues, and normalized building-name flag.
- Handwritten or visual-only repaired images remain a visual/OCR follow-up unless the read flag is preserved as evidence.
- The corpus smoke includes a strings-based artifact.

### Traffic

Common first moves:

- Confirm the capture type and protocol hierarchy.
- Search payload bytes for direct markers, then pivot to DNS, HTTP, TCP streams, SMTP/FTP/object export, and suspicious long labels.
- Treat DNS labels, TXT answers, HTTP objects, and TCP streams as possible encoded carriers.
- If the parser reports a corrupt PCAP length, attempt bounded classic-PCAP record resync and rerun carrier extraction on the repaired capture.
- Preserve stream IDs and tool commands for replay.

ForgeFlag coverage today:

- `TrafficSolver` runs tshark summaries, DNS summary, TCP shortlist, HTTP request/artifact scans, and flag scans.
- TrafficSolver extracts generic `flag{...}` / `f1ag{...}` markers from decoded HTTP artifact text and exported webshell response objects even when wrappers such as `X@Y` are adjacent to the marker.
- TrafficSolver also performs a bounded raw capture printable-byte scan for direct CTF flags that remain in PCAP payload bytes even when tshark summaries miss them.
- TrafficSolver repairs classic PCAP record-length drift by resynchronizing plausible record headers, then decodes repeated IPv4 Identification stego marker packets such as `where is the flag?`.
- Traffic triage should extract data URI images from raw TCP payloads and preserve rendered artifacts plus SHA-256 hashes for visual flags.
- TrafficSolver can decode blue-trace ASK/OOK Manchester waveform images and preserves carrier period, half-bit width, byte alignment, Manchester polarity, and decoded flag candidates.
- The corpus smoke generates a real PCAP with an HTTP payload flag and runs it through the Web service.

### Reverse

Common first moves:

- Run `file` and `strings` first; many warmups are direct strings or simple transformations.
- Check packers and format hints before decompilation.
- Move into IDA/Ghidra/r2 only after preserving basic static evidence.
- For validation binaries, recover input constraints and produce a small solver script.

ForgeFlag coverage today:

- Local reverse triage uses file/strings, `readelf` section listing, `objdump` disassembly and section dumps, radare2 metadata/string hints, ROPgadget/ropper, and optional IDA MCP.
- ReverseSolver can statically recover Python VM challenges that decrypt `flag_enc` with `sha1(str(perfect_number))` after checking a modulo predicate over known Mersenne-prime perfect numbers; it tries decoy `MOV` constants and repeats the digest to the encrypted flag length.
- ReverseSolver can recover Python 8x8 grid-verifier challenges by modeling grid cells as Z3 0/1 variables, preserving solved grid bits and byte-register evidence.
- ReverseSolver can recover compiled byte-equality chains that encode input bytes as tagged immediates such as `input_byte * 2`, including a raw-binary fallback when `objdump` text is truncated.
- ReverseSolver can recover MLVM pixel-art validation bytecode by inverting 4-byte color-chunk checks, rendering the 17x17 canvas, and matching conservative object templates such as `gameboy`.
- The corpus smoke compiles a small binary and verifies strings-based recovery.

### Pwn

Common first moves:

- Run `file`, `checksec`, and strings.
- Identify the bug class: stack overflow, off-by-one, format string, integer overflow, UAF, heap/tcache, ret2win, ret2csu, ret2libc, or sandbox escape.
- Reproduce the crash locally before exploit generation.
- Generate pwntools workspaces only after offsets, protections, and I/O shape are understood.
- For teaching-style ret2win binaries, inspect the input layer before choosing payload bytes. Some challenges accept literal escaped bytes such as `\41`, so the replay payload must match the program's parser rather than sending raw packed bytes.
- For game-style integer overflow tasks, model the exact C integer width and signedness first. Repeated safe actions can wrap `short int` health or score counters into the win condition faster and more reliably than interactive guessing.
- For heap warmups, inspect whether a one-byte overflow reaches the next chunk size field. If the program later frees that chunk and accepts a controlled allocation size, model the allocator layout and aim for an overlapping chunk that exposes adjacent flag data.
- For fixed-suffix stack overflows, inspect target addresses as bytes. A custom linker or unusual section placement can make a useful address appear inside appended text such as `.com\\0\\0\\0\\0`; the input length then becomes the alignment primitive.
- For account/menu UAF challenges, trace allocation and free order across related structs. A freed user chunk can become a later list-entry chunk, and uninitialized `next` or `prev` pointers may inherit old controlled fields.
- For AArch64 pointer-authentication challenges, look for in-program signing oracles before brute-forcing PAC. A helper that signs writable function table entries can turn arbitrary write plus signed-pointer printing into a controlled indirect call.
- For glibc heap menu challenges, separate leak setup from write setup. Print-after-free may reveal the safe-linking heap mask for tcache, while large freed chunks can reveal libc arena pointers for hook or GOT targets.
- For VM pwn handouts, check artifact completeness before exploit work. QEMU challenges that reference `vmlinuz-linux`, `initramfs.cpio.gz`, `run.sh`, and a rootfs `/target` should stay in backlog_gap until those bytes are present and the exploit can be replayed against the local authorized VM.

ForgeFlag coverage today:

- Local pwn triage uses file/strings/checksec/ROPgadget/ropper and optional IDA MCP.
- Source-level format-string patterns now produce a pwntools harness for `%p` offset probing, offset replay, and optional `fmtstr_payload` target writes.
- Source-level ret2win patterns now produce a crash harness, cyclic offset instruction, and a configurable pwntools exploit script with `--find-offset`, `--offset`, local binary mode, and remote host/port mode.
- Binary triage can infer ret2win workflow hints when tool output exposes win-like symbols and unsafe input symbols, then pass the win symbol into the generated exploit script.
- `scripts/solve_bof_school.py` replays a fixed-address ret2win challenge inside an Ubuntu container by parsing the `win` symbol, sending escaped little-endian bytes, and rejecting placeholder training flags.
- `scripts/solve_epic_boss_fight.py` replays a signed 16-bit health overflow inside an Ubuntu container by computing the minimal defend count and emitting both service and manifest-normalized flag evidence.
- `scripts/solve_baby_heap.py` replays a one-byte heap size overwrite by choosing the forged size byte, requesting the overlapping allocation, and preserving the printed reader-chunk flag.
- `scripts/solve_insanity_check.py` replays a fixed-suffix stack overflow by aligning the suffix email's `.com\\0\\0\\0\\0` bytes with saved RIP, reaching the `.flag` `win` symbol at `0x6d6f632e`.
- `scripts/solve_sign_in.py` replays a freed user/list-entry chunk reuse bug by pointing an uninitialized linked-list `next` field at a stable zero-filled region, then signing in as an empty uid-0 user.
- `scripts/solve_pac_shell.py` replays AArch64 PAC signing-oracle exploitation in Docker by deriving PIE/libc from helper leaks, locating the active stack via `environ`, asking the challenge to sign a libc gadget, and reading `flag.txt` from the running service.
- `scripts/solve_chisel.py` replays glibc tcache poisoning in Docker by deriving heap/libc bases from freed chunk leaks, poisoning a safe-linked tcache fd to reach `__malloc_hook`, and triggering `system("/bin/sh")` to read `flag.txt`.
- `scripts/solve_maze_of_mist_static.py` records the HTB Maze of Mist ret2vdso payload shape and reports missing VM handout artifacts; it is intentionally a blocker helper until the QEMU/rootfs/target files are available for local replay.
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
- Crypto: unknown-key Vigenere/substitution hints, broader crib extraction for self-synchronizing XOR, and Sage/LLL solve-script generation for harder RSA/lattice cases.
- Misc: small scripting puzzle harnesses and sandbox/pickle blackbox notes.
- Forensics: zip-with-comment/password hint, PNG/JPEG visual preview, and disk image timeline fixtures.
- Traffic: DNS label reconstruction across multiple packets, TXT extraction, HTTP object export, SMTP/FTP exfil, and stream reassembly.
- Reverse/Pwn: crash reproduction, offset discovery, ret2win sample, and generated pwntools workspace.
