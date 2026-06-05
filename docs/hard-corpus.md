# ForgeFlag Hard Corpus

`scripts/forgeflag-hard-corpus` runs higher-difficulty public CTF patterns through the ForgeFlag Web API.

Unlike the medium corpus, the hard corpus is a benchmark for capability gaps. Some cases are expected to produce a flag today, while others score whether ForgeFlag recognized the right technique, evidence, and next-step workflow.

## Sources

The fixtures are generated locally and safely. They are distilled from public write-ups and challenge indexes, not vendored challenge archives:

- DownUnderCTF 2024 public challenges: hard crypto, pwn, reverse, web, hardware, forensics, and misc difficulty tables.
- HackTheBox Cyber Apocalypse 2024 official writeups: multi-category star-rated patterns across crypto, forensics, pwn, reversing, web, and misc.
- Real World CTF 2023 Dark Portal writeup: multi-stage web-to-Java-reversing workflow.
- CrewCTF 2023 writeups: realistic forensics, memory, malware/log, and web RCE workflows.
- Google CTF 2023 writeups: complex web/crypto and multi-component challenge chains.

## Usage

```bash
scripts/forgeflag-control start
scripts/forgeflag-hard-corpus --url http://127.0.0.1:8080 --keep
```

List cases without running them:

```bash
scripts/forgeflag-hard-corpus --list
```

Enable configured LLM planning during the run:

```bash
scripts/forgeflag-hard-corpus --url http://127.0.0.1:8080 --llm --keep
```

Fail the script when any case misses its full score:

```bash
scripts/forgeflag-hard-corpus --url http://127.0.0.1:8080 --strict
```

## Scoring

Each row reports:

- `flag_ok`: expected flag was accepted, or no flag was expected for analysis-only cases.
- `matched_evidence`: required technique/evidence strings found in ForgeFlag findings, observations, summary, or report.
- `missing_evidence`: evidence ForgeFlag should learn to produce.
- `score` / `max_score`: one point for flag success plus one point per required evidence item.
- `improvement_hint`: the next solver or LLM capability suggested by the case.

Required evidence is intentionally broader than a flag: cases can score classification, bug class or crypto primitive, reproduction-oriented evidence, solver/tool routing, and Post-run Critic guidance when a run stalls.

## Current Cases

| ID | Category | Pattern | Expected |
| --- | --- | --- | --- |
| `hard-web-api-options` | web | client script hints at a hidden API route | flag and route extraction |
| `hard-web-source-routes` | web | source-only route and sink triage | route extraction plus API option, JWT/session, SSRF, and path traversal hints |
| `hard-crypto-aes-ctr-reuse` | crypto | AES-CTR nonce reuse | classify stream keystream reuse |
| `hard-crypto-poly1305-reuse` | crypto | Poly1305 one-time key reuse | classify MAC algebra workflow |
| `hard-crypto-rsa-low-exponent` | crypto | RSA low exponent without padding | recover exact integer-root plaintext and emit replay script |
| `hard-crypto-rsa-common-modulus` | crypto | RSA common modulus pair | recover plaintext with extended-gcd ciphertext combination |
| `hard-crypto-rsa-shared-prime` | crypto | RSA shared-prime moduli | recover shared factor with gcd and decrypt |
| `hard-crypto-rsa-broadcast` | crypto | RSA broadcast e=3 | combine ciphertexts with CRT and recover exact root |
| `hard-traffic-dns-split` | traffic | split DNS label exfiltration | reconstruct encoded flag |
| `hard-traffic-http-stream-follow` | traffic | HTTP payload in an interesting TCP stream | follow stream id and recover payload flag |
| `hard-traffic-http-object-export` | traffic | HTTP response object export | exported object hash, preview, and flag |
| `hard-traffic-smtp-stream-summary` | traffic | SMTP control stream with DATA content | protocol commands and payload flag |
| `hard-forensics-mail-powershell` | forensics | suspicious mail with encoded PowerShell | mail and encoded command triage |
| `hard-reverse-packed-away` | reverse | packer marker before decompilation | UPX/packed binary recognition |
| `hard-pwn-format-string` | pwn | source-level `printf(user_input)` bug | format string and pwntools workflow |
| `hard-pwn-ret2win-source` | pwn | win-like target plus unsafe stack input | ret2win, cyclic offset, and pwntools replay workflow |
| `hard-misc-pickle-sandbox` | misc | `pickle.loads` blacklist sandbox | pickle sink and sandbox workflow |
| `expert-web-java-reverse-chain` | web | LFI to WAR then Java static analysis | multi-stage WebSolver -> ReverseSolver plan |

## 2026-06-02 Web Benchmark Result

Verified with:

```bash
scripts/forgeflag-control restart
scripts/forgeflag-hard-corpus --url http://127.0.0.1:8080 --keep --strict
```

Result: 18/18 cases reached full score through the Web API.

| Area | Improvement Verified |
| --- | --- |
| Web | Follows same-origin routes mentioned in client-side script strings, including hidden JSON APIs. |
| Web | Parses source attachments for framework routes and source-derived API option leakage, JWT/session, SSRF, and path traversal hints. |
| Web | Stores plain-text response samples and emits chain hints such as LFI, WAR, and Java. |
| Traffic | Reconstructs split encoded DNS labels before decoding exfiltrated flags. |
| Traffic | Follows shortlisted TCP streams and stores stream id, hints, payload sample, and recovered flags. |
| Traffic | Exports HTTP objects and stores file name, path, size, SHA256, preview, and recovered flags. |
| Traffic | Summarizes cleartext SMTP/FTP/IRC-style streams with protocol, commands, sample, and flags. |
| Crypto | Recognizes AES-CTR nonce/keystream reuse and emits a crib/keystream solve helper; Poly1305 key reuse emits a Sage algebra helper; RSA low-exponent exact roots, common-modulus pairs, shared-prime moduli, and broadcast e=3 cases recover flags and emit direct replay scripts. |
| Forensics | Re-runs transforms on decoded mail/PowerShell content and recovers nested base64 flags. |
| Pwn | Recognizes source-level `printf(user_input)` format string sinks and emits a pwntools probe/write harness. |
| Pwn | Recognizes ret2win source patterns and records crash harness, cyclic offset, and pwntools payload template guidance. |
| Misc | Recognizes `pickle.loads` blacklist sandbox patterns and records a reproduction-oriented next step. |

## LLM Opportunities

The hard corpus is where the GLM integration should help most:

- Summarize long source/traffic/tool output into a small hypothesis set.
- Classify hard primitives such as AES mode misuse, MAC algebra, pickle sandbox, and format strings.
- Propose exact solver/tool routing, for example WebSolver followed by ReverseSolver for WAR analysis.
- Generate safe solve-script outlines without executing exploit payloads automatically.
- Critique failed runs by comparing missing evidence against the case playbook. ForgeFlag now records this as `llm_post_run_critic` observations with blockers, missing evidence, suggested solvers, tool hints, next actions, and a rerun reason.
