# ForgeFlag Expanded Corpus

`scripts/forgeflag-expanded-corpus` runs a broader public-CTF-pattern benchmark through the ForgeFlag Web API.

The corpus is designed for continuous solver improvement. It does not vendor large original challenge attachments; instead it distills stable techniques from public writeups, forums, challenge indexes, notes, and benchmark papers into safe local fixtures.

## Sources

- picoCTF Solutions and picoCTF writeup indexes: broad beginner-to-medium Web, Crypto, Forensics, Reverse, Binary Exploitation, and General Skills patterns.
- HackTheBox Cyber Apocalypse 2024 official/public writeups: modern Web, Crypto, Pwn, Reverse, Forensics, and Misc challenge patterns.
- DownUnderCTF 2024 public challenges and statistics: category/difficulty spread across Web, Crypto, Rev, Pwn, Forensics, Misc, and hardware-style tasks.
- YBN CTF 2024 HackMD writeups: forum-style category table with Web, Crypto, Misc, and Forensics concepts.
- HackTricks crypto, stego, and forensics methodology pages: repeatable first-pass triage workflows.
- ir0nstone binary exploitation notes: ret2win, padding discovery, and pwntools replay patterns.
- CryptoHack XOR starter/properties and picoCTF Vigenere writeups: classical XOR and Vigenere recovery patterns.
- NYU CTF Bench paper: benchmark-oriented examples across crypto, forensics, pwn, rev, web, and misc.

## Usage

```bash
scripts/forgeflag-control start
scripts/forgeflag-expanded-corpus --url http://127.0.0.1:8080 --keep --strict
```

List cases without running them:

```bash
scripts/forgeflag-expanded-corpus --list
```

Enable configured LLM planning during the run:

```bash
scripts/forgeflag-expanded-corpus --url http://127.0.0.1:8080 --llm --keep
```

## Current Coverage

The current expanded corpus has 73 cases:

| Category | Cases | Pattern Families |
| --- | ---: | --- |
| Web | 10 | visible flags, linked routes, script API routes, LFI chain hints, forms, hidden JS routes, source routes, JWT/session, SSRF, path traversal |
| Crypto | 13 | hex, Base32, Base64, binary ASCII, ROT13, Caesar, Morse, decimal ASCII, octal ASCII, single-byte XOR, repeating-key XOR with supplied key, Vigenere with supplied key, RSA known factors |
| Forensics | 10 | strings, zip preview, PNG text, PNG trailing data, JPEG comment, encoded log content, binary artifact strings |
| Traffic | 10 | HTTP payloads, DNS exfil labels, SMTP streams |
| Reverse | 10 | compiled static strings, packed/UPX marker, encoded static strings |
| Pwn | 10 | strings/checksec baseline, ret2win source triage, format-string source triage, scoped TCP service banner |
| Misc | 10 | binary ASCII, Caesar, Morse, decimal/octal ASCII, nested Base64/HTML, zip, PNG, pickle sandbox, hash triage |

## 2026-06-03 Result

Verified with:

```bash
scripts/forgeflag-control restart
scripts/forgeflag-expanded-corpus --url http://127.0.0.1:8080 --keep --strict
```

Result: 73/73 cases reached full score through the Web API.

The run also verified the Web UI state after upload: the local page at `http://127.0.0.1:8080/` showed the expanded benchmark challenges in the challenge list after the Web API run.
