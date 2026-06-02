# ForgeFlag Medium Corpus

`scripts/forgeflag-medium-corpus` runs a reproducible medium-difficulty CTF-pattern corpus through the ForgeFlag Web API.

The cases are generated locally so they are stable in tests, but the patterns are derived from public CTF archives and write-up guidance:

- CryptoHack CTF Archive: public crypto challenge archive with `release_files` structure and MIT-licensed submissions.
- warlocksmurf/bluelobster-grimoire: public CTF challenge repository with medium-labeled forensics/crypto examples.
- Trail of Bits CTF forensics notes: archive, image, PCAP, and packet-carving triage patterns.
- Google CTF archive: public multi-category CTF challenge archive used as reverse/pwn pattern inspiration.

## Usage

```bash
scripts/forgeflag-control start
scripts/forgeflag-medium-corpus --url http://127.0.0.1:8080 --keep
```

Use `--list` to inspect the cases without running them.

```bash
scripts/forgeflag-medium-corpus --list
```

The corpus currently covers:

- Web: same-origin visible-link follow-up.
- Crypto: RSA with known factors.
- Misc: archive preview with decoy entries.
- Forensics: archive bundle triage with small text evidence.
- Traffic: DNS query-label exfiltration.
- Reverse: static binary triage.
- Pwn: scoped TCP service transcript.

The script prints a JSON result table with `expected`, `accepted_flags`, `ok`, and `findings` for each case.
