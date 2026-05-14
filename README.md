# ForgeFlag

ForgeFlag is a scoped multi-agent assistant for CTF and authorized security competitions.

The project starts with the architecture discussed for a full-coverage competition agent:

- `Manager`: classifies challenges, dispatches solvers, and coordinates runs.
- `Shared Notebook`: SQLite-backed blackboard for findings, evidence, tool logs, and solver state.
- `Harness`: prevents loops, records budget use, and forces strategy changes when work stalls.
- `Solvers`: pluggable workers for `recon`, `web`, `pwn`, `reverse`, `crypto`, `forensics`, `misc`, and infrastructure-style lab tasks.
- `Verifier`: accepts only evidence-backed flag candidates before submission.

This repository is intentionally scoped for CTFs, labs, and authorized competitions. It is not designed for unauthorized scanning or exploitation.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
forgeflag init --db .forgeflag/notebook.sqlite
forgeflag add-challenge web-01 --category web --target http://127.0.0.1:8080 --tag login
forgeflag run web-01 --db .forgeflag/notebook.sqlite --allow-host 127.0.0.1
forgeflag findings web-01 --db .forgeflag/notebook.sqlite
```

Without installing the package, run commands with `PYTHONPATH=src`, or use:

```bash
make test
make smoke
```

## Current Milestone

The first milestone is a working skeleton:

1. Add and list challenges.
2. Dispatch challenges through `Manager`.
3. Store structured findings in the shared notebook.
4. Enforce a scope policy before active probing.
5. Keep every solver behind a common interface.

Future milestones add real solver depth for Web, Crypto, Reverse, Pwn, Forensics, and mixed attack-defense lab tasks.
