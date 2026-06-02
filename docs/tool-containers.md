# ForgeFlag Tool Containers

ForgeFlag keeps heavyweight CTF tools out of the local Python venv. Use Docker targets when a tool has large system dependencies, needs a special runtime, or is better isolated from the host.

## Core Image

Build the default CTF image:

```bash
docker build -f docker/Dockerfile.ctf -t forgeflag-ctf .
```

The default target is `forgeflag-default`, based on `forgeflag-core`. It includes common CTF CLI tools, `pwntools`, `angr`, `ROPgadget`, `ropper`, `z3-solver`, `tshark`, and scoped web tooling. It deliberately does not include SageMath, Volatility, or Ghidra.

## Heavyweight Targets

Build only the profile you need:

```bash
docker build -f docker/Dockerfile.ctf --target forgeflag-volatility -t forgeflag-ctf:volatility .
docker build -f docker/Dockerfile.ctf --target forgeflag-sagemath -t forgeflag-ctf:sagemath .
docker build -f docker/Dockerfile.ctf --target forgeflag-ghidra-headless -t forgeflag-ctf:ghidra-headless .
```

Use these targets for:

- `forgeflag-volatility`: memory forensics tasks and dump triage.
- `forgeflag-sagemath`: lattice, finite-field, elliptic-curve, and other math-heavy crypto tasks.
- `forgeflag-ghidra-headless`: scripted reverse-engineering export flows.

## Invocation Boundary

Run tools only against a registered attachment copied into `.forgeflag/artifacts/<challenge_id>/`. Mount the project read-only when practical, and write outputs to an explicit artifact directory:

```bash
docker run --rm \
  -v "$PWD/.forgeflag/artifacts:/artifacts:ro" \
  -v "$PWD/.forgeflag/tool-output:/tool-output" \
  forgeflag-ctf:volatility \
  bash -lc 'vol -f /artifacts/<challenge_id>/memory.raw windows.info > /tool-output/volatility-info.txt'
```

Solvers should consume the resulting output files as structured evidence instead of trusting raw tool output as a final answer.

## Runtime Smoke Checks

Verify host wrapper readiness with:

```bash
scripts/forgeflag-tool-smoke
```

The default smoke only runs local/offline wrapper checks. It reports missing tools separately from failing tools, and it treats the curated project catalog as recommended integration candidates rather than tools that must all be installed on the host.

Optional bounded checks:

```bash
scripts/forgeflag-tool-smoke --include-active-network
scripts/forgeflag-tool-smoke --include-cracking
```

The active-network mode only targets a local temporary service or `127.0.0.1` through ForgeFlag scope controls. Cracking mode uses a tiny dictionary fixture and should stay opt-in because hashcat/John environments vary by host.

## Read-Only Adapter Pattern

External binary-analysis tools should follow the existing IDA MCP adapter pattern:

- Disabled by default through environment config.
- Read-only by default.
- Operates only on a registered attachment path.
- Calls a small allowlisted set of external tool operations.
- Returns structured function names, strings, call evidence, notes, and artifact paths.
- Never exposes arbitrary shell execution through MCP.

The same pattern should be used for future Ghidra/headless export adapters. A headless Ghidra adapter may import a binary and export strings/functions/decompiler snippets, but it must not modify challenge artifacts or execute target code.
