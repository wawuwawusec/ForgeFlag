# ForgeFlag Tool Containers

ForgeFlag keeps heavyweight CTF tools out of the local Python venv. Use Docker targets when a tool has large system dependencies, needs a special runtime, or is better isolated from the host.

For the full workstation dependency matrix, local deployment commands, MCP/LLM configuration, release checks, and GitHub publish workflow, see [docs/dependencies-and-deployment.md](dependencies-and-deployment.md). This file focuses on the Docker image and wrapper boundary.

## Core Image

Build the default CTF image:

```bash
scripts/forgeflag-control docker-build
```

The default target is `forgeflag-default`, based on `forgeflag-core`. It includes common CTF CLI tools, `pwntools`, `angr`, `ROPgadget`, `ropper`, `RsaCtfTool`, `z3-solver`, `objdump`/`readelf`, `radare2`, `foremost`, `yara`, `tshark`, and scoped web tooling. It deliberately does not include SageMath, Volatility, or Ghidra.

`docker-build` tags the image as `forgeflag-ctf:latest` by default and writes `.forgeflag/docker.env`:

```bash
FORGEFLAG_TOOL_DOCKER_IMAGE=forgeflag-ctf:latest
FORGEFLAG_TOOL_DOCKER_MOUNT=/path/to/ForgeFlag
```

`scripts/forgeflag-control start`, `restart`, `status`, and `docker-smoke` load this file automatically. Restart the Web UI after building so `/api/tools` and the Tools view reflect the Docker fallback state.

You can still build manually:

```bash
docker build -f docker/Dockerfile.ctf --target forgeflag-default -t forgeflag-ctf:latest .
```

Then set `FORGEFLAG_TOOL_DOCKER_IMAGE` and `FORGEFLAG_TOOL_DOCKER_MOUNT` yourself.

The Web UI Tools tab reads the same inventory as `/api/tools`. It groups host wrappers, Docker-backed wrappers, missing wrappers, heavyweight Docker profiles, and the recommended project catalog so operators can distinguish "runnable now" from "build this profile when needed" and "future integration candidate."

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

The Tools tab reports these profile images separately from the default wrapper inventory. A profile can be `not built` while the default wrapper inventory is still fully available.

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
scripts/forgeflag-control docker-smoke
scripts/forgeflag-tool-smoke --include-active-network
scripts/forgeflag-tool-smoke --include-cracking
```

The active-network mode only targets a local temporary service or `127.0.0.1` through ForgeFlag scope controls. Cracking mode uses a tiny dictionary fixture and should stay opt-in because hashcat/John environments vary by host. Hashcat needs an exposed OpenCL/CUDA device; on OrbStack without such a device, the smoke check records hashcat as skipped instead of failing the project. John runs CPU dictionary checks through the Docker fallback.

## Automatic Docker Fallback

ForgeFlag wrapper inventory now reports separate host and Docker availability:

```bash
scripts/forgeflag-control status
.venv/bin/forgeflag tools
curl -s http://127.0.0.1:8080/api/tools
curl -s 'http://127.0.0.1:8080/api/analysis-hints?category=traffic'
```

`ToolRunner` prefers a host executable when present. If a wrapper command is missing locally and `FORGEFLAG_TOOL_DOCKER_IMAGE` points to an existing image, it runs the command through:

```bash
docker run --rm -e TERM=xterm -e PATH=/opt/forgeflag-venv/bin:... -v "$FORGEFLAG_TOOL_DOCKER_MOUNT:/workspace" -w /workspace "$FORGEFLAG_TOOL_DOCKER_IMAGE" ...
```

Absolute paths under the mounted project are rewritten to `/workspace/...`, including `--wordlist=/path/to/file` style arguments. This keeps uploaded artifacts and generated wordlists visible to container-backed tools such as `ffuf` and `john`.
The explicit PATH entry is important for Python-installed tools such as `ROPgadget`, `ropper`, and `RsaCtfTool`, which live in the container venv rather than the system binary directories.

## Read-Only Adapter Pattern

External binary-analysis tools should follow the existing IDA MCP adapter pattern:

- Disabled by default through environment config.
- Read-only by default.
- Operates only on a registered attachment path.
- Calls a small allowlisted set of external tool operations.
- Returns structured function names, strings, call evidence, notes, and artifact paths.
- Never exposes arbitrary shell execution through MCP.

The same pattern should be used for future Ghidra/headless export adapters. A headless Ghidra adapter may import a binary and export strings/functions/decompiler snippets, but it must not modify challenge artifacts or execute target code.
