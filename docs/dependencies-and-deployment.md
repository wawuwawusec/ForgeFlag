# ForgeFlag Dependencies and Deployment

ForgeFlag is a local CTF and authorized lab research workbench. This guide collects the runtime dependencies, optional toolchain profiles, deployment commands, and release checks needed to reproduce the project from a fresh checkout.

## Deployment Targets

ForgeFlag has three practical deployment shapes:

- **Local analyst workstation**: Python virtual environment, SQLite notebook, Web UI on `127.0.0.1:8080`, and optional host tools.
- **Local workstation with Docker or OrbStack**: same Python app plus `forgeflag-ctf:latest` for missing CTF wrappers and repeatable tool execution.
- **Agent or MCP-enabled workstation**: local app plus optional MCP server, LLM provider configuration, and read-only binary-analysis adapters.

The default posture is local-only. Do not bind the Web UI or MCP server to a public interface unless you have added your own access controls and understand the exposure.

## Required System Dependencies

Install these first:

- Python 3.11 or newer.
- Git.
- A POSIX shell environment. The project scripts are tested from `zsh` / `bash`.
- `make`, used by `make test` and `make smoke`.
- `screen`, optional but recommended. `scripts/forgeflag-control` uses it for managed background Web UI and MCP sessions when available.
- SQLite support, normally included with Python and available as `sqlite3` on most systems.

Recommended for full CTF workflows:

- Docker Desktop or OrbStack. OrbStack works well on macOS and is the expected local Docker runtime in this workspace.
- Node.js and npm only when running the browser-player benchmark.
- A browser such as Chrome or Chromium for visual Web UI verification.

## Python Package Dependencies

The Python package metadata is the source of truth:

```toml
requires-python = ">=3.11"
dependencies = [
  "capstone>=5",
  "cryptography>=41",
  "Pillow>=10",
  "python-registry>=1.3",
  "z3-solver>=4.12",
]

[project.optional-dependencies]
mcp = ["mcp[cli]>=1.0,<2"]
```

Install a development checkout:

```bash
git clone https://github.com/wawuwawusec/ForgeFlag.git
cd ForgeFlag
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e .
```

Install optional MCP support when you need the MCP server:

```bash
pip install -e '.[mcp]'
```

If the package is not installed, most developer commands still work with:

```bash
PYTHONPATH=src python3 -m forgeflag.cli --help
```

## Runtime State and Generated Files

ForgeFlag stores local runtime state under `.forgeflag/`:

- `.forgeflag/notebook.sqlite`: default SQLite notebook.
- `.forgeflag/artifacts/<challenge_id>/`: managed challenge attachments.
- `.forgeflag/web.pid` and `.forgeflag/web.log`: managed Web UI process state.
- `.forgeflag/mcp.pid` and `.forgeflag/mcp.log`: managed MCP process state.
- `.forgeflag/docker.env`: Docker fallback image and mount configuration.
- `.forgeflag/capability-benchmark-latest.json`: latest readiness scorecard for the Web UI Benchmark tab.
- `.forgeflag/capability-benchmark-history.jsonl`: benchmark history.

These files are local runtime artifacts and should not be committed. Challenge handouts that should be shared belong in a fixture or manifest path reviewed for repository safety, not in `.forgeflag/artifacts/`.

## Environment Variables

The project can load `.env` plus `.forgeflag/docker.env`. Start from:

```bash
cp .env.example .env
```

Important variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FORGEFLAG_DB` | `.forgeflag/notebook.sqlite` | SQLite notebook path. |
| `FORGEFLAG_WEB_HOST` | `127.0.0.1` | Web UI bind host. Keep local by default. |
| `FORGEFLAG_WEB_PORT` | `8080` | Web UI port. |
| `FORGEFLAG_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Active-probe and MCP network allowlist. |
| `FORGEFLAG_TOOL_DOCKER_IMAGE` | empty or `forgeflag-ctf:latest` | Docker fallback image. |
| `FORGEFLAG_TOOL_DOCKER_MOUNT` | empty or repo path | Host project path mounted into the tool container. |
| `FORGEFLAG_LLM_PROVIDER` | `disabled` | `openai`, `zhipu`, or `disabled`. |
| `FORGEFLAG_LLM_MODEL` | empty | Provider model name, for example `gpt-4.1` or `glm-5.1`. |
| `FORGEFLAG_LLM_API_KEY` | empty | Generic LLM key. Provider-specific keys also work. |
| `OPENAI_API_KEY` | empty | OpenAI key for the Responses API adapter. |
| `ZAI_API_KEY` | empty | Zhipu GLM key for the OpenAI-compatible chat-completions adapter. |
| `FORGEFLAG_LLM_BASE_URL` | provider default | Override provider API base URL. |
| `FORGEFLAG_LLM_TIMEOUT_SECONDS` | `30` | LLM request timeout. |
| `FORGEFLAG_IDA_MCP_ENABLED` | `false` | Enables optional read-only IDA MCP adapter. |
| `FORGEFLAG_IDA_MCP_COMMAND` | `ida-mcp --read-only` | Command used to start IDA MCP. |
| `PYTHON_BIN` | `python3` | Python used by `scripts/forgeflag-control` to create `.venv`. |

LLM API keys entered in the Web UI are stored only in the browser local storage for that browser profile. ForgeFlag does not write those tokens to SQLite.

## One-Command Local Deployment

The control script is the recommended way to operate the local workbench:

```bash
scripts/forgeflag-control start
scripts/forgeflag-control status
scripts/forgeflag-control doctor
scripts/forgeflag-control smoke
scripts/forgeflag-control gate
scripts/forgeflag-control stop
```

`start` performs the local setup sequence:

1. Creates `.forgeflag/` when needed.
2. Loads `.env` and `.forgeflag/docker.env`.
3. Creates `.venv` if missing.
4. Installs `pip install -e .` when the source or package metadata changed.
5. Initializes the SQLite notebook.
6. Starts the Web UI at `http://127.0.0.1:8080/`.

`doctor` prints JSON readiness diagnostics without requiring the Web UI. It reuses the same health engine as `/api/system-health` and includes notebook state, required Python import availability, wrapper availability, heavyweight Docker profile status, saved capability benchmark status, LLM runtime configuration state, next actions, and a redacted diagnostic bundle:

```bash
scripts/forgeflag-control doctor
forgeflag --db .forgeflag/notebook.sqlite doctor
```

Use a different local port when 8080 is busy:

```bash
FORGEFLAG_WEB_PORT=8090 scripts/forgeflag-control start
```

Run the Web UI directly when you do not want process management:

```bash
forgeflag --db .forgeflag/notebook.sqlite web --host 127.0.0.1 --port 8080
```

## Docker and OrbStack Toolchain

ForgeFlag keeps heavyweight CTF tools out of the Python virtual environment. Build the default CTF image when host tools are missing or you want repeatable wrapper execution:

```bash
scripts/forgeflag-control docker-build
scripts/forgeflag-control docker-smoke
scripts/forgeflag-control restart
```

`docker-build` builds `docker/Dockerfile.ctf` target `forgeflag-default`, tags it as `forgeflag-ctf:latest`, and writes:

```bash
FORGEFLAG_TOOL_DOCKER_IMAGE=forgeflag-ctf:latest
FORGEFLAG_TOOL_DOCKER_MOUNT=/absolute/path/to/ForgeFlag
```

to `.forgeflag/docker.env`.

The default image includes common tools such as:

- Binary and pwn: `binutils`, `checksec`, `gdb`, `gdbserver`, `socat`, `pwntools`, `angr`, `ROPgadget`, `ropper`.
- Reverse and file triage: `file`, `objdump`, `readelf`, `radare2`, `strings` through binutils.
- Crypto and password triage: `RsaCtfTool`, `z3-solver`, `hashcat`, `john`, `pycryptodome`.
- Web and recon for scoped local or authorized targets: `ffuf`, `nmap`, `sqlmap`.
- Forensics and traffic: `binwalk`, `exiftool`, `foremost`, `tshark`, `tcpdump`, `yara`, `steghide`, `stegseek`.
- General utilities: `curl`, `jq`, `p7zip-full`, `unzip`, `wget`.

`ToolRunner` prefers host executables when present. If a wrapper is missing locally and `FORGEFLAG_TOOL_DOCKER_IMAGE` points to an existing image, ForgeFlag runs the typed wrapper through Docker with the project mounted at `/workspace`.

On OrbStack:

- Start OrbStack before `docker-build`.
- Hashcat may not see GPU or OpenCL devices. Treat a hashcat skip as an environment limitation, not a ForgeFlag failure.
- John CPU dictionary checks still work through Docker fallback.
- For amd64 pwn services on Apple Silicon, use `--platform linux/amd64`.

Example pwn service workspace:

```bash
docker run --rm -it --platform linux/amd64 \
  -p 31337:31337 \
  -v "$PWD:/workspace" \
  -w /workspace \
  forgeflag-ctf:latest \
  bash
```

## Heavyweight Tool Profiles

The default image deliberately excludes SageMath, Volatility, and Ghidra. Build these only when a challenge needs them:

```bash
docker build -f docker/Dockerfile.ctf --target forgeflag-volatility -t forgeflag-ctf:volatility .
docker build -f docker/Dockerfile.ctf --target forgeflag-sagemath -t forgeflag-ctf:sagemath .
docker build -f docker/Dockerfile.ctf --target forgeflag-ghidra-headless -t forgeflag-ctf:ghidra-headless .
```

Profile usage:

- `forgeflag-ctf:volatility`: memory forensics and dump triage.
- `forgeflag-ctf:sagemath`: lattice, finite-field, elliptic-curve, and algebra-heavy crypto.
- `forgeflag-ctf:ghidra-headless`: scripted reverse-engineering export flows.

The Web UI Tools tab and `/api/tools` report these profile image states separately from default wrapper availability. An unbuilt heavyweight profile does not mean the default toolchain is broken.

## Optional MCP Deployment

Install the optional dependency and start MCP only when needed:

```bash
pip install -e '.[mcp]'
FORGEFLAG_ALLOWED_HOSTS=127.0.0.1,localhost scripts/forgeflag-control start --mcp
```

Or run the MCP entry point directly:

```bash
export FORGEFLAG_ALLOWED_HOSTS=127.0.0.1,localhost
forgeflag-mcp
```

Current MCP wrappers are typed CTF operations, not arbitrary shell access. Network-capable wrappers must obey `FORGEFLAG_ALLOWED_HOSTS` and active-probe intent.

## Optional LLM Deployment

LLM planning is optional. Deterministic solvers and verifier evidence remain authoritative.

OpenAI example:

```bash
export FORGEFLAG_LLM_PROVIDER=openai
export FORGEFLAG_LLM_MODEL=gpt-4.1
export OPENAI_API_KEY="sk-..."
```

Zhipu GLM example:

```bash
export FORGEFLAG_LLM_PROVIDER=zhipu
export FORGEFLAG_LLM_MODEL=glm-5.1
export ZAI_API_KEY="..."
```

Before running an LLM-assisted release gate, verify the command-line provider configuration:

```bash
scripts/forgeflag-control gate --llm
```

If provider, model, or key is missing, `gate --llm` exits early instead of silently reporting deterministic-only results as LLM-assisted.

## Browser-Player Benchmark Dependencies

The browser-player benchmark uses Playwright outside the Python package. The generated Node workspace lives under `.forgeflag/web-player-benchmark/`.

Install and run:

```bash
scripts/forgeflag-control start
scripts/forgeflag-web-player-benchmark --url http://127.0.0.1:8080 --run
```

If the benchmark workspace is missing dependencies, install them from the generated directory:

```bash
cd .forgeflag/web-player-benchmark
npm install
npx playwright install chromium
```

Keep `.forgeflag/web-player-benchmark/` out of Git.

## Release and Readiness Checks

Use these checks before pushing changes:

```bash
make test
make smoke
scripts/forgeflag-control smoke
scripts/forgeflag-control status
scripts/forgeflag-control gate
```

Toolchain checks:

```bash
scripts/forgeflag-control doctor
scripts/forgeflag-tool-smoke
scripts/forgeflag-control docker-smoke
.venv/bin/forgeflag tools
curl -s http://127.0.0.1:8080/api/tools
curl -s http://127.0.0.1:8080/api/system-health
```

Capability checks:

```bash
scripts/forgeflag-capability-benchmark --url http://127.0.0.1:8080
scripts/forgeflag-capability-benchmark \
  --url http://127.0.0.1:8080 \
  --output .forgeflag/capability-benchmark-latest.json \
  --history .forgeflag/capability-benchmark-history.jsonl
```

Held-out or real-corpus manifests should be run with explicit local artifact paths and local or authorized services:

```bash
scripts/forgeflag-capability-benchmark \
  --url http://127.0.0.1:8080 \
  --manifest-only \
  --manifest .forgeflag/heldout-platform-manifest.json
```

For documentation-only changes, at minimum run a targeted unit suite that covers the control script and Web/API surfaces:

```bash
PYTHONPATH=src python3 -m unittest \
  tests.test_control_script \
  tests.test_tool_smoke_script \
  tests.test_webapp \
  tests.test_pwn_replay
```

## GitHub Publish Workflow

Recommended developer flow:

```bash
git status --short --branch
git switch -c codex/dependency-deployment-docs
git add README.md CHANGELOG.md docs/dependencies-and-deployment.md docs/tool-containers.md docs/codex-handoff.md skills/forgeflag-ctf-tools/SKILL.md AGENTS.md
git diff --cached --stat
git commit -m "document dependencies and deployment workflow"
git push -u origin codex/dependency-deployment-docs
gh pr create --draft --base main --head codex/dependency-deployment-docs --fill
```

Do not commit local runtime folders such as `.forgeflag/`, `.playwright-cli/`, or `output/`.

## Troubleshooting

### Port 8080 Is Busy

Use a different port:

```bash
FORGEFLAG_WEB_PORT=8090 scripts/forgeflag-control start
```

Or stop the managed process:

```bash
scripts/forgeflag-control stop
```

### Stale PID Files

`scripts/forgeflag-control status` cleans stale PID files when it can. If the Web UI is visibly stopped but a PID file remains, run:

```bash
scripts/forgeflag-control stop
scripts/forgeflag-control start
```

### Docker Is Missing

Start OrbStack or Docker Desktop, then rerun:

```bash
docker version
scripts/forgeflag-control docker-build
```

### Docker Image Built but Tools Still Show Missing

Restart the Web UI so it reloads `.forgeflag/docker.env`:

```bash
scripts/forgeflag-control restart
```

Then check:

```bash
scripts/forgeflag-control status
curl -s http://127.0.0.1:8080/api/tools
```

### Hashcat Skips on OrbStack

This usually means the container has no OpenCL/CUDA device. Use John CPU checks for bounded dictionary verification, or run hashcat on a host/runtime with GPU passthrough.

### MCP Starts but Cannot Reach a Target

Confirm the target is explicitly allowlisted and local or authorized:

```bash
export FORGEFLAG_ALLOWED_HOSTS=127.0.0.1,localhost,challenge.local
```

Network-capable wrappers still need active-probe intent through ForgeFlag controls.

### LLM Button Has No Effect

Check provider, model, key, timeout, and `/api/llm/test` from the Web UI. From the terminal, run:

```bash
scripts/forgeflag-control gate --llm
```

If this exits before the benchmark, fix provider configuration first. If the provider works but no flag is found, inspect the Agent tab for `llm_solver_plan`, `llm_post_run_critic`, missing evidence, and suggested reruns.
