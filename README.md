# ForgeFlag

ForgeFlag is a scoped multi-agent assistant for CTF and authorized security competitions.

The project starts with the architecture discussed for a full-coverage competition agent:

- `Manager`: classifies challenges, dispatches solvers, and coordinates runs.
- `Shared Notebook`: SQLite-backed blackboard for findings, evidence, tool logs, and solver state.
- `Harness`: prevents loops, records budget use, and forces strategy changes when work stalls.
- `Solvers`: pluggable workers for `recon`, `web`, `pwn`, `reverse`, `crypto`, `forensics`, `traffic`, `misc`, and infrastructure-style lab tasks.
- `Verifier`: accepts only evidence-backed flag candidates before submission.
- `MCP tools`: optional allowlisted wrappers around common CTF tools.

This repository is intentionally scoped for CTFs, labs, and authorized competitions. It is not designed for unauthorized scanning or exploitation.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
forgeflag --db .forgeflag/notebook.sqlite init
forgeflag --db .forgeflag/notebook.sqlite add-challenge web-01 --category web --target http://127.0.0.1:8080 --tag login
forgeflag --db .forgeflag/notebook.sqlite run web-01 --allow-host 127.0.0.1 --active-probe
forgeflag --db .forgeflag/notebook.sqlite findings web-01
forgeflag --db .forgeflag/notebook.sqlite observations web-01
forgeflag --db .forgeflag/notebook.sqlite report web-01
```

Run a local smoke test that does not need any network service:

```bash
make smoke
```

Use the local control script for one-command setup and lifecycle checks:

```bash
scripts/forgeflag-control start
scripts/forgeflag-control status
scripts/forgeflag-control smoke
scripts/forgeflag-control stop
```

`start` launches the Web UI at [http://127.0.0.1:8080/](http://127.0.0.1:8080/) by default and records a managed PID under `.forgeflag/web.pid`. The Web UI includes a category workspace so Web, Pwn, Reverse, Crypto, Forensics, Traffic, Misc, and Infra challenges can be filtered separately before running solvers. Start the optional MCP server only when you need it:

```bash
FORGEFLAG_ALLOWED_HOSTS=127.0.0.1,localhost scripts/forgeflag-control start --mcp
scripts/forgeflag-control stop
```

You can also start only the Web UI from the console entry point:

```bash
forgeflag --db .forgeflag/notebook.sqlite web --host 127.0.0.1 --port 8080
```

Or use the installed console entry point directly:

```bash
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite tools
```

For local artifact challenges, register attachments when creating the challenge. ForgeFlag copies each attachment into `.forgeflag/artifacts/<challenge_id>/` and stores that managed path in the notebook:

```bash
forgeflag --db .forgeflag/notebook.sqlite add-challenge forensic-01 --category forensics --attachment ./challenge.zip
forgeflag --db .forgeflag/notebook.sqlite artifacts forensic-01
forgeflag --db .forgeflag/notebook.sqlite run forensic-01
```

LLM strategy planning is optional and disabled by default. Configure keys with environment variables, then opt in per run:

```bash
cp .env.example .env
export FORGEFLAG_LLM_PROVIDER=openai
export FORGEFLAG_LLM_MODEL=gpt-4.1
export OPENAI_API_KEY="sk-..."
forgeflag --db .forgeflag/notebook.sqlite run forensic-01 --llm-provider openai --llm-model gpt-4.1
```

For 智谱 GLM, choose `zhipu` and use the OpenAI-compatible base URL:

```bash
export FORGEFLAG_LLM_PROVIDER=zhipu
export FORGEFLAG_LLM_MODEL=glm-5.1
export ZAI_API_KEY="..."
forgeflag --db .forgeflag/notebook.sqlite run forensic-01 --llm-provider zhipu --llm-model glm-5.1
```

`LLMSolver` writes planning guidance to the notebook. If the model returns JSON with `summary`, `suggested_solvers`, `next_actions`, and `tool_hints`, ForgeFlag stores it as an `llm_solver_plan` observation and can insert suggested solvers into the remaining run queue. Specialist solvers still perform scoped tool execution and the verifier only accepts evidence-backed flags.

The Web UI also has a per-run "大模型分析" switch. Select `智谱 GLM`, enter a GLM model such as `glm-5.1`, and paste the API key. The UI can save provider/model/base URL/timeout to browser local storage and includes a connection test button. API keys are not stored unless you explicitly tick "记住 API Key", and ForgeFlag never writes the token to SQLite.

IDA MCP reverse-engineering support is also optional. When enabled, `ReverseSolver` and `PwnSolver` call a read-only IDA MCP server for registered binary attachments and store function, string, and disassembly/decompiler pivot evidence in the notebook:

```bash
pip install -e '.[mcp]'
export FORGEFLAG_IDA_MCP_ENABLED=true
export FORGEFLAG_IDA_MCP_COMMAND='ida-mcp --read-only'
forgeflag --db .forgeflag/notebook.sqlite add-challenge rev-01 --category reverse --attachment ./rev.bin
forgeflag --db .forgeflag/notebook.sqlite run rev-01
```

Without installing the package, run commands with `PYTHONPATH=src`, or use:

```bash
make test
make smoke
PYTHONPATH=src python3 -m forgeflag.cli tools
```

## Tooling

Build and enable the CTF tool container with Docker or OrbStack:

```bash
scripts/forgeflag-control docker-build
scripts/forgeflag-control docker-smoke
scripts/forgeflag-control restart
```

`docker-build` builds `forgeflag-ctf:latest`, writes `.forgeflag/docker.env`, and enables automatic Docker fallback for missing host tools. `ToolRunner` still prefers host commands when present, but can run container-backed wrappers such as `checksec`, `ROPgadget`, `ropper`, `RsaCtfTool`, `hashcat`, `john`, and `ffuf` with project paths mounted under `/workspace`. Use `scripts/forgeflag-control status`, `.venv/bin/forgeflag tools`, or `/api/tools` to inspect whether each wrapper is using `host`, `docker`, or `missing`.

Hashcat is installed in the image, but GPU/OpenCL access depends on the Docker runtime. On OrbStack without a passed-through cracking device, the smoke test reports hashcat as skipped while John CPU dictionary checks can still run.

Run the optional MCP server:

```bash
pip install -e '.[mcp]'
export FORGEFLAG_ALLOWED_HOSTS=127.0.0.1,challenge.local
forgeflag-mcp
```

See [docs/mcp.md](docs/mcp.md) for the current MCP tool list.

## Current Milestone

The current milestone is a working skeleton plus the first scoped WebSolver, ForensicsSolver, TrafficSolver, and optional IDA MCP binary-analysis workflows:

1. Add and list challenges.
2. Dispatch challenges through `Manager`.
3. Store structured findings in the shared notebook.
4. Enforce a scope policy before active probing.
5. Keep every solver behind a common interface.
6. Distill high-confidence solver output into shared observations that later solvers receive in context.
7. When a flag is verified, generate a replay report with the shortest evidence path.
8. Optionally ask an LLM provider for scoped solve strategy guidance and solver-order hints.
9. For web challenges, probe allowlisted HTTP targets and extract visible HTML structure plus flag candidates.
10. For forensics challenges, register local attachments and triage them with `file`, `strings`, `binwalk`, and `exiftool`.
11. For traffic challenges and PCAP attachments, run PCAP-focused `tshark` summaries and extract evidence-backed flag candidates.
12. For reverse and pwn binary attachments, optionally call a read-only IDA MCP adapter for function, string, and pivot evidence.

Future milestones add real solver depth for Web, Crypto, Reverse, Pwn, Forensics, and mixed attack-defense lab tasks.
