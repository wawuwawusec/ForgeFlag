# Codex Handoff

This file is the handoff context for continuing ForgeFlag in a fresh Codex session.

## Project

- Local path: `/Users/5haw0/Documents/ForgeFlag`
- GitHub repo: `https://github.com/wawuwawusec/ForgeFlag`
- Visibility: private
- Default branch: `main`
- Python package metadata name: `ForgeFlag`
- Python import package and CLI command: `forgeflag`

## Current State

ForgeFlag is a scoped multi-agent assistant for CTF and authorized security competitions.

Implemented so far:

- Manager dispatch loop.
- SQLite shared notebook.
- Observer-distilled shared observations.
- Automatic replay reports for accepted flags.
- Optional LLM planning layer:
  - `LLMConfig` reads `FORGEFLAG_LLM_PROVIDER`, `FORGEFLAG_LLM_MODEL`, `FORGEFLAG_LLM_API_KEY`, `OPENAI_API_KEY`, `ZAI_API_KEY`, and `FORGEFLAG_LLM_BASE_URL`
  - `OpenAIResponsesProvider` uses the Responses API via standard-library HTTP
  - `ZhipuChatCompletionsProvider` uses `/chat/completions` at `https://open.bigmodel.cn/api/paas/v4`
  - `LLMSolver` writes scoped strategy guidance; it does not submit unverified flag candidates
  - structured JSON plans become `llm_solver_plan` observations and can insert suggested solvers into the remaining queue
- Optional IDA MCP binary-analysis layer:
  - `IDAMCPConfig` reads `FORGEFLAG_IDA_MCP_ENABLED`, `FORGEFLAG_IDA_MCP_COMMAND`, `FORGEFLAG_IDA_MCP_READ_ONLY`, and `FORGEFLAG_IDA_MCP_TIMEOUT_SECONDS`
  - `ReverseSolver` and `PwnSolver` call the adapter only for registered binary attachments
  - default config is disabled and keeps existing placeholder behavior
- Harness loop controls.
- Solver interface and starter solvers for Web, Pwn, Reverse, Crypto, Forensics, Traffic, Misc, and Infra.
- Scoped WebSolver workflow:
  - allowlist-gated HTTP probing
  - HTML title/link/form parsing
  - flag candidate extraction
  - verifier integration
- Artifact workspace:
  - CLI attachment registration copies files into `.forgeflag/artifacts/<challenge_id>/`
  - challenge attachment paths persist in SQLite
- Scoped ForensicsSolver workflow:
  - local attachment triage with `file`, `strings`, `binwalk`, and `exiftool`
- Scoped TrafficSolver workflow:
  - PCAP/PCAPNG follow-up with `tshark_pcap_summary`, `tshark_traffic_analysis`, and `tshark_flag_scan`
  - structured tool evidence in notebook
  - flag candidate extraction from packet capture output
- CTF tool layer:
  - allowlisted `ToolRunner`
  - wrappers for `file`, `strings`, `checksec`, `binwalk`, `exiftool`, `tshark`, `tshark_traffic_analysis`, `tshark_flag_scan`, `nmap_tcp_basic`
  - `forgeflag tools` CLI inventory
- Optional MCP server:
  - `forgeflag-mcp`
  - streamable HTTP endpoint can run at `http://127.0.0.1:8000/mcp`
- Local Web UI:
  - challenge creation and attachment upload
  - category workspace filters for Web, Pwn, Reverse, Crypto, Forensics, Traffic, Misc, and Infra queues
  - per-run LLM provider/model/API key controls; entered keys are used for the run request and not stored in SQLite
  - run, findings, observations, replay report, and tools views
- CTF Dockerfile:
  - `docker/Dockerfile.ctf`
- Project skill template:
  - `skills/forgeflag-ctf-tools/SKILL.md`

## Local Runtime

The local folder was renamed from:

`/Users/5haw0/Documents/New project`

to:

`/Users/5haw0/Documents/ForgeFlag`

The old Codex session may show a warning because its original working directory no longer exists. Continue in a fresh Codex session opened at `/Users/5haw0/Documents/ForgeFlag`.

Current local setup after migration:

- `.venv` rebuilt in `/Users/5haw0/Documents/ForgeFlag`
- Homebrew tools installed and detected:
  - `nmap`
  - `binwalk`
  - `exiftool`
  - `tshark`
- Tests passed: 46 tests OK

Useful commands:

```bash
cd /Users/5haw0/Documents/ForgeFlag
.venv/bin/forgeflag tools
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite tools
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m pip install -e .
make smoke
scripts/forgeflag-control start
scripts/forgeflag-control status
scripts/forgeflag-control smoke
scripts/forgeflag-control stop
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite web --host 127.0.0.1 --port 8080
.venv/bin/forgeflag observations <challenge_id>
.venv/bin/forgeflag report <challenge_id>
```

Optional LLM run:

```bash
export FORGEFLAG_LLM_PROVIDER=openai
export FORGEFLAG_LLM_MODEL=gpt-4.1
export OPENAI_API_KEY="sk-..."
.venv/bin/forgeflag run <challenge_id> --llm-provider openai --llm-model gpt-4.1

export FORGEFLAG_LLM_PROVIDER=zhipu
export FORGEFLAG_LLM_MODEL=glm-4.7
export ZAI_API_KEY="..."
.venv/bin/forgeflag run <challenge_id> --llm-provider zhipu --llm-model glm-4.7
```

Optional IDA MCP run:

```bash
pip install -e '.[mcp]'
export FORGEFLAG_IDA_MCP_ENABLED=true
export FORGEFLAG_IDA_MCP_COMMAND='ida-mcp --read-only'
.venv/bin/forgeflag add-challenge rev-01 --category reverse --attachment ./rev.bin
.venv/bin/forgeflag run rev-01
```

MCP was started with:

```bash
screen -dmS forgeflag-mcp /bin/zsh -lc 'cd /Users/5haw0/Documents/ForgeFlag && export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" && export FORGEFLAG_ALLOWED_HOSTS="127.0.0.1,localhost" && .venv/bin/python -c "from forgeflag.mcp_server import mcp; mcp.run(transport=\"streamable-http\")" >> .forgeflag/mcp.log 2>&1'
```

Check/stop MCP:

```bash
screen -ls
tail -f .forgeflag/mcp.log
screen -S forgeflag-mcp -X quit
```

## Git History

Recent commits:

- `f785f05 Rename project metadata to ForgeFlag`
- `14bbd6c Add CTF toolchain MCP wrappers`
- `6794090 Add scoped web response analysis`
- `75f8b53 Initial ForgeFlag agent scaffold`

## Next Recommended Work

Recommended next milestone:

1. Add richer traffic analyzers:
   - DNS query summary
   - HTTP object extraction and host/URI summary
   - TCP stream extraction by stream id
2. Add archive/carving follow-up from `binwalk_scan`.
3. Add image/stego metadata hints.
4. Add a CLI command to list registered artifacts per challenge.
5. Push changes when ready.

## Safety Boundary

Keep the project scoped to CTFs, labs, and explicitly authorized targets.

Rules to preserve:

- No arbitrary shell exposed through MCP.
- Network tools require explicit allowlist scope.
- Solvers write structured evidence to the notebook.
- Verifier only accepts evidence-backed flag candidates.
