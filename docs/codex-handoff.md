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
  - Reports now include a write-up style structure and Markdown in addition to the legacy flag/path replay data
- Optional LLM planning layer:
  - `LLMConfig` reads `FORGEFLAG_LLM_PROVIDER`, `FORGEFLAG_LLM_MODEL`, `FORGEFLAG_LLM_API_KEY`, `OPENAI_API_KEY`, `ZAI_API_KEY`, and `FORGEFLAG_LLM_BASE_URL`
  - `OpenAIResponsesProvider` uses the Responses API via standard-library HTTP
  - `ZhipuChatCompletionsProvider` uses `/chat/completions` at `https://open.bigmodel.cn/api/paas/v4`
  - `LLMSolver` writes scoped strategy guidance; it does not submit unverified flag candidates
  - structured Planner v2 JSON plans become `llm_solver_plan` observations and can insert suggested solvers into the remaining queue
  - Planner v2 accepts plain or markdown-fenced JSON and records `summary`, `hypotheses`, `suggested_solvers`, `next_actions`, `tool_hints`, `expected_evidence`, and `fallback_plan`
  - LLM provider/config failures are recorded as `LLMSolver` `config_error` findings and do not block deterministic solvers
- Optional IDA MCP binary-analysis layer:
  - `IDAMCPConfig` reads `FORGEFLAG_IDA_MCP_ENABLED`, `FORGEFLAG_IDA_MCP_COMMAND`, `FORGEFLAG_IDA_MCP_READ_ONLY`, and `FORGEFLAG_IDA_MCP_TIMEOUT_SECONDS`
  - `ReverseSolver` and `PwnSolver` call the adapter only for registered binary attachments
  - default config is disabled and keeps existing placeholder behavior
- Local pwn/reverse binary triage:
  - PwnSolver runs `file`, `strings`, `checksec`, `ROPgadget`, and `ropper` against registered attachments when IDA MCP is disabled
  - ReverseSolver runs `file`, `strings`, `ROPgadget`, and `ropper` against registered attachments when IDA MCP is disabled
  - missing gadget tools are recorded as structured `missing` tool results, not fatal errors
- Harness loop controls.
- Solver interface and starter solvers for Web, Pwn, Reverse, Crypto, Forensics, Traffic, Misc, and Infra.
- CyberChef-style transform pipeline:
  - `forgeflag.transforms.transform_candidates`
  - bounded transform chaining for hex, Base32, Base64, binary ASCII, ROT13, URL decoding, and HTML entity decoding
  - shared by CryptoSolver, MiscSolver, and TrafficSolver
- Flag extraction preserves common platform prefixes such as `picoCTF{...}`, `HTB{...}`, `DUCTF{...}`, `f1ag{...}`, `flag{...}`, and `ctf{...}`
- Crypto/RSA triage:
  - `forgeflag.crypto_analysis.rsa_summary_from_text`
  - extracts common RSA parameters (`n`, `e`, `c`, `p`, `q`, `d`, `phi`) and PEM key markers
  - `CryptoSolver` records RSA hints and recommends RsaCtfTool/SageMath/Z3 follow-up
- Hash/password triage:
  - `forgeflag.hash_analysis.hash_summary_from_text`
  - fingerprints common MD5/NTLM-length, SHA1, SHA256, bcrypt, and sha512crypt candidates
  - `CryptoSolver` and `MiscSolver` record likely hash modes before generic transform decoding
  - hashcat and John wrappers are exposed as typed, bounded dictionary operations but are not run automatically
- Scoped WebSolver workflow:
  - allowlist-gated HTTP probing
  - HTML title/link/form parsing
  - low-budget `ffuf` route discovery only when active probing and allowed-host scope are enabled
  - flag candidate extraction
  - verifier integration
- Artifact workspace:
  - CLI attachment registration copies files into `.forgeflag/artifacts/<challenge_id>/`
  - challenge attachment paths persist in SQLite
  - `forgeflag artifacts <challenge_id>` and the Web UI Artifacts tab report registered attachment existence, size, and SHA256
- Scoped ForensicsSolver workflow:
  - local attachment triage with `file`, `strings`, `binwalk`, and `exiftool`
- Reusable image puzzle analysis:
  - PNG IHDR height/CRC mismatch detection with repaired PNG artifact output
  - PNG text chunk, IEND trailing-data, JPEG comment, and JPEG APP marker summaries for stego-style hints
  - `ForensicsSolver` uses it after local artifact triage
  - `MiscSolver` uses it directly for misc image puzzles before broader puzzle triage and submits image-derived flag candidates to the verifier
- Archive triage:
  - `forgeflag.archive_analysis.analyze_archive`
  - supports zip, tar, and gzip structure summaries
  - `ForensicsSolver` and `MiscSolver` record archive entries, encryption state, comments, and interesting names without extracting by default
- Scoped TrafficSolver workflow:
  - PCAP/PCAPNG follow-up with `tshark_pcap_summary`, `tshark_traffic_analysis`, `tshark_flag_scan`, `tshark_dns_summary`, `tshark_tcp_streams`, `tshark_http_requests`, and `tshark_http_artifact_scan`
  - HTTP artifact payload decoding via shared transform candidates before flag extraction
  - DNS query/TXT/rcode summary, encoded DNS query-label hints, and TCP stream shortlist evidence
  - support for common CTF typo markers such as `f1ag{...}`
  - structured tool evidence in notebook
  - flag candidate extraction from packet capture output
- CTF tool layer:
  - allowlisted `ToolRunner`
  - wrappers for `file`, `strings`, `checksec`, `ROPgadget`, `ropper`, `RsaCtfTool`, `hashcat`, `john`, `binwalk`, `exiftool`, `tshark`, `tshark_traffic_analysis`, `tshark_dns_summary`, `tshark_tcp_streams`, `tshark_http_requests`, `tshark_http_artifact_scan`, `tshark_flag_scan`, `ffuf`, `nmap_tcp_basic`
  - `forgeflag tools` CLI inventory
  - `ToolRunner` avoids counting unavailable pyenv shims as runnable tools
  - `ToolRunner` can use Docker fallback for missing host wrappers through `FORGEFLAG_TOOL_DOCKER_IMAGE` and `FORGEFLAG_TOOL_DOCKER_MOUNT`
  - `scripts/forgeflag-tool-smoke` performs fixture-backed runtime smoke checks for wrapper execution
- Curated CTF project catalog:
  - `forgeflag catalog` and `forgeflag catalog --category <category>`
  - `/api/project-catalog`
  - Web UI Catalog tab
  - catalog entries are integration candidates, not implicit bulk installs
  - Web UI Tools tab combines local wrapper availability with the recommended CTF tool catalog
- Optional MCP server:
  - `forgeflag-mcp`
  - streamable HTTP endpoint can run at `http://127.0.0.1:8000/mcp`
- Local Web UI:
  - challenge creation and attachment upload
  - category workspace filters for Web, Pwn, Reverse, Crypto, Forensics, Traffic, Misc, and Infra queues
  - per-run LLM provider/model/API key controls, browser-local non-secret config saving, optional local key remembering, and `/api/llm/test`
  - entered LLM keys are used for run/test requests and are never stored in SQLite
  - run, auto-loaded findings, observations, artifact summaries, replay report, tools, and catalog views
  - Summary, Findings, Observations, Artifacts, Report, Tools, and Catalog render as readable cards with collapsible raw JSON for debugging
  - Tools tab shows host/Docker/missing wrapper counts, per-wrapper source, and Docker build/smoke commands
  - Challenge list and Tools tab use collapsible groups to avoid flat long lists
- Web-run CTF corpus smoke:
  - `scripts/forgeflag-corpus-smoke --url http://127.0.0.1:8080`
  - Generates local fixtures for web, crypto, misc, forensics, traffic, reverse, and pwn
  - Submits challenges through the Web API and exits non-zero if expected flags are not accepted
- CTF playbook notes:
  - `docs/ctf-playbook.md`
  - Summarizes public CTF writeup-derived first moves and current ForgeFlag coverage by category
  - Includes community source notes and method cards for Web, Crypto, Forensics/Stego, Traffic, Reverse, Pwn, and Misc
- One-command lifecycle script:
  - `scripts/forgeflag-control start/status/smoke/stop/docker-build/docker-smoke`
  - Web UI start uses `.venv/bin/python -m forgeflag.cli` and stores the managed Python process PID in `.forgeflag/web.pid`
  - status cleans invalid/stale PID files and reports managed Web/MCP state
  - status reports `tool_docker=ready|missing`
- CTF Dockerfile:
  - `docker/Dockerfile.ctf`
  - default `forgeflag-core` / `forgeflag-default` image keeps heavyweight tools out of the base venv
  - default image includes common Kali CLI tools plus Python CTF packages such as `ROPgadget`, `ropper`, `RsaCtfTool`, `pwntools`, `angr`, and `z3-solver`
  - explicit Docker targets: `forgeflag-volatility`, `forgeflag-sagemath`, `forgeflag-ghidra-headless`
- Tool container guidance:
  - `docs/tool-containers.md`
  - future heavy external adapters should follow the IDA MCP pattern: disabled by default, read-only by default, registered attachments only, typed operations only
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
- Docker fallback enabled through OrbStack:
  - image: `forgeflag-ctf:latest`
  - env file: `.forgeflag/docker.env`
  - host wrappers: `file`, `strings`, `binwalk`, `exiftool`, `tshark`, `nmap_tcp_basic`
  - Docker wrappers: `checksec`, `ROPgadget`, `ropper`, `RsaCtfTool`, `hashcat`, `john`, `ffuf`
  - hashcat is installed, but current OrbStack runtime does not expose an OpenCL/CUDA device, so cracking smoke skips hashcat device execution
- Tests passed: 123 tests OK

Useful commands:

```bash
cd /Users/5haw0/Documents/ForgeFlag
.venv/bin/forgeflag tools
scripts/forgeflag-tool-smoke
scripts/forgeflag-tool-smoke --include-active-network
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite tools
.venv/bin/forgeflag catalog
.venv/bin/forgeflag catalog --category traffic
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m pip install -e .
make smoke
scripts/forgeflag-control start
scripts/forgeflag-control status
scripts/forgeflag-control smoke
scripts/forgeflag-control docker-build
scripts/forgeflag-control docker-smoke
scripts/forgeflag-control stop
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite web --host 127.0.0.1 --port 8080
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite artifacts <challenge_id>
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
export FORGEFLAG_LLM_MODEL=glm-5.1
export ZAI_API_KEY="..."
.venv/bin/forgeflag run <challenge_id> --llm-provider zhipu --llm-model glm-5.1
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

- `f7e22fc Add CTF tool smoke verification`
- `f785f05 Rename project metadata to ForgeFlag`
- `14bbd6c Add CTF toolchain MCP wrappers`
- `6794090 Add scoped web response analysis`
- `75f8b53 Initial ForgeFlag agent scaffold`

## Next Recommended Work

Recommended next milestone:

1. Add richer traffic analyzers:
   - TCP stream extraction by stream id
   - HTTP object export when a capture contains downloaded files
   - Scapy helpers for DNS exfil reconstruction across split labels/packets
2. Promote selected project catalog items into wrappers:
   - `sqlmap` only behind active-probe scope controls
   - `Scapy` helper for custom traffic parsing
3. Add archive/carving follow-up from `binwalk_scan`.
4. Add image/stego metadata hints.
5. Add a CLI command to list registered artifacts per challenge.

## Safety Boundary

Keep the project scoped to CTFs, labs, and explicitly authorized targets.

Rules to preserve:

- No arbitrary shell exposed through MCP.
- Network tools require explicit allowlist scope.
- Solvers write structured evidence to the notebook.
- Verifier only accepts evidence-backed flag candidates.
