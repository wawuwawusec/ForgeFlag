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
- Declarative subagent roster:
  - `forgeflag.agent_roster` defines `ForgeFlagManager` plus 9 professional subagent identities
  - roles cover triage, LLM route planning, Web, Crypto, Binary, Forensics, Traffic, Evidence Judge, and Browser Player QA
  - `forgeflag agents` lists the active roster; `forgeflag agents --write-default` writes `.forgeflag/agent-roster.json`
  - enabled agents contribute their declared solver names in roster order; disabled agents remove their managed solvers from the queue
  - `subagent_work_policy` defaults to conservative/local-first operation: `max_parallel=1`, `cooldown_seconds=120`, and one 429/rate-limit/quota signal trips the circuit breaker
  - run summaries include an `agent_roster` section with coordinator, selected category, solver queue, and participating identities
  - Web UI exposes `/api/agents` and the Agent tab shows configured identities, per-run identities, and the current subagent work policy
  - documented in `docs/agent-roster.md`
- SQLite shared notebook.
- Observer-distilled shared observations.
- Automatic CTF write-ups for accepted flags.
  - Write-ups now use conclusion, solving idea, reproduction steps, and key evidence as the primary structure, with Markdown output in addition to legacy flag/path replay data
  - Manager records `solve_trace_step` observations after each solver run
  - Write-ups expose `solve_trace`, per-flag `trace_path`, and write-up `shortest_discovery_path`
- Optional LLM planning layer:
  - `LLMConfig` reads `FORGEFLAG_LLM_PROVIDER`, `FORGEFLAG_LLM_MODEL`, `FORGEFLAG_LLM_API_KEY`, `OPENAI_API_KEY`, `ZAI_API_KEY`, `FORGEFLAG_LLM_BASE_URL`, and rate-limit controls `FORGEFLAG_LLM_MAX_RETRIES`, `FORGEFLAG_LLM_RETRY_INITIAL_SECONDS`, `FORGEFLAG_LLM_RETRY_MAX_SECONDS`, `FORGEFLAG_LLM_COOLDOWN_SECONDS`
  - `OpenAIResponsesProvider` uses the Responses API via standard-library HTTP
  - `ZhipuChatCompletionsProvider` uses `/chat/completions` at `https://open.bigmodel.cn/api/paas/v4`
  - LLM provider calls are process-serialized and retry `429`/temporary `5xx` responses with `Retry-After` or bounded exponential backoff before entering a cooldown circuit breaker
  - `LLMSolver` writes scoped strategy guidance; it does not submit unverified flag candidates
  - `forgeflag.llm_prompts.category_playbook` injects category-specific CTF method cards into LLM prompts
  - `forgeflag.knowledge` retrieves matching `docs/ctf-playbook.md` method cards and prior notebook write-up Markdown for LLM prompt grounding
  - structured Planner v2 JSON plans become `llm_solver_plan` observations and can insert suggested solvers into the remaining queue
  - Planner v2 accepts plain or markdown-fenced JSON and records `summary`, `hypotheses`, `suggested_solvers`, `next_actions`, `tool_hints`, `expected_evidence`, and `fallback_plan`
  - Post-run Critic runs after LLM-enabled runs that do not find a flag and records `llm_post_run_critic` observations with blockers, missing evidence, suggested solvers, tool hints, next actions, and rerun reason
  - Web UI Agent view renders Post-run Critic guidance as a first-class card instead of burying it in debug JSON
  - LLM provider/config failures are recorded as `LLMSolver` `config_error` findings and do not block deterministic solvers
- Optional IDA MCP binary-analysis layer:
  - `IDAMCPConfig` reads `FORGEFLAG_IDA_MCP_ENABLED`, `FORGEFLAG_IDA_MCP_COMMAND`, `FORGEFLAG_IDA_MCP_READ_ONLY`, and `FORGEFLAG_IDA_MCP_TIMEOUT_SECONDS`
  - `ReverseSolver` and `PwnSolver` call the adapter only for registered binary attachments
  - default config is disabled and keeps existing placeholder behavior
- Local pwn/reverse binary triage:
  - PwnSolver runs `file`, `strings`, `checksec`, `ROPgadget`, and `ropper` against registered attachments when IDA MCP is disabled
  - PwnSolver runs a bounded `tcp_interact` transcript against scoped service targets when no binary attachment is registered and active probing is enabled
  - PwnSolver recognizes source-level ret2win patterns from win-like functions plus unsafe input calls and emits a crash harness, cyclic offset, and pwntools payload template
  - PwnSolver infers ret2win workflow hints from binary tool output when win-like symbols and dangerous input symbols appear in `strings`/tool evidence
  - ReverseSolver runs `file`, `strings`, `ROPgadget`, and `ropper` against registered attachments when IDA MCP is disabled
  - missing gadget tools are recorded as structured `missing` tool results, not fatal errors
- Harness loop controls.
- Solver interface and starter solvers for Web, Pwn, Reverse, Crypto, Forensics, Traffic, Misc, and Infra.
- CyberChef-style transform pipeline:
  - `forgeflag.transforms.transform_candidates`
  - bounded transform chaining for hex, Base32, Base64, binary ASCII, ROT13, Caesar shifts, Morse, decimal/octal ASCII, URL decoding, and HTML entity decoding
  - shared by CryptoSolver, MiscSolver, and TrafficSolver
- Flag extraction preserves common platform prefixes such as `picoCTF{...}`, `HTB{...}`, `DUCTF{...}`, `f1ag{...}`, `flag{...}`, and `ctf{...}`
- Crypto/RSA triage:
  - `forgeflag.crypto_analysis.rsa_summary_from_text`
  - extracts common RSA parameters (`n`, `e`, `c`, `p`, `q`, `d`, `phi`) and PEM key markers
  - `CryptoSolver` records RSA hints and recommends RsaCtfTool/SageMath/Z3 follow-up
  - `CryptoSolver` recovers common classical crypto flags for single-byte XOR, supplied-key repeating XOR, and supplied-key Vigenere
- Hash/password triage:
  - `forgeflag.hash_analysis.hash_summary_from_text`
  - fingerprints common MD5/NTLM-length, SHA1, SHA256, bcrypt, and sha512crypt candidates
  - `CryptoSolver` and `MiscSolver` record likely hash modes before generic transform decoding
  - hashcat and John wrappers are exposed as typed, bounded dictionary operations but are not run automatically
- Scoped WebSolver workflow:
  - allowlist-gated HTTP probing
  - HTML title/link/form parsing
  - bounded response header and `Set-Cookie` capture, with flag extraction from headers/cookies
  - source attachment route extraction for common Flask/FastAPI/Express/Django/Laravel-style route declarations
  - source-derived bug-class hints for API option leakage, JWT/session, SSRF, and path traversal sinks
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
  - PNG independent/extra IDAT zlib payload extraction, including truncated extra IDAT chunks that hide printable flag text
  - `ForensicsSolver` uses it after local artifact triage
  - `MiscSolver` uses it directly for misc image puzzles before broader puzzle triage and submits image-derived flag candidates to the verifier
- Archive triage:
  - `forgeflag.archive_analysis.analyze_archive`
  - supports zip, tar, and gzip structure summaries
  - `ForensicsSolver` and `MiscSolver` record archive entries, encryption state, comments, and interesting names without extracting by default
- Scoped TrafficSolver workflow:
  - PCAP/PCAPNG follow-up with `tshark_pcap_summary`, `tshark_traffic_analysis`, `tshark_flag_scan`, `tshark_dns_summary`, `tshark_tcp_streams`, `tshark_http_requests`, `tshark_http_artifact_scan`, and `tshark_http_object_export`
  - HTTP artifact payload decoding via shared transform candidates before flag extraction
  - DNS query/TXT/rcode summary, encoded DNS query-label hints, and TCP stream shortlist evidence
  - HTTP object export summaries with file name, path, size, SHA256, text preview, and recovered flags
  - shortlisted TCP stream follow-up with stream id, hints, payload sample, and recovered flag evidence
  - cleartext SMTP/FTP/IRC-style protocol stream summaries with commands, sample, and recovered flag evidence
  - support for common CTF typo markers such as `f1ag{...}`
  - structured tool evidence in notebook
  - flag candidate extraction from packet capture output
- CTF tool layer:
  - allowlisted `ToolRunner`
  - wrappers for `file`, `strings`, `checksec`, `ROPgadget`, `ropper`, `RsaCtfTool`, `hashcat`, `john`, `binwalk`, `exiftool`, `tshark`, `tshark_traffic_analysis`, `tshark_dns_summary`, `tshark_tcp_streams`, `tshark_http_requests`, `tshark_http_artifact_scan`, `tshark_http_object_export`, `tshark_flag_scan`, `ffuf`, `nmap_tcp_basic`
  - `forgeflag.tool_compression` adds compact `compressed_summary` data to stored tool runs and promotes it into `tool_summary` observations
  - `tcp_interact` opens one scoped TCP service interaction, captures a bounded transcript, and is exposed through the optional MCP server
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
  - per-run LLM provider/model/API key controls, browser-local config saving including API key, masked saved-key dropdown selection, and `/api/llm/test`
  - entered LLM keys can be restored or selected from browser local storage for run/test requests and are never stored in SQLite
  - run, auto-loaded findings, observations, artifact summaries, Write-up, tools, and catalog views
  - Summary, Findings, Observations, Artifacts, Write-up, Tools, and Catalog render as readable cards with collapsible debug JSON
  - Tools tab shows host/Docker/missing wrapper counts, per-wrapper source, and Docker build/smoke commands
  - Challenge list and Tools tab use collapsible groups to avoid flat long lists
- Web-run CTF corpus smoke:
  - `scripts/forgeflag-corpus-smoke --url http://127.0.0.1:8080`
  - Generates local fixtures for web, crypto, misc, forensics, traffic, reverse, and pwn
  - Submits challenges through the Web API and exits non-zero if expected flags are not accepted
- Web-run hard/expert CTF corpus benchmark:
  - `scripts/forgeflag-hard-corpus --url http://127.0.0.1:8080 --keep --strict`
  - Generates safe local fixtures distilled from public CTF writeup patterns
  - Covers hidden Web APIs, source route/sink triage, crypto primitive misuse, DNS exfil, TCP stream follow-up, HTTP object export, SMTP stream summaries, mail/PowerShell forensics, packed reverse, format-string pwn, ret2win pwn, pickle sandbox, and Web-to-Java chains
  - Current strict result: 14/14 full score through the Web API
- Web-run expanded CTF corpus benchmark:
  - `scripts/forgeflag-expanded-corpus --url http://127.0.0.1:8080 --keep --strict`
  - Generates safe local fixtures distilled from public CTF writeups, forums, challenge indexes, and benchmark papers
  - Covers 74 cases total: Web has 11 cases, Crypto has 13 cases, and Forensics, Traffic, Reverse, Pwn, and Misc each have at least 10 cases
  - Current strict result: 74/74 full score through the Web API
- Browser-player Web UI benchmark:
  - `scripts/forgeflag-web-player-benchmark --url http://127.0.0.1:8080 --run`
  - Uses Playwright to operate the visible Web UI like a human player: save challenge, upload attachments, run, inspect Summary, inspect Write-up, and delete cleanup challenges
  - Supports deterministic, `--llm`, and `--both` comparison variants; `--both --list` is safe because it only lists variants without calling a model
  - Current first-pass result: 7/7 cases passed through the browser for Web, Crypto, Misc, Forensics, Traffic, Reverse, and Pwn
  - Setup is documented in `docs/web-player-benchmark.md`
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
  - `ToolRunner` automatically reads `.forgeflag/docker.env` when explicit Docker tool environment variables are unset, so direct CLI/Web runs show the same Docker fallback inventory as `scripts/forgeflag-control`
- Tests passed: 223 tests OK
- Browser-player benchmark passed: 7/7 Web UI flows OK

Useful commands:

```bash
cd /Users/5haw0/Documents/ForgeFlag
.venv/bin/forgeflag tools
scripts/forgeflag-tool-smoke
scripts/forgeflag-tool-smoke --include-active-network
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite tools
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite agents
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite agents --write-default
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
scripts/forgeflag-web-player-benchmark --list
scripts/forgeflag-web-player-benchmark --url http://127.0.0.1:8080 --run
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite web --host 127.0.0.1 --port 8080
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite artifacts <challenge_id>
.venv/bin/forgeflag observations <challenge_id>
.venv/bin/forgeflag report <challenge_id>
```

If a Codex/subagent run hits `429 Too Many Requests`, rate-limit, or quota pressure, stop spawning subagents for that task. Continue with local verification first:

```bash
.venv/bin/python -m unittest discover -s tests
scripts/forgeflag-tool-smoke
scripts/forgeflag-web-player-benchmark --url http://127.0.0.1:8080 --run
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
   - HTTP object export when a capture contains downloaded files
   - Scapy helpers for deeper DNS exfil reconstruction across split labels/packets
   - protocol-specific stream summaries for FTP/SMTP/IRC-style CTF captures
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
