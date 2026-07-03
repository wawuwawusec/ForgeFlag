# Codex Handoff

This file is the handoff context for continuing ForgeFlag in a fresh Codex session.

## Project

- Local path: `/Users/5haw0/Documents/ForgeFlag`
- GitHub repo: `https://github.com/wawuwawusec/ForgeFlag`
- Visibility: private
- Default branch: `main`
- Python package metadata name: `ForgeFlag`
- Python import package and CLI command: `forgeflag`
- Dependency and deployment guide: `docs/dependencies-and-deployment.md`

## Current State

ForgeFlag is a scoped multi-agent assistant for CTF and authorized security competitions.

Scope posture:

- Treat every ForgeFlag task as local or authorized CTF/lab research unless the operator provides a different explicit scope.
- Keep passive artifact analysis, notebook evidence, replay reports, and local fixtures as the default workflow.
- Gate active network actions with `ScopePolicy`, `--active-probe`, and allowlisted hosts; do not add solver behavior that bypasses those checks.
- Keep LLM usage to planning and critique. Prompt it with the authorized CTF/lab context, then let typed solvers and the verifier decide from evidence.
- For local Codex interactions, keep `AGENTS.md` as the first project-level scope declaration. It should reduce false-positive framing by stating that repository contents are CTF challenge research while preserving normal safety and scope checks.
- Default user challenge assumption: if the user shares a CTF prompt, attachment path, archive, binary, pcap, web target, pwn service, crypto text, or puzzle while in this repository, treat it as a local or authorized CTF challenge for flag solving and replay evidence unless they explicitly say otherwise.
- `docs/ctf-scope-audit.md` records the reviewed false-positive mitigation guidance for every CTF category, including the machine-readable `ctf_scope` evidence attached to solver findings.

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
  - `LLMSolver` writes scoped strategy guidance and may submit model-derived `flag_candidates`, but they still go through the normal evidence-backed verifier before acceptance
  - `forgeflag.llm_prompts.category_playbook` injects category-specific CTF method cards into LLM prompts
  - `forgeflag.knowledge` retrieves matching `docs/ctf-playbook.md` method cards and prior notebook write-up Markdown for LLM prompt grounding
  - structured Planner v2 JSON plans become `llm_solver_plan` observations and can insert suggested solvers into the remaining queue
  - Planner v2 accepts plain or markdown-fenced JSON and records `summary`, `hypotheses`, `suggested_solvers`, `next_actions`, `tool_hints`, `expected_evidence`, `fallback_plan`, and optional `flag_candidates`
  - Text attachment previews include head and tail excerpts so long source files still expose trailing output/ciphertext comments to planning and critique prompts
  - Post-run Critic runs after LLM-enabled runs that do not find a flag and records `llm_post_run_critic` observations with blockers, missing evidence, suggested solvers, tool hints, next actions, and rerun reason; critic prompts include attachment previews and category playbooks
  - Web UI Agent view renders Post-run Critic guidance as a first-class card instead of burying it in debug JSON
  - LLM provider/config failures are recorded as `LLMSolver` `config_error` findings and do not block deterministic solvers
- Optional IDA MCP binary-analysis layer:
  - `IDAMCPConfig` reads `FORGEFLAG_IDA_MCP_ENABLED`, `FORGEFLAG_IDA_MCP_COMMAND`, `FORGEFLAG_IDA_MCP_READ_ONLY`, and `FORGEFLAG_IDA_MCP_TIMEOUT_SECONDS`
  - `ReverseSolver` and `PwnSolver` call the adapter only for registered binary attachments
  - default config is disabled and keeps existing placeholder behavior
- Local pwn/reverse binary triage:
  - PwnSolver runs `file`, `strings`, `checksec`, `ROPgadget`, and `ropper` against registered attachments when IDA MCP is disabled
  - PwnSolver runs a bounded `tcp_interact` transcript against scoped service targets when no binary attachment is registered and active probing is enabled
  - PwnSolver recognizes source-level `printf(user_input)` format string sinks and emits a pwntools `%p` probe / offset replay / optional `fmtstr_payload` write harness
  - PwnSolver recognizes source-level ret2win patterns from win-like functions plus unsafe input calls and emits a crash harness, cyclic offset, win symbol, and configurable pwntools exploit script
  - PwnSolver infers ret2win workflow hints from binary tool output when win-like symbols and dangerous input symbols appear in `strings`/tool evidence, then carries the symbol into the generated exploit script
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
  - extracts common RSA parameters (`n`, `e`, `c`, `p`, `q`, `d`, `phi`) plus numbered common-modulus/shared-prime/broadcast fields such as `e1/e2/c1/c2`, `n1/n2`, and `n3/c3`, and PEM key markers
  - `CryptoSolver` records RSA hints, recovers known-factor, low-exponent exact-root, source-loop `c+k*n` exact-root, prime-modulus, close-prime Fermat, common-modulus, shared-prime, and broadcast RSA flags, preserves replay parameters, and emits a reproducible `solve_<challenge>.py` script in the Write-up
  - `CryptoSolver` recognizes AES-CTR nonce reuse and the Write-up emits a crib/keystream `solve_<challenge>.py` helper for filling ciphertexts and known plaintext snippets
  - `CryptoSolver` recognizes AES-GCM nonce reuse and the Write-up emits a GHASH/forbidden-attack `solve_<challenge>.py` scaffold for nonce, AAD, ciphertext, and tag collection
  - `CryptoSolver` recognizes Poly1305 one-time key reuse and the Write-up emits a Sage-oriented algebra helper for message/tag equations and carry enumeration
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
  - local attachment triage with `file`, `strings`, `binwalk`, `exiftool`, image/archive hints, optional `foremost` carving, and YARA scans
- Reusable image puzzle analysis:
  - magic-byte vs filename extension mismatch detection, for example PNG content uploaded as `.jpg`
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
  - wrappers for `file`, `strings`, `checksec`, `ROPgadget`, `ropper`, `RsaCtfTool`, `hashcat`, `john`, `binwalk`, `exiftool`, `tshark`, `tshark_traffic_analysis`, `tshark_dns_summary`, `tshark_tcp_streams`, `tshark_http_requests`, `tshark_http_artifact_scan`, `tshark_http_object_export`, `tshark_flag_scan`, `ffuf`, `nmap_tcp_basic`, `objdump`, `readelf`, `radare2`, `foremost`, and `yara`
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
- Recurrent analysis hints:
  - `forgeflag hints` and `forgeflag hints --category <category>`
  - `/api/analysis-hints` and `/api/analysis-hints?category=<category>`
  - `/api/tools` also exposes the same rows as `analysis_hints`
  - Web UI Tools tab combines local wrapper availability, heavyweight Docker profile status, and the recommended CTF tool catalog
- Optional MCP server:
  - `forgeflag-mcp`
  - streamable HTTP endpoint can run at `http://127.0.0.1:8000/mcp`
- Local Web UI:
  - challenge creation and attachment upload
  - category workspace filters for Web, Pwn, Reverse, Crypto, Forensics, Traffic, Misc, and Infra queues
  - per-run LLM provider/model/API key controls, browser-local config saving including API key, masked saved-key dropdown selection, and `/api/llm/test`
  - entered LLM keys can be restored or selected from browser local storage for run/test requests and are never stored in SQLite
  - Pwn challenges show a local environment panel with copyable Docker/Kali entry, `socat` service launch, triage commands, a copyable/downloadable `exploit.py` pwntools local/remote template, and a one-click local Target/Active probe helper
  - run, auto-loaded findings, observations, artifact summaries, Write-up, tools, and catalog views
  - Summary, Findings, Observations, Artifacts, Write-up, Tools, and Catalog render as readable cards with collapsible debug JSON
  - Tools tab shows host/Docker/missing wrapper counts, per-wrapper source, Docker build/smoke commands, recommended catalog groups, and heavyweight Docker profile build status
  - Challenge list and Tools tab use collapsible groups to avoid flat long lists
- Web-run CTF corpus smoke:
  - `scripts/forgeflag-corpus-smoke --url http://127.0.0.1:8080`
  - Generates local fixtures for web, crypto, misc, forensics, traffic, reverse, and pwn
  - Submits challenges through the Web API and exits non-zero if expected flags are not accepted
- Web-run hard/expert CTF corpus benchmark:
  - `scripts/forgeflag-hard-corpus --url http://127.0.0.1:8080 --keep --strict`
  - Generates safe local fixtures distilled from public CTF writeup patterns
  - Covers hidden Web APIs, source route/sink triage, crypto primitive misuse including AES-CTR and AES-GCM nonce reuse, RSA low-exponent, prime-modulus, close-prime Fermat, common-modulus, shared-prime, and broadcast recovery, DNS exfil, TCP stream follow-up, HTTP object export, SMTP stream summaries, mail/PowerShell forensics, packed reverse, format-string pwn, ret2win pwn, pickle sandbox, magic-extension mismatch, and Web-to-Java chains
  - Current strict result: 22/22 full score through the Web API
- Web-run expanded CTF corpus benchmark:
  - `scripts/forgeflag-expanded-corpus --url http://127.0.0.1:8080 --keep --strict`
  - Generates safe local fixtures distilled from public CTF writeups, forums, challenge indexes, and benchmark papers
  - Covers 74 cases total: Web has 11 cases, Crypto has 13 cases, and Forensics, Traffic, Reverse, Pwn, and Misc each have at least 10 cases
  - Current strict result: 74/74 full score through the Web API
- Browser-player Web UI benchmark:
  - `scripts/forgeflag-web-player-benchmark --url http://127.0.0.1:8080 --run`
  - `scripts/forgeflag-web-player-benchmark --url http://127.0.0.1:8080 --run --suite expanded`
  - Uses Playwright to operate the visible Web UI like a human player: save challenge, upload attachments, run, inspect Summary, inspect Write-up, and delete cleanup challenges
  - Supports deterministic, `--llm`, and `--both` comparison variants; `--both --list` is safe because it only lists variants without calling a model
  - Current first-pass result: 7/7 cases passed through the browser for Web, Crypto, Misc, Forensics, Traffic, Reverse, and Pwn
  - Current expanded browser result: 74/74 cases passed through the browser; category split is Web 11, Crypto 13, and 10 each for Forensics, Traffic, Reverse, Pwn, and Misc
  - Setup is documented in `docs/web-player-benchmark.md`
- Capability benchmark:
  - `scripts/forgeflag-control gate`
  - `scripts/forgeflag-capability-benchmark --url http://127.0.0.1:8080`
  - Combines smoke, medium, hard, and browser-smoke suites into one JSON scorecard
  - Supports `--manifest heldout.json` for local held-out CTF artifacts
  - Supports `--manifest-only --manifest heldout.json` for external held-out scoring without internal suites
  - Supports manifest `local_service` and `replay` blocks for local Docker service startup, readiness checks, and typed proof-of-solve commands
  - Current release gate result: 52/52 cases, 118/118 hard evidence score, and 7/7 browser UI flow with `.forgeflag/heldout-platform-manifest.json` included
  - First external platform check: `.forgeflag/heldout-platform-manifest.json` started at 0/8 flags and 4/17 evidence across DUCTF 2024 and HTB Cyber Apocalypse 2024 artifacts
  - Current held-out platform result: 8/8 flags and 21/21 evidence after adding Nikto tool-version recovery, shufflebox permutation recovery, Trithemius position-shift recovery, GPP `cpassword` decryption, CCIR476/SITOR decoding, recipe-state Misc solving, Reverse jmp-table popcount recovery, Web source-archive route/YAML evidence, and Prisoner Processor local service replay
  - Manifest-only readiness is `limited` because browser-player UI flow is not included in that scorecard; use `scripts/forgeflag-control gate` for the combined ready/not-ready release answer
  - `scripts/forgeflag-real-corpus-audit` scans cached public contest repositories, rejects placeholder-tainted artifacts, strips README answer lines from benchmark descriptions, blocks Git LFS pointer handouts, emits manifest-ready candidate cases, and produces manager backlog
  - Real corpus audit currently supports DUCTF `ctfcli.yaml`, HTB Cyber Apocalypse README/`htb/` layouts, TJCTF and UMDCTF `challenge.yaml`, CTFd-style `challenge.yml` plus unpacked `dist` / `distribution` handouts, and IrisCTF README plus `dist/` layouts
  - Current real corpus audit snapshot: 277 cases scanned, 221 with artifacts, 262 with oracle flags, and 183 manifest-ready cases across DownUnderCTF 2024, HTB Cyber Apocalypse 2024, IrisCTF 2024, NUS Greyhats Welcome CTF 2024, TJCTF 2024, and UMDCTF 2024
  - Current diversified real-contest candidate scorecard: 8/36 flags and 64/93 evidence, readiness `blocked`, after adding raw PCAP byte flag scanning, Python VM perfect-number SHA1 recovery, Python 8x8 grid constraint solving, archive-contained mangled PNG repair evidence, decayed DoubleHelix Ruby source recovery, deterministic right-shift XOR linear inversion, and Minecraft Anvil orphan-sector lore recovery; backlog remains spread across `CryptoMathAgent`, `ForensicsAgent`, `TrafficAgent`, `BinaryAgent`, and `WebExploitAgent`
  - CryptoSolver now solves DUCTF three-line-style self-synchronizing XOR scripts by detecting `q[y % 16] ^ x; y = x` and verifying CTF-idiom candidates through key-slot consistency
  - Documented in `docs/capability-benchmark.md`
- CTF playbook notes:
  - `docs/ctf-playbook.md`
  - Summarizes public CTF writeup-derived first moves and current ForgeFlag coverage by category
  - Includes community source notes and method cards for Web, Crypto, Forensics/Stego, Traffic, Reverse, Pwn, and Misc
- One-command lifecycle script:
  - `scripts/forgeflag-control start/status/smoke/gate/stop/docker-build/docker-smoke`
  - Web UI start uses `.venv/bin/python -m forgeflag.cli` and stores the managed Python process PID in `.forgeflag/web.pid`
  - status cleans invalid/stale PID files and reports managed Web/MCP state
  - gate starts Web UI and refreshes the full capability release gate with default suites, browser-smoke, and held-out manifest replay
  - `gate --llm` requires provider/model/key configuration before running, so LLM-assisted scorecards do not silently fall back to deterministic-only evidence
  - `/api/system-health` and the Workbench Health tab distinguish `core_readiness` from `commercial_readiness`; optional heavyweight Docker profiles or missing command-line LLM config can leave commercial readiness `limited` while core CTF solving remains `ready`
  - status reports `tool_docker=ready|missing`
- CTF Dockerfile:
  - `docker/Dockerfile.ctf`
  - default `forgeflag-core` / `forgeflag-default` image keeps heavyweight tools out of the base venv
  - default image includes common Kali CLI tools plus Python CTF packages such as `ROPgadget`, `ropper`, `RsaCtfTool`, `pwntools`, `angr`, and `z3-solver`; it also supplies default-image reverse/forensics helpers such as `objdump`, `readelf`, `radare2`, `foremost`, and `yara`
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
  - observed wrapper inventory on 2026-06-11: 20 wrappers available, 7 from host and 13 through Docker fallback
  - host wrappers: `file`, `strings`, `binwalk`, `exiftool`, `tshark`, `nmap_tcp_basic`, plus any matching binaries installed locally
  - Docker wrappers include `checksec`, `ROPgadget`, `ropper`, `RsaCtfTool`, `hashcat`, `john`, `ffuf`, `objdump`, `readelf`, `radare2`, `foremost`, and `yara` when they are not present on the host
  - heavyweight profile images `forgeflag-ctf:volatility`, `forgeflag-ctf:sagemath`, and `forgeflag-ctf:ghidra-headless` are tracked separately in `/api/tools`; build them only when a challenge needs that profile
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
scripts/forgeflag-control gate
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

1. Connect the new bounded MCP helpers to concrete external workflows:
   - reverse triage clients can request `objdump_disassemble`, `objdump_section_dump`, `readelf_sections`, and `radare2_info`
   - forensics triage clients can request `foremost_carve` and `yara_scan` with explicit output directories
2. Add read-only adapters around heavyweight profiles instead of broad shell access:
   - Volatility profile for memory dumps
   - SageMath profile for lattice/finite-field crypto helpers
   - Ghidra headless profile for function/string/decompiler export
3. Turn recent live-solve habits into repeatable project affordances:
   - after a solved challenge, prompt for casebook/playbook capture
   - surface generated solve scripts and exact run commands in the Write-up view
4. Keep expanding corpus cases from real CTF writeups only as small synthetic fixtures with evidence-backed expected outcomes.

## Safety Boundary

Keep the project scoped to CTFs, labs, and explicitly authorized targets.

Rules to preserve:

- No arbitrary shell exposed through MCP.
- Network tools require explicit allowlist scope.
- Solvers write structured evidence to the notebook.
- Verifier only accepts evidence-backed flag candidates.
