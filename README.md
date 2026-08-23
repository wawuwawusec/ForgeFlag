# ForgeFlag

ForgeFlag is a scoped multi-agent assistant for CTF and authorized security competitions.

The project starts with the architecture discussed for a full-coverage competition agent:

- `Manager`: classifies challenges, dispatches solvers, and coordinates runs.
- `Shared Notebook`: SQLite-backed blackboard for findings, evidence, tool logs, and solver state.
- `Harness`: prevents loops, records budget use, and forces strategy changes when work stalls.
- `Solvers`: pluggable workers for `recon`, `web`, `pwn`, `reverse`, `crypto`, `forensics`, `traffic`, `misc`, and infrastructure-style lab tasks.
- `Verifier`: accepts only evidence-backed flag candidates before submission.
- `MCP tools`: optional allowlisted wrappers around common CTF tools.

ForgeFlag's role layer is documented in [docs/agent-roster.md](docs/agent-roster.md) and [docs/team-operating-model.md](docs/team-operating-model.md). The top-level `ForgeFlagManager` coordinates stream-aligned, enabling, complicated-subsystem, and platform responsibilities so solver work, evidence quality, UI workflow, and held-out benchmarks improve together.

This repository is intentionally scoped for CTFs, labs, and authorized competitions. It is not designed for unauthorized scanning or exploitation.

## CTF Research Scope

ForgeFlag treats CTF solving as a controlled research workflow:

- Default work is passive local artifact analysis, solver planning, replay reporting, and benchmark fixtures.
- Active network actions require explicit operator intent through `--active-probe` plus allowlisted hosts such as `127.0.0.1`, `localhost`, or an authorized competition target.
- MCP and Docker-backed tooling expose typed CTF wrappers through `ToolRunner`; they do not expose arbitrary shell access.
- LLM output is planning guidance only. Specialist solvers, scoped wrappers, and verifier evidence remain authoritative.
- Reports and prompts should describe findings as challenge evidence and reproducible CTF replay steps, not as instructions for unauthorized real-world use.
- Local Codex/agent sessions should read [AGENTS.md](AGENTS.md) first so interactions start from the CTF/lab research context and avoid repeatedly re-litigating the project scope.
- When you share a challenge inside this repository, ForgeFlag assumes it is a local or authorized CTF challenge with local/provided attachments and a flag-reproduction goal unless you explicitly say otherwise.
- Every solver category should carry explicit CTF wording. Web, reverse, and pwn are the easiest to misread, but crypto, forensics, traffic, misc, recon, and infra findings also preserve `ctf_scope` evidence for reports, UI views, and LLM critique.

See [docs/ctf-scope-audit.md](docs/ctf-scope-audit.md) for the reviewed project scope and category-specific wording guidance.

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

### Auto-solve client

`run-all` turns ForgeFlag into a continuous auto-solving client: it scans the
notebook for unsolved challenges, runs the Manager on each, retries failures,
and stops only when every challenge is solved, per-challenge retry budgets are
exhausted, or the round limit is reached.

```bash
# Solve every pending challenge once with default budgets
forgeflag --db .forgeflag/notebook.sqlite run-all

# Retry failed challenges up to 3 attempts each, across at most 20 rounds
forgeflag --db .forgeflag/notebook.sqlite run-all --attempts 3 --rounds 20

# Keep running and pick up newly added challenges (daemon-style watch loop)
forgeflag --db .forgeflag/notebook.sqlite run-all --watch --poll-interval 30 --allow-host 127.0.0.1 --active-probe
```

A challenge counts as solved when its latest run reaches `flag_found` or
`exploit_verified` in the Verifier-backed proof status.

When an LLM provider is configured, every AI call is metered per challenge:
`run` summaries carry a `token_usage` block (calls, prompt/completion/total
tokens, solver vs. critic breakdown), `run-all` reports cross-challenge token
totals, and each usage snapshot persists in the notebook as a `token_usage`
observation. Solver crashes are
caught and recorded as `error` progress so one broken challenge never kills the
loop; `Ctrl-C` prints the progress collected so far. Scope controls
(`--allow-host`, `--active-probe`) are identical to the single-challenge `run`
command, so active probing still requires explicit operator intent.


## Installation

ForgeFlag is a cross-platform client (macOS / Linux / Windows). Pick a channel —
see [docs/delivery.md](docs/delivery.md) for details:

- **Standalone executable** (no Python needed): download from [Releases](https://github.com/wawuwawusec/ForgeFlag/releases) — one binary per platform, built by CI on every tag.
- **pip**: `pip install git+https://github.com/wawuwawusec/ForgeFlag.git` (Python 3.11+).
- **Docker**: `make docker-build` builds the Kali-based toolchain image ToolRunner falls back to when host tools are missing.
- **Source**: clone, `pip install -e .`, then `make test && make smoke`.

## Reviewer agent and auto-optimization

Every failed run is judged by the `ReviewerAgent` (deterministic evidence
checks + LLM-as-judge over the trajectory), which records a quality verdict and
a reflection hint that later retries consume. Corpus-level optimization:

```bash
forgeflag optimize --scorecard .forgeflag/mixed200-result.json \
  --manifests .forgeflag/ductf-mixed.json --top 10
forgeflag review <challenge_id>   # single-challenge trajectory judging
```

The optimizer buckets failures (near-miss / service-deployable / no-progress /
harness), emits a prioritized retry manifest, and reports flaky challenges from
scorecard history — grounding in CTFJudge-style judging and reflection-retry
research.

## LLM providers

`FORGEFLAG_LLM_PROVIDER` supports `zhipu` (BigModel pay-per-use), `anthropic`
(GLM Coding Plan subscription quota via `https://open.bigmodel.cn/api/anthropic`
— no recharge needed), and any OpenAI-compatible endpoint. Coding Plan setup:

```bash
export FORGEFLAG_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=<your BigModel key>
export FORGEFLAG_LLM_MODEL=glm-5.3
export FORGEFLAG_LLM_BASE_URL=https://open.bigmodel.cn/api/anthropic
export FORGEFLAG_LLM_TIMEOUT_SECONDS=300
```

## Dual-metric accuracy (never conflated)

| Metric | Accuracy | What it measures |
| --- | --- | --- |
| **Synthetic curriculum** (204 seeded challenges, 6 tiers) | **81.4%** (166/204) | the product's own capability envelope: encoding 97%, forensics 100%, logic 100%, mini-VM rev 97%, classic crypto 94%, cyclic-offset pwn 0% (counted) |
| **Real multi-platform corpus** (192 exact-flag challenges, 7 competitions) | **10.4%** (20/192) | generalization to real competition difficulty |

```bash
python scripts/forgeflag-curriculum-generator --count 204   # regenerate the curriculum
python scripts/forgeflag-capability-benchmark --manifest-only --manifest .forgeflag/curriculum-manifest.json
```

## Real-challenge corpus

Beyond the synthetic suites, ForgeFlag benchmarks against real public CTF
challenges with verified ground truth:

```bash
git clone --depth 1 https://github.com/google/google-ctf /tmp/google-ctf
python scripts/forgeflag-real-corpus-collector --source gctf --root /tmp/google-ctf --output .forgeflag/gctf-manifest.json
python scripts/forgeflag-capability-benchmark --manifest-only --manifest .forgeflag/gctf-manifest.json
```

The verified corpus shipped with this release covers **218 medium-plus real
challenges across seven platforms** (adds SekaiCTF 2024), with `--resume`
support for iterating on 1000-case corpora and per-challenge token accounting (Google CTF quals, DUCTF, IrisCTF, HTB,
idekCTF, SekaiCTF) with exact expected flags and A/B LLM evaluation
(`FORGEFLAG_LLM_PROVIDER=zhipu`, `ZAI_API_KEY`, `FORGEFLAG_LLM_MODEL`); per-challenge
token usage is recorded in every scorecard. The previous release (Google CTF quals 2021-2025 plus SekaiCTF 2025) scored against
exact expected flags, with challenge content kept in the gitignored local
cache (upstream licenses). Deterministic solvers complete triage and evidence
across the corpus; exact-flag auto-solving at this difficulty depends on the
LLM planning layer, so configure `FORGEFLAG_LLM_PROVIDER` +
`FORGEFLAG_LLM_API_KEY` before expecting flag captures on hard challenges.

## Capability benchmark

The product carries its own solve-rate benchmark so capability regressions fail
CI instead of shipping:

```bash
forgeflag --db .forgeflag/benchmark.sqlite web --port 8080 &   # benchmark drives the HTTP API
python scripts/forgeflag-capability-benchmark                  # exits non-zero on any failed case
```

Current verified scorecard: **46/46 cases (100%) · hard evidence 104/104 ·
browser UI flow 7/7 · held-out replay 10/10 across 7 competitions (incl. unseen SekaiCTF 2025) · readiness `ready`**.
Flag extraction generalizes to unseen competition prefixes (`extract_flags_generic`),
and solver triage recognizes restricted-pickle sources and Lua/LuaJIT VM artifacts. CI reruns the
built-in suites on every push; the held-out manifest (real public CTF
challenges kept out of the repo) is a local release gate:

```bash
python scripts/forgeflag-capability-benchmark --manifest .forgeflag/heldout-platform-manifest.json
```

Run a local smoke test that does not need any network service:

```bash
make smoke
```

Use the local control script for one-command setup and lifecycle checks:

```bash
scripts/forgeflag-control start
scripts/forgeflag-control status
scripts/forgeflag-control doctor
scripts/forgeflag-control smoke
scripts/forgeflag-control gate
scripts/forgeflag-control stop
```

`start` launches the Web UI at [http://127.0.0.1:8080/](http://127.0.0.1:8080/) by default and records a managed PID under `.forgeflag/web.pid`. `doctor` shows the same Python dependency, deployment, toolchain, benchmark, LLM, and diagnostic-bundle readiness used by the Web UI Health tab. The control script defaults to a readable text summary; use `doctor --format json` for automation, `doctor --strict` to enforce core solving readiness, or `doctor --strict commercial` for the complete optional-integration gate. `gate` runs the full practical readiness check: API suites, hard evidence scoring, browser-player smoke, and held-out manifest replay, then refreshes `.forgeflag/capability-benchmark-latest.json` for the Web UI Benchmark tab. `gate --llm` fails fast when the command-line LLM provider/key/model are missing, so an LLM-assisted scorecard cannot silently fall back to deterministic-only evidence. The Web UI includes a category workspace so Web, Pwn, Reverse, Crypto, Forensics, Traffic, Misc, and Infra challenges can be filtered separately before running solvers. Start the optional MCP server only when you need it:

For a complete workstation setup, dependency list, Docker/OrbStack toolchain, MCP/LLM configuration, release checks, and GitHub publish workflow, see [docs/dependencies-and-deployment.md](docs/dependencies-and-deployment.md).

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

`LLMSolver` writes planning guidance to the notebook. If the model returns JSON with `summary`, `suggested_solvers`, `next_actions`, `tool_hints`, and optional `flag_candidates`, ForgeFlag stores it as an `llm_solver_plan` observation and can insert suggested solvers into the remaining run queue. Candidate flags from the model are not auto-trusted: they are submitted through the same evidence-backed verifier as specialist solver output. Text attachments are previewed with both head and tail excerpts so source files that place ciphertext/output comments at the end still give the model useful context.

ForgeFlag treats LLM rate limits as a normal runtime condition. LLM HTTP calls are serialized inside the process, retry `429`/temporary `5xx` responses with `Retry-After` or bounded exponential backoff, and enter a cooldown circuit breaker after the retry budget is exhausted. You can tune the defaults when needed:

```bash
export FORGEFLAG_LLM_MAX_RETRIES=2
export FORGEFLAG_LLM_RETRY_INITIAL_SECONDS=1
export FORGEFLAG_LLM_RETRY_MAX_SECONDS=20
export FORGEFLAG_LLM_COOLDOWN_SECONDS=120
```

The Web UI also has a per-run "大模型分析" switch. Select `智谱 GLM`, enter a GLM model such as `glm-5.1`, and paste the API key. The UI can save provider/model/API key/base URL/timeout to browser local storage, list saved keys in a masked dropdown, and includes a connection test button. API keys are restored from the current browser before LLM runs/tests, but ForgeFlag never writes the token to SQLite.

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
PYTHONPATH=src python3 -m forgeflag.cli hints --category traffic
```

To measure practical CTF-solving capability instead of only unit-test health, run the capability scorecard:

```bash
scripts/forgeflag-capability-benchmark --url http://127.0.0.1:8080
```

To make the latest result visible in the Workbench Benchmark tab, save it to the standard scorecard path:

```bash
scripts/forgeflag-capability-benchmark --url http://127.0.0.1:8080 --output .forgeflag/capability-benchmark-latest.json --history .forgeflag/capability-benchmark-history.jsonl
```

The Benchmark tab now shows a readiness gate in addition to pass rates. A smoke-only 7/7 run is marked `limited`; ForgeFlag only shows `ready` when the scorecard has no failures and includes hard evidence, browser UI flow, and held-out manifest coverage.

For external CTF artifacts that should not be mixed with the internal corpus score, use:

```bash
scripts/forgeflag-capability-benchmark --url http://127.0.0.1:8080 --manifest-only --manifest .forgeflag/heldout-platform-manifest.json
```

Held-out manifest cases can include local Docker service startup and typed replay commands. This is how ForgeFlag checks proof-of-solve scripts against local or explicitly authorized challenge services without blending those results into the internal fixture score.

To expand beyond handpicked cases, audit cached public contest artifacts and emit a manager-reviewed candidate manifest:

```bash
PYTHONPATH=src scripts/forgeflag-real-corpus-audit \
  --root .forgeflag/heldout-cache \
  --emit-manifest .forgeflag/real-contest-candidates-manifest.json \
  --manifest-limit 20

PYTHONPATH=src scripts/forgeflag-capability-benchmark \
  --manifest .forgeflag/real-contest-candidates-manifest.json \
  --manifest-only \
  --output .forgeflag/real-contest-candidates-scorecard.json
```

The audit rejects handout artifacts that contain placeholder or template flags, strips README answer lines from benchmark descriptions, blocks Git LFS pointer files until real handout bytes are fetched, then assigns unsolved real cases to owner roles such as `CryptoMathAgent`, `ForensicsAgent`, `TrafficAgent`, `BinaryAgent`, and `WebExploitAgent`. Current real-corpus parsing covers DUCTF `ctfcli.yaml`, HTB Cyber Apocalypse README/`htb/` layouts, TJCTF and UMDCTF `challenge.yaml`, CTFd-style `challenge.yml` plus unpacked `dist` / `distribution` handouts, and IrisCTF README plus `dist/` layouts.

See [docs/capability-benchmark.md](docs/capability-benchmark.md) for suites, metrics, readiness gates, role-owned backlog output, and the held-out manifest format.

Recent real-contest replay notes:

- Current cleaned 36-case real-contest scorecard remains 34/36 flags and 91/93 hard evidence. The remaining HTB `Maze of Mist` pwn item is now classified as a ret2vdso VM artifact-completeness blocker: `scripts/solve_maze_of_mist_static.py` parses the exploit constants, but refuses proof-of-solve until `vmlinuz-linux`, `initramfs.cpio.gz`, `run.sh`, and the rootfs `target` are available for local replay.

## Tooling

Build and enable the CTF tool container with Docker or OrbStack:

```bash
scripts/forgeflag-control docker-build
scripts/forgeflag-control docker-smoke
scripts/forgeflag-control restart
```

`docker-build` builds `forgeflag-ctf:latest`, writes `.forgeflag/docker.env`, and enables automatic Docker fallback for missing host tools. `ToolRunner` still prefers host commands when present, but can run container-backed wrappers such as `checksec`, `ROPgadget`, `ropper`, `RsaCtfTool`, `hashcat`, `john`, `ffuf`, `objdump`, `readelf`, `radare2`, `foremost`, and `yara` with project paths mounted under `/workspace`. Use `scripts/forgeflag-control status`, `.venv/bin/forgeflag tools`, or `/api/tools` to inspect whether each wrapper is using `host`, `docker`, or `missing`.

The full dependency and deployment matrix is maintained in [docs/dependencies-and-deployment.md](docs/dependencies-and-deployment.md); the lower-level container profile notes are in [docs/tool-containers.md](docs/tool-containers.md).

The Web UI Tools tab shows runnable wrappers, the recommended project catalog, and heavyweight Docker profiles. Profiles such as `forgeflag-volatility`, `forgeflag-sagemath`, and `forgeflag-ghidra-headless` are not part of the default image; the tab shows whether each profile image is built and includes the exact `docker build` / `docker image inspect` commands.

Hashcat is installed in the image, but GPU/OpenCL access depends on the Docker runtime. On OrbStack without a passed-through cracking device, the smoke test reports hashcat as skipped while John CPU dictionary checks can still run.

For manual Pwn work, select a `Pwn` challenge in the Web UI. ForgeFlag shows a "Pwn 本地环境" panel with copyable Docker, `socat`, and triage commands, plus a house-style pwntools exploit template that can switch between local `process()` and remote `remote(host, port)` mode. The template follows the local `freenote_x64.py` convention: debug-local default, `ELF`/`libc` setup, `debugf()`, menu helpers, separated `leak()` / `exploit()` / `proof()` phases, and a `--proof` mode that runs `cat flag` to verify the local test flag before treating a Pwn case as exploit-verified. The template can be copied or downloaded as `exploit.py`. The panel also includes a button that fills `tcp://127.0.0.1:31337`, `127.0.0.1,localhost`, and `Active probe` for the selected challenge. You can also enter the same environment directly:

```bash
docker run --rm -it --platform linux/amd64 \
  -p 31337:31337 \
  -v "$PWD:/workspace" \
  -w /workspace \
  forgeflag-ctf:latest \
  bash
```

Run the optional MCP server:

```bash
pip install -e '.[mcp]'
export FORGEFLAG_ALLOWED_HOSTS=127.0.0.1,challenge.local
forgeflag-mcp
```

See [docs/mcp.md](docs/mcp.md) for the current MCP tool list.

## Knowledge Base

ForgeFlag keeps reusable CTF solving experience in [docs/ctf-playbook.md](docs/ctf-playbook.md), concrete replay notes in [docs/ctf-casebook.md](docs/ctf-casebook.md), ad-hoc proof-of-solve helper alignment in [docs/solve-scripts.md](docs/solve-scripts.md), and practical capability scoring in [docs/capability-benchmark.md](docs/capability-benchmark.md). The same recurring patterns surface as Tools-tab analysis hints, `/api/analysis-hints`, and `forgeflag hints --category <category>`. Recent entries include matrix-conjugation crypto with bad-pivot factor recovery, stripped ELF `.rodata` inversion, self-synchronizing XOR key-slot crib recovery, right-shift XOR linear inversion, LFSR Berlekamp-Massey recovery, Python random prime-offset recovery, PRNG/stream-cipher local replay for LCG, LFSR, and MT19937 sample packs, shifted RSA factor-leak replay, RSA source-loop `c+k*n` low-exponent recovery, De Bruijn PIN replay, ChaCha state-as-keystream replay, composite-ring NTRU CRT lattice replay, recursive regex golf replay, Python eval blacklist suffix-comment replay, sparse adversarial pixel replay scaffolding with exact score-only evaluation, bounded unstable-pixel seed sweeps, and cached payload artifacts, Vivado DCP/EDIF LUT-netlist replay, I2C EEPROM schematic dump replay, Basic Auth prefix-compare replay, PHP pack/procfs replay, Web loopback-alias SSRF replay, Web Python class-pollution replay, Web HTTP/3-to-H1 request-smuggling replay, Web iframe-gated note-search substring oracle replay, Pwn escaped-byte ret2win replay, Pwn signed-short HP overflow replay, Pwn heap off-by-one overlap replay, Pwn fixed-suffix return-address alignment replay, Pwn UAF linked-list reuse replay, Pwn AArch64 PAC signing-oracle replay, Pwn glibc tcache malloc-hook replay, Pwn ret2vdso VM artifact-completeness checks, renderer SSRF rebinding, Prisoner Processor local Bun/Hono replay, ECDSA repeated-nonce recovery, visual-cryptography image shares, raw TCP data URI image recovery, RF image ASK/OOK Manchester recovery, HTTP webshell delimited flag extraction, bounded raw PCAP byte flag scanning, corrupt PCAP record resync plus IPv4 Identification stego, registry WiFi SSID recovery, BMP QuickStego/Braille transforms, OSINT building geolocation replay, OSINT music cross-reference replay, archive-contained mangled PNG repair with preserved visual transcription, Minecraft Anvil orphan-sector lore recovery, recipe-state Misc solving, decayed DoubleHelix Ruby source recovery, Reverse ELF argv repeating-XOR recovery, Reverse jmp-table popcount recovery, Reverse compiled byte equality-chain recovery, Reverse MLVM pixel-art recovery, Reverse Python VM perfect-number SHA1 recovery, Reverse Python 8x8 grid constraint solving, and current competition discovery habits for online and China-based events. Current external checks: held-out platform `8/8`; diversified real-contest `34/36`, `91/93`, readiness `blocked`; supplemental local replays include NUS Private Hidden Paths and Stack BOF School.

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
10. For forensics challenges, register local attachments and triage them with `file`, `strings`, `binwalk`, `exiftool`, `foremost`, and `yara` where useful.
11. For traffic challenges and PCAP/RF image attachments, run PCAP-focused `tshark` summaries or waveform decoding and extract evidence-backed flag candidates.
12. For reverse and pwn binary attachments, preserve local `file`/`strings` evidence, run bounded binary wrappers such as `objdump`, `readelf`, `radare2`, `ROPgadget`, and `ropper`, and optionally call a read-only IDA MCP adapter for function, string, and pivot evidence.

Future milestones add real solver depth for Web, Crypto, Reverse, Pwn, Forensics, and mixed attack-defense lab tasks.
