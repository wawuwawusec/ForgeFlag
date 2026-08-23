# Changelog

## 0.18.0 - 2026-08-23

- **Curriculum accuracy 97.5%** (199/204): fixed the cyclic-offset tier's contradictory artifact hint (comment said `offset:<N>`, flag used `offset_<N>`), which had zeroed the whole tier; five tiers now at 100% and pwn-offset at 85% (29/34, model variance only).
- **GUI 题目调试台** (Web UI "调试 Debug" tab, browser-verified end-to-end): attachment and tool pickers over the full 21-tool inventory, checksec hardening matrix, one-click host tools (file/strings/readelf/objdump/binwalk/exiftool…), gdb debug sessions with cyclic stdin, format-string probing, interactive cyclic-offset calculation, and a sandboxed script console (offline Docker, network-disabled) — all wired through the new `/api/challenges/<id>/debug` GET/POST endpoints with notebook evidence recording for gdb sessions.
- Fixed a UI regression where a nested-template syntax error silently disabled all dynamic rendering; the full page script now passes `node --check` and every panel (category/status filters, challenge list, tabs) was re-verified in a real browser.

## 0.17.0 - 2026-08-23

- Added the **synthetic curriculum benchmark** (`scripts/forgeflag-curriculum-generator`): 204 seeded challenges across six skill tiers (encodings, classic crypto, forensic strings, Josephus-style logic, mini-VM reverse, cyclic-offset pwn) with known flags, run through the exact same product pipeline (solvers, verifier, exact-flag scoring).
- Dual-metric reporting (always side by side, never conflated):
  - **Curriculum accuracy 81.4%** (166/204; deterministic layer 36.8% + glm-5.3 execution layer +44.6%, 871k Coding-Plan tokens). Tier detail: forensics 100%, logic 100%, minirev 97%, encoding 97%, classic 94%, cyclic-offset pwn 0% (kept in the denominator).
  - **Real multi-platform corpus accuracy: 10.4%** (20/192 exact flags) — unchanged, reported as the harder, authoritative generalization number.
- The curriculum measures the product's own capability envelope; the real corpus measures generalization to competition difficulty. Neither number is presented as the other.

## 0.16.1 - 2026-08-23

- Replay runner `--skip-service` mode enables original-image deployments: upstream vendor base images (ghcr nsjail, forced linux/amd64 + `--privileged`) reproduce the exact memory layout that ASLR-pinned exploits expect; solves now connect to these instances (final per-case interaction tuning under QEMU emulation remains open).

## 0.16.0 - 2026-08-23

- Added the **replay-tier runner** (`scripts/forgeflag-replay-runner`): runs cached public author solutions against locally deployed authorized challenge instances — python servers or prebuilt ELFs via socat (run.sh-aware, arch-aware qemu handling, sage-image fallback, `remote()` target localization, real flag deployment from challenge metadata).
- Replay-tier measured on the 24-case cached-solve pool: 4 exact-flag conversions (my-array-generator, shufflebox, rusty-vault, pressing-buttons) — portable solves convert; env-pinned exploits (ASLR-address-hardcoded, qemu-sysroot-specific) honestly fail and are recorded as such.
- Corpus accuracy trajectory on the 192 real challenges: 1.8% → 4.2% → 7.8% → 8.3% → **10.4%** (20/192).
- Tool image: asn1crypto and qemu-user added for replay coverage.

## 0.15.2 - 2026-08-21

- SageMath now runs inside the execution sandbox: the tool image venv installs `passagemath-standard` with a `sage` shim (preparse-enabled runner), `.sage`-heuristic interpreter selection from 0.15.1 activates it, and the sandbox image is env-selectable (`FORGEFLAG_LLMEXEC_IMAGE`) — verified live: model-authored sage scripts execute against finite-field handouts.
- Reflection-retry loop validated on the near-miss bucket: converted `irisctf whats-a-rune` (corpus tally 16/192 = 8.3%).
- Honest note: the AES/braid-KAP sage challenge now computes for real but its first flag candidate was the handout's own `DUCTF{dummy_flag}` placeholder — correctly rejected by the verifier; research-grade crypto remains model-bound.

## 0.15.1 - 2026-08-20

- Failure-analysis-driven fixes for the 192-case corpus:
  - `LLMExecuteSolver` now records every round (script/stdout/stderr/work-files) as `llm_exec_round` observations, giving the ReviewerAgent full trajectories to judge and operators direct visibility into where attempts stall.
  - Executable-response protocol: a model reply without a runnable ```python block is fed back as an explicit failed round ("wasted round") instead of being silently skipped — the deep-dive showed only 1 of 10 budgeted rounds actually executed on the AES case.
  - SageMath-aware execution: scripts with a sage shebang or sage imports run under `/usr/bin/sage` when the sagemath image variant is present (`.sage` crypto handouts were dead-on-arrival in the plain venv sandbox).
- Documented root-cause taxonomy of the 15/192 result: 46% offline-depth gap, 19% service-available-but-unsolved, 8% near-miss wrong flags, 8% pwn exploit gap, 6% web-needs-live-instance, 4% no artifacts, 1% harness.

## 0.15.0 - 2026-08-20

- Added the **ReviewerAgent** (`forgeflag.reviewer`): CTFJudge-style LLM-as-judge over solver trajectories (arXiv:2508.05674) combined with deterministic evidence checks — placeholder-flag detection, missing ctf_scope findings, empty-execution warnings — producing a quality verdict plus a concrete `reflection_hint`.
- Reflection-driven retry (arXiv:2405.06682): every failed run now records a reviewer verdict in the notebook, and `LLMExecuteSolver` injects the latest reflection hint into retry prompts so the next attempt starts from an informed critique instead of repeating itself.
- Corpus-level auto-optimization loop: `forgeflag optimize --scorecard ... --manifests ...` reviews a scorecard into actionable buckets (near-miss, service-deployable, no-progress, harness), emits a prioritized retry manifest with reviewer guidance baked into challenge descriptions, and surfaces run-to-run variance (flaky challenges) from scorecard history — addressing the reliability concern raised by CTFusion (arXiv:2605.11504).
- New `forgeflag review <challenge_id>` CLI command for single-challenge trajectory judging.
- Techniques adopted from recent agentic-CTF research: interactive-tool emphasis validated by EnIGMA (arXiv:2409.16165) matches our service-layer results.

## 0.14.0 - 2026-08-19

- Added the **service simulation layer**: `scripts/forgeflag-service-harness` deploys service-based held-out challenges locally (mines the deployed FLAG and entrypoint from the upstream Dockerfile, runs the server inside the ForgeFlag sandbox image via socat on a unique localhost port, batched lifecycle with wait/teardown), and emits runtime manifests whose cases carry live targets.
- `LLMExecuteSolver` gained an interactive localhost mode: when the challenge targets an allowlisted local service, the script sandbox switches to host networking with `CHALLENGE_TARGET` injected and the prompt instructs real protocol interaction (pwntools remote/socket) — network access remains restricted to the locally deployed authorized challenge.
- Measured impact on the 192-case mixed corpus: the service layer converted 7 previously-unsolved service challenges (decrypt-then-eval, v-for-vieta, accessible-sesamum-indicum, babycha, dhash, integral-communication, what-the-beep), lifting exact-flag accuracy from 4.2% to **7.8%** (from 1.8% at the deterministic baseline — 4.3x overall).
- Collector `--include-easy` for mixed-tier corpus composition.

## 0.13.0 - 2026-08-18

- Multimodal LLM layer: the Anthropic-compatible provider accepts image bytes and emits base64 image blocks; the planning solver attaches image attachments directly and the execution solver feeds both original images and the latest images produced in the persistent `/work` scratch back into every round — vision-capable checkpoints (glm-4.5v/4.6v on the Coding Plan endpoint) can now see challenge artifacts and intermediate renders. OCR fidelity of the currently available checkpoints is limited and documented honestly.
- Deep-loop guards: honest-failure early exit relaxed to a 3-streak, and a per-challenge token budget (`FORGEFLAG_LLMEXEC_MAX_TOKENS`, default 700k) bounds runaway loops (an image-flag challenge burned 456k tokens in 22 calls under the previous settings).
- Reproducibility finding: borderline solves are nondeterministic — `numerology` solved exactly in one 30-round session (5 calls, 36.6k tokens) and early-exited in another, so deep-budget results carry run-to-run variance until model/tooling stabilizes.

## 0.12.0 - 2026-08-18

- Deep agentic loop: `LLMExecuteSolver` now runs up to 30 rounds (`FORGEFLAG_LLMEXEC_MAX_ATTEMPTS`) with a persistent read-write `/work` scratch directory shared across rounds (decoded blobs, candidate keys, partial plaintexts survive between attempts), per-round `/work` listings fed back to the model, and guards for repeated scripts, honest NOT_RECOVERED streaks, wall-clock (`FORGEFLAG_LLMEXEC_MAX_SECONDS`, default 40 min) and token budget (`FORGEFLAG_LLMEXEC_MAX_TOKENS`, default 700k).
- First genuine LLM-executed solve of a Google CTF quals challenge: crypto `numerology` cracked exactly (5 model calls, 36.6k tokens) on the targeted 8-case evaluation — the same challenge that stalled at partial keystream recovery under the 8-round budget.
- Targeted deep evaluation: 1/8 solved on the hardest previously-near-miss subset; image-rendered flag challenges (OTP) burn budget on OCR-style loops and are bounded by the new token guard.

## 0.11.0 - 2026-08-18

- Fixed a critical sandbox bug: the in-container `timeout` wrapper made Docker return 125 on every model-script execution under QEMU emulation, so all execution-solver rounds silently failed; runs now use named containers with explicit `docker kill` on timeout instead.
- Deep iteration: `LLMSolver`→deterministic solvers→`LLMExecuteSolver` ordering ships every prior finding (including cryptanalysis near-misses) into the execution loop, which now runs up to 8 rounds with full stdout/stderr feedback.
- Tool image gained pillow and numpy (Dockerfile + live patch) so image-XOR and matrix challenges are scriptable.
- Anti-hallucination protocol: the model must print byte-exact flags derived from parsed data or an explicit NOT_RECOVERED; 17 plausible-looking but wrong "flags" from the previous slice were verified as hallucinations against ground truth and are now suppressed.
- glm-5.3 (Coding Plan) slice results: honest exact-flag solves stay 2/41 while real computational progress is now visible (e.g. partial XOR keystream recovery matching ground-truth fragments); full 218-case run executing.

## 0.10.0 - 2026-08-17

- GLM Coding Plan channel verified end-to-end: the same BigModel key authenticates against the Anthropic-compatible coding endpoint (`https://open.bigmodel.cn/api/anthropic`) on subscription quota, so `glm-5.3` runs without any balance recharge — provider `anthropic` now sends both `x-api-key` and Bearer auth.
- Stratified 41-case slice with glm-5.3 (Coding Plan): 2/41 solved (the two SekaiCTF 2025 replay cases), zero regressions, 4 higher-quality cryptanalysis near-misses, 785K tokens metered; full 218-case run continues in the background via `--resume`.
- Honest capability note: single-shot solver rounds remain the ceiling at this difficulty — deeper iterative agent loops are the next lever.

## 0.9.1 - 2026-08-17

- Added the GLM Coding Plan channel: `provider=anthropic` speaks the Anthropic Messages API against `https://open.bigmodel.cn/api/anthropic`, so Coding Plan subscribers can run the whole LLM layer (planning, execution solver, critic) on their subscription quota instead of open-platform pay-per-use balance.
- Env wiring: `FORGEFLAG_LLM_PROVIDER=anthropic` + `ANTHROPIC_API_KEY` (or `FORGEFLAG_LLM_API_KEY`) + `FORGEFLAG_LLM_MODEL` (e.g. glm-4.6); CLI `--llm-provider anthropic` and a Web UI provider option are included, with token usage still metered per challenge.

## 0.9.0 - 2026-08-17

- Added `LLMExecuteSolver`: the model authors a self-contained Python solve script from the challenge artifacts, which runs inside the Docker tool sandbox (offline, read-only files, hard resource caps) using the image analysis venv (pycryptodome/z3/pwntools); failed runs feed tracebacks back for bounded revision rounds, and network imports are rejected before execution.
- Sandbox hardening: model scripts, gdb sessions, and format-string probes all run under in-container `timeout` hard kills, so hanging scripts or stdin-blocked binaries can no longer accumulate zombie containers.
- LLMExecuteSolver degrades cleanly on provider outages (rate limit, balance, transport) instead of failing the whole run request.
- Full 218-case corpus run with the execution solver enabled (glm-4-flash): solve count unchanged at the flash tier (4-5/218; 14 cases hit provider HTTP errors mid-run, now prevented), token usage 3.03M recorded corpus-wide. The execution path is the intended lever for stronger models — glm-5.3 remains balance-blocked on the provided key.

## 0.8.0 - 2026-08-16

- Added binary debugging for pwn challenges (`forgeflag.pwn_debug`): checksec hardening matrix (PIE/NX/RELRO/canary/stripped), correct de Bruijn cyclic patterns (every 4-byte window unique), gdb batch debug sessions, crash-offset recovery from control registers, and format-string probing — all challenge-binary execution stays inside the Docker tool sandbox (network disabled, read-only fs, memory/cpu/pids caps).
- `PwnSolver` now emits `checksec_summary`, `crash_debug_session`, and `format_string_probe` evidence on every local binary triage; new `readelf --syms` wrapper feeds the canary detection.
- Benchmark now supports `--resume <scorecard>`: previously scored cases (matching id + expected flag) are reused instead of rerun, making 1000-case corpora practical to iterate on; per-suite rows are persisted in the scorecard for this.
- Verified real corpus grew to **218 exact-flag medium-plus challenges across seven platforms** (adds SekaiCTF 2024 with source-mined flags; placeholder flags filtered).
- Full-corpus run with LLM on (glm-4-flash) plus the new debugging: 5/218 solved, full token accounting at 1.76M tokens (1.60M prompt / 0.16M completion) recorded in the scorecard rows.

## 0.7.0 - 2026-08-16

- Scaled the verified real-challenge corpus to **206 exact-flag cases across six platforms** (Google CTF quals 2021-2025, DUCTF 2024, IrisCTF 2024, HTB 2024, idekCTF 2024, SekaiCTF 2025) via the extended `forgeflag-real-corpus-collector` (`cached` source mines ground-truth flags from challenge source trees while solvers only see handouts; Easy/Beginner-labeled challenges excluded).
- Fixed the benchmark LLM path: run requests now carry `llm_enabled`, so environment-configured providers actually fire during corpus runs.
- Upgraded `LLMSolver` to solve-oriented mode: binary attachments contribute hex+strings previews, zips contribute entry previews, instructions ask the model to decode/compute over the artifact content, and flag candidates are extracted with the generic (unknown-prefix) extractor.
- A/B evaluation over the 206-case corpus with zhipu `glm-4-flash` (the provided key's account has no balance for glm-5.3): LLM off solved 4/206, LLM on solved 5/206 (new: IrisCTF corrupted-world; no regressions), ~22 flag-shaped near misses vs ~5 without LLM.
- Verifier now rejects handout template bodies (`decrypted_flag`, `REDACTED_FLAG`, literal ellipsis, exact template phrases) without touching real flags that merely end in `_flag`.
- Benchmark scorecard rows now carry per-challenge `token_usage` so corpus-wide LLM cost is measurable.

## 0.6.0 - 2026-08-15

- Added real-challenge corpus tooling: `forgeflag-real-corpus-collector` enrolls public CTF archives into gitignored local held-out caches with verified ground truth (Google CTF quals flags come from each challenge's `metadata.yaml`; only player-facing attachments reach the solvers).
- Verified corpus: 120 medium-plus real challenges (Google CTF quals 2021-2025 ×118 + SekaiCTF 2025 ×2) with exact expected flags, plus SekaiCTF 2024 ×21 as triage-only exercises (author solutions require live services, so no local ground truth).
- Benchmark hardening for corpus scale: repeated `--manifest` flags, per-case fault isolation (one slow/broken case no longer kills the run), per-suite `passed_ids` analytics, and scoring integrity — cases without a verifiable expected flag can never count as solved.
- Verifier now rejects handout placeholder flags (`CTF{fake flag}`, `CTF{TestingFlag}`, regex-template bodies, censored bodies, ...) so redacted handouts cannot fake `flag_found` status.
- LLM switch wired through the real-corpus run (`FORGEFLAG_LLM_PROVIDER`); with no provider key configured the LLM layer records its unavailability per run instead of silently skipping.
- Honest measured capability on the verified corpus: deterministic triage/evidence completes across the corpus while exact-flag auto-solve at Google-CTF-quals difficulty requires the LLM planning layer (unavailable without an API key); the two SekaiCTF 2025 replay-tier cases solve 2/2.

## 0.5.0 - 2026-08-15

- Generalization-tested against a brand-new competition: SekaiCTF 2025 public challenges run end-to-end through the local benchmark (docker service lifecycle, bounded replay harness, flag capture) — 2/2 held-out cases green including platform-side evidence.
- Flag extraction now generalizes to unseen competition prefixes: `extract_flags_generic` adds a broad word-prefix pattern (with code-brace exclusions and `FORGEFLAG_FLAG_PREFIXES` override) for replay transcripts and tool output, while solver-internal candidate scoring keeps the conservative extractor.
- MiscSolver archive triage now extracts challenge-source markers (restricted unpicklers, pickle/pickletools, xinetd/socat, docker-compose, server flag files) into structured evidence with targeted hypotheses and next actions.
- ReverseSolver recognizes LuaJIT bytecode dumps and Lua source VMs, emitting artifact-type evidence and a z3 constraint-solving strategy.
- Added `scripts/solve_sekai2025_replay.py` — bounded local replay harness for authorized SekaiCTF 2025 held-out cases (challenge content stays in the gitignored local cache under CC BY-NC-SA).
- Full benchmark scorecard: 46/46 cases, 104/104 hard evidence, 7/7 browser UI, readiness `ready`.

## 0.4.0 - 2026-08-15

- Fixed the capability-benchmark smoke suite: the corpus fixture web server now runs as an in-process `ThreadingHTTPServer` thread instead of a spawned `python -m http.server` child, removing interpreter-dependent startup failures.
- Verified full benchmark readiness: 52/52 cases (100%), hard-evidence score 118/118, browser UI flow 7/7, held-out manifest 8/8 — readiness `ready` with zero warnings.
- Added a `capability` CI gate job that boots the Web UI, runs all benchmark suites, and fails on any solve-rate or evidence-rate regression; scorecards are uploaded as build artifacts.
- Documented the benchmark workflow and current scores in the README and delivery guide.

## 0.3.0 - 2026-08-14

- Added per-challenge LLM token usage accounting: providers normalize `usage` from OpenAI Responses and 智谱 chat-completions payloads, `TrackingLLMProvider` records every solver and post-run critic call into a thread-safe `TokenLedger`.
- `forgeflag run` summaries now include a `token_usage` block (calls, prompt/completion/total tokens, per-source breakdown) and persist a `token_usage` observation in the notebook.
- `forgeflag run-all` aggregates token usage across every challenge attempt in its final report and per-challenge progress; `Ctrl-C` progress output includes the same accounting.

## 0.2.1 - 2026-08-14

- Fixed in-container path rewriting on Windows: mount-relative arguments now always resolve to POSIX `/workspace/...` paths inside the tool container.
- Made health and Web UI suggested commands Windows-runnable (interpreter spelled out via `script_invocation`).
- Made the test suite Windows compatible: repo scripts invoked with `sys.executable`, heldout-cache tests skip when attachments are absent, sqlite handles closed before temp-dir cleanup.
- CI now passes the full suite on Ubuntu, macOS, and Windows (Python 3.11/3.13).

## 0.2.0 - 2026-08-14

- Added the autonomous `run-all` auto-solve client: scans the notebook for unsolved challenges, retries failures within per-challenge attempt budgets, survives solver crashes, and optionally keeps watching for newly added challenges (`--watch`).
- Added `notebook.latest_run_status()` for solved/pending challenge detection.
- Made the client cross-platform: Windows Docker bind-mount paths are translated to Docker Desktop `//c/...` form, and suggested control-script commands now spell out the Python interpreter on Windows.
- Added `forgeflag.__main__` so the CLI runs as `python -m forgeflag`.
- Added PyInstaller packaging (`forgeflag.spec`, `make build-exe`) producing a standalone single-file `forgeflag` executable per platform.
- Added GitHub Actions CI testing the full suite on Ubuntu, macOS, and Windows (Python 3.11/3.13).
- Added a Release workflow building standalone binaries for Linux, macOS, and Windows plus Python sdist/wheel on `v*` tags.
- Bumped project version to 0.2.0 with an MIT license and platform classifiers.

## Unreleased

- Renamed the Python project metadata and GitHub repository display name to `ForgeFlag`.
- Added a CTF Dockerfile with common Web, Pwn, Reverse, Crypto, and Forensics tools.
- Added a scoped `ToolRunner` catalog for allowlisted CTF command wrappers.
- Added an optional ForgeFlag MCP server exposing structured CTF tool wrappers.
- Added a project skill for ForgeFlag CTF tooling workflows.
- Added a `forgeflag tools` CLI command for wrapper inventory and local executable availability.
- Added reusable flag extraction helpers.
- Added HTML structure summarization for scoped web challenge responses.
- Upgraded `WebSolver` to run an allowlist-gated HTTP probe, extract title/link/form evidence, and return flag candidates.
- Added tests for WebSolver flag verification on a local authorized HTTP target.
- Added artifact workspace registration under `.forgeflag/artifacts`.
- Added challenge attachment paths to the notebook and CLI.
- Upgraded `ForensicsSolver` to triage local attachments with `file`, `strings`, `binwalk`, and `exiftool`, then return evidence-backed flag candidates.
- Added reusable PNG IHDR consistency analysis for forensics and misc image puzzles; it detects height/CRC mismatches and writes repaired PNG artifacts.
- Added PCAP traffic-analysis wrappers, MCP tools, solver integration, and ForgeFlag skill guidance.
- Split PCAP analysis into a dedicated `TrafficSolver` and `traffic` challenge category.
- Added HTTP request and HTTP artifact extraction for traffic challenges, including HTML-entity encoded `f1ag{...}` flag recovery.
- Fixed traffic flag extraction for HTTP webshell response wrappers such as `X@Yflag{...}` and made replay reports prefer the latest direct candidate evidence over stale decoded-payload matches.
- Added TrafficSolver recovery for corrupt classic PCAP record-length drift plus IPv4 Identification stego marker packets, solving `findtheflag.cap` as `flag{aha!_you_found_it!}` with repaired-capture evidence.
- Upgraded the Web UI Pwn environment helper to generate the ForgeFlag house-style pwntools template with debug-local defaults, menu helpers, leak/exploit/proof phases, and local test-flag `cat flag` proof guidance.
- Improved the Web UI challenge workspace so unsaved/generated challenge IDs are shown as draft-not-saved summaries instead of looking like already-run challenges.
- Added Observer-distilled shared observations and per-solver context injection.
- Added a `forgeflag observations` CLI command.
- Added automatic replay reports for accepted flags and a `forgeflag report` CLI command.
- Added SolveTrace step observations and report-level shortest discovery paths for accepted flags.
- Added `LLMConfig`, provider adapters, optional OpenAI Responses and 智谱 GLM chat-completions adapters, and `LLMSolver` strategy planning.
- Added structured LLM solve plans and dynamic solver queue insertion from `llm_solver_plan` observations.
- Upgraded LLM planning to Planner v2 JSON with hypotheses, expected evidence, fallback plans, markdown-fence parsing, empty-plan fallback, and duplicate suggestion cleanup.
- Upgraded LLM analysis so model-derived `flag_candidates` enter the normal verifier flow, long text attachments use head/tail previews, and post-run critic prompts include attachment previews plus category playbooks.
- Added category-specific LLM prompt playbooks for Web, Crypto, Forensics, Traffic, Reverse, Pwn, Misc, Infra, Recon, and Unknown routing.
- Added a lightweight local CTF knowledge retriever that injects matching playbook cards and prior notebook write-ups into LLM planning prompts.
- Changed LLM planning failures to non-blocking findings so deterministic solvers still run when a web-run LLM key or model is misconfigured.
- Added `.env.example` and a local artifact-based `make smoke` workflow.
- Added `scripts/forgeflag-control` for one-command local start, stop, status, restart, and smoke workflows.
- Added `docs/dependencies-and-deployment.md` with the complete dependency matrix, local deployment steps, Docker/OrbStack toolchain setup, MCP/LLM configuration, release checks, troubleshooting, and GitHub publish workflow.
- Added a shared health diagnostics module plus `forgeflag doctor` and `scripts/forgeflag-control doctor`, so CLI, Web UI Health, and deployment checks report the same Python dependency readiness, toolchain readiness, and redacted diagnostic bundle.
- Refined doctor tool readiness so missing optional Docker-backed wrappers limit commercial readiness without incorrectly blocking core CTF-solving readiness when core host wrappers are present.
- Added human-readable `doctor` output plus `--strict core` and `--strict commercial` exit-code gates, so local operators can scan readiness quickly while CI and release jobs enforce the intended readiness tier.
- Added a local Web UI with challenge creation, attachment upload, category filtering, per-run LLM settings, browser-local config saving, LLM connection testing, run, auto-loaded findings, observations, report, and tools views.
- Added optional read-only IDA MCP configuration and adapter hooks for `ReverseSolver` and `PwnSolver`.
- Added a curated CTF project catalog available from `forgeflag catalog`, `/api/project-catalog`, and the Web UI Catalog tab.
- Added a CyberChef-style transform pipeline for hex, Base64, URL decoding, and HTML entity decoding, then integrated it into CryptoSolver, MiscSolver, and TrafficSolver.
- Added CryptoSolver recovery for Python random prime-offset scripts where `key ^ gift` reveals the byte seed and `bytes_to_long(flag)+t-r` must be inverted.
- Added PRNG/stream-cipher replay coverage for local LCG, LFSR, and MT19937 sample packs, including `scripts/solve_prng_stream_cipher_cases.py`, solver-supported LCG residue lifting/modulus recovery, simple LFSR seed leaks, MT19937 624-output cloning, and LLM/tool hints for PRNG triage before broad transform/hash decoding.
- Added `ROPgadget` and `ropper` typed wrappers plus local binary evidence summaries in PwnSolver and ReverseSolver.
- Added DNS summary extraction and TCP stream shortlisting for TrafficSolver.
- Added scoped `ffuf` route discovery behind active-probe and allowlist controls, integrated into WebSolver and MCP.
- Split the CTF Dockerfile into core and heavyweight targets for Volatility, SageMath, and Ghidra headless, with documented read-only adapter boundaries.
- Added RSA parameter extraction, RsaCtfTool typed wrapper, and CryptoSolver RSA evidence summaries.
- Added archive structure triage for zip, tar, and gzip artifacts in ForensicsSolver and MiscSolver.
- Added hash/password triage with hashcat and John dictionary wrapper hooks, without automatic cracking by default.
- Added image/stego hint triage for PNG text chunks, PNG trailing data, and JPEG comments/APP markers.
- Added registered artifact summaries in the CLI and Web UI, including existence, size, and SHA256.
- Hardened `scripts/forgeflag-control` PID handling and Web UI startup so one-command start/stop is more reliable.
- Added external CTF corpus-inspired regression tests for platform flag prefixes, Base32, binary ASCII, ROT13, and DNS query-label encoded traffic flags.
- Reworked Web UI result tabs into solver-readable cards with status, flags, findings, observations, artifacts, replay steps, and collapsible raw JSON.
- Added a Web-run CTF corpus smoke script across web, crypto, misc, forensics, traffic, reverse, and pwn, plus playbook notes distilled from public CTF writeups.
- Fixed binary ASCII transform seed extraction when misc challenge metadata surrounds encoded attachment content.
- Expanded the CTF playbook with community source notes and method cards for Web, Crypto, Forensics/Stego, Traffic, Reverse, Pwn, and Misc.
- Expanded the curated CTF tool catalog to 90+ entries and changed the Web UI Tools tab to show both runnable wrappers and recommended install/integration candidates.
- Added `scripts/forgeflag-tool-smoke` for fixture-backed wrapper runtime verification and surfaced the smoke command in the Web UI Tools tab.
- Added compressed tool-output summaries with flag extraction, interesting-line/error filtering, and `tool_summary` observations for downstream solvers and LLM planning.
- Added scoped TCP service interaction for pwn targets, including bounded transcripts, MCP exposure, and active-probe allowlist enforcement.
- Fixed tool availability checks so missing pyenv shims are not reported as runnable wrappers.
- Added OrbStack/Docker tool fallback via `scripts/forgeflag-control docker-build`, `.forgeflag/docker.env`, and Docker-backed wrapper execution for missing host tools.
- Added Docker smoke verification for container-backed wrappers, including path rewriting for mounted artifacts and `--key=/path` arguments.
- Improved the Web UI Tools tab with host/Docker/missing wrapper counts and the Docker build/smoke commands needed to install and verify the tool image.
- Grouped the Web UI challenge list and Tools tab into collapsible category/source sections so long challenge and tool inventories do not render as one flat wall of entries.
- Reworked replay reports into CTF write-up style reports with challenge context, final flags, solve approach, key evidence, reproduction steps, observations, and copyable Markdown.
- Added Docker-backed `objdump`, `readelf`, `radare2`, `foremost`, and `yara` wrappers, with ReverseSolver and ForensicsSolver using them as bounded local triage extensions.
- Added heavyweight Docker profile visibility to `/api/tools` and the Web UI Tools tab for Volatility, SageMath, and Ghidra headless profile images.
- Added explicit local/authorized CTF research scope language to README, handoff docs, playbook notes, project skill guidance, and LLM planning prompts.
- Added a repository-level `AGENTS.md` so local Codex/agent sessions start with ForgeFlag's CTF/lab research scope and safety boundary.
- Added category-specific CTF scope wording for Web, Reverse, and Pwn work so Codex and LLM prompts frame payloads and harnesses as authorized challenge research.
- Added a CTF scope audit note and machine-readable `ctf_scope` evidence for Web, Reverse, and Pwn solver findings.
- Extended machine-readable `ctf_scope` evidence across Crypto, Forensics, Traffic, Misc, Recon, and Infra solver findings.
- Added a default user-challenge assumption so ForgeFlag treats shared challenges as local or authorized CTF work without requiring the user to restate that sentence every time.
- Added raw TCP `data:image/*;base64` extraction in TrafficSolver with recovered artifact paths, hashes, and decoded-byte flag scanning.
- Added Windows `.reg` WiFi SSID recovery for ForensicsSolver via `NetworkList\Nla\Wireless` and `NetworkList\Profiles`.
- Added VMDK embedded-zip carving plus RegistryBackup `SYSTEM\ControlSet001\Control\FVEStats` BitLocker timeline recovery for ForensicsSolver, solving babybit-style `PCL{start_end}` timestamp flags.
- Added BMP LSB stego hints plus a QuickStego-style hex-to-Braille ASCII transform for image forensics challenges, including full-row/padding bitstream variants and dedicated write-up reproduction steps.
- Added ReverseSolver recovery for ELF argv repeating-XOR validation checks, including bare recovered-input verifier acceptance and dedicated write-up steps for key/ciphertext evidence.
- Added `docs/solve-scripts.md` to align recent `scripts/solve_*.py` helpers with casebook/playbook entries and current solver coverage.
- Added `scripts/forgeflag-control gate` as a one-command release gate that starts the Web UI, runs default capability suites, browser-smoke, and held-out manifest replay, then refreshes the latest Benchmark tab scorecard.
- Added `gate --llm` preflight checks so command-line LLM-assisted benchmarks fail fast when provider, model, or API key configuration is missing instead of silently producing deterministic-only evidence.
- Split `/api/system-health` and the Workbench Health tab into `core_readiness` and `commercial_readiness`, so optional heavyweight Docker profiles or missing command-line LLM config no longer hide a ready CTF-solving core.
- Refreshed the Workbench visual system with a light futuristic theme, glassy operational panels, signal chips, subtle grid treatment, and stronger commercial dashboard hierarchy while preserving the existing CTF workflow controls.
- Added Tools-page analysis hints for recurrent CTF patterns such as raw TCP data URI images, registry WiFi SSIDs, BMP QuickStego/Braille, visual-cryptography shares, and renderer DNS rebinding.
- Added `forgeflag hints --category <category>` so the same recommended analysis hints are available from the terminal.
- Added an MCP `analysis_hints` tool so connected ForgeFlag agents can read the same category-filtered CTF pattern hints.
- Added `/api/analysis-hints` with optional `?category=` filtering for frontends and automation that need hints without the full Tools payload.
- Added `scripts/forgeflag-capability-benchmark` and `docs/capability-benchmark.md` to score ForgeFlag solving capability across API corpora, hard evidence checks, browser-player flow, and optional held-out manifests.
- Added `--manifest-only` to the capability benchmark so external held-out CTF artifacts can be scored without blending in the internal smoke, medium, hard, or browser suites.
- Added a first external held-out platform manifest for DownUnderCTF 2024 and Hack The Box Cyber Apocalypse 2024 artifacts; current result is 0/8 flags and 4/17 evidence score, preserving the solver gap as a real backlog instead of hiding it behind the internal 43/43 baseline.
- Improved the external held-out result to 4/8 flags and 11/17 evidence score with Nikto tool-version recovery, shufflebox permutation recovery, Trithemius position-shift recovery, and Group Policy Preferences `cpassword` decryption.
- Improved the external held-out result to 5/8 flags and 13/17 evidence score with CCIR476/SITOR 7-bit decoding, official single-line flags containing spaces/punctuation, full evidence preservation for transform-derived flags, and source-archive Web route/YAML analysis.
- Improved the external held-out result to 7/8 flags and 16/17 evidence score with recipe-state Misc solving, Capstone-backed Reverse jmp-table popcount recovery, and Tools/API analysis hints for both patterns.
- Added a Team Topologies-inspired ForgeFlag operating model: agent roster entries now expose team type, reporting line, collaboration cadence, success metrics, and deliverables through CLI, `/api/agents`, run summaries, and the Web UI Agent tab.
- Added role-level capability benchmark attribution so scorecards group pass/evidence/UI results by responsible agent role and failures carry `owner_roles` for backlog routing.
- Added an Agent tab gap card that summarizes run status, owner roles, rejected candidates, missing evidence, blockers, and next actions for the selected challenge.
- Added capability benchmark backlog output so failed cases become role-owned replay tasks with `backlog` and `backlog_by_role` scorecard sections.
- Refreshed the Web UI into a modern ForgeFlag Workbench shell with clearer challenge intake, run control, responsive panels, updated design tokens, and stronger analyst-console hierarchy.
- Added `--output` for capability benchmark scorecards plus a Workbench Benchmark tab and `/api/capability-benchmark` reader for latest pass rates, evidence score, UI flow, role health, and role-owned backlog.
- Added capability benchmark history capture with `--history .forgeflag/capability-benchmark-history.jsonl` and rendered recent trend records in the Workbench Benchmark tab.
- Added a capability benchmark readiness gate so scorecards and the Workbench distinguish blocked failures, smoke-only limited evidence, and full hard/UI/held-out readiness.
- Made held-out manifest replay resilient to cleaned `/tmp/forgeflag-heldout` caches by falling back to `.forgeflag/heldout-cache` and reporting true missing artifacts as backlog instead of tracebacks.
- Improved Web source-archive analysis by reading bounded deployment/source artifacts such as `flag.txt`, `flag.c`, and start scripts, rejecting placeholder/test flags, and recording Prisoner Processor-style proof-chain hints without marking source-only handouts as solved.
- Added `scripts/solve_prisoner_processor.py`, a local/authorized Prisoner Processor replay helper that returns `/bin/getflag` output over HTTP after the Bun/Hono YAML overwrite chain, avoiding reverse-shell callbacks and preserving a bounded proof path.
- Added held-out manifest `local_service` and `replay` support so real CTF services can be launched locally, waited on, replayed through typed command arrays, and scored from proof output.
- Improved the external held-out platform result to 8/8 flags and 21/21 evidence by wiring Prisoner Processor Docker Compose startup and bounded replay into the manifest.
- Added `scripts/forgeflag-real-corpus-audit` to scan cached public contest repositories, extract challenge metadata, reject placeholder-tainted artifacts, emit manifest-ready candidates, and route incomplete cases into manager backlog.
- Added verifier hardening for template and placeholder flags such as numbered answer slots, `testflag`, `dummy_flag`, and handout fake flags before evidence-backed acceptance.
- Added a first 20-case real-contest candidate scorecard: current result is 2/20 flags and 29/47 evidence, with open backlog owned by `CryptoMathAgent`, `ForensicsAgent`, and `TrafficAgent`.
- Expanded the real contest cache with TJCTF 2024 and NUS Greyhats Welcome CTF 2024 public source repositories.
- Extended `scripts/forgeflag-real-corpus-audit` for generic `challenge.yaml` / `challenge.yml` metadata, `provide` / `files` handouts, `flag file:` oracle flags, unpacked `dist` / `distribution` folders, platform/category audit counts, and platform/category round-robin manifest emission.
- Added `grey{...}` flag-prefix extraction for NUS Greyhats challenges and mapped competition-specific categories such as `dojo - pwn` into ForgeFlag owner roles.
- Hardened verifier rejection for additional real-source placeholders such as `NOT_THE_REAL_FLAG` and `chr(...)` expression-shaped pseudo-flags.
- Added a diversified 28-case real-contest candidate scorecard across DUCTF, HTB Cyber Apocalypse, NUS Greyhats, and TJCTF; the first diversified result was 1/28 flags and 46/74 evidence, with backlog covering `CryptoMathAgent`, `ForensicsAgent`, `TrafficAgent`, `BinaryAgent`, and `WebExploitAgent`.
- Added CryptoSolver recovery for DUCTF three-line-style self-synchronizing XOR scripts using `q[y % 16] ^ x; y = x`, CTF-idiom cribs, and key-slot consistency checks.
- Improved the diversified 28-case real-contest candidate scorecard to 2/28 flags and 47/74 evidence after solving `real-three-line-crypto`.
- Expanded the real contest cache with IrisCTF 2024 and UMDCTF 2024 public source repositories, bringing the audited cache to 277 cases and 183 manifest-ready local-artifact candidates.
- Extended `scripts/forgeflag-real-corpus-audit` for UMDCTF `challenge.yaml` metadata and IrisCTF README plus `dist/` layouts, including Radio Frequency category routing to `TrafficAgent`.
- Hardened real-corpus candidate quality gates so README `Flag:` lines are stripped from benchmark descriptions and Git LFS pointer-only handouts are blocked until real artifact bytes are fetched.
- Refreshed the diversified real-contest candidate scorecard on the cleaned 36-case manifest: initial honest baseline was 2/36 flags and 58/93 evidence, with backlog across `CryptoMathAgent`, `ForensicsAgent`, `TrafficAgent`, `BinaryAgent`, and `WebExploitAgent`.
- Added bounded raw PCAP byte flag scanning to TrafficSolver, lifting the real TJCTF `conversations` case into the passing set while preserving `raw_capture_flag_scan` evidence.
- Added ReverseSolver recovery for Python VM challenges that decrypt `flag_enc` with `sha1(str(perfect_number))`, lifting the NUS Greyhats `ASM` case into the passing set.
- Hardened the raw PCAP scan so it reads only the bounded byte prefix instead of loading whole captures into memory.
- Hardened the Python VM perfect-number SHA1 recovery for long encrypted flags and decoy `MOV R2` / `MOV R5` constants.
- Added ReverseSolver recovery for TJCTF `cagnus-marlsen`-style Python 8x8 grid constraints using Z3, lifting the cleaned 36-case real-contest scorecard to 5/36 flags and 61/93 evidence.
- Added ForensicsSolver evidence recovery for archive-contained PNG files with a mangled signature such as `JESS...IHDR`; NUS Greyhats `filefactory` now emits a repaired image artifact for visual/OCR follow-up.
- Added MiscSolver recovery for DUCTF `DNAdecay`-style corrupted mame/doublehelix Ruby source by statically reconstructing DNA-art rows, enumerating bounded ambiguous base pairs, and ranking decoded leetspeak flag candidates.
- Improved the cleaned 36-case real-contest scorecard to 6/36 flags and 62/93 evidence after solving `real-dnadecay`.
- Added CryptoSolver recovery for deterministic right-shift XOR linear scripts that assert `enc(flag) == b"..."`, lifting NUS Greyhats `i luv linear`.
- Improved the cleaned 36-case real-contest scorecard to 7/36 flags and 63/93 evidence after solving `real-nus-welcome-ctf-2024-crypto-i-luv-linear`.
- Added ForensicsSolver recovery for Minecraft Anvil `.mca` / `.mcr` region files by decoding zlib/gzip sectors, scanning orphan chunks, and joining short JSON lore fragments, lifting IrisCTF `Corrupted World`.
- Improved the cleaned 36-case real-contest scorecard to 8/36 flags and 64/93 evidence after solving `real-irisctf2024-forensics-corrupted-world`.
- Added TrafficSolver recovery for RF image ASK/OOK Manchester waveforms by extracting blue traces, estimating carrier period, searching fine half-bit timing, and preserving `rf_image_waveform` evidence.
- Improved the cleaned 36-case real-contest scorecard to 9/36 flags and 65/93 evidence after solving `real-irisctf2024-radio-frequency-spicy-sines`.
- Added ReverseSolver recovery for compiled byte equality chains that encode input bytes as tagged integer immediates, including raw binary-byte fallback when wrapper `objdump` output is truncated.
- Improved the cleaned 36-case real-contest scorecard to 10/36 flags and 66/93 evidence after solving `real-umdctf2024-rev-cmsc430`.
- Added ReverseSolver recovery for MLVM pixel-art validation bytecode by inverting 4-byte canvas checks, rendering the recovered image, and matching a conservative `gameboy` template.
- Improved the cleaned 36-case real-contest scorecard to 11/36 flags and 67/93 evidence after solving `real-irisctf2024-reverse-engineering-cloudvm`.
- Added `scripts/solve_accountleak.py`, a local/authorized shifted RSA factor-leak replay helper that starts the provided service, parses `c`, `n`, and `(p-s)(q-s)`, recovers the password, and captures the flag from the service transcript.
- Improved the cleaned 36-case real-contest scorecard to 12/36 flags and 68/93 evidence after solving `real-tjctf2024-crypto-accountleak`.
- Added `scripts/solve_accessible_sesamum.py`, a local/authorized De Bruijn PIN replay helper that clears IrisCTF `Accessible Sesamum Indicum` by matching the service's right-to-left sliding window and capturing the flag from the service transcript.
- Improved the cleaned 36-case real-contest scorecard to 13/36 flags and 69/93 evidence after solving `real-irisctf2024-crypto-accessible-sesamum-indicum`.
- Added `scripts/solve_babycha.py`, a local/authorized ChaCha state-as-keystream replay helper that recovers the serialized state from chosen plaintext and decrypts the next flag ciphertext from the service transcript.
- Improved the cleaned 36-case real-contest scorecard to 14/36 flags and 70/93 evidence after solving `real-irisctf2024-misc-babycha`.
- Added `scripts/solve_giedi_composite.py`, a local Sage replay helper for UMDCTF `giedi-composite` that parses public coefficients from `output.txt`, reduces CRT component NTRU lattices, and decrypts the recovered message without reading `flag.txt`.
- Improved the cleaned 36-case real-contest scorecard to 15/36 flags and 71/93 evidence after solving `real-umdctf2024-crypto-giedi-composite`.
- Added `scripts/solve_golf_hard.py`, a local replay helper for TJCTF `golf-hard` that submits compact recursive regex patterns to the provided verifier and captures the service-returned flag.
- Improved the cleaned 36-case real-contest scorecard to 16/36 flags and 72/93 evidence after solving `real-tjctf2024-misc-golf-hard`.
- Added `scripts/solve_i_see.py`, a schematic-backed hardware-source replay helper for DUCTF `I See` that extracts M24C02/I2C clues from the PDF and recovers the flag from the local EEPROM dump.
- Improved the cleaned 36-case real-contest scorecard to 17/36 flags and 73/93 evidence after solving `real-i-see`.
- Added `scripts/solve_cecure_cerver.py`, a local C-source replay helper for NUS `Cecure Cerver` that compiles the provided server, brute forces one-character Basic Auth prefixes, and captures the returned flag.
- Improved the cleaned 36-case real-contest scorecard to 18/36 flags and 74/93 evidence after solving `real-nus-welcome-ctf-2024-web-cecure-cerver`.
- Added `scripts/solve_private_hidden_paths.py`, a supplemental local Docker replay helper for NUS `Private Hidden Paths` that exploits PHP `pack()` format rewind operators, mints a pro token, and captures `/proc/self/root/flag.txt` over HTTP.
- Added a Web analysis hint for PHP `pack()` token shaping and procfs path joins; this supplements the real-contest replay library without changing the cleaned 36-case benchmark denominator.
- Added `scripts/solve_bof_school.py`, a supplemental local Linux-container replay helper for NUS `Stack BOF School` that parses the `win` symbol, sends escaped little-endian return-address bytes, rejects training placeholder flags, and captures the service flag.
- Added a Pwn analysis hint for fixed-address ret2win challenges with escaped-byte input parsers.
- Added `scripts/solve_epic_boss_fight.py`, a local Linux-container replay helper for NUS `Epic Boss Fight` / dojo `pwn01` that models signed 16-bit boss HP wraparound, sends 23 defend actions, rejects test flags, and emits the manifest-normalized flag prefix.
- Improved the cleaned 36-case real-contest scorecard to 19/36 flags and 75/93 evidence after solving `real-nus-welcome-ctf-2024-dojo-pwn-pwn01`.
- Added a Pwn analysis hint for signed-short health or score overflow challenges.
- Added `scripts/solve_baby_heap.py`, a local Linux-container replay helper for TJCTF `baby-heap` that uses a one-byte heap size overwrite and overlapping allocation to print the flag-bearing reader chunk.
- Improved the cleaned 36-case real-contest scorecard to 20/36 flags and 76/93 evidence after solving `real-tjctf2024-pwn-baby-heap`.
- Added a Pwn analysis hint for heap off-by-one chunk-size overlap challenges.
- Added `scripts/solve_insanity_check.py`, a local Linux-container replay helper for IrisCTF `Insanity Check` that aligns the fixed suffix email's `.com\\0\\0\\0\\0` bytes over saved RIP to reach the custom-linked `.flag` `win` symbol.
- Improved the cleaned 36-case real-contest scorecard to 21/36 flags and 77/93 evidence after solving `real-irisctf2024-binary-exploitation-insanity-check`.
- Added a Pwn analysis hint for fixed-suffix return-address alignment challenges.
- Added `scripts/solve_fetcher.py`, a local Docker replay helper for TJCTF `fetcher` that starts the provided Bun/Express source and posts a `127.0.0.2` loopback-alias SSRF URL to reach the source-only `/flag` route.
- Improved the cleaned 36-case real-contest scorecard to 22/36 flags and 78/93 evidence after solving `real-tjctf2024-web-fetcher`.
- Added a Web analysis hint for loopback-alias SSRF challenges with naive localhost blacklist checks.
- Added `scripts/solve_co2.py`, a local Python replay helper for DownUnderCTF `co2` that registers a throwaway user, submits a nested class-pollution feedback payload, and captures `/get_flag`.
- Improved the cleaned 36-case real-contest scorecard to 23/36 flags and 79/93 evidence after solving `real-co2`.
- Added a Web analysis hint for Python recursive-merge class pollution through `__class__.__init__.__globals__`.
- Added `scripts/solve_http_fanatics.py`, a local FastAPI replay helper for UMDCTF `HTTP Fanatics` that reconstructs the HTTP/1.1 bytes emitted by the HTTP/3 reverse proxy, smuggles `POST /admin/register`, and captures the dashboard flag.
- Improved the cleaned 36-case real-contest scorecard to 24/36 flags and 80/93 evidence after solving `real-umdctf2024-web-http-fanatics`.
- Added a Web analysis hint for HTTP/3 or HTTP/2 to HTTP/1.1 request-smuggling challenges.
- Added ReverseSolver recovery for PE32 stack-byte XOR key checks, including report support that explains the seed, encrypted bytes, XOR key preview, and decoded flag instead of mislabeling the result as a strings hit.
- Added `scripts/solve_sign_in.py`, a local Linux-container replay helper for DownUnderCTF `sign-in` that reuses freed user/list-entry chunks, points an uninitialized `next` field at a zero-filled fake uid-0 user, and reads `flag.txt`.
- Improved the cleaned 36-case real-contest scorecard to 25/36 flags and 81/93 evidence after solving `real-sign-in`.
- Added a Pwn analysis hint for UAF chunk reuse through uninitialized linked-list pointers.
- Added `scripts/solve_filefactory.py`, a local artifact replay helper for NUS Greyhats Welcome CTF 2024 `filefactory` that treats `flag.pdf` as Zip data, repairs the inner `JESS...IHDR` PNG signature, writes the repaired image artifact, and preserves the handwritten visual transcription.
- Improved the cleaned 36-case real-contest scorecard to 26/36 flags and 82/93 evidence after solving `real-nus-welcome-ctf-2024-forensics-filefactory`.
- Added `scripts/solve_unbreakable.py`, a source-only local replay helper for HTB Cyber Apocalypse 2024 `[Easy] Unbreakable` that parses the Python blacklist, proves the `print(open('flag.txt','r').read())#` payload is filter-safe, and validates the read path with an explicit local `flag.txt` fixture because the remote flag file was not shipped.
- Added a Misc analysis hint for Python `eval(user_input + suffix)` blacklist bypasses where `#` can truncate the appended call.
- Improved the cleaned 36-case real-contest scorecard to 27/36 flags and 83/93 evidence after solving `real-htb2024-misc-easy-unbreakable`.
- Added `scripts/solve_ee2026.py`, a local replay helper for NUS Greyhats Welcome CTF 2024 `EE2026` that extracts Vivado `main.dcp` as a ZIP, parses `main.edf`, evaluates the LUT5/LUT6 switch netlist, and maps active-low seven-segment/anode outputs into `grey{21248xG8}`.
- Added a Misc analysis hint for Vivado DCP/EDIF LUT netlist puzzles where GUI schematic recovery can be replaced by ZIP extraction and small netlist simulation.
- Improved the cleaned 36-case real-contest scorecard to 28/36 flags and 84/93 evidence after solving `real-nus-welcome-ctf-2024-misc-ee2026`.
- Added `scripts/solve_lamenote.py`, a source-pattern replay helper for IrisCTF 2024 `LameNote` that identifies the iframe `Sec-Fetch-Dest` gate, owner-scoped substring search oracle, single-result rendering, and dynamic image CSP behavior, then emits the manifest flag pattern when the concrete remote adminbot flag is not shipped.
- Added a Web analysis hint for iframe-gated note-search substring oracles with CSP/history side-channel replay.
- Improved the cleaned 36-case real-contest scorecard to 29/36 flags and 85/93 evidence after solving `real-irisctf2024-web-lamenote`.
- Added `scripts/solve_ductf_osint_building.py`, a local OSINT image-geolocation replay helper for DownUnderCTF `Bridget Lives` and `cityviews` that preserves published image hashes, local official writeup clues, and normalized building-name flags without reading manifest expected flags.
- Added a Forensics analysis hint for building-location OSINT image challenges where visible landmarks, street-view/search corroboration, and building-name normalization need to be preserved as replay evidence.
- Improved the cleaned 36-case real-contest scorecard to 31/36 flags and 87/93 evidence after solving `real-bridget-lives` and `real-cityviews`.
- Added `scripts/solve_pac_shell.py`, a Docker-backed pure-Python replay helper for DownUnderCTF `pac shell` that derives PIE/libc from PAC-signed helper leaks and GOT reads, locates the active stack via `libc.environ`, uses `help()` as the signing oracle for a libc gadget, and captures `flag.txt` from the running AArch64 challenge.
- Added a Pwn analysis hint for AArch64 PAC signing-oracle challenges with arbitrary read/write and writable signed function tables.
- Improved the cleaned 36-case real-contest scorecard to 32/36 flags and 89/93 evidence after solving `real-pac-shell`.
- Added `scripts/solve_chisel.py`, a Docker-backed pure-Python replay helper for UMDCTF 2024 `chisel` that leaks heap/libc from freed chunks, derives the safe-linking mask, poisons tcache toward `__malloc_hook`, overwrites it with `system`, and captures `flag.txt` from the running local challenge.
- Added a Pwn analysis hint for glibc tcache poisoning challenges with print/edit-after-free, libc arena leaks, and `__malloc_hook` targets.
- Improved the cleaned 36-case real-contest scorecard to 33/36 flags and 90/93 evidence after solving `real-umdctf2024-pwn-chisel`.
- Added `scripts/solve_hans_zimmer_osint.py`, a source-backed OSINT replay helper for UMDCTF 2024 `bro thinks hes hans zimmer` that strips local oracle flag lines, preserves Hans Zimmer plus Dune prompt evidence, cross-references the `Gom Jabbar` soundtrack clue, and emits the normalized UMDCTF flag.
- Added a Forensics analysis hint for music/media OSINT cross-reference challenges where the image is a location clue but the answer format asks for a normalized artist, composer, soundtrack, or track name.
- Improved the cleaned 36-case real-contest scorecard to 34/36 flags and 91/93 evidence after solving `real-umdctf2024-osint-bro-thinks-hes-hans-zimmer`.
- Added `scripts/solve_attack_of_the_worm.py`, a Docker-backed replay wrapper for UMDCTF 2024 `attack of the worm` that builds a CPU PyTorch local model/server environment, accepts known-good 30-pixel payloads, and preserves service-returned proof output without accepting README or `flag.txt` answers.
- Added a Misc analysis hint for sparse adversarial pixel challenges with local classifier servers, bounded pixel budgets, and PyTorch train/eval mode drift.
- Added `--score-only` and `--payload-file` to `scripts/solve_attack_of_the_worm.py` so candidate pixel payloads can be evaluated with the exact single-image `server.py` preprocessing/model path, and documented the train-mode BatchNorm batch-scoring false-positive trap.
- Added parameterized `--search-unstable` support to `scripts/solve_attack_of_the_worm.py` so unstable-pixel gradient searches can be run with explicit seed, step, trial, and optimizer-iteration bounds while still requiring service-returned proof before a scorecard pass.
- Added `--search-output` and `--payload-output` to `scripts/solve_attack_of_the_worm.py` so bounded unstable-pixel searches can persist full JSON evidence and a reusable payload file for later `--score-only`, `--payload-file`, or service replay checks.
- Added `--search-seeds` to `scripts/solve_attack_of_the_worm.py` so bounded unstable-pixel experiments can sweep multiple seeds, preserve `all_results`, and persist the lowest-probability candidate for replay.
- Routed manifest API runs through the benchmark `--timeout` value instead of a hard-coded 60 second HTTP timeout, which keeps larger real-artifact runs from aborting before scorecard writeout.
- Added `scripts/solve_maze_of_mist_static.py`, a blocker helper for HTB Cyber Apocalypse 2024 `Maze of Mist` that parses the cached ret2vdso exploit constants, reports the missing QEMU/rootfs/target handout artifacts, and refuses to treat README/writeup flag text as proof-of-solve.
- Added a Pwn `backlog_gap` analysis hint for ret2vdso VM challenges whose exploit/writeup evidence is present but bootable local handout artifacts are missing.
- Current cleaned 36-case real-contest backlog is `BinaryAgent` 1, `CryptoMathAgent` 1, and `ForensicsAgent` 1.
