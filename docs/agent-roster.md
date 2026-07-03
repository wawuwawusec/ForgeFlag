# ForgeFlag Subagent Roster

ForgeFlag uses a scoped roster instead of an unbounded agent swarm. The goal is to make each role explicit, auditable, and cheap enough to run during CTF work.

The runtime remains `Manager -> Solvers -> Notebook -> Verifier -> Write-up`. The roster adds professional identities and operating contracts on top of existing solvers. See [ForgeFlag Team Operating Model](team-operating-model.md) for the manager/team cadence and metrics.

## Commands

List the active roster:

```bash
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite agents
```

Write the default project config:

```bash
.venv/bin/forgeflag --db .forgeflag/notebook.sqlite agents --write-default
```

The generated config lives at:

```text
.forgeflag/agent-roster.json
```

The file is safe to edit and does not store LLM API keys.

## Rate-limit-safe Work Policy

The roster also carries a machine-readable `subagent_work_policy`. The default policy is intentionally conservative:

- `mode: conservative`
- `max_parallel: 1`
- `cooldown_seconds: 120`
- `failure_circuit_breaker: 1`
- `prefer_local_verification: true`
- `blocked_after`: `429 Too Many Requests`, `rate limit`, `quota`

In practice this means ForgeFlag should use one subagent-style investigation at a time, stop immediately after a rate-limit signal, and switch to local verification: unit tests, deterministic solvers, tool smoke checks, and `scripts/forgeflag-web-player-benchmark`.

Recommended subagent uses are narrow:

- independent code review after deterministic tests pass
- read-only architecture exploration with no shared file edits
- disjoint implementation work with explicit file ownership

Avoid parallel benchmark runners, repeated reviewer retries, or multiple agents calling the same LLM provider during quota pressure.

## Runtime Effect

The roster now influences the solver queue:

- enabled agents contribute their declared `solvers` in roster order
- disabled agents remove their owned solvers from the managed queue
- custom/injected test solvers that are not named in the roster pass through unchanged
- `LLMSolver` is listed by the route-planner identity, but it only runs when the configured LLM provider is enabled
- `Verifier` and `ReportBuilder` are role markers for evidence judging and write-up work, not executable solvers

For example, disabling `WebExploitAgent` removes `WebSolver` from Web challenge runs while keeping `ChallengeTriageAgent`/`ReconSolver` available. Moving `TrafficAgent` earlier in the JSON makes traffic-related solvers run earlier for matching categories.

## Default Roles

| Role | Team type | Cadence | Purpose |
| --- | --- | --- | --- |
| `ForgeFlagManager` | manager | continuous | Coordinates scoped solving, shared evidence, verification, write-up generation, benchmark status, and improvement backlog. |
| `ChallengeTriageAgent` | stream-aligned | per challenge | Reads statement, metadata, and attachments to correct category routing before deep solving. |
| `LLMRoutePlannerAgent` | enabling | when deterministic routing stalls | Uses the configured LLM for hypotheses, solver route planning, expected evidence, and fallback actions. |
| `WebExploitAgent` | stream-aligned | per web challenge | Handles scoped Web analysis: routes, source sinks, API leaks, JWT/session, SSRF, path traversal, and allowlisted probing. |
| `CryptoMathAgent` | complicated-subsystem | per crypto or math-heavy misc challenge | Handles crypto primitive recognition, encoding transforms, XOR/Vigenere/RSA/hash triage, and external math-tool recommendations. |
| `BinaryAgent` | complicated-subsystem | per reverse or pwn challenge | Handles Reverse and Pwn triage: strings, `objdump`/`readelf`, radare2 hints, checksec, gadgets, ret2win, format string, IDA/Ghidra routes, and exploit templates. |
| `ForensicsAgent` | stream-aligned | per forensics or file-heavy misc challenge | Handles local artifact triage, images, archives, metadata, stego hints, carving/YARA follow-up, scripts, and evidence promotion. |
| `TrafficAgent` | stream-aligned | per traffic or pcap-backed challenge | Handles PCAP reconstruction across DNS, HTTP, SMTP, FTP, IRC-style streams, TCP streams, and exported objects. |
| `EvidenceJudgeAgent` | enabling | every run | Accepts only evidence-backed flags, tracks rejected candidates, and keeps reproduction-focused write-ups. |
| `BrowserPlayerQAAgent` | enabling | after UI or workflow changes | Uses the Web UI like a CTF player via `scripts/forgeflag-web-player-benchmark` to catch workflow regressions. |

Each role now exposes `team_type`, `reports_to`, `cadence`, `success_metrics`, and `deliverables` through `forgeflag agents`, `/api/agents`, run summaries, and the Web UI Agent tab.

## Web UI

The Agent tab shows:

- configured subagent identities from `/api/agents`
- team type, reporting line, collaboration cadence, success metrics, and deliverables
- the active `subagent_work_policy`, including serial execution and 429 circuit breaker settings
- agents that participated in the latest run summary
- LLM planning cards
- action queue changes
- Post-run Critic feedback
- tool summaries
- SolveTrace
- shortest discovery path

This keeps the answerer view focused on who did what and which evidence supports the result.

## Operating Rules

- Default subagent work is local-first and serial. Keep `max_parallel` at `1` unless quota headroom is known and the task has clean file ownership boundaries.
- A single `429 Too Many Requests`, rate-limit, or quota error trips the circuit breaker. Do not start retry loops; wait for cooldown and continue with local checks.
- LLM agents plan and critique; they do not directly execute arbitrary tools or submit unsupported flags.
- Active network probing remains gated by allowlisted hosts and `active_probe`.
- IDA MCP and heavy tool integrations stay disabled/read-only by default unless explicitly configured.
- The roster config may disable or rename roles, but solver names should stay exact so Manager scheduling and Planner v2 suggestions continue to work.
- The verifier and write-up builder remain the final authority for accepted flags and reproducible steps.

## Next Expansion

The current roster is declarative and queue-aware. The next useful step is to make benchmarks report role-level scores:

- deterministic-only versus GLM-assisted browser-player tests
- hard benchmark scorecards by role
- optional parallel sidecar investigations for independent challenge families
