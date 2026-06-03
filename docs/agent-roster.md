# ForgeFlag Subagent Roster

ForgeFlag uses a scoped roster instead of an unbounded agent swarm. The goal is to make each role explicit, auditable, and cheap enough to run during CTF work.

The runtime remains `Manager -> Solvers -> Notebook -> Verifier -> Write-up`. The roster adds professional identities and operating contracts on top of existing solvers.

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

## Default Roles

| Role | Purpose |
| --- | --- |
| `ForgeFlagManager` | Coordinates scoped solving, shared evidence, verification, and write-up generation. |
| `ChallengeTriageAgent` | Reads statement, metadata, and attachments to correct category routing before deep solving. |
| `LLMRoutePlannerAgent` | Uses the configured LLM for hypotheses, solver route planning, expected evidence, and fallback actions. |
| `WebExploitAgent` | Handles scoped Web analysis: routes, source sinks, API leaks, JWT/session, SSRF, path traversal, and allowlisted probing. |
| `CryptoMathAgent` | Handles crypto primitive recognition, encoding transforms, XOR/Vigenere/RSA/hash triage, and external math-tool recommendations. |
| `BinaryAgent` | Handles Reverse and Pwn triage: strings, checksec, gadgets, ret2win, format string, IDA/Ghidra routes, and exploit templates. |
| `ForensicsAgent` | Handles local artifact triage, images, archives, metadata, stego hints, scripts, and evidence promotion. |
| `TrafficAgent` | Handles PCAP reconstruction across DNS, HTTP, SMTP, FTP, IRC-style streams, TCP streams, and exported objects. |
| `EvidenceJudgeAgent` | Accepts only evidence-backed flags, tracks rejected candidates, and keeps reproduction-focused write-ups. |
| `BrowserPlayerQAAgent` | Uses the Web UI like a CTF player via `scripts/forgeflag-web-player-benchmark` to catch workflow regressions. |

## Web UI

The Agent tab shows:

- configured subagent identities from `/api/agents`
- agents that participated in the latest run summary
- LLM planning cards
- action queue changes
- Post-run Critic feedback
- tool summaries
- SolveTrace
- shortest discovery path

This keeps the answerer view focused on who did what and which evidence supports the result.

## Operating Rules

- LLM agents plan and critique; they do not directly execute arbitrary tools or submit unsupported flags.
- Active network probing remains gated by allowlisted hosts and `active_probe`.
- IDA MCP and heavy tool integrations stay disabled/read-only by default unless explicitly configured.
- The roster config may disable or rename roles, but solver names should stay exact so Manager scheduling and Planner v2 suggestions continue to work.
- The verifier and write-up builder remain the final authority for accepted flags and reproducible steps.

## Next Expansion

The current roster is declarative. The next useful step is to let the roster influence solver ordering and benchmark modes:

- category-specific role priority
- deterministic-only versus GLM-assisted browser-player tests
- hard benchmark scorecards by role
- optional parallel sidecar investigations for independent challenge families
