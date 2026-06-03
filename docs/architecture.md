# ForgeFlag Architecture

## Layers

### 1. Execution Layer

The execution layer runs tools in an isolated, auditable environment. The local starter implementation includes safe wrappers only; production competition usage should run tool workers in containers or disposable VMs.

### 2. Tool Layer

Tools return structured results with evidence and artifacts. Solvers should never depend on unstructured terminal output when a parser can be used.

### 3. Agent Layer

The agent layer is split into a manager and specialist solvers. Each solver owns its own local reasoning state and writes only structured notes to the shared notebook.

ForgeFlag also has a declarative subagent roster in `forgeflag.agent_roster`. The roster gives professional identities and operating contracts to the manager, LLM planner, category specialists, evidence judge, and browser-player QA role without replacing the existing solver interface.

## Core Components

### Manager

The manager dispatches a challenge to solvers based on category and tags, then asks the verifier to inspect flag candidates. During a run, it can also consume `llm_solver_plan` observations and insert suggested solvers into the remaining queue without letting the LLM execute tools directly.

Each run summary includes an `agent_roster` section showing the coordinator, selected category, solver queue, and enabled subagent identities that apply to the challenge.

### Subagent Roster

The default roster contains `ChallengeTriageAgent`, `LLMRoutePlannerAgent`, `WebExploitAgent`, `CryptoMathAgent`, `BinaryAgent`, `ForensicsAgent`, `TrafficAgent`, `EvidenceJudgeAgent`, and `BrowserPlayerQAAgent`. It can be listed with `forgeflag agents` and persisted to `.forgeflag/agent-roster.json` with `forgeflag agents --write-default`.

The roster is configuration, not a secret store. API keys stay in runtime LLM config or Web request payloads and are not written to the roster file.

### Shared Notebook

The notebook is the durable blackboard. It stores challenges, attachment paths, findings, distilled observations, tool runs, and run summaries in SQLite.

### Observer

The observer filters noisy solver output into high-value observations. The manager reloads these observations before each solver call, so later solvers inherit concise progress signals without reading every raw finding or tool log.

### Tool Output Compression

Tool runs keep their raw stdout/stderr in SQLite, but ForgeFlag also stores a compact `compressed_summary` with extracted flags, interesting lines, errors, hints, truncation state, and tool metadata. Each scoped tool run with a challenge id is promoted into a `tool_summary` observation so later solvers and LLM planning can consume concise evidence instead of long command output.

### Interactive Service Sessions

ForgeFlag starts with a bounded `tcp_interact` primitive for CTF service targets. It requires active probing and an allowlisted host, opens a single TCP connection, optionally sends a small payload, captures a bounded transcript, and records the result as ordinary tool evidence. `PwnSolver` uses this when a pwn challenge has a service target but no binary attachment, preserving the transcript for later pwntools-style follow-up without attempting automatic exploitation.

### SolveTrace

After each solver run, the manager records a `solve_trace_step` observation with the step index, solver status, finding summaries, flag candidates, progress signal, and any matching LLM plan rationale. Write-ups use these trace observations to expose the full solver timeline and a per-flag shortest discovery path.

### LLM Planning

`LLMSolver` is optional and disabled unless an LLM provider is configured. The prompt includes a category-specific playbook for Web, Crypto, Forensics, Traffic, Reverse, Pwn, Misc, Infra, Recon, or Unknown routing, then asks for free-form strategy text or compact Planner v2 JSON with `summary`, `hypotheses`, `suggested_solvers`, `next_actions`, `tool_hints`, `expected_evidence`, and `fallback_plan`; the observer promotes structured plans into shared observations for the manager to use in solver scheduling.

After an LLM-enabled run stalls without an accepted flag, the manager can call a Post-run Critic. The critic compares findings, observations, solver results, and missing evidence, then records an `llm_post_run_critic` observation with blockers, missing evidence, suggested solvers, tool hints, next actions, and rerun reason.

### Local Knowledge Retrieval

ForgeFlag has a lightweight local retriever for LLM planning. It indexes method-card blocks from `docs/ctf-playbook.md` and successful write-up Markdown already stored in the notebook, then ranks blocks by category match and keyword overlap with the current challenge text, tags, attachments, and observations. Retrieved blocks are injected into the LLM prompt as `retrieved_knowledge` without requiring an external vector database.

### IDA MCP Adapter

IDA MCP support is optional and disabled by default. When `FORGEFLAG_IDA_MCP_ENABLED=true`, the manager injects a read-only IDA adapter into `ReverseSolver` and `PwnSolver`. Those solvers use registered binary attachments only, call the configured MCP command, and write structured function names, strings, tool-call evidence, and flag candidates to the notebook.

### Write-up

When the verifier accepts a flag, the report builder traces the shortest evidence path from accepted flag back to matching findings and observations. The primary output is a CTF write-up with conclusion, solving idea, reproduction steps, and key evidence. Legacy replay data remains available for compatibility and debugging, and the latest write-up can be retrieved with `forgeflag report <challenge_id>`.

### Artifact Workspace

Local challenge attachments are copied into `.forgeflag/artifacts/<challenge_id>/` before solver runs. Solvers consume these managed paths instead of arbitrary shell input, keeping artifact access auditable and scoped to registered files.

### Harness

The harness tracks iteration count, repeated actions, budget pressure, and stall conditions. Its job is to keep long CTF runs from becoming repetitive or context-poisoned.

### Solvers

Solvers share the same interface:

```python
class Solver:
    name: str
    supported_categories: set[str]
    def solve(self, context: SolverContext) -> SolverResult: ...
```

Forensics and traffic are split by artifact type. `ForensicsSolver` owns broad local artifact triage; `TrafficSolver` owns packet capture workflows and may also run on forensics challenges when PCAP attachments are present.

## NSFOCUS AI Team Alignment

ForgeFlag follows the same broad control/communication/execution split described in public NSFOCUS AI CTF writeups: `Manager` handles global scheduling, SQLite notebook plus observations provide non-blocking shared memory, solvers perform specialist execution, and `Harness` guards long-running work from repetitive loops.

## Safety Boundary

ForgeFlag requires an explicit scope policy for active target interaction. Only authorized CTF targets and lab hosts should be allowed.
