# ForgeFlag Architecture

## Layers

### 1. Execution Layer

The execution layer runs tools in an isolated, auditable environment. The local starter implementation includes safe wrappers only; production competition usage should run tool workers in containers or disposable VMs.

### 2. Tool Layer

Tools return structured results with evidence and artifacts. Solvers should never depend on unstructured terminal output when a parser can be used.

### 3. Agent Layer

The agent layer is split into a manager and specialist solvers. Each solver owns its own local reasoning state and writes only structured notes to the shared notebook.

## Core Components

### Manager

The manager dispatches a challenge to solvers based on category and tags, then asks the verifier to inspect flag candidates. During a run, it can also consume `llm_solver_plan` observations and insert suggested solvers into the remaining queue without letting the LLM execute tools directly.

### Shared Notebook

The notebook is the durable blackboard. It stores challenges, attachment paths, findings, distilled observations, tool runs, and run summaries in SQLite.

### Observer

The observer filters noisy solver output into high-value observations. The manager reloads these observations before each solver call, so later solvers inherit concise progress signals without reading every raw finding or tool log.

### SolveTrace

After each solver run, the manager records a `solve_trace_step` observation with the step index, solver status, finding summaries, flag candidates, progress signal, and any matching LLM plan rationale. Reports use these trace observations to expose the full solver timeline and a per-flag shortest discovery path.

### LLM Planning

`LLMSolver` is optional and disabled unless an LLM provider is configured. It may return free-form strategy text or compact Planner v2 JSON with `summary`, `hypotheses`, `suggested_solvers`, `next_actions`, `tool_hints`, `expected_evidence`, and `fallback_plan`; the observer promotes structured plans into shared observations for the manager to use in solver scheduling.

### IDA MCP Adapter

IDA MCP support is optional and disabled by default. When `FORGEFLAG_IDA_MCP_ENABLED=true`, the manager injects a read-only IDA adapter into `ReverseSolver` and `PwnSolver`. Those solvers use registered binary attachments only, call the configured MCP command, and write structured function names, strings, tool-call evidence, and flag candidates to the notebook.

### Replay Report

When the verifier accepts a flag, the report builder traces the shortest evidence path from accepted flag back to matching findings and observations. The latest report is stored in the run summary and can be retrieved with `forgeflag report <challenge_id>`.

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
