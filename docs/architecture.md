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

The manager dispatches a challenge to solvers based on category and tags, then asks the verifier to inspect flag candidates.

### Shared Notebook

The notebook is the durable blackboard. It stores challenges, findings, tool runs, and run summaries in SQLite.

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

## Safety Boundary

ForgeFlag requires an explicit scope policy for active target interaction. Only authorized CTF targets and lab hosts should be allowed.

