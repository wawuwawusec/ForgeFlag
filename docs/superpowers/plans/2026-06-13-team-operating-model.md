# ForgeFlag Team Operating Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a lightweight team operating model so ForgeFlag has a top-level manager, explicit role teams, shared metrics, and a repeatable improvement cadence.

**Architecture:** Extend the existing `AgentRoster` model instead of creating a separate organization system. Each `AgentIdentity` gains team metadata that is serialized through CLI/API/Web UI, while docs explain how the roles collaborate around benchmarks, casebook writeback, and CTF scope controls.

**Tech Stack:** Python dataclasses, ForgeFlag CLI/API/Web UI, unittest, Markdown docs.

---

### Task 1: Roster Schema

**Files:**
- Modify: `src/forgeflag/agent_roster.py`
- Test: `tests/test_agent_roster.py`

- [ ] Add failing tests for `team_type`, `reports_to`, `cadence`, `success_metrics`, and `deliverables`.
- [ ] Extend `AgentIdentity` with those fields and preserve backwards compatibility for old JSON configs.
- [ ] Populate the default manager and agents using Team Topologies-style categories.
- [ ] Run `PYTHONPATH=src python3 -m unittest tests.test_agent_roster`.

### Task 2: CLI/API/UI Visibility

**Files:**
- Modify: `src/forgeflag/webapp.py`
- Test: `tests/test_cli.py`, `tests/test_webapp.py`

- [ ] Assert `forgeflag agents` exposes team fields.
- [ ] Assert `/api/agents` exposes manager/team fields.
- [ ] Update the Agent tab copy/rendering so the team hierarchy is visible.
- [ ] Run focused CLI/Web tests.

### Task 3: Operating Docs

**Files:**
- Create: `docs/team-operating-model.md`
- Modify: `docs/agent-roster.md`, `README.md`, `CHANGELOG.md`

- [ ] Document the manager role, team types, collaboration cadence, DORA-like metrics, CTF scope boundary, and backlog gates.
- [ ] Link the model from existing roster and README docs.
- [ ] Preserve the held-out benchmark as the main truth source for solver capability.

### Task 4: Verification

**Files:**
- No production edits.

- [ ] Run `PYTHONPATH=src python3 -m unittest tests.test_agent_roster tests.test_cli tests.test_webapp`.
- [ ] Run `PYTHONPATH=src python3 -m unittest discover tests`.
- [ ] Summarize sidecar PM/code-review findings and the remaining backlog.
