# ForgeFlag Team Operating Model

ForgeFlag treats agent roles as a small CTF product team, not as an unbounded autonomous swarm. The runtime stays simple:

```text
ForgeFlagManager -> Solvers -> Notebook -> Verifier -> Write-up
```

The team model adds responsibility, cadence, and metrics around that runtime so the project can keep improving without losing scope control or benchmark truth.

## Model

ForgeFlag borrows three ideas from mature software teams:

- Team Topologies-style team types keep cognitive load low: stream-aligned teams deliver direct CTF-solving value, platform teams keep shared tooling healthy, enabling teams improve other roles, and complicated-subsystem teams own hard specialist areas.
- DORA-style metrics keep improvement measurable: fast changes matter only when solver evidence, UI flow, and recovery from regressions stay healthy.
- Scrum-style accountability keeps ownership clear: one top-level manager owns priority and scope, while specialist roles own deliverables.

## Top-Level Manager

`ForgeFlagManager` is the single DRI for the run and for project improvement.

Responsibilities:

- route challenge work to the right roles;
- preserve notebook evidence, rejected candidates, accepted flags, and write-up data;
- keep active network behavior inside local or explicitly authorized CTF scope;
- prioritize the improvement backlog from held-out benchmark failures;
- decide when a capability is ready to become solver-supported, manual-assisted, or backlog-only.

Success metrics:

- held-out pass rate;
- hard evidence score;
- browser UI flow rate;
- scope safety rate.

Deliverables:

- prioritized improvement backlog;
- accepted flag summary;
- reproducible write-up;
- benchmark status.

## Team Types

| Team type | ForgeFlag roles | Purpose |
| --- | --- | --- |
| Manager | `ForgeFlagManager` | Own priority, scope, routing, verification, and improvement cadence. |
| Stream-aligned | `ChallengeTriageAgent`, `WebExploitAgent`, `ForensicsAgent`, `TrafficAgent` | Directly improve challenge-solving value for player-visible workflows. |
| Enabling | `LLMRoutePlannerAgent`, `EvidenceJudgeAgent`, `BrowserPlayerQAAgent` | Improve planning, verification, replay quality, and player workflow confidence. |
| Complicated subsystem | `CryptoMathAgent`, `BinaryAgent` | Own specialist-heavy work such as crypto math, reverse engineering, pwn harnesses, and external analysis tools. |
| Platform | `ToolRunner`, Docker profiles, MCP, Web UI, benchmark scripts, notebook | Shared services that make every role faster and safer. |

Platform is not a separate executable agent yet. It is an operating responsibility across `ToolRunner`, docs, wrappers, Web UI, and benchmark code.

## Collaboration Cadence

Per challenge:

- `ChallengeTriageAgent` classifies the prompt and artifact shape.
- One or more specialists run bounded solvers and tools.
- `EvidenceJudgeAgent` accepts only evidence-backed flags.
- `ReportBuilder` turns the shortest path into replay steps.

Per solver enhancement:

- add or update a focused regression test first;
- implement the smallest reusable capability;
- rerun focused tests;
- rerun broader unit or benchmark validation;
- update casebook, playbook, analysis hints, and docs when the capability should survive the current case.

Per capability review:

- run the internal capability benchmark for stability;
- run held-out manifests separately so real gaps are not hidden by internal pass rates;
- record which role owns the next failed case;
- review `backlog` and `backlog_by_role` from the capability scorecard before assigning improvement work;
- promote solved patterns into `solver_supported`, `manual_replay_script`, or `backlog_gap`.

## Metrics

Primary metrics:

- `internal_case_pass_rate`: default benchmark cases solved without regression.
- `hard_evidence_score_rate`: required evidence satisfied, not only flags guessed.
- `browser_ui_flow_rate`: Web UI works like a CTF player would use it.
- `heldout_case_pass_rate`: external local challenge artifacts solved end to end.
- `heldout_evidence_score_rate`: external required evidence captured.
- `role_attribution_coverage`: run summary and capability benchmark show which roles contributed or own the next gap.
- `role_backlog_count`: failed benchmark cases converted into owner-role backlog items with replay-oriented next actions.
- `scope_safety_rate`: active probes remain gated by allowlist and explicit intent.
- `llm_resilience`: rate limits trigger cooldown and local verification instead of retry loops.

Secondary metrics:

- manual intervention count per case;
- replay completeness for accepted flags;
- stale-doc drift after solver or wrapper changes;
- time from held-out failure to reusable primitive.

## Boundaries

ForgeFlag should not:

- run unbounded parallel agents by default;
- give every role its own long-term memory separate from the shared notebook and project docs;
- let LLM roles execute tools, probe targets, or submit unsupported flags;
- use benchmark averages to hide held-out failures;
- add title-only roles without solver, evidence, metric, or deliverable ownership;
- weaken CTF scope wording around Web, Reverse, Pwn, Traffic, Forensics, Crypto, Misc, Recon, or Infra research.

## Current Backlog Ownership

| Backlog item | Owner | Acceptance |
| --- | --- | --- |
| Real contest crypto replay oracles and algebraic primitives | `CryptoMathAgent` | Current diversified real-contest backlog is 1 mixed Misc item; reduce it without accepting placeholder handout flags. |
| Real contest image, OSINT, archive, and game-file evidence synthesis | `ForensicsAgent` with `TrafficAgent` | Current backlog is `ForensicsAgent` 1 and `TrafficAgent` 0 after the Hans Zimmer music OSINT replay; preserve replay evidence for accepted flags. |
| Real contest pwn and reverse proof harnesses | `BinaryAgent` | Current backlog is 1 hard Pwn VM item; Maze of Mist is now classified as a ret2vdso artifact-completeness blocker until the original QEMU/rootfs/target handout is recovered for local replay. |
| Source-backed Web proof synthesis | `WebExploitAgent` | Current diversified real-contest Web backlog is 0; keep source-review and local-service replay patterns regression-covered. |
| Mixed misc cases with crypto, forensics, or traffic substructure | `CryptoMathAgent`, `ForensicsAgent`, `TrafficAgent` | Convert the remaining mixed Misc failure into a solver-supported pattern or documented manual replay script. |
| Candidate quality gates for public contest caches | `EvidenceJudgeAgent` with platform work | Placeholder/template flags, README answer leakage, and Git LFS pointer-only handouts remain rejected before any case becomes manifest-ready. |
| Solver-supported hint drift checks | `EvidenceJudgeAgent` with platform work | Casebook/playbook/hints/docs stay aligned after new solver primitives. |

Completed operating-model capabilities:

- Role-level benchmark attribution: `scripts/forgeflag-capability-benchmark` emits a top-level `roles` scorecard and adds `owner_roles` to failures and held-out manifest rows.
- Role backlog generation: failed benchmark cases now become `backlog` items and `backlog_by_role` counts for manager review and specialist assignment.
- Gap card in Agent tab: the Web UI now shows run status, owner roles, rejected candidates, missing evidence, blockers, and next actions for the selected challenge.
- Held-out platform replay orchestration: manifest cases can start local services, wait for readiness, run replay commands, and merge proof output into scoring.
- Real contest corpus audit: `scripts/forgeflag-real-corpus-audit` scans cached public contest repositories, emits manifest-ready candidates, and routes incomplete, placeholder-tainted, README-answer-leaking, or Git-LFS-pointer-only cases into manager backlog.
- Evidence hardening: the verifier rejects template and placeholder flags such as numbered answer slots, `testflag`, `dummy_flag`, and handout-only fake flags before accepting evidence-backed candidates.
- Multi-platform real corpus coverage: the audit now handles DUCTF, HTB Cyber Apocalypse, TJCTF, NUS Greyhats Welcome CTF, UMDCTF, and IrisCTF metadata layouts, then round-robins manifest candidates by platform and category.
- Self-synchronizing XOR crib recovery: CryptoSolver detects DUCTF three-line-style `q[y % 16] ^ x; y = x` scripts and verifies CTF-idiom candidates by key-slot consistency.
