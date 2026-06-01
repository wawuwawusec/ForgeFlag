# Changelog

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
- Added Observer-distilled shared observations and per-solver context injection.
- Added a `forgeflag observations` CLI command.
- Added automatic replay reports for accepted flags and a `forgeflag report` CLI command.
- Added `LLMConfig`, provider adapters, optional OpenAI Responses and 智谱 GLM chat-completions adapters, and `LLMSolver` strategy planning.
- Added structured LLM solve plans and dynamic solver queue insertion from `llm_solver_plan` observations.
- Changed LLM planning failures to non-blocking findings so deterministic solvers still run when a web-run LLM key or model is misconfigured.
- Added `.env.example` and a local artifact-based `make smoke` workflow.
- Added `scripts/forgeflag-control` for one-command local start, stop, status, restart, and smoke workflows.
- Added a local Web UI with challenge creation, attachment upload, category filtering, per-run LLM settings, browser-local config saving, LLM connection testing, run, auto-loaded findings, observations, report, and tools views.
- Added optional read-only IDA MCP configuration and adapter hooks for `ReverseSolver` and `PwnSolver`.
- Added a curated CTF project catalog available from `forgeflag catalog`, `/api/project-catalog`, and the Web UI Catalog tab.
