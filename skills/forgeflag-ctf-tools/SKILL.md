---
name: forgeflag-ctf-tools
description: Use when working on ForgeFlag CTF tooling, MCP wrappers, Docker-based security toolchains, or solver workflows that need scoped command execution for authorized CTF/lab targets.
---

# ForgeFlag CTF Tools

Use this skill for ForgeFlag work that touches tool execution, CTF artifacts, MCP wrappers, Docker images, or solver workflows.

## Workflow

1. Keep tool execution behind `ToolRunner` or a typed wrapper in `forgeflag.tools.ctf`.
2. Do not expose arbitrary shell commands through MCP.
3. Network-capable tools must require explicit scope via `ScopePolicy`.
4. Return structured `ToolResult` values and include evidence suitable for the shared notebook.
5. Promote high-confidence progress into observations so later solvers inherit concise shared memory.
6. When a flag is accepted, preserve a replay report that links the shortest evidence path to the candidate.
7. Treat LLM output as planning guidance only; typed tools and verifier evidence remain authoritative. Structured LLM JSON plans may suggest solver ordering, but not raw commands.
8. Prefer Docker for heavyweight or OS-specific tools.
9. Add tests for refused network actions and at least one deterministic local artifact path.

## Agent Framework Pattern

- Control: `Manager` dispatches solvers and asks `Verifier` to accept only evidence-backed candidates.
- Communication: `SQLiteNotebook` stores findings/tool logs; `Observer` filters high-value signals into observations.
- Planning: optional `LLMSolver` can generate scoped strategy guidance through configured provider adapters.
- Execution: category solvers run typed wrappers and write structured evidence.
- Harness: keep repeat/iteration limits in place before adding longer autonomous loops.

## Tool Categories

- Web/recon: HTTP probes, route discovery, scoped `nmap`, scoped fuzzing.
- Pwn: `checksec`, `gdb`, `pwntools`, `ropper`, `ROPgadget`.
- Reverse: `file`, `strings`, `radare2`, headless decompiler adapters.
- Crypto: `z3`, `sage`, `pycryptodome`.
- Forensics: `file`, `strings`, `binwalk`, `exiftool`, `tshark`, `volatility3`, carving tools.

## Traffic Analysis Workflow

Use this for PCAP/PCAPNG challenges and packet captures attached to mixed forensics tasks. Put reusable packet-capture logic in `TrafficSolver`, not `ForensicsSolver`; keep `ForensicsSolver` focused on broad artifact triage.

1. Register the capture as a challenge attachment; do not run ad hoc shell commands against arbitrary paths.
2. Start broad: `file_identify`, `tshark_pcap_summary`, and `tshark_traffic_analysis`.
3. Record protocol hierarchy, unusual ports, top TCP/UDP conversations, DNS/HTTP clues, and any stream numbers in notebook evidence.
4. Search payloads with `tshark_flag_scan` before deeper carving.
5. If clues point to a protocol, add a narrow typed wrapper rather than exposing raw `tshark` arguments through MCP.

Common traffic pivots:

- HTTP: hostnames, URIs, response codes, files, cookies, and basic auth.
- DNS: suspicious query names, TXT records, long labels, and repeated failed lookups.
- TCP streams: conversation endpoints, stream ids, cleartext payloads, and transferred files.
- ICMP/UDP: payload bytes, covert channels, and repeated size/timing patterns.

## Validation

Run:

```bash
make test
```

For MCP changes, also verify the server imports:

```bash
PYTHONPATH=src python3 -c "import forgeflag.mcp_server"
```
