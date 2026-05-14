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
5. Prefer Docker for heavyweight or OS-specific tools.
6. Add tests for refused network actions and at least one deterministic local artifact path.

## Tool Categories

- Web/recon: HTTP probes, route discovery, scoped `nmap`, scoped fuzzing.
- Pwn: `checksec`, `gdb`, `pwntools`, `ropper`, `ROPgadget`.
- Reverse: `file`, `strings`, `radare2`, headless decompiler adapters.
- Crypto: `z3`, `sage`, `pycryptodome`.
- Forensics: `binwalk`, `exiftool`, `tshark`, `volatility3`, carving tools.

## Validation

Run:

```bash
make test
```

For MCP changes, also verify the server imports:

```bash
PYTHONPATH=src python3 -c "import forgeflag.mcp_server"
```

