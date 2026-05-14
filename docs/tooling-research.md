# Tooling Research Notes

ForgeFlag's tooling layer borrows patterns from a few well-regarded CTF and agent-tool projects:

- `zardus/ctf-tools`: broad CTF tool coverage with repeatable install scripts and CI-style installation checks.
- `skysider/pwndocker`: containerized Pwn-focused environment, useful as a model for debugger and exploit-development ergonomics.
- `modelcontextprotocol/python-sdk`: official Python SDK for exposing tools through MCP, including the `FastMCP` decorator API and `mcp[cli]` installation path.

Design choices adopted here:

- Package heavyweight security tools in Docker instead of assuming they exist on every host.
- Expose tools through a small allowlisted catalog, not arbitrary shell execution.
- Treat network-capable tools as active probes that require explicit scope.
- Return structured `ToolResult` payloads so solvers can record evidence in the shared notebook.

References:

- https://deepwiki.com/zardus/ctf-tools
- https://hub.docker.com/r/skysider/pwndocker
- https://github.com/modelcontextprotocol/python-sdk

