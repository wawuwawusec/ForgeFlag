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
