# Codex Handoff

This file is the handoff context for continuing ForgeFlag in a fresh Codex session.

## Project

- Local path: `/Users/5haw0/Documents/ForgeFlag`
- GitHub repo: `https://github.com/wawuwawusec/ForgeFlag`
- Visibility: private
- Default branch: `main`
- Python package metadata name: `ForgeFlag`
- Python import package and CLI command: `forgeflag`

## Current State

ForgeFlag is a scoped multi-agent assistant for CTF and authorized security competitions.

Implemented so far:

- Manager dispatch loop.
- SQLite shared notebook.
- Harness loop controls.
- Solver interface and starter solvers for Web, Pwn, Reverse, Crypto, Forensics, Misc, and Infra.
- Scoped WebSolver workflow:
  - allowlist-gated HTTP probing
  - HTML title/link/form parsing
  - flag candidate extraction
  - verifier integration
- CTF tool layer:
  - allowlisted `ToolRunner`
  - wrappers for `file`, `strings`, `checksec`, `binwalk`, `exiftool`, `tshark`, `nmap_tcp_basic`
  - `forgeflag tools` CLI inventory
- Optional MCP server:
  - `forgeflag-mcp`
  - streamable HTTP endpoint can run at `http://127.0.0.1:8000/mcp`
- CTF Dockerfile:
  - `docker/Dockerfile.ctf`
- Project skill template:
  - `skills/forgeflag-ctf-tools/SKILL.md`

## Local Runtime

The local folder was renamed from:

`/Users/5haw0/Documents/New project`

to:

`/Users/5haw0/Documents/ForgeFlag`

The old Codex session may show a warning because its original working directory no longer exists. Continue in a fresh Codex session opened at `/Users/5haw0/Documents/ForgeFlag`.

Current local setup after migration:

- `.venv` rebuilt in `/Users/5haw0/Documents/ForgeFlag`
- Homebrew tools installed and detected:
  - `nmap`
  - `binwalk`
  - `exiftool`
  - `tshark`
- Tests passed: 9 tests OK

Useful commands:

```bash
cd /Users/5haw0/Documents/ForgeFlag
.venv/bin/forgeflag tools
.venv/bin/python -m unittest discover -s tests
```

MCP was started with:

```bash
screen -dmS forgeflag-mcp /bin/zsh -lc 'cd /Users/5haw0/Documents/ForgeFlag && export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" && export FORGEFLAG_ALLOWED_HOSTS="127.0.0.1,localhost" && .venv/bin/python -c "from forgeflag.mcp_server import mcp; mcp.run(transport=\"streamable-http\")" >> .forgeflag/mcp.log 2>&1'
```

Check/stop MCP:

```bash
screen -ls
tail -f .forgeflag/mcp.log
screen -S forgeflag-mcp -X quit
```

## Git History

Recent commits:

- `f785f05 Rename project metadata to ForgeFlag`
- `14bbd6c Add CTF toolchain MCP wrappers`
- `6794090 Add scoped web response analysis`
- `75f8b53 Initial ForgeFlag agent scaffold`

## Next Recommended Work

Recommended next milestone:

1. Add artifact workspace management under `.forgeflag/artifacts`.
2. Teach Manager/Solvers to accept challenge attachment paths.
3. Deepen ForensicsSolver first:
   - `file_identify`
   - `strings_extract`
   - `binwalk_scan`
   - `exiftool_read`
   - structured findings and flag extraction from local artifacts
4. Add tests with deterministic sample artifact files.
5. Update CHANGELOG and push changes.

## Safety Boundary

Keep the project scoped to CTFs, labs, and explicitly authorized targets.

Rules to preserve:

- No arbitrary shell exposed through MCP.
- Network tools require explicit allowlist scope.
- Solvers write structured evidence to the notebook.
- Verifier only accepts evidence-backed flag candidates.

