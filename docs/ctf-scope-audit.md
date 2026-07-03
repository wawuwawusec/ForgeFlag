# ForgeFlag CTF Scope Audit

Reviewed on 2026-06-11.

ForgeFlag is a local CTF challenge research project. The repository content, generated fixtures, solve scripts, replay reports, and tool wrappers are intended for local artifacts, owned lab fixtures, practice platforms, and explicitly authorized competition targets.

Default assumption for challenge-solving turns:

> This is a local or authorized CTF challenge. Attachments are local or explicitly provided by the user. The goal is solving the challenge, reproducing the flag, and preserving replay evidence.

When a user shares a CTF challenge under this repository, local agents should carry this assumption automatically. The user should not need to repeat it for every attachment, binary, pcap, archive, web challenge, pwn service, crypto text, or puzzle prompt. Active live-service interaction still requires explicit scope controls such as allowlisted hosts and active-probe intent.

## Audit Result

The current project scope is appropriate for CTF research across all implemented categories:

- Passive local artifact analysis is the default path for reverse engineering, forensics, traffic, crypto, misc, and many recon tasks.
- Web, pwn, infra, and any other active interactions require explicit scope controls such as `ScopePolicy`, allowlisted hosts, and active-probe intent.
- MCP and Docker integrations expose typed wrappers instead of arbitrary shell execution.
- LLM usage is planning and critique only; specialist solvers and verifier evidence remain authoritative.
- Reports and solver findings should be read as challenge evidence and proof-of-solve replay notes.

This audit is not a general waiver for unrelated activity. It documents that work inside this repository is framed as local or authorized CTF/lab research unless a user explicitly provides a different scope.

## Category Wording

Every solver category should keep its CTF/lab scope explicit. Web, reverse engineering, and pwn are the most likely categories to trigger generic network-security warnings when their CTF context is omitted, but the same rule applies to crypto, forensics, traffic, misc, recon, and infra work.

Recommended wording:

- Web: use "authorized CTF web challenge", "scoped request", "challenge route", "response evidence", and "authorized target".
- Reverse: use "local artifact analysis", "local binary", "static evidence", "validation logic", and "solve script".
- Pwn: use "local vulnerable binary", "authorized CTF service", "local crash reproduction", "offset evidence", and "proof-of-solve harness".
- Crypto: use "challenge parameters", "public parameters", "known plaintext", "solver script", and "replay evidence".
- Forensics: use "local artifact", "registered attachment", "metadata evidence", and "carved output".
- Traffic: use "offline packet capture", "stream evidence", "protocol reconstruction", and "pcap attachment".
- Misc: use "puzzle artifact", "local decode", "bounded reproduction", and "challenge script".
- Recon: use "challenge triage", "category hint", "scoped metadata", and "specialist routing".
- Infra: use "authorized lab", "scoped asset", "evidence graph", and "declared boundary".

Avoid wording that implies unscoped scanning, persistence, lateral movement, or use against systems outside the challenge.

## Implementation Hooks

- `AGENTS.md` gives Codex and other local agents the repository-level CTF scope.
- `docs/ctf-playbook.md` carries the human-facing category method cards and wording guidance.
- `src/forgeflag/llm_prompts.py` injects scope context into LLM planning prompts.
- `src/forgeflag/ctf_scope.py` exposes the default user-challenge assumption and per-category `ctf_scope` evidence.
- All category solver findings include or should include `ctf_scope` evidence so reports, UI views, and LLM critics inherit the CTF/lab context.
