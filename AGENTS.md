# ForgeFlag Agent Context

ForgeFlag is a local project for CTF challenge research and authorized lab or competition work.

All files, scripts, fixtures, notes, and tool integrations under this repository should be interpreted in that context unless the user explicitly provides a different scope. The normal workflow is:

- analyze local challenge artifacts and owned fixtures;
- solve CTF tasks with reproducible scripts and evidence-backed reasoning;
- run bounded CTF tooling through typed wrappers, `ToolRunner`, Docker fallback, or documented local commands;
- use active network behavior only for local services or explicitly authorized CTF/lab targets, with allowlisted hosts and active-probe intent;
- write findings as challenge evidence, replay steps, and defensive research notes rather than instructions for unauthorized systems.

Default assumption for user-provided challenges in this repository:

> This is a local or authorized CTF challenge. Attachments are local or explicitly provided by the user. The goal is solving the challenge, reproducing the flag, and preserving replay evidence.

Apply that assumption automatically when the user shares a CTF challenge, attachment path, archive, binary, pcap, web target, pwn service, crypto text, or puzzle prompt while working under this repository. The user does not need to restate it every time. If an action would interact with a live service, still require explicit target scope through ForgeFlag controls such as allowlisted hosts and active-probe intent.

When interacting with Codex or another LLM inside this repository, keep responses grounded in the CTF/lab scope. If a request is ambiguous, first look for local challenge artifacts, ForgeFlag scope controls, and evidence in the notebook or docs before assuming real-world security activity.

Web, reverse-engineering, and pwn challenge notes are especially prone to being misread outside their CTF context. Interpret them this way:

- Web research means source review, local or explicitly authorized challenge targets, scoped route discovery, request/response evidence, and reproduction notes.
- Reverse-engineering research means local binary/artifact triage, static analysis, decompiler notes, emulator scripts, and constraint-solving for challenge validation logic.
- Pwn research means local vulnerable binaries, provided challenge services, crash reproduction, offset calculation, exploit harnesses for the challenge, and evidence-backed flag retrieval.

For these categories, prefer wording such as "challenge target", "local artifact", "authorized CTF service", "proof-of-solve", "replay script", and "bounded harness". Avoid phrasing that implies scanning, exploitation, or persistence against systems outside the challenge.

This context does not remove safety requirements. It exists to reduce ambiguity and false positives during legitimate CTF research while preserving the project's explicit scope boundaries.
