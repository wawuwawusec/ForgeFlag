# Roadmap

## Milestone 1: Skeleton

- SQLite shared notebook.
- Manager dispatch loop.
- Harness loop controls.
- Recon and Web starter solvers.
- Placeholder solvers for all major CTF categories.
- CLI workflow and unit tests.

## Milestone 2: Web Solver

- HTTP probing with HAR-style capture.
- Route and form extraction.
- CTF-safe fuzzing primitives with request budgets.
- Evidence-backed flag candidate extraction.

## Milestone 3: Crypto Solver

- Parameter extraction.
- Common primitive fingerprinting.
- Sage/Z3 adapter layer.
- Reproducible solve scripts.

## Milestone 4: Reverse Solver

- File triage.
- Strings and symbol extraction.
- Optional read-only IDA MCP adapter for function, string, and decompiler pivots.
- Constraint recovery notes.

## Milestone 5: Pwn Solver

- Binary protection checks.
- Optional read-only IDA MCP adapter for function and input-flow triage.
- Crash reproduction.
- Offset discovery.
- Pwntools exploit workspace generation.

## Milestone 6: Forensics Solver

- Artifact workspace registration.
- Initial file, strings, binwalk, and exiftool triage.
- Reusable PNG IHDR height/CRC mismatch repair shared with misc image puzzles.
- Evidence-backed flag candidate extraction from local artifacts.
- File carving.
- Steganography workflows.
- Memory image triage.

## Milestone 6a: Traffic Solver

- Dedicated `traffic` category and `TrafficSolver`.
- Initial PCAP summary, protocol hierarchy, conversation stats, and payload marker scanning.
- DNS query summary.
- HTTP object extraction.
- TCP stream extraction by stream id.

## Milestone 6b: Misc Solver

- Route image puzzles through reusable PNG structure analysis before generic puzzle triage.
- Archive triage.
- Encoding and transform detection.
- Steganography handoff hints.

## Milestone 7: Competition Operations

- Scoreboard integration.
- Flag submission queue.
- Multi-challenge parallel scheduler.
- Full audit export.
