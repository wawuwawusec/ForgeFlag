# CTF Tool Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Incrementally turn the curated CTF project catalog into concrete ForgeFlag solver capabilities.

**Architecture:** Keep external tools behind typed wrappers, keep pure transform logic in focused Python modules, and integrate one category at a time. Start with dependency-light decoding inspired by CyberChef, then move to binary/pwn wrappers, scoped web probes, and heavyweight Docker/MCP integrations.

**Tech Stack:** Python standard library, `unittest`, ForgeFlag `Manager`/`Solver`/`ToolRunner`, optional external tools through allowlisted wrappers.

---

### Phase 1: CyberChef-Style Transform Pipeline

**Files:**
- Create: `src/forgeflag/transforms.py`
- Modify: `src/forgeflag/solvers/crypto.py`
- Modify: `src/forgeflag/solvers/misc.py`
- Modify: `src/forgeflag/solvers/traffic.py`
- Test: `tests/test_transforms.py`
- Test: `tests/test_crypto_solver.py`
- Test: `tests/test_misc_solver.py`
- Test: `tests/test_traffic_solver.py`

- [x] **Step 1: Write failing transform tests**

```python
from forgeflag.transforms import transform_candidates


def test_transform_candidates_decodes_common_layers() -> None:
    text = "666c61677b6865785f666c61677d"
    candidates = transform_candidates(text)
    assert "flag{hex_flag}" in [candidate.value for candidate in candidates]


def test_transform_candidates_chains_url_and_html_entities() -> None:
    text = "%26%23102%3B%26%23108%3B%26%2397%3B%26%23103%3B%26%23123%3B%26%23117%3B%26%23114%3B%26%23108%3B%26%23125%3B"
    candidates = transform_candidates(text)
    assert "flag{url}" in [candidate.value for candidate in candidates]
```

Run: `.venv/bin/python -m unittest tests.test_transforms`
Expected: FAIL because `forgeflag.transforms` does not exist.

- [x] **Step 2: Implement transform module**

Implement a small breadth-first transform engine with bounded depth. Support hex, base64, URL decoding, HTML entity decoding, and printable candidate filtering. Return structured candidates with value, recipe, and source.

- [x] **Step 3: Integrate CryptoSolver**

CryptoSolver should analyze challenge title, description, tags, and text attachments. If transform candidates contain flags, return `flag_candidate`; otherwise return a transform evidence finding instead of a placeholder-only result.

- [x] **Step 4: Integrate MiscSolver**

MiscSolver should run image checks first, then transform analysis over description and text attachments. If flags are found, return `flag_candidate`; otherwise preserve the existing placeholder path.

- [x] **Step 5: Refactor TrafficSolver decoding**

Replace local URL/HTML decode helpers with shared transform candidates for HTTP artifact payloads while preserving the current successful pcap behavior.

### Phase 2: Pwn/Reverse Wrapper Candidates

**Files:**
- Modify: `src/forgeflag/tools/ctf.py`
- Modify: `src/forgeflag/solvers/pwn.py`
- Modify: `src/forgeflag/solvers/reverse.py`
- Test: `tests/test_tools.py`
- Test: `tests/test_pwn_solver.py`
- Test: `tests/test_reverse_solver.py`

- [x] **Step 1: Add ROPgadget and ropper typed wrappers**

Add wrappers only if local executables exist. Keep missing-tool behavior structured through `ToolRunner`.

- [x] **Step 2: Add pwn/reverse evidence summaries**

Record checksec, strings, gadget availability, and IDA MCP output in a compact finding.

### Phase 3: Traffic/Scapy Expansion

**Files:**
- Create: `src/forgeflag/traffic_analysis.py`
- Modify: `src/forgeflag/solvers/traffic.py`
- Test: `tests/test_traffic_analysis.py`

- [x] **Step 1: Add DNS summary extraction**

Extract query names, TXT answers, long labels, and repeated failed lookups using typed tshark fields.

- [x] **Step 2: Add TCP stream shortlist**

Rank streams by HTTP clues, printable payload hints, and flag-like transform candidates.

### Phase 4: Scoped Web Tooling

**Files:**
- Modify: `src/forgeflag/tools/ctf.py`
- Modify: `src/forgeflag/solvers/web.py`
- Test: `tests/test_tools.py`
- Test: `tests/test_workflow.py`

- [x] **Step 1: Add ffuf wrapper behind active scope**

Require `ScopePolicy.active_probe` and allowed host. Add request budget and timeout.

- [x] **Step 2: Keep sqlmap/nuclei as manual candidates first**

Expose them in catalog and docs, but do not auto-run until safety UX is explicit.

### Phase 5: Heavyweight Tool Containers/MCP

**Files:**
- Modify: `docker/Dockerfile.ctf`
- Modify: `docs/mcp.md`
- Modify: `docs/tooling-research.md`

- [x] **Step 1: Add Docker profiles for SageMath/Volatility/Ghidra-headless**

Keep these out of the base venv. Document invocation boundaries and artifacts.

- [x] **Step 2: Add read-only external adapter pattern**

Use the current IDA MCP adapter as the template for Ghidra/headless export adapters.

### Phase 6: Crypto RSA Triage

**Files:**
- Create: `src/forgeflag/crypto_analysis.py`
- Modify: `src/forgeflag/solvers/crypto.py`
- Modify: `src/forgeflag/tools/ctf.py`
- Test: `tests/test_crypto_analysis.py`
- Test: `tests/test_crypto_solver.py`
- Test: `tests/test_tools.py`

- [x] **Step 1: Add RSA parameter summary extraction**

Extract common RSA fields from challenge text and attachments: `n`, `e`, `c`, `p`, `q`, `d`, and `phi`. Detect PEM public/private key markers and emit hints such as `low_exponent`, `known_factors`, and `rsa_n_e_c`.

- [x] **Step 2: Add RsaCtfTool wrapper and solver evidence**

Add a typed `RsaCtfTool` wrapper that accepts a registered public key and optional ciphertext artifact. CryptoSolver records RSA evidence and recommends RsaCtfTool/SageMath/Z3 follow-up without running heavyweight tools by default.

### Phase 7: Archive Triage

**Files:**
- Create: `src/forgeflag/archive_analysis.py`
- Modify: `src/forgeflag/solvers/forensics.py`
- Modify: `src/forgeflag/solvers/misc.py`
- Test: `tests/test_archive_analysis.py`
- Test: `tests/test_forensics_solver.py`
- Test: `tests/test_misc_solver.py`

- [x] **Step 1: Add archive structure summaries**

Detect zip, tar, and gzip artifacts without extracting by default. Record entry names, sizes, encryption state, archive comments, and interesting entry names such as flag, secret, hint, readme, password, and key.

- [x] **Step 2: Integrate archive summaries into solvers**

ForensicsSolver and MiscSolver store archive evidence and recommend managed extraction or password-hint collection as the next action.

### Phase 8: Hash and Password Triage

**Files:**
- Create: `src/forgeflag/hash_analysis.py`
- Modify: `src/forgeflag/solvers/crypto.py`
- Modify: `src/forgeflag/solvers/misc.py`
- Modify: `src/forgeflag/tools/ctf.py`
- Modify: `src/forgeflag/mcp_server.py`
- Test: `tests/test_hash_analysis.py`
- Test: `tests/test_crypto_solver.py`
- Test: `tests/test_misc_solver.py`
- Test: `tests/test_tools.py`
- Test: `tests/test_mcp_tools.py`

- [x] **Step 1: Fingerprint common hash candidates**

Detect MD5/NTLM-length, SHA1, SHA256, bcrypt, and sha512crypt values in challenge text and attachments. Record hashcat modes, John formats, confidence, and recommended tools.

- [x] **Step 2: Prioritize hash evidence before generic transforms**

CryptoSolver and MiscSolver record hash evidence before transform decoding so short hex hashes are not misrouted as ordinary encoded strings.

- [x] **Step 3: Add bounded cracking wrappers**

Expose hashcat and John dictionary wrappers through the allowlisted tool catalog and MCP server. Solvers recommend these tools but do not automatically run password cracking.

### Phase 9: Image and Stego Hint Triage

**Files:**
- Modify: `src/forgeflag/image.py`
- Modify: `src/forgeflag/solvers/forensics.py`
- Modify: `src/forgeflag/solvers/misc.py`
- Modify: `tests/png_fixtures.py`
- Test: `tests/test_image.py`
- Test: `tests/test_forensics_solver.py`
- Test: `tests/test_misc_solver.py`

- [x] **Step 1: Summarize lightweight image stego hints**

Detect PNG text chunks, PNG data appended after IEND, JPEG comment segments, and JPEG APP markers. Keep previews bounded and structured for notebook evidence.

- [x] **Step 2: Integrate image hints into solvers**

ForensicsSolver stores image hint evidence alongside file/strings/binwalk/exiftool output. MiscSolver routes image puzzles through this evidence before generic transforms and submits image-derived flag candidates to the verifier.

### Phase 10: Artifact Visibility

**Files:**
- Modify: `src/forgeflag/artifacts.py`
- Modify: `src/forgeflag/cli.py`
- Modify: `src/forgeflag/webapp.py`
- Test: `tests/test_artifacts.py`
- Test: `tests/test_cli.py`
- Test: `tests/test_webapp.py`

- [x] **Step 1: Add artifact metadata summaries**

Summarize registered attachment paths with name, managed path, existence, size, and SHA256. Missing registered paths stay visible with null metadata.

- [x] **Step 2: Expose summaries in CLI and Web UI**

Add `forgeflag artifacts <challenge_id>` and a Web UI Artifacts tab so operators can confirm uploaded/registered files before running solvers.

### Phase 11: Local Lifecycle Reliability

**Files:**
- Modify: `scripts/forgeflag-control`
- Test: `tests/test_control_script.py`

- [x] **Step 1: Harden PID handling**

Validate PID files before using them. Remove invalid or stale PID files from status checks and make stop tolerate missing or malformed state.

- [x] **Step 2: Stabilize Web UI startup**

Start the Web UI with `.venv/bin/python -m forgeflag.cli`, store the managed Python process PID, and use a detached screen session when available so the service survives the launching shell.

### Phase 12: External Corpus-Inspired Regression Coverage

**Files:**
- Modify: `src/forgeflag/flags.py`
- Modify: `src/forgeflag/transforms.py`
- Modify: `src/forgeflag/traffic_analysis.py`
- Modify: `src/forgeflag/solvers/traffic.py`
- Test: `tests/test_flags.py`
- Test: `tests/test_transforms.py`
- Test: `tests/test_traffic_analysis.py`
- Test: `tests/test_traffic_solver.py`

- [x] **Step 1: Research public CTF archives for coverage gaps**

Use public archives and writeup indexes as pattern sources, including pwn.college CTF Archive, CryptoHack CTF Archive, OOO DEF CON archive, picoCTF writeup indexes, and PCAP-focused CTFtime writeups. Do not vendor full challenge archives.

- [x] **Step 2: Add failing regression tests for common misses**

Cover full platform flag prefixes, Base32, binary ASCII, ROT13, and DNS query-label encoded flags.

- [x] **Step 3: Implement deterministic decoding improvements**

Extend the transform pipeline with Base32, binary ASCII, and ROT13. Preserve platform flag prefixes and surface DNS query decoded hints through `TrafficSolver`.
