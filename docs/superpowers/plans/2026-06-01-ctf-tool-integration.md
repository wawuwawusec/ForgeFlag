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

- [ ] **Step 1: Add ROPgadget and ropper typed wrappers**

Add wrappers only if local executables exist. Keep missing-tool behavior structured through `ToolRunner`.

- [ ] **Step 2: Add pwn/reverse evidence summaries**

Record checksec, strings, gadget availability, and IDA MCP output in a compact finding.

### Phase 3: Traffic/Scapy Expansion

**Files:**
- Create: `src/forgeflag/traffic_analysis.py`
- Modify: `src/forgeflag/solvers/traffic.py`
- Test: `tests/test_traffic_analysis.py`

- [ ] **Step 1: Add DNS summary extraction**

Extract query names, TXT answers, long labels, and repeated failed lookups using typed tshark fields.

- [ ] **Step 2: Add TCP stream shortlist**

Rank streams by HTTP clues, printable payload hints, and flag-like transform candidates.

### Phase 4: Scoped Web Tooling

**Files:**
- Modify: `src/forgeflag/tools/ctf.py`
- Modify: `src/forgeflag/solvers/web.py`
- Test: `tests/test_tools.py`
- Test: `tests/test_workflow.py`

- [ ] **Step 1: Add ffuf wrapper behind active scope**

Require `ScopePolicy.active_probe` and allowed host. Add request budget and timeout.

- [ ] **Step 2: Keep sqlmap/nuclei as manual candidates first**

Expose them in catalog and docs, but do not auto-run until safety UX is explicit.

### Phase 5: Heavyweight Tool Containers/MCP

**Files:**
- Modify: `docker/Dockerfile.ctf`
- Modify: `docs/mcp.md`
- Modify: `docs/tooling-research.md`

- [ ] **Step 1: Add Docker profiles for SageMath/Volatility/Ghidra-headless**

Keep these out of the base venv. Document invocation boundaries and artifacts.

- [ ] **Step 2: Add read-only external adapter pattern**

Use the current IDA MCP adapter as the template for Ghidra/headless export adapters.
