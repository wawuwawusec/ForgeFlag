# ForgeFlag Web Player Benchmark

`scripts/forgeflag-web-player-benchmark` runs ForgeFlag like a human player in the Web UI.

Unlike the API corpus scripts, this benchmark uses Playwright browser automation to create a challenge from the page, upload attachments, click the run button, read Summary and Write-up, and delete the benchmark challenge afterwards.

## Setup

The Playwright runner is installed outside git under `.forgeflag/web-player-benchmark/`:

```bash
npm --prefix .forgeflag/web-player-benchmark install @playwright/test
.forgeflag/web-player-benchmark/node_modules/.bin/playwright install chromium
```

## Usage

Start the local Web UI:

```bash
scripts/forgeflag-control start
```

List browser-player cases:

```bash
scripts/forgeflag-web-player-benchmark --list
```

Run all current cases through the browser:

```bash
scripts/forgeflag-web-player-benchmark --url http://127.0.0.1:8080 --run
```

The default run output is a compact scorecard:

```text
ForgeFlag browser player benchmark: 7/7 passed
Duration: 10.1s
Category results:
- crypto: 1/1
- forensics: 1/1
...
Case results:
- PASS [web] player-web-visible agents=ChallengeTriageAgent,WebExploitAgent,EvidenceJudgeAgent
...
```

Use `--json` when you need the raw Playwright reporter output for debugging:

```bash
scripts/forgeflag-web-player-benchmark --url http://127.0.0.1:8080 --run --json
```

Run one case and keep it in the notebook for manual inspection:

```bash
scripts/forgeflag-web-player-benchmark --url http://127.0.0.1:8080 --run --case player-crypto-base32 --keep
```

## Current Cases

The browser-player set checks UI plumbing and category-specific solving through the same controls a human uses:

| Case | Category | Flow |
| --- | --- | --- |
| `player-web-visible` | Web | typed prompt with visible flag |
| `player-crypto-base32` | Crypto | attachment upload plus Base32 decode |
| `player-misc-binary` | Misc | attachment upload plus binary ASCII decode |
| `player-forensics-strings` | Forensics | binary artifact upload plus strings triage |
| `player-traffic-http` | Traffic | PCAP upload plus HTTP payload recovery |
| `player-reverse-static` | Reverse | binary artifact upload plus static strings |
| `player-pwn-strings` | Pwn | pwn artifact upload plus local strings/checksec triage |

## Scoring Intent

The benchmark checks:

- `flag_found`: the verifier accepted the expected flag.
- `category_correct`: the challenge was submitted with the intended category through the Web UI.
- `human_ui_flow`: the player used visible Web controls for save, run, Summary, and Write-up.
- `writeup_reproducible`: the Write-up tab includes solving idea and reproduction steps.
- `agent_route_correct`: the Agent tab shows the expected ForgeFlag subagent identities for the category.
- `no_ui_error`: the page did not surface an error state during the browser flow.

This is the starting point for a dedicated browser-player agent. Future expansions should add medium and hard fixtures per category, with LLM-enabled and deterministic-only variants, so ForgeFlag can be evaluated from the same interface a real CTF player uses.
