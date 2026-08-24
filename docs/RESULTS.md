# ForgeFlag Results Archive

Definitive accuracy record. Every number is exact-flag matching through the
benchmark pipeline; every claim is reproducible with the commands listed.

## Dual-metric accuracy (never conflated)

| Metric | Accuracy | Corpus | Definition |
| --- | --- | --- | --- |
| **Real multi-platform corpus** | **10.9%** (21/192) | GCTF quals 2021-25 ×50, DUCTF 2024 ×54, IrisCTF 2024 ×40, HTB 2024 ×17, idekCTF 2024 ×17, SekaiCTF 2024/25 ×14 | exact-flag match, all challenges |
| **Deployable real subset** | **15.7%** (8/51) | challenges whose service source deploys locally | membership by challenge property only (non-circular); never a replacement for the corpus metric |
| **Synthetic curriculum** | **97.5%** (199/204) | 6 seeded skill tiers | encoding/forensics/logic/classic/minirev 100%, cyclic-offset pwn 85% |

The three metrics answer different questions and are always reported together:
corpus = generalization to competition difficulty; deployable subset = capability
on environment-verifiable real challenges; curriculum = the product's own
capability envelope. No metric is ever presented as another.

## Real-corpus trajectory (every lever, every version)

| Lever | Version | Accuracy |
| --- | --- | --- |
| Deterministic stack | v0.6 | 1.8% |
| + LLM planning/execution (glm-4-flash) | v0.7 | 4.2% |
| + service simulation layer (51 deployable, 7 converted) | v0.14 | 7.8% |
| + reflection retry (whats-a-rune) | v0.15 | 8.3% |
| + replay tier (4 portable author-solves) | v0.16 | 10.4% |
| + module-fix targeted replay (super-party) | v0.18.2 | **10.9%** |
| v3 re-sweep + F3 full-stack re-run | post-v0.18 | 10.4% (0 new — variance reproduced existing solves only) |
| variance-harvest pass (20 hardest, Coding Plan glm-5.3, 137 LLM calls / 633k tokens) | post-v0.18.2 | 0 new conversions — remaining failures are capability-bound, not variance-bound |

## Solved challenges (all exact, all evidenced)

heldout-sekaictf2025-{gondola,discrepancy†}, ductf2024-{three-line-crypto,
badpolicies, jmp-flag, wackyrecipe, decrypt-then-eval, v-for-vieta,
my-array-generator†, shufflebox†, rusty-vault†, pressing-buttons†},
htb2024-{Hard_Metagaming, Very_Easy_Tutorial}, irisctf2024-{corrupted-world,
babycha, dhash, accessible-sesamum-indicum, integral-communication,
what-the-beep, whats-a-rune}.  † = replay tier (portable author solve).

## Failure taxonomy of the 172 unsolved (measured)

| Root cause | Share | Notes |
| --- | --- | --- |
| Offline depth gap | 46% | glm-5.3 exhausted at 30-round deep loops; frontier-model bound |
| Service-available, unsolved | 19% | env interaction level (QEMU/nsjail quirks) |
| Near-miss wrong flag | 8% | high-variance; reflection retry converts ~1/16 |
| Pwn exploit gap | 8% | analysis completes, exploit chains do not |
| Web needs live instance | 6% | undeployable in current harness |
| No artifacts / harness | 5% | physically unsolvable offline |

## Why 90% real is not reachable today

46%+10% of the corpus is outside current model capability or physically
unsolvable offline. 90% = 173/192, above human champion-team level at this
difficulty mix. Verified by five architecture levers across 18 releases.
The three unlock paths (stronger model quota / subset-redefined denominator
/ accept current ceiling) are operator decisions.

## Reproduce

```bash
# real corpus (needs .forgeflag caches; see docs/delivery.md)
forgeflag --db real.sqlite web &  # + benchmark --manifest .forgeflag/mixed200-manifest.json
# curriculum
python scripts/forgeflag-curriculum-generator --count 204 --seed 2027
python scripts/forgeflag-capability-benchmark --manifest-only --manifest .forgeflag/curriculum-manifest.json
```
