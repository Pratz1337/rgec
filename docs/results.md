# Results and interpretation

[Overview](overview.md) · [Methodology](methodology.md) · [Evidence index](../evidence/README.md)

The latest intervention was executed on **22 October 2026**. Earlier phases use recorded experiments from **11 October**; repository publication on 21 October did not rerun those. Counts apply to their own phase.

## Latest finding: sanitizer-dependent candidate

The matched intervention keeps the compiler, unchanged sources, `-O1`, frame-pointer/debug settings and fuzz-build macro fixed. It varies ASan and coverage flags, comparing original, unpatched native and census compilers within each setting. Two seeded blocks complete **18 full zlib workflows**, upstream tests, **54 real-file round trips** and **nine C++ compilations**: **423 actual compiler executions**, with **345 driver plans counted separately**. Configure and image-preparation compiler actions are additional. All recorded within-setting status, stream, artifact and runtime controls pass.

| Flag setting | Wrapped native call records | Selected ADD64(SRL, Constant) outer windows |
|---|---:|---:|
| ASan + coverage | 606,379 | 21,522 |
| Coverage only | 219,369 | 6 |
| Neither | 136,654 | 6 |

Each row combines two profiled zlib builds and one profiled C++ compilation. Selected family counts require scalar, depth-zero, demanded-element-one, same-CPU outer windows. Removing ASan reduces this family by **99.97% in this sample**. The four earlier arithmetic captures contain shift `3` and addend `0x7fff8000`, matching [ASan's documented shadow mapping](https://github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm). The census does not capture every constant payload; it does not identify every node's source insertion.

The separate Modal data auditor verifies 2,558 archive members and **962,402 wrapped calls**: 946,257 outer windows and 16,145 nested records. It executes zero compiler actions. The ASan-family median is 622 TSC ticks, including instrumentation overhead; this is neither complete CPU savings nor a worst-case bound. One worker, two blocks and one C++ source limit generalization.

**Decision:** reject this arithmetic family as the principal useful-cache candidate. The earlier negative direct-evaluation comparison remains a separate result. A corrected proof of this small arithmetic, more supported operators or a higher hit rate would not establish the requested useful new policy.

Source: [original intervention audit](../evidence/sanitizer-intervention/audit.json).

## Scalar reuse candidate

| Measure | Recorded result |
|---|---:|
| Complete unchanged zlib workflows | 19 |
| Unchanged C++ compilations | 7 |
| Actual compiler executions | 444 |
| Real-file round trips | 57 |
| Comparisons with native analysis answers | 64,525 |
| Observed answer disagreements | 0 |

The recorded compiler status, streams and artifacts pass the finite controls. Upstream tests and real-file round trips also pass. These results support tested behavior in the selected scalar domain, not universal equivalence.

The following child-plus-controller CPU medians are from three seeded order blocks on one worker:

| Mode | Median complete-build CPU (seconds) |
|---|---:|
| Original native compiler | 4.71 |
| Instrumented native control | 4.98 |
| Guard-only native execution | 4.82 |
| Cold-cache reuse | 4.79 |
| Peer-warm reuse | 4.85 |
| Direct evaluation | 4.77 |

**Interpretation:** peer-warm reuse did not outperform the capable direct evaluator. Its high hit rate did not establish useful complete-build savings. Keep this implementation as a baseline rather than claim a performance improvement. Setup, producer transfer/storage and protected-observer capacity are not a complete amortized cost accounting.

Source: [original scalar audit](../evidence/scalar-scope/audit.json).

## Native cost census

Six full zlib workflows and three C++ compilations contain 141 actual compiler executions. The observer records **606,379 wrapped native calls**, including **599,060 outer windows** and **7,319 nested records**. Compiler outputs and the complete-workflow controls match their native references.

The 64-bit ADD over a shifted value and constant was the largest aggregate nonconstant family in the selected scalar outer-window grouping. Its 21,522 sampled windows have a median of 600 TSC ticks. This is a profiling result with instrumentation limits, not a cache speedup or a population timing guarantee.

Source: [original cost-census audit](../evidence/cost-census/audit.json).

## TLS-corrected native model

Three complete zlib workflows and three C++ controls provide 72 compiler executions and nine real-file round trips. Four actual TRUNCATE/CopyFromReg templates pass finite native transition checks. Four conditional contracts additionally support eight independently placed aligned disjoint objects and selected irrelevant recipient state under stated memory premises.

All four templates return unknown bits. The contracts do not enforce runtime ownership or cover general aliasing, lifetimes, concurrent mutation, native faults/resources or the full adaptive observer.

An earlier native-entry witness was withdrawn for omitted FS/GS context. The corrected record is the one published here.

Sources: [native audit](../evidence/native-transition/audit.json), [contract audit](../evidence/native-transition/contract-audit.json), [conditional contracts](../evidence/native-transition/conditional-contract.json).

## Arithmetic candidate

Three full workflows, nine real-file round trips and three C++ controls pass, alongside four finite native model checks. Three templates execute 240 model blocks and one executes 351. The later address/shift-parameter contract attempt exits 1 on an input-shape assertion; it does not produce a valid parameterized arithmetic proof.

Source: [original arithmetic native audit](../evidence/arithmetic/audit.json). The failed construction is described in the [handoff](HANDOFF.md).

## What these results support

The evidence supports implemented compiler instrumentation, finite native controls, measured candidate-selection data and conditional model results. A useful new general cache policy, substantial comparative novelty, complete replication bundle and end-to-end noninterference remain open. No completed multi-agent model study or journal acceptance is claimed.
