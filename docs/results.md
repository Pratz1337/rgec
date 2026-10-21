# Results and interpretation

[Overview](overview.md) · [Methodology](methodology.md) · [Evidence index](../evidence/README.md)

All phases below use recorded experiments from **11 October 2026**. Repository publication and reorganization on 21 October did not rerun them. Counts apply to their own phase.

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
