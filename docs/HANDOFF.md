# Research handoff — updated 22 October 2026

This is the current public entry point. The latest native intervention ran on 22 October; earlier experiments were recorded on 11 October. The proposed policy is RGEC. Its security and novelty goals remain research obligations.

## Latest completed phases

The [22 October intervention](../evidence/sanitizer-intervention/audit.json) completes 18 authentic full zlib workflows, nine unchanged C++ compilations and 54 real-file round trips: 423 actual compiler executions, with 345 driver plans counted separately. All recorded within-setting controls pass. Removing ASan reduces selected ADD64(SRL, Constant) outer windows from 21,522 to six across two profiled zlib builds and one C++ compilation per setting. Reject this family as the principal useful-cache candidate. The separate Modal data auditor verifies 962,402 wrapped records and 2,558 archive members with zero additional compiler actions; it is not an independent semantic proof. See [results and limits](results.md#latest-finding-sanitizer-dependent-candidate).

The [scalar candidate](../evidence/scalar-scope/audit.json) passed 19 authentic full zlib workflows and seven unchanged C++ compilations: 444 actual compiler executions, 57 real-file round trips and 64,525 native-answer comparisons without an observed disagreement. Native, guard-only, cold-cache, peer-warm and direct-evaluation variants were compared. High hit rates did not produce a complete-build benefit over capable direct evaluation; retain this implementation as a baseline.

The [cost census](../evidence/cost-census/audit.json) recorded 606,379 wrapped LLVM calls, including 599,060 outer windows and 7,319 nested calls, in six unchanged full zlib workflows and three C++ compilations. The native compiler always executed. RDTSCP windows include calibration overhead, preemption and possible nested instrumentation. The 64-bit ADD(SRL, Constant) family was selected using aggregate observed cost and varying native answers, not a claimed speedup.

The [TLS-corrected native phase](../evidence/native-transition/audit.json) supplied four finite native checks after three full workflows and three C++ controls. Its [four conditional address contracts](../evidence/native-transition/conditional-contract.json) allow eight independently placed aligned disjoint objects and selected irrelevant recipient state. Readability, stable ownership and code binding remain premises. These templates all return unknown; a guarded direct specialization is essential. The earlier V2 native-entry model was withdrawn because it omitted actual FS/GS state; its full-workflow controls remain historical.

The [arithmetic phase](../evidence/arithmetic/audit.json) passed three complete workflows, nine real-file round trips, three C++ controls and four finite native model checks. Three templates use 240 model blocks and one uses 351. All observed outputs mark the top two bits zero. The following address/shift-parameter contract attempt exited 1 on a proposed right-operand input-shape assertion. It produced no valid arithmetic parameter contract. Finite native checks must not be described as a successful parameterized proof.

## Next construction

The four captured arithmetic graphs contain shift `3` and addend `0x7fff8000`, not the attempted contract's assumed addend `1`. Preserve that failed attempt. Select useful expensive work in the non-ASan native pipeline, establish supported-domain native equivalence, and enforce before-lookup admission and reconstruction. Compare against a guarded native/direct evaluator and equally scoped normal-fill memoization with full costs. A successful symbolic relation alone does not demonstrate useful caching or establish priority over prior work.

Ownership, alias/lifetime behavior, native ISA fidelity, faults/resources, adaptive release, cold capacity, ordered effects and cancellation remain open obligations. Production shared reuse is disabled. No complete multi-agent model/GPU study or journal acceptance is claimed.

## Working with this snapshot

Use Modal for substantive compiler/model experiments. Local work can edit files, orchestrate and inspect retained evidence. Compiler studies use cloud CPUs; use GPUs only for the later real model workload. Preserve failed attempts and compare complete native controls; do not substitute mock outputs or smoke checks for research evidence.

Public audit files are summaries, not a complete raw replication archive. See [README.md](../README.md) for environment dependencies and [evidence/README.md](../evidence/README.md) for exact included digests.
