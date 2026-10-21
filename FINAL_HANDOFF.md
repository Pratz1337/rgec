# Research handoff — public snapshot, 21 October 2026

This is the current public entry point. The underlying experiments below were recorded on 11 October; publication did not rerun them. The proposed policy is RGEC. Its security and novelty goals remain research obligations.

## Latest completed phases

The [scalar candidate](evidence/scalar-scope/audit.json) passed 19 authentic full zlib workflows and seven unchanged C++ compilations: 444 actual compiler executions, 57 real-file round trips and 64,525 native-answer comparisons without an observed disagreement. Native, guard-only, cold-cache, peer-warm and direct-evaluation variants were compared. High hit rates did not produce a complete-build benefit over capable direct evaluation; retain this implementation as a baseline.

The [cost census](evidence/cost-census/audit.json) recorded 606,379 wrapped LLVM calls, including 599,060 outer windows and 7,319 nested calls, in six unchanged full zlib workflows and three C++ compilations. The native compiler always executed. RDTSCP windows include calibration overhead, preemption and possible nested instrumentation. The 64-bit ADD(SRL, Constant) family was selected using aggregate observed cost and varying native answers, not a claimed speedup.

The [TLS-corrected native phase](evidence/native-transition/audit.json) supplied four finite native checks after three full workflows and three C++ controls. Its [four conditional address contracts](evidence/native-transition/conditional-contract.json) allow eight independently placed aligned disjoint objects and selected irrelevant recipient state. Readability, stable ownership and code binding remain premises. These templates all return unknown; a guarded direct specialization is essential. The earlier V2 native-entry model was withdrawn because it omitted actual FS/GS state; its full-workflow controls remain historical.

The [arithmetic phase](evidence/arithmetic/audit.json) passed three complete workflows, nine real-file round trips, three C++ controls and four finite native model checks. Three templates use 240 model blocks and one uses 351. All observed outputs mark the top two bits zero. The following address/shift-parameter contract attempt exited 1 on a proposed right-operand input-shape assertion. It produced no valid arithmetic parameter contract. Finite native checks must not be described as a successful parameterized proof.

## Next construction

First derive the arithmetic input relation from the actual captured graph, rather than assume a constant operand value. Then establish supported-domain native equivalence and enforce before-lookup admission and reconstruction. Compare against a guarded native/direct evaluator and equally scoped normal-fill memoization with full costs. A successful symbolic relation alone does not demonstrate useful caching or establish priority over prior work.

Ownership, alias/lifetime behavior, native ISA fidelity, faults/resources, adaptive release, cold capacity, ordered effects and cancellation remain open obligations. Production shared reuse is disabled. No complete multi-agent model/GPU study or journal acceptance is claimed.

## Working with this snapshot

Use Modal for substantive compiler/model experiments. Local work can edit files, orchestrate and inspect retained evidence. Compiler studies use cloud CPUs; use GPUs only for the later real model workload. Preserve failed attempts and compare complete native controls; do not substitute mock outputs or smoke checks for research evidence.

Public audit files are summaries, not a complete raw replication archive. See [README.md](README.md) for environment dependencies and [evidence/README.md](evidence/README.md) for exact included digests.
