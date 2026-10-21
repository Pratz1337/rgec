# Methodology

[Overview](overview.md) · [Results](results.md) · [Reproducibility](reproducibility.md)

## Native workload evaluation

The compiler experiments use unchanged zlib source files and an unchanged libFuzzer C++ translation unit. Complete zlib workflows include compilation and linking, upstream tests, and compression/decompression of actual repository files. Source code is not replaced with a mock workload.

Comparison variants include the original compiler, an instrumented native control, guard-only execution, cold-cache reuse, peer-warm reuse and direct evaluation over the same manually selected scalar projection. Recorded comparisons cover exit status, exact stdout/stderr, object/archive/executable bytes and the tested runtime outputs.

The scalar study uses three seeded order blocks on one worker. This limits independence and statistical generalization. A high cache-hit rate is not treated as evidence of complete-workflow benefit.

## Cost profiling

The cost census observes original native computations; it never substitutes an analysis answer. It records wrapped call windows and answer families, retains timer calibration, identifies nested wrapper calls and records clock migration information. Candidate selection uses aggregate observed cost and varying native answers.

RDTSCP windows contain instrumentation overhead and may include preemption and nested logging. They are not automatically native CPU time, a worst-case execution bound or the compute savings of a complete cache policy.

## Native transition checks

Actual compiler execution supplies entry arguments, readable/writable memory, thread-local context and output bytes. The strict angr/VEX checker executes the pinned ELF model and checks the recorded output, preserved registers and stack state. Unsupported accesses, effects, hooks and external execution reject a candidate.

The corrected thread boundary binds actual FS. Where GS capture is unavailable, GS remains symbolic rather than being assumed zero. The conditional address contracts vary declared object placements and selected irrelevant state while requiring valid, stable and disjoint memory.

These are instruction-model results for stated templates, not a complete native ISA, operating-system or resource/fault proof.

## Evidence accounting

- Compiler executions, driver plans, configure probes and image preparation are distinct accounting categories.
- Symbolic parameter variations are not additional native experiments.
- A data audit authenticates retained records; it does not independently rerun the compiler experiment or prove its symbolic claims.
- Failed attempts and negative utility findings remain part of the research record.
- This public snapshot includes selected summaries, not the raw process-memory or full replication archives.

The [evidence index](../evidence/README.md) links the included original records and their digests.
