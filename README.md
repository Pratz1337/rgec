# RGEC: Compiler Cache Safety for AI Agents

Research code for **Receipt-Gated Epoch Cache (RGEC)**, a proposed recipient-aware cache policy. The project investigates when compiler computation can be reused while preserving the recipient's native diagnostics, output authority, filesystem effects and failures, and how shared reuse could be composed with a defined observation boundary for AI agents.

**Status: ongoing research.** This repository contains experimental implementations, authentic compiler-workload evaluation and conditional symbolic results. End-to-end noninterference, a generally sound native admission rule and substantial algorithmic novelty are not established. The implemented scalar cache did not demonstrate a complete-build performance benefit. No journal acceptance or completed multi-agent model study is claimed.

## Measured results

These are retained experiments from **11 October 2026**, packaged for publication on **21 October 2026**. Separate rows describe separate phases; symbolic cases and byte audits are not additional physical experiments.

| Phase | Evidence | Interpretation |
|---|---|---|
| Scalar reuse candidate | 19 full unchanged zlib workflows, seven C++ compilations, 444 compiler executions, 57 real-file round trips; 64,525 comparisons with native analysis and no observed mismatches | Tested correctness controls passed; peer-warm reuse failed to outperform the capable direct baseline |
| Native cost survey | 606,379 wrapped LLVM calls across six full zlib workflows and three C++ compilations; 141 compiler executions | Observational profiling, with calibration and nested-call accounting; no cache speedup follows |
| TLS-corrected transition model | Three full workflows and three C++ controls; four native templates checked in angr/VEX, plus four conditional address-parametric contracts | Model reasoning under stable, readable, disjoint-memory premises; no native ISA or resource/fault theorem |
| Arithmetic candidate | Three full workflows and three C++ controls; four finite native transition checks | The subsequent parameterized-contract attempt failed an input-shape assertion and remains unfinished |

Compiler counts exclude separately recorded driver plans, configure probes and image preparation. Matching finite controls do not establish universal correctness. Audit summaries authenticate recorded bytes; they do not independently prove symbolic claims. See [the evidence index](evidence/README.md) for the original summaries and hashes.

## Repository map

- [Current handoff](FINAL_HANDOFF.md) and [brief research goal](FINAL_GOAL.md).
- [Policy and conditional security argument](CACHE_POLICY_NONINTERFERENCE.md).
- [Native scope construction](NATIVE_SCOPE_CONSTRUCTION.md) and [native admission obligations](NATIVE_ADMISSION_CONTRACT.md).
- `src/unauthorized_channels/`: C++ compiler instrumentation, experimental recipe stores, recipient-native continuations and the earlier agent-evaluation framework.
- `scripts/`: experiment workers, native model checking and data auditors.
- `modal_rgec_*.py`: Modal orchestration for the research phases.
- `tests/` and `configs/`: supporting framework tests and the secondary model-study configuration. Their presence is not evidence that model episodes have run.

## Environment and replication boundary

The host package requires **Python 3.11+**. Native experiments use Linux, the pinned Clang/LLVM 7 environment and Modal CPU workers. The symbolic workers use **Python 3.12 and angr/claripy/pyvex 9.2.223**. GPU inference is a separate, unfinished study.

```bash
python -m pip install -e ".[research]"
```

The package can be installed from this snapshot. Historical phase controllers additionally refer to retained phase files, account-owned Modal images and durable volumes. Those dependencies must be rebuilt or rebound in the replicator's own account; this is **not yet a complete clean-clone replication bundle**. Installation does not run or validate the experiments. Inspect the selected controller before launching paid cloud work.

The public base compiler environment is pinned in `src/unauthorized_channels/build_broker.py`. Current source differs from some frozen experimental sources: use the audit pins to identify the exact measured version. The most recent arithmetic contract branch is experimental and has a recorded failed construction attempt.

## Publication contents

This is a fresh source snapshot with a new Git history. Credentials, personal workstation paths, original private Git history, raw process-memory captures, binary toolchains, large run archives and obsolete review reports are excluded. The included audit/contract JSON files are byte-identical copies of the selected retained records; they are summaries rather than raw-data replication packages. [PUBLICATION_MANIFEST.json](PUBLICATION_MANIFEST.json) records every packaged file and its digest.

Maintained by [Pratz1337](https://github.com/Pratz1337).
