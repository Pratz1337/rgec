# Implementation guide

[Project overview](../docs/overview.md) · [Methodology](../docs/methodology.md) · [Reproducibility](../docs/reproducibility.md)

This directory keeps the implementation's original internal layout. Use `code/` as the working directory for installation and historical experiment controllers. Moving the whole tree together preserves their relative imports and source paths.

## Native C++ instrumentation

| File | Role |
|---|---|
| [clang_knownbits_scope.cpp](src/unauthorized_channels/clang_knownbits_scope.cpp) | Experimental scalar projection, memoization, direct evaluation and native-answer comparison |
| [clang_knownbits_cost_census.cpp](src/unauthorized_channels/clang_knownbits_cost_census.cpp) | Observational native call timing and answer-family census |
| [clang_native_entry_capture.cpp](src/unauthorized_channels/clang_native_entry_capture.cpp) | Actual entry memory, arguments, thread-local context and output capture |
| [clang_backend_continuation.cpp](src/unauthorized_channels/clang_backend_continuation.cpp) | Experimental backend cutpoint and recipient-native continuations |

## Experiment orchestration

| Controller | Role |
|---|---|
| [modal_rgec_knownbits_scope.py](modal_rgec_knownbits_scope.py) | Complete-workflow scalar candidate and baselines |
| [modal_rgec_knownbits_cost.py](modal_rgec_knownbits_cost.py) | Native cost and result census |
| [modal_rgec_native_transition.py](modal_rgec_native_transition.py) | Native capture and finite transition-model checks |
| [modal_rgec_native_contract.py](modal_rgec_native_contract.py) | Conditional native memory-contract construction |
| [modal_rgec_native_sample_audit.py](modal_rgec_native_sample_audit.py) | Separate byte/data audits |

The remaining `modal_rgec_*.py` files retain earlier native-effect, backend, failure and baseline phases. Their presence does not indicate that every phase is complete or independently reproducible from this snapshot.

## Verification and worker code

- [Strict native transition checker](scripts/check_rgec_native_transition.py).
- [Conditional contract derivation](scripts/derive_rgec_native_contract.py); the arithmetic extension has a recorded failed construction attempt.
- [Native transition data auditor](scripts/audit_rgec_native_transition.py).
- [Scalar candidate auditor](scripts/audit_rgec_knownbits_scope.py) and [cost census auditor](scripts/audit_rgec_native_cost.py).
- `scripts/rgec_*.py`: experiment-specific workers and native-control probes.
- `src/unauthorized_channels/`: Python runtime, recipe stores, compiler workers and the earlier agent-evaluation framework.

## Secondary study and tests

`configs/`, `data/descriptions/`, `modal_llm.py` and parts of the runtime support the secondary agent/model study. No completed multi-agent model result is claimed. `tests/` contains supporting framework tests; those tests must not be substituted for the authentic compiler experiments in the results.

Install from this directory with `python -m pip install -e ".[research]"`. Read the [replication requirements](../docs/reproducibility.md) before attempting a cloud experiment.
