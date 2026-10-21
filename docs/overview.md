# Project overview

[Repository home](../README.md) · [Results](results.md) · [Methodology](methodology.md) · [Roadmap](roadmap.md)

## Research problem

Sharing compiler results can save repeated computation. For independently tasked AI agents, however, the cache also becomes shared infrastructure: a recipient's observations could depend on another agent's prior work. Hiding the cache directory alone does not establish that outputs, timing or filesystem behavior are independent of that shared state.

A second question concerns correctness. Reusing a producer's successful result must not override a recipient's own permission failure, diagnostic policy or native output behavior. This project studies those native execution boundaries rather than treating identical final object bytes as a complete correctness argument.

## Research objective

RGEC proposes admitting reusable computation only where a checkable contract separates computation dependencies from recipient-specific authority and effects. The longer-term security target is adaptive agent-observation noninterference under a defined observer, release schedule and resource model.

The proposed contribution to establish is a useful native admission and reconstruction rule with an explicit security boundary. Memoization, signed receipts, dependency tracking and symbolic execution are existing techniques; their presence alone does not establish novelty.

## Implementation completed

- Native C++ instrumentation around LLVM/Clang analysis and backend execution.
- Experimental scalar reuse, direct-evaluation and native comparison modes.
- Python orchestration of complete compiler workloads on Modal CPU workers.
- Capture of actual native entry memory, arguments, output and thread-local context.
- angr/VEX transition checking and conditional address-parametric model contracts for selected templates.
- Byte-level evidence audits and documented negative results.

The [results page](results.md) gives the measured scope. The [code guide](../code/README.md) connects each component to its implementation.

## Current interpretation

The work provides implemented research components and finite native controls. It does not yet establish a generally sound native admission mechanism, useful end-to-end cache policy, adaptive noninterference guarantee or completed multi-agent model evaluation. The newest arithmetic parameter-contract attempt remains unfinished after an input-shape assertion failed.

The next phase must turn the selected native-state relation into enforced admission and demonstrate a useful advantage against capable direct evaluation and memoization. See the [research roadmap](roadmap.md).
