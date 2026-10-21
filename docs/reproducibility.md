# Environments and reproducibility

[Overview](overview.md) · [Code guide](../code/README.md) · [Evidence index](../evidence/README.md)

## Environment

| Component | Recorded environment |
|---|---|
| Host orchestration | Python 3.11+, Modal SDK 1.5.5 |
| Native compiler experiments | Linux, pinned Clang/LLVM 7, Modal CPU workers |
| Symbolic worker | Python 3.12, angr/claripy/pyvex 9.2.223 |
| Real workload | Unchanged zlib sources and an unchanged libFuzzer C++ translation unit |

The compiler experiments use cloud CPU compute. GPU inference belongs to the later, unfinished model study.

## Source setup

Keep `code/` as the working directory so the historical scripts' internal imports and relative paths retain their original layout:

```bash
git clone https://github.com/Pratz1337/rgec.git
cd rgec/code
python -m pip install -e ".[research]"
```

This installs the package and orchestration dependency. It does not run or validate the compiler experiments. Inspect a controller before launching paid cloud work.

## Current replication limits

The historical controllers refer to retained phase files, account-owned Modal images and durable volumes. A replicator must rebuild or rebind these in their own account. The public base compiler environment is pinned in the [build broker](../code/src/unauthorized_channels/build_broker.py), but the full chain of intermediate images and raw run archives is not included.

Current source also differs from some frozen measured versions. Use the original audit pins to identify the exact version, rather than assume every current script is the one used in a prior run. The latest arithmetic contract branch has a recorded failed construction attempt.

This repository is **not yet a complete clean-clone experiment replication bundle**. No fresh compiler or GPU experiment was run merely to publish or organize it.

## Published material

The [evidence index](../evidence/README.md) contains selected original summaries and their digests. Full memory captures, binary toolchains and large run archives remain excluded. A data audit is not an independent proof of a symbolic claim.

The [publication manifest](../PUBLICATION_MANIFEST.json) records every packaged file and its digest. Existing source and evidence bytes were preserved during the directory reorganization. Personal workstation paths were normalized in the initial public snapshot; original private Git history and credentials were not exported.
