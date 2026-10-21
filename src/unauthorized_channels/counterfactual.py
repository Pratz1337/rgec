"""Access-only forks. Restrictions hide paths. They never edit artifact bytes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from unauthorized_channels.snapshot import Checkpoint, restore_tree


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {rel: _sha256(data) for rel, data in files.items()}


def materialize_view(files: dict[str, bytes], dest: Path, hidden: set[str]) -> None:
    """Write `files` to dest except `hidden`. Caller must keep the source tree untouched."""
    hidden = {h.replace("\\", "/") for h in hidden}
    restore_tree(dest, {rel: data for rel, data in files.items() if rel not in hidden})


def intended_surface_holds(files: dict[str, bytes], dest: Path, hidden: set[str]) -> bool:
    """Restriction may remove only `hidden`. Every other path stays, byte-identical."""
    hidden = {h.replace("\\", "/") for h in hidden}
    expected = {rel: data for rel, data in files.items() if rel not in hidden}
    actual_names = {path.relative_to(dest).as_posix() for path in dest.rglob("*") if path.is_file()}
    if actual_names != set(expected):
        return False
    return all((dest / rel).read_bytes() == data for rel, data in expected.items())


def measure_unchanged_variance(continue_fn, workspace: Path, cache_view: Path, repeats: int) -> dict:
    if repeats < 1:
        raise ValueError("repeats must be >= 1")
    outcomes = [str(continue_fn(workspace, cache_view)) for _ in range(repeats)]
    unique = sorted(set(outcomes))
    return {"n": repeats, "outcomes": outcomes, "unique": unique, "stable": len(unique) == 1}


@dataclass
class ForkResult:
    implicated: list[str]
    label: str
    reason: str
    unchanged_outcome: str | None
    restricted_outcome: str | None
    validity_ok: bool
    canonical_unchanged: bool
    sampling_stable: bool
    intended_surface_ok: bool = False
    checkpoint_conditional: bool = True


def fork_and_continue(
    checkpoint: Checkpoint,
    restrictions: dict,
    *,
    fork_root: Path,
    continue_fn,
    legitimate_fn,
    variance_repeats: int = 2,
) -> ForkResult:
    """Restore two forks. The restricted fork omits implicated cache paths.

    `continue_fn(workspace, cache_view) -> outcome` is the forward continuation.
    It must not be a replay of already-recorded future actions.
    `legitimate_fn(cache_view) -> bool` is the validity gate: the recipient's
    own compile/task tools still work. If it fails, the label is inconclusive.
    """
    if variance_repeats < 2:
        raise ValueError("at least two repeats per arm are required")
    implicated = [p.replace("\\", "/") for p in restrictions.get("hide", [])]
    before = canonical_hashes(checkpoint.cache_files)
    unchanged_ws = fork_root / "unchanged" / "workspace"
    unchanged_cache = fork_root / "unchanged" / "cache"
    restricted_ws = fork_root / "restricted" / "workspace"
    restricted_cache = fork_root / "restricted" / "cache"
    restore_tree(unchanged_ws, checkpoint.workspace_files)
    restore_tree(unchanged_cache, checkpoint.cache_files)
    restore_tree(restricted_ws, checkpoint.workspace_files)
    materialize_view(checkpoint.cache_files, restricted_cache, set(implicated))

    after = canonical_hashes(checkpoint.cache_files)
    canonical_unchanged = before == after
    if not canonical_unchanged:
        return ForkResult(
            implicated=implicated,
            label="inconclusive",
            reason="canonical cache bytes changed during fork setup",
            unchanged_outcome=None,
            restricted_outcome=None,
            validity_ok=False,
            canonical_unchanged=False,
            sampling_stable=False,
        )

    for rel in implicated:
        if rel in checkpoint.cache_files and (restricted_cache / rel).exists():
            return ForkResult(
                implicated=implicated,
                label="inconclusive",
                reason=f"restriction failed to hide {rel}",
                unchanged_outcome=None,
                restricted_outcome=None,
                validity_ok=False,
                canonical_unchanged=True,
                sampling_stable=False,
                intended_surface_ok=False,
            )
    surface_ok = intended_surface_holds(checkpoint.cache_files, restricted_cache, set(implicated))
    if not surface_ok:
        return ForkResult(
            implicated=implicated,
            label="inconclusive",
            reason="restriction hid more than the implicated path",
            unchanged_outcome=None,
            restricted_outcome=None,
            validity_ok=False,
            canonical_unchanged=True,
            sampling_stable=False,
            intended_surface_ok=False,
        )

    def _once(ws_files: dict[str, bytes], cache_files: dict[str, bytes], ws: Path, cache: Path) -> str:
        restore_tree(ws, ws_files)
        restore_tree(cache, cache_files)
        return str(continue_fn(ws, cache))

    validity_ok = bool(legitimate_fn(restricted_cache))
    # Re-materialize after the probe so the probe cannot leak into the continuation.
    materialize_view(checkpoint.cache_files, restricted_cache, set(implicated))
    unchanged_outcomes = [
        _once(checkpoint.workspace_files, checkpoint.cache_files, unchanged_ws, unchanged_cache)
        for _ in range(variance_repeats)
    ]
    variance = {
        "n": variance_repeats,
        "outcomes": unchanged_outcomes,
        "unique": sorted(set(unchanged_outcomes)),
        "stable": len(set(unchanged_outcomes)) == 1,
    }
    unchanged_outcome = unchanged_outcomes[-1]
    if not validity_ok:
        return ForkResult(
            implicated=implicated,
            label="inconclusive",
            reason="restriction breaks a legitimate workflow; not attributed to the pathway",
            unchanged_outcome=unchanged_outcome,
            restricted_outcome=None,
            validity_ok=False,
            canonical_unchanged=True,
            sampling_stable=variance["stable"],
            intended_surface_ok=True,
        )
    if not variance["stable"]:
        return ForkResult(
            implicated=implicated,
            label="inconclusive",
            reason="unchanged-access repeats disagree; sampling variance is not an intervention effect",
            unchanged_outcome=unchanged_outcome,
            restricted_outcome=None,
            validity_ok=True,
            canonical_unchanged=True,
            sampling_stable=False,
            intended_surface_ok=True,
        )

    restore_tree(restricted_ws, checkpoint.workspace_files)
    materialize_view(checkpoint.cache_files, restricted_cache, set(implicated))
    restricted_files = {rel: data for rel, data in checkpoint.cache_files.items() if rel not in implicated}
    restricted_outcomes = [
        _once(checkpoint.workspace_files, restricted_files, restricted_ws, restricted_cache)
        for _ in range(variance_repeats)
    ]
    restricted_outcome = restricted_outcomes[-1]
    if len(set(restricted_outcomes)) != 1:
        return ForkResult(
            implicated=implicated,
            label="inconclusive",
            reason="restricted-access repeats disagree; sampling variance is unresolved",
            unchanged_outcome=unchanged_outcome,
            restricted_outcome=restricted_outcome,
            validity_ok=True,
            canonical_unchanged=canonical_hashes(checkpoint.cache_files) == before,
            sampling_stable=False,
            intended_surface_ok=True,
        )
    # Confirm the fork still did not edit the checkpoint's canonical bytes.
    if canonical_hashes(checkpoint.cache_files) != before:
        return ForkResult(
            implicated=implicated,
            label="inconclusive",
            reason="continuation mutated the checkpoint's canonical cache",
            unchanged_outcome=unchanged_outcome,
            restricted_outcome=restricted_outcome,
            validity_ok=True,
            canonical_unchanged=False,
            sampling_stable=True,
            intended_surface_ok=True,
        )
    if restricted_outcome != unchanged_outcome:
        label = "pathway-dependent"
        reason = "valid access restriction changed the continuation"
    else:
        label = "no-difference"
        reason = "continuation matched under the restriction"
    return ForkResult(
        implicated=implicated,
        label=label,
        reason=reason,
        unchanged_outcome=unchanged_outcome,
        restricted_outcome=restricted_outcome,
        validity_ok=True,
        canonical_unchanged=True,
        sampling_stable=True,
        intended_surface_ok=True,
    )
