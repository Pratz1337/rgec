"""Tool-boundary checkpoints. Restoration must reproduce bytes, not a summary."""

from __future__ import annotations

import copy
import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path


def _files(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    if not root.exists():
        return out
    for path in root.rglob("*"):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            out[rel] = path.read_bytes()
    return out


def tree_manifest(root: Path) -> dict[str, str]:
    return {rel: hashlib.sha256(data).hexdigest() for rel, data in _files(root).items()}


def restore_tree(root: Path, files: dict[str, bytes]) -> None:
    """Replace root so it contains exactly `files`. Does not touch any other directory."""
    root.mkdir(parents=True, exist_ok=True)
    existing = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    for rel in existing - set(files):
        target = root / rel
        target.unlink()
    for rel, data in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    # Drop directories that the snapshot does not need.
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()


@dataclass
class Checkpoint:
    """State immediately before a tool action (before a possible read)."""

    checkpoint_id: str
    agent_id: str
    step_index: int
    messages: list[dict]
    workspace_files: dict[str, bytes]
    cache_files: dict[str, bytes]
    scheduler: dict
    remaining_actions: int
    remaining_tokens: int

    def manifests(self) -> dict[str, dict[str, str]]:
        def digest(files: dict[str, bytes]) -> dict[str, str]:
            return {rel: hashlib.sha256(data).hexdigest() for rel, data in files.items()}

        return {"workspace": digest(self.workspace_files), "cache": digest(self.cache_files)}


def capture_checkpoint(
    *,
    checkpoint_id: str,
    agent_id: str,
    step_index: int,
    messages: list[dict],
    workspace: Path,
    cache_dir: Path,
    scheduler_state: dict,
    remaining_actions: int,
    remaining_tokens: int,
) -> Checkpoint:
    return Checkpoint(
        checkpoint_id=checkpoint_id,
        agent_id=agent_id,
        step_index=step_index,
        messages=copy.deepcopy(messages),
        workspace_files=_files(workspace),
        cache_files=_files(cache_dir),
        scheduler=copy.deepcopy(scheduler_state),
        remaining_actions=remaining_actions,
        remaining_tokens=remaining_tokens,
    )


def restore_checkpoint(checkpoint: Checkpoint, workspace: Path, cache_dir: Path) -> None:
    restore_tree(workspace, checkpoint.workspace_files)
    restore_tree(cache_dir, checkpoint.cache_files)


def states_match(checkpoint: Checkpoint, workspace: Path, cache_dir: Path, scheduler_state: dict) -> bool:
    return (
        tree_manifest(workspace) == checkpoint.manifests()["workspace"]
        and tree_manifest(cache_dir) == checkpoint.manifests()["cache"]
        and scheduler_state == checkpoint.scheduler
    )


def restore_episode_state(checkpoint: Checkpoint, workspace: Path, cache_dir: Path) -> dict:
    """Put files back and rebuild the scheduler. Conversation and budget come from the checkpoint."""
    from unauthorized_channels.scheduler import InterleavedScheduler

    restore_checkpoint(checkpoint, workspace, cache_dir)
    scheduler = InterleavedScheduler.from_dict(checkpoint.scheduler)
    return {
        "messages": copy.deepcopy(checkpoint.messages),
        "scheduler": scheduler,
        "remaining_actions": checkpoint.remaining_actions,
        "remaining_tokens": checkpoint.remaining_tokens,
    }


def wipe_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
