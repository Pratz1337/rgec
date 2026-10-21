"""Drive the shipped solo launcher, not a reimplementation."""

from __future__ import annotations

import json
from pathlib import Path

from unauthorized_channels.cache import CacheMode
from unauthorized_channels.outcomes import TaskOutcome
from unauthorized_channels.runtime import docker_probe, launch_solo
from unauthorized_channels.tasks import CALIBRATION_POOL, MODELS, parse_task_id


def test_container_names_include_task_and_do_not_collide() -> None:
    from unauthorized_channels.runtime import container_name

    a = container_name("qwen3-coder-30b-a3b-instruct", "arvo:10400")
    b = container_name("qwen3-coder-30b-a3b-instruct", "arvo:1065")
    assert a != b
    assert "10400" in a
    assert "1065" in b
    assert len(a) <= 63
    dup = container_name("qwen3-coder-30b-a3b-instruct-arvo-10400", "arvo:10400")
    assert dup.count("10400") == 1
    assert "1065" not in dup


def test_pool_is_larger_than_sixteen() -> None:
    assert len(CALIBRATION_POOL) > 16
    parse_task_id(CALIBRATION_POOL[0])
    parse_task_id(CALIBRATION_POOL[-1])


def test_launch_solo_records_outcome(tmp_path: Path) -> None:
    rec = launch_solo(
        model_id=MODELS[0],
        task_id="arvo:10400",
        run_root=tmp_path / "run-qwen",
        cache_mode=CacheMode.PRIVATE,
        agent_id="solo-qwen",
        max_actions=4,
    )
    assert rec.outcome in TaskOutcome
    assert rec.task_id == "arvo:10400"
    assert rec.model_id == MODELS[0]
    saved = json.loads((tmp_path / "run-qwen" / "run.json").read_text(encoding="utf-8"))
    assert saved["outcome"] == rec.outcome.value
    argv = rec.extra["docker_argv"]
    assert argv[argv.index("--network") + 1] == "none"
    assert "docker" in " ".join(argv).lower() or argv[0].endswith("wsl") or "wsl" in argv[0].lower()
    usable, _ = docker_probe()
    if not usable:
        assert rec.outcome is TaskOutcome.INFRASTRUCTURE_FAILURE
        assert rec.infrastructure_error


def test_launch_solo_shared_and_private_use_same_entry_point(tmp_path: Path) -> None:
    rec_priv = launch_solo(
        model_id=MODELS[1],
        task_id="arvo:10400",
        run_root=tmp_path / "priv",
        cache_mode=CacheMode.PRIVATE,
        agent_id="a-priv",
        max_actions=4,
    )
    rec_shared = launch_solo(
        model_id=MODELS[1],
        task_id="arvo:10400",
        run_root=tmp_path / "shared",
        cache_mode=CacheMode.SHARED,
        agent_id="a-shared",
        max_actions=4,
    )
    assert rec_priv.cache_mode == "private"
    assert rec_shared.cache_mode == "shared"
    assert rec_priv.extra["docker_argv"][rec_priv.extra["docker_argv"].index("--network") + 1] == "none"
    def cache_vol(argv: list[str]) -> str:
        vols = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-v"]
        hits = [v for v in vols if "/ccache" in v]
        assert hits
        return hits[0]
    assert cache_vol(rec_priv.extra["docker_argv"]) != cache_vol(rec_shared.extra["docker_argv"])
    assert "mailbox" not in json.dumps(rec_shared.to_dict())
