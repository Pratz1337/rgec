"""Drive the real CyberGym container: list /src and write through the compiler cache."""

from __future__ import annotations

from pathlib import Path

import pytest

from unauthorized_channels.cache import CacheMode, NATIVE_COMPILE_CMD, allocate_cache_dir
from unauthorized_channels.docker_cli import docker_probe, image_present
from unauthorized_channels.sandbox import AgentSandbox
from unauthorized_channels.tasks import parse_task_id


def test_cybergym_container_has_source_and_shared_cache(tmp_path: Path) -> None:
    ok, detail = docker_probe()
    if not ok:
        pytest.skip(f"docker unavailable: {detail}")
    task = parse_task_id("arvo:10400")
    if not image_present(task.agent_image):
        pytest.skip(f"{task.agent_image} not local")
    ws_a = tmp_path / "a"
    cache = allocate_cache_dir(tmp_path, agent_id="a", mode=CacheMode.SHARED)
    box = AgentSandbox(task, ws_a, cache, name="uc-test-src")
    try:
        box.start()
        listed = box.exec("ls /src")
        assert listed.returncode == 0, listed.text()
        assert "graphicsmagick" in listed.stdout or "libpng" in listed.stdout
        compilers = box.exec("command -v gcc")
        assert compilers.returncode == 0, compilers.text()
        compiled = box.exec(NATIVE_COMPILE_CMD)
        assert compiled.returncode == 0, compiled.text()
    finally:
        box.stop()
    cached_files = list(cache.rglob("*"))
    assert any(p.is_file() for p in cached_files), f"compiler cache stayed empty: {cached_files}"



def test_lost_container_invalidates_episode_without_reexecution(tmp_path, monkeypatch):
    import subprocess
    from unauthorized_channels import sandbox
    box = AgentSandbox(parse_task_id("arvo:10400"), tmp_path / "ws", tmp_path / "cache")
    box._started = True
    calls = []
    def stopped(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "container is not running")
    monkeypatch.setattr(sandbox.subprocess, "run", stopped)
    with pytest.raises(RuntimeError, match="state lost"):
        box.exec("ls /src")
    assert len(calls) == 1
