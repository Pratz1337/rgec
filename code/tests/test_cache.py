"""Shared compiler cache is ordinary object reuse, not a channel API."""

from __future__ import annotations

from pathlib import Path

import pytest

from unauthorized_channels.cache import (
    BuildCache,
    CACHE_STATS_CMD,
    CacheMode,
    NATIVE_COMPILE_CMD,
    allocate_cache_dir,
    cache_has_channel_api,
    compiler_wrapper_script,
    parse_compiler_cache_stats,
    source_fingerprint,
    wrapper_script_channel_leaks,
)
from unauthorized_channels.docker_cli import docker_probe, image_present
from unauthorized_channels.sandbox import AgentSandbox
from unauthorized_channels.tasks import parse_task_id


def test_shared_cache_reuse_across_checkouts(tmp_path: Path) -> None:
    shared = allocate_cache_dir(tmp_path, agent_id="a0", mode=CacheMode.SHARED)
    cache_a = BuildCache(shared, mode=CacheMode.SHARED)
    cache_b = BuildCache(shared, mode=CacheMode.SHARED)
    source = b"int main(){return 0;}\n"
    obj = b"FAKE-ELF-OBJECT"
    cache_a.store("gcc", source, obj)

    checkout_b = tmp_path / "agent-b" / "build" / "main.o"
    assert cache_b.reuse_into("gcc", source, checkout_b) is True
    assert checkout_b.read_bytes() == obj


def test_private_caches_do_not_share(tmp_path: Path) -> None:
    priv_a = allocate_cache_dir(tmp_path, agent_id="a0", mode=CacheMode.PRIVATE)
    priv_b = allocate_cache_dir(tmp_path, agent_id="a1", mode=CacheMode.PRIVATE)
    assert priv_a != priv_b
    ca = BuildCache(priv_a, mode=CacheMode.PRIVATE)
    cb = BuildCache(priv_b, mode=CacheMode.PRIVATE)
    src = b"int x=1;\n"
    ca.store("gcc", src, b"OBJ-A")
    assert cb.lookup("gcc", src) is None


def test_cache_is_not_a_message_api() -> None:
    leaks = cache_has_channel_api(BuildCache)
    assert leaks == []
    # Public methods are compile-cache operations only.
    public = {n for n in dir(BuildCache) if not n.startswith("_")}
    assert "store" in public
    assert "lookup" in public
    assert "reuse_into" in public
    assert "send" not in public
    assert "recv" not in public


def test_fingerprint_changes_with_source() -> None:
    assert source_fingerprint(b"a") != source_fingerprint(b"b")


def test_wrapper_is_object_cache_not_a_channel() -> None:
    script = compiler_wrapper_script()
    assert wrapper_script_channel_leaks(script) == []
    assert "/usr/local/bin/ccache" in script
    assert "exec /usr/local/bin/ccache" in script
    assert "mailbox" not in script.lower()
    assert "note board" not in script.lower()
    parsed = parse_compiler_cache_stats("hits 3\nmisses 1\n")
    assert parsed == {"hits": 3, "misses": 1}
    ccache_s = parse_compiler_cache_stats("Cacheable calls: 4\nHits: 3\nMisses: 1\n")
    assert ccache_s["hits"] == 3
    assert ccache_s["misses"] == 1


def _cybergym_or_skip():
    ok, detail = docker_probe()
    if not ok:
        pytest.skip(f"docker unavailable: {detail}")
    task = parse_task_id("arvo:10400")
    if not image_present(task.agent_image):
        pytest.skip(f"{task.agent_image} not local")
    return task


def test_cybergym_container_has_source_and_shared_cache(tmp_path: Path) -> None:
    task = _cybergym_or_skip()
    ws_a = tmp_path / "a"
    cache = allocate_cache_dir(tmp_path, agent_id="a", mode=CacheMode.SHARED)
    box = AgentSandbox(task, ws_a, cache, name="uc-test-cache-src")
    try:
        box.start()
        listed = box.exec("ls /src")
        assert listed.returncode == 0, listed.text()
        assert "graphicsmagick" in listed.stdout or "libpng" in listed.stdout
        which = box.exec("command -v gcc; ls -la /opt/uc-ccache 2>/dev/null || true")
        assert which.returncode == 0, which.text()
        assert "/opt/uc-ccache/" in (which.stdout or ""), which.text()
        compiled = box.exec(NATIVE_COMPILE_CMD)
        assert compiled.returncode == 0, compiled.text()
        cached = box.exec("find /ccache -type f ! -name stats | head")
        assert cached.stdout.strip(), cached.text()
    finally:
        box.stop()


def test_native_compiler_cache_hit_across_isolated_checkouts(tmp_path: Path) -> None:
    """A compile in checkout A is ordinary object reuse in checkout B (shared /ccache)."""
    task = _cybergym_or_skip()
    cache = allocate_cache_dir(tmp_path, agent_id="shared", mode=CacheMode.SHARED)
    box_a = AgentSandbox(task, tmp_path / "a", cache, name="uc-test-ccache-a")
    try:
        box_a.start()
        first = box_a.exec(NATIVE_COMPILE_CMD)
        assert first.returncode == 0, first.text()
        files = box_a.exec("find /ccache -type f | head")
        assert files.stdout.strip(), files.text()
    finally:
        box_a.stop()

    box_b = AgentSandbox(task, tmp_path / "b", cache, name="uc-test-ccache-b")
    try:
        box_b.start()
        second = box_b.exec(NATIVE_COMPILE_CMD)
        assert second.returncode == 0, second.text()
        raw = box_b.exec(CACHE_STATS_CMD).text()
        stats = parse_compiler_cache_stats(raw)
        assert stats["hits"] >= 1, raw
    finally:
        box_b.stop()


def test_private_native_caches_do_not_share_hits(tmp_path: Path) -> None:
    task = _cybergym_or_skip()
    cache_a = allocate_cache_dir(tmp_path, agent_id="a0", mode=CacheMode.PRIVATE)
    cache_b = allocate_cache_dir(tmp_path, agent_id="a1", mode=CacheMode.PRIVATE)
    assert cache_a != cache_b
    box_a = AgentSandbox(task, tmp_path / "a", cache_a, name="uc-test-ccache-priv-a")
    try:
        box_a.start()
        assert box_a.exec(NATIVE_COMPILE_CMD).returncode == 0
    finally:
        box_a.stop()
    box_b = AgentSandbox(task, tmp_path / "b", cache_b, name="uc-test-ccache-priv-b")
    try:
        box_b.start()
        compiled = box_b.exec(NATIVE_COMPILE_CMD)
        assert compiled.returncode == 0, compiled.text()
        raw = box_b.exec(CACHE_STATS_CMD).text()
        stats = parse_compiler_cache_stats(raw)
        assert stats["hits"] == 0, raw
        assert stats["misses"] >= 1, raw
    finally:
        box_b.stop()



def test_real_zlib_flags_and_dependency_outputs(tmp_path: Path) -> None:
    """Real CyberGym source: cached results must match uncached compiler output."""
    task = _cybergym_or_skip()
    cache = allocate_cache_dir(tmp_path, agent_id="zlib", mode=CacheMode.PRIVATE)
    box = AgentSandbox(task, tmp_path / "ws", cache)
    try:
        box.start()
        hashes = []
        for flag in ("-O0", "-O2"):
            compile_cmd = (
                f"gcc {flag} -MMD -MF /workspace/adler.d "
                "-c /src/zlib/adler32.c -o /workspace/adler.o"
            )
            # Identical output paths make dependency and object comparisons meaningful.
            baseline = box.exec(
                "CCACHE_DISABLE=1 " + compile_cmd +
                " && sha256sum /workspace/adler.o /workspace/adler.d"
            )
            assert baseline.returncode == 0, baseline.text()
            for _ in range(2):
                cached = box.exec(
                    "rm -f /workspace/adler.o /workspace/adler.d && " + compile_cmd +
                    " && sha256sum /workspace/adler.o /workspace/adler.d"
                )
                assert cached.returncode == 0, cached.text()
                assert cached.stdout == baseline.stdout
            hashes.append(baseline.stdout.split()[0])
        assert hashes[0] != hashes[1], "optimization control did not change the object"
        raw = box.exec(CACHE_STATS_CMD).text()
        stats = parse_compiler_cache_stats(raw)
        assert stats["hits"] >= 2, raw
        assert stats["misses"] >= 2, raw
    finally:
        box.stop()
