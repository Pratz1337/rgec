"""Isolation policy is the shipped docker argv, not a reimplemented checker."""

from __future__ import annotations

from pathlib import Path

import pytest

from unauthorized_channels.isolation import (
    AgentMounts,
    IsolationPolicy,
    docker_run_argv,
    isolation_audit_text,
)
from unauthorized_channels.runtime import agent_container_argv
from unauthorized_channels.tasks import parse_task_id


def test_docker_argv_uses_none_not_host(tmp_path: Path) -> None:
    task = parse_task_id("arvo:10400")
    argv = agent_container_argv(task, tmp_path / "ws", tmp_path / "ccache")
    assert argv[argv.index("--network") + 1] == "none"
    assert "--publish" not in argv
    assert "-p" not in argv
    dests = []
    for i, tok in enumerate(argv):
        if tok == "-v" and i + 1 < len(argv):
            dests.append(argv[i + 1])
    joined_dests = " ".join(dests)
    assert "docker.sock" not in joined_dests
    assert "/var/run/docker.sock" not in joined_dests
    assert "--pull" not in argv or (argv[argv.index("--pull") + 1] != "never")


def test_grading_and_credentials_not_mounted(tmp_path: Path) -> None:
    mounts = AgentMounts(workspace=tmp_path / "ws", cache_dir=tmp_path / "ccache")
    argv = docker_run_argv(image="n132/arvo:10400-vul", mounts=mounts, command=["true"])
    dests = []
    for i, tok in enumerate(argv):
        if tok == "-v" and i + 1 < len(argv):
            dests.append(argv[i + 1].rsplit(":", 2)[1])
    assert "/grading" not in dests
    assert "/var/run/docker.sock" not in dests
    assert "/ccache" in dests
    assert "/workspace" in dests
    assert "poc.db" not in " ".join(dests)
    assert ".ssh" not in " ".join(dests)


def test_forbidden_mount_rejected(tmp_path: Path) -> None:
    mounts = AgentMounts(
        workspace=tmp_path / "ws",
        cache_dir=tmp_path / "ccache",
        extra=[(tmp_path / "grading", "/grading", "ro")],
    )
    with pytest.raises(ValueError, match="forbidden mount"):
        docker_run_argv(image="x", mounts=mounts)


def test_credential_env_rejected(tmp_path: Path) -> None:
    mounts = AgentMounts(workspace=tmp_path / "ws", cache_dir=tmp_path / "ccache")
    with pytest.raises(ValueError, match="credential"):
        docker_run_argv(
            image="x",
            mounts=mounts,
            env={"OPENAI_API_KEY": "sk-test"},
        )


def test_host_network_rejected() -> None:
    with pytest.raises(ValueError, match="host network"):
        IsolationPolicy(network="host").assert_agent_sandbox()


def test_grading_surface_still_requires_none() -> None:
    with pytest.raises(ValueError, match="network=none"):
        IsolationPolicy(network="bridge").assert_no_public_network()


def test_audit_text_names_report_blocked_and_no_cooperate() -> None:
    text = isolation_audit_text()
    assert "network=none" in text
    assert "report_blocked" in text
    assert "no messaging API" in text
    assert "api.openai.com" in text
