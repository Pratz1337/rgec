"""Real agent loop: scripted tool calls executed inside a CyberGym container."""

from __future__ import annotations

from pathlib import Path

import pytest

from unauthorized_channels.agent import (
    _normalize_call,
    parse_tool_calls,
    run_episode,
    sanitize_shell_command,
)
from unauthorized_channels.cache import CacheMode, allocate_cache_dir
from unauthorized_channels.docker_cli import docker_probe, image_present
from unauthorized_channels.outcomes import TaskOutcome
from unauthorized_channels.runtime import prepare_workspace
from unauthorized_channels.sandbox import AgentSandbox
from unauthorized_channels.tasks import parse_task_id


class ScriptedModel:
    """Issues the same inspection commands a human would run on a CyberGym image."""

    def __init__(self) -> None:
        self.i = 0
        self.steps = [
            "```bash\nls /src\n```",
            "```bash\nls /out | head\n```",
            "```bash\nhead -40 /bin/arvo\n```",
            "report_blocked: inspected /src, /out, and /bin/arvo; no reproducing input constructed",
        ]

    def complete(self, messages, tools=None):
        text = self.steps[min(self.i, len(self.steps) - 1)]
        self.i += 1
        return {"text": text, "tokens": 80, "tool_calls": []}


def test_run_shell_colon_payload_executes_command_not_token(tmp_path: Path) -> None:
    """Qwen without a tool schema emits `run_shell: ls /src`; exec must run `ls /src`."""
    parsed = parse_tool_calls("run_shell: ls /src")
    assert parsed and parsed[0]["name"] == "run_shell"
    name, args = _normalize_call(parsed[0])
    assert name == "run_shell"
    cmd = sanitize_shell_command(args["command"])
    assert cmd == "ls /src"
    assert not cmd.lower().startswith("run_shell")

    ok, detail = docker_probe()
    if not ok:
        pytest.skip(f"docker unavailable: {detail}")
    task = parse_task_id("arvo:10400")
    if not image_present(task.agent_image):
        pytest.skip(f"{task.agent_image} not local")

    class PrefixedModel:
        def __init__(self) -> None:
            self.i = 0

        def complete(self, messages, tools=None):
            assert tools, "run_episode must pass the tool schema into complete()"
            self.i += 1
            if self.i == 1:
                return {"text": "run_shell: ls /src", "tokens": 20, "tool_calls": []}
            return {
                "text": "report_blocked: listed /src",
                "tokens": 10,
                "tool_calls": [],
            }

    workspace = prepare_workspace(tmp_path / "run", task)
    cache = allocate_cache_dir(tmp_path, agent_id="prefixed", mode=CacheMode.PRIVATE)
    box = AgentSandbox(task, workspace, cache, name="uc-test-runshell-prefix")
    rec = run_episode(
        model=PrefixedModel(),
        sandbox=box,
        workspace=workspace,
        model_id="prefixed-inspector",
        task_id=task.task_id,
        cache_mode="private",
        max_actions=4,
    )
    shell = [t for t in rec.extra["trace"] if t.get("tool") == "run_shell"]
    assert shell
    assert shell[0]["command"] == "ls /src"
    assert not str(shell[0]["command"]).lower().startswith("run_shell")
    assert "run_shell:" not in (shell[0].get("output") or "")
    assert "graphicsmagick" in (shell[0].get("output") or "") or "libpng" in (shell[0].get("output") or "")


def test_parse_qwen_and_fence_and_blocked() -> None:
    fence = parse_tool_calls("here\n```bash\nls /src\n```\n")
    assert fence and fence[0]["name"] == "run_shell"
    assert "ls /src" in fence[0]["arguments"]["command"]
    blocked = parse_tool_calls("report_blocked: missing harness")
    assert blocked[0]["name"] == "report_blocked"
    qwen = parse_tool_calls(
        "<tool_call>\n<function=run_shell>\n<parameter=command>\nls /out\n</parameter>\n</function>\n</tool_call>"
    )
    assert qwen[0]["name"] == "run_shell"
    assert "ls /out" in qwen[0]["arguments"]["command"]


def test_episode_inspects_cybergym_tree_and_can_report_blocked(tmp_path: Path) -> None:
    ok, detail = docker_probe()
    if not ok:
        pytest.skip(f"docker unavailable: {detail}")
    task = parse_task_id("arvo:10400")
    if not image_present(task.agent_image):
        pytest.skip(f"{task.agent_image} not local")
    workspace = prepare_workspace(tmp_path / "run", task)
    cache = allocate_cache_dir(tmp_path, agent_id="scripted", mode=CacheMode.PRIVATE)
    box = AgentSandbox(task, workspace, cache, name="uc-test-agent")
    rec = run_episode(
        model=ScriptedModel(),
        sandbox=box,
        workspace=workspace,
        model_id="scripted-inspector",
        task_id=task.task_id,
        cache_mode="private",
        max_actions=6,
    )
    assert rec.outcome is TaskOutcome.REPORT_BLOCKED
    assert rec.tool_actions >= 2
    trace = rec.extra["trace"]
    shell = [t for t in trace if t.get("tool") == "run_shell"]
    joined = "\n".join(t.get("output", "") for t in shell)
    assert "graphicsmagick" in joined or "libpng" in joined
    assert "coder_" in joined or "fuzzer" in joined.lower() or "arvo" in joined.lower()
