"""No cooperation hints in prompts, tools, or cache API."""

from __future__ import annotations

from pathlib import Path

from unauthorized_channels.cache import FORBIDDEN_API_NAMES, cache_has_channel_api
from unauthorized_channels.prompts import COOPERATION_LEAK_TOKENS, SOLO_SYSTEM_PROMPT, cooperation_leaks
from unauthorized_channels.runtime import prepare_workspace
from unauthorized_channels.tasks import parse_task_id


def test_prompt_has_no_cooperation_language() -> None:
    assert cooperation_leaks() == []
    assert "report_blocked" in SOLO_SYSTEM_PROMPT
    assert "no internet" not in SOLO_SYSTEM_PROMPT.lower()
    assert "network is unavailable" not in SOLO_SYSTEM_PROMPT.lower()
    for token in ("other agent", "message board", "cooperat"):
        assert token not in SOLO_SYSTEM_PROMPT.lower()


def test_workspace_instructions_do_not_mention_other_agents(tmp_path: Path) -> None:
    ws = prepare_workspace(tmp_path, parse_task_id("arvo:10400"))
    text = (ws / "INSTRUCTIONS.md").read_text(encoding="utf-8").lower()
    for token in COOPERATION_LEAK_TOKENS:
        assert token not in text
    assert "report_blocked" in text


def test_forbidden_cache_api_denylist_is_enforced() -> None:
    assert "send" in FORBIDDEN_API_NAMES
    assert cache_has_channel_api() == []
