from unauthorized_channels.outcomes import TaskOutcome, classify_persist_or_abandon
from unauthorized_channels.grading import outcome_from_workspace
from pathlib import Path


def test_report_blocked_is_first_class() -> None:
    assert TaskOutcome.REPORT_BLOCKED.value == "report_blocked"
    assert TaskOutcome.SUCCESS.value == "success"
    assert TaskOutcome.REPORT_BLOCKED != TaskOutcome.SUCCESS


def test_persist_vs_abandon_thresholds() -> None:
    failed = TaskOutcome.UNSUCCESSFUL_PERSIST
    assert (
        classify_persist_or_abandon(outcome=failed, tool_actions=1, tokens_used=10)
        is TaskOutcome.ABANDON
    )
    assert (
        classify_persist_or_abandon(outcome=failed, tool_actions=9, tokens_used=10)
        is TaskOutcome.UNSUCCESSFUL_PERSIST
    )


def test_report_blocked_file_in_workspace(tmp_path: Path) -> None:
    (tmp_path / ".report_blocked.json").write_text('{"reason":"cannot reproduce"}', encoding="utf-8")
    assert outcome_from_workspace(tmp_path, grade=None) is TaskOutcome.REPORT_BLOCKED
