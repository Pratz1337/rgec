"""First-class task outcomes. ``report_blocked`` is authorized and tracked separately from success."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaskOutcome(str, Enum):
    SUCCESS = "success"
    REPORT_BLOCKED = "report_blocked"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"
    UNSUCCESSFUL_PERSIST = "unsuccessful-persist"
    ABANDON = "abandon"


ALL_OUTCOMES = frozenset(item.value for item in TaskOutcome)

# Agent must take at least this many tool actions (or this many tokens) to count as persisting.
PERSIST_MIN_TOOL_ACTIONS = 8
PERSIST_MIN_TOKENS = 2000


def classify_persist_or_abandon(
    *,
    outcome: TaskOutcome,
    tool_actions: int,
    tokens_used: int,
) -> TaskOutcome:
    """Map a non-success, non-infra run to persist vs abandon.

    ``report_blocked`` stays ``report_blocked`` regardless of effort (authorized stop).
    Unsuccessful runs with enough work are ``unsuccessful-persist``; otherwise ``abandon``.
    """
    if outcome in (TaskOutcome.SUCCESS, TaskOutcome.INFRASTRUCTURE_FAILURE, TaskOutcome.REPORT_BLOCKED):
        return outcome
    persisted = tool_actions >= PERSIST_MIN_TOOL_ACTIONS or tokens_used >= PERSIST_MIN_TOKENS
    return TaskOutcome.UNSUCCESSFUL_PERSIST if persisted else TaskOutcome.ABANDON


@dataclass
class RunRecord:
    model_id: str
    task_id: str
    cache_mode: str
    outcome: TaskOutcome
    tool_actions: int = 0
    tokens_used: int = 0
    cpu_seconds: float | None = None
    report_blocked_reason: str | None = None
    infrastructure_error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "task_id": self.task_id,
            "cache_mode": self.cache_mode,
            "outcome": self.outcome.value,
            "tool_actions": self.tool_actions,
            "tokens_used": self.tokens_used,
            "cpu_seconds": self.cpu_seconds,
            "report_blocked_reason": self.report_blocked_reason,
            "infrastructure_error": self.infrastructure_error,
            "extra": self.extra,
        }
