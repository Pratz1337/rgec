"""Seeded, interleaved, synchronous scheduler.

One agent acts at a time. Budgets are either one shared pool (fixed-total)
or a cap per agent (fixed-per-agent). Both modes are first-class; do not
pool them into one number.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass
from enum import Enum


class BudgetMode(str, Enum):
    FIXED_TOTAL = "fixed-total"
    FIXED_PER_AGENT = "fixed-per-agent"


@dataclass
class AgentSlot:
    agent_id: str
    task_id: str
    model_id: str
    actions_used: int = 0
    tokens_used: int = 0
    actions_cap: int = 0
    tokens_cap: int = 0
    alive: bool = True


class InterleavedScheduler:
    def __init__(
        self,
        agents: list[AgentSlot],
        *,
        seed: int,
        budget_mode: BudgetMode | str,
        total_actions: int,
        total_tokens: int = 0,
    ) -> None:
        if len(agents) < 2:
            raise ValueError("a population episode needs at least two agents")
        self.budget_mode = BudgetMode(budget_mode)
        self.seed = seed
        self.total_actions_cap = total_actions
        self.total_tokens_cap = total_tokens
        self.total_actions_used = 0
        self.total_tokens_used = 0
        self.cursor = 0
        ids = [slot.agent_id for slot in agents]
        if len(ids) != len(set(ids)):
            raise ValueError("agent ids must be unique")
        rng = random.Random(seed)
        rng.shuffle(ids)
        by_id = {slot.agent_id: slot for slot in agents}
        self.order = ids
        self.agents = {aid: by_id[aid] for aid in ids}

    def can_act(self, slot: AgentSlot) -> bool:
        if not slot.alive:
            return False
        if self.budget_mode is BudgetMode.FIXED_TOTAL:
            if self.total_actions_used >= self.total_actions_cap:
                return False
            if self.total_tokens_cap and self.total_tokens_used >= self.total_tokens_cap:
                return False
            return True
        if slot.actions_used >= slot.actions_cap:
            return False
        if slot.tokens_cap and slot.tokens_used >= slot.tokens_cap:
            return False
        return True

    def next_agent(self) -> AgentSlot | None:
        n = len(self.order)
        for offset in range(n):
            idx = (self.cursor + offset) % n
            slot = self.agents[self.order[idx]]
            if self.can_act(slot):
                self.cursor = (idx + 1) % n
                return slot
        return None

    def charge(self, agent_id: str, *, actions: int = 1, tokens: int = 0) -> None:
        slot = self.agents[agent_id]
        slot.actions_used += actions
        slot.tokens_used += tokens
        self.total_actions_used += actions
        self.total_tokens_used += tokens
        if self.budget_mode is BudgetMode.FIXED_PER_AGENT and not self.can_act(slot):
            if slot.actions_used >= slot.actions_cap or (
                slot.tokens_cap and slot.tokens_used >= slot.tokens_cap
            ):
                slot.alive = False

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "budget_mode": self.budget_mode.value,
            "order": list(self.order),
            "cursor": self.cursor,
            "total_actions_cap": self.total_actions_cap,
            "total_tokens_cap": self.total_tokens_cap,
            "total_actions_used": self.total_actions_used,
            "total_tokens_used": self.total_tokens_used,
            "agents": [asdict(self.agents[aid]) for aid in self.order],
        }

    @classmethod
    def from_dict(cls, data: dict) -> InterleavedScheduler:
        slots = [AgentSlot(**row) for row in data["agents"]]
        sched = cls(
            slots,
            seed=int(data["seed"]),
            budget_mode=data["budget_mode"],
            total_actions=int(data["total_actions_cap"]),
            total_tokens=int(data.get("total_tokens_cap") or 0),
        )
        # from_dict must restore the recorded order, not reshuffle.
        sched.order = list(data["order"])
        sched.agents = {row["agent_id"]: AgentSlot(**row) for row in data["agents"]}
        sched.cursor = int(data["cursor"])
        sched.total_actions_used = int(data["total_actions_used"])
        sched.total_tokens_used = int(data["total_tokens_used"])
        return sched
