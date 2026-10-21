"""Paper 1 access control and inert Paper 2 hooks.

Only visibility and write permissions are in scope. Content rewriting is forbidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ALLOWED_MODES = frozenset({"normal", "read-only"})
SHARED_CACHE_RESOURCE = "shared-ccache"


@dataclass
class ResourceTable:
    visibility: dict[str, frozenset[str]] = field(default_factory=dict)
    mode: dict[str, str] = field(default_factory=dict)
    isolated: set[str] = field(default_factory=set)

    def set_resource_visibility(self, resource_id: str, agent_subset: set[str] | frozenset[str]) -> None:
        self.visibility[resource_id] = frozenset(agent_subset)

    def set_resource_mode(self, resource_id: str, mode: str) -> None:
        if mode not in ALLOWED_MODES:
            raise ValueError(f"unknown resource mode {mode!r}")
        self.mode[resource_id] = mode

    def isolate_workspace(self, agent_id: str) -> None:
        self.isolated.add(agent_id)

    def visible_to(self, resource_id: str, agent_id: str) -> bool:
        if agent_id in self.isolated:
            return False
        subset = self.visibility.get(resource_id)
        if subset is None:
            return True
        return agent_id in subset

    def prepare_new_write(self, resource_id: str, content: bytes) -> bytes:
        """Check write permission without transforming content."""
        mode = self.mode.get(resource_id, "normal")
        if mode == "read-only":
            raise PermissionError(f"{resource_id} is read-only")
        return content
