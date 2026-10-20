from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Mapping

if TYPE_CHECKING:
    from vigil.agents.base import BaseAgent


PLUGIN_NAME = re.compile(r"^[a-z][a-z0-9._-]*$")
STANDARD_DEPENDENCIES = frozenset(
    {"runtime", "store", "connector", "validator", "settings", "model_manager"}
)


class PluginLoadError(RuntimeError):
    """Raised when an agent plugin does not satisfy VIGIL's plugin contract."""


@dataclass(frozen=True, slots=True)
class AgentPlugin:
    """Declarative plugin manifest for one or more agent classes."""

    plugin_id: str
    agents: Mapping[str, type["BaseAgent"]]
    requires: frozenset[str] = field(default_factory=lambda: STANDARD_DEPENDENCIES)
    description: str = ""

    def validate(self, dependencies) -> None:
        from vigil.agents.base import BaseAgent

        if not PLUGIN_NAME.fullmatch(self.plugin_id):
            raise PluginLoadError(
                f"invalid plugin id {self.plugin_id!r}; use lowercase letters, numbers, dots, underscores, or hyphens"
            )
        if not self.agents:
            raise PluginLoadError(f"plugin {self.plugin_id!r} does not provide an agent")
        missing = sorted(name for name in self.requires if not hasattr(dependencies, name))
        if missing:
            raise PluginLoadError(
                f"plugin {self.plugin_id!r} requires unavailable dependencies: {', '.join(missing)}"
            )
        for agent_id, agent_type in self.agents.items():
            if not PLUGIN_NAME.fullmatch(agent_id):
                raise PluginLoadError(f"invalid agent id {agent_id!r} in plugin {self.plugin_id!r}")
            if not isinstance(agent_type, type) or not issubclass(agent_type, BaseAgent):
                raise PluginLoadError(
                    f"plugin {self.plugin_id!r} agent {agent_id!r} must subclass BaseAgent"
                )
            declared_id = getattr(agent_type, "agent_id", None)
            if isinstance(declared_id, str) and declared_id != agent_id:
                raise PluginLoadError(
                    f"plugin {self.plugin_id!r} maps {agent_id!r} to class id {declared_id!r}"
                )
