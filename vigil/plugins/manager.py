from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points
from typing import Iterable

from vigil.plugins.contracts import AgentPlugin, PluginLoadError


ENTRY_POINT_GROUP = "vigil.agent_plugins"


def builtin_plugins() -> tuple[AgentPlugin, ...]:
    """Return the four built-in agents as ordinary plugin manifests."""
    from vigil.agents.hunter.agent import HunterAgent
    from vigil.agents.malware.agent import MalwareAgent
    from vigil.agents.orchestrator.agent import OrchestratorAgent
    from vigil.agents.triage.agent import TriageAgent

    return (
        AgentPlugin("vigil.orchestrator", {"orchestrator": OrchestratorAgent}, description="Case routing and reporting"),
        AgentPlugin("vigil.triage", {"triage": TriageAgent}, description="Alert and session triage"),
        AgentPlugin("vigil.malware", {"malware": MalwareAgent}, description="Safe file and indicator analysis"),
        AgentPlugin("vigil.hunter", {"hunter": HunterAgent}, description="Bounded hypothesis-driven hunting"),
    )


def installed_plugin_entry_points() -> list[EntryPoint]:
    """Find installed packages that explicitly publish a VIGIL agent plugin."""
    discovered = entry_points()
    if hasattr(discovered, "select"):
        return sorted(discovered.select(group=ENTRY_POINT_GROUP), key=lambda item: item.name)
    return sorted(discovered.get(ENTRY_POINT_GROUP, ()), key=lambda item: item.name)


class PluginManager:
    """Validate plugins, prevent collisions, and create their registered agents."""

    def __init__(self, dependencies, plugins: Iterable[AgentPlugin] = ()) -> None:
        self.dependencies = dependencies
        self._plugins: dict[str, AgentPlugin] = {}
        self._agent_types: dict[str, type] = {}
        self._agent_owners: dict[str, str] = {}
        for plugin in plugins:
            self.register(plugin)

    def register(self, plugin: AgentPlugin) -> None:
        plugin.validate(self.dependencies)
        if plugin.plugin_id in self._plugins:
            raise PluginLoadError(f"plugin id already registered: {plugin.plugin_id}")
        duplicates = sorted(set(plugin.agents).intersection(self._agent_types))
        if duplicates:
            owners = ", ".join(
                f"{agent_id} ({self._agent_owners[agent_id]})" for agent_id in duplicates
            )
            raise PluginLoadError(f"agent id already registered: {owners}")
        self._plugins[plugin.plugin_id] = plugin
        for agent_id, agent_type in plugin.agents.items():
            self._agent_types[agent_id] = agent_type
            self._agent_owners[agent_id] = plugin.plugin_id

    def load_installed(self, points: Iterable[EntryPoint] | None = None) -> None:
        for point in points if points is not None else installed_plugin_entry_points():
            try:
                loaded = point.load()
                plugin = loaded if isinstance(loaded, AgentPlugin) else loaded()
            except Exception as exc:
                raise PluginLoadError(
                    f"could not load plugin entry point {point.name!r}: {type(exc).__name__}: {exc}"
                ) from exc
            if not isinstance(plugin, AgentPlugin):
                raise PluginLoadError(
                    f"plugin entry point {point.name!r} must expose AgentPlugin or a zero-argument factory"
                )
            self.register(plugin)

    def create(self, agent_id: str):
        try:
            agent_type = self._agent_types[agent_id]
        except KeyError as exc:
            raise ValueError(f"unknown agent: {agent_id}") from exc
        return agent_type(self.dependencies)

    def list_agents(self) -> list[str]:
        return list(self._agent_types)

    def list_plugins(self) -> list[dict[str, object]]:
        return [
            {
                "plugin_id": plugin.plugin_id,
                "agents": list(plugin.agents),
                "requires": sorted(plugin.requires),
                "description": plugin.description,
            }
            for plugin in self._plugins.values()
        ]


def build_plugin_manager(dependencies, *, load_external: bool = True) -> PluginManager:
    manager = PluginManager(dependencies, builtin_plugins())
    if load_external:
        manager.load_installed()
    return manager
