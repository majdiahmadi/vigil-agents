import pytest

from vigil.agents.triage.agent import TriageAgent
from vigil.plugins import AgentPlugin, PluginLoadError


def test_four_builtin_agent_plugins_are_loaded(registry):
    assert registry.list() == ["orchestrator", "triage", "malware", "hunter"]
    assert [item["plugin_id"] for item in registry.list_plugins()] == [
        "vigil.orchestrator",
        "vigil.triage",
        "vigil.malware",
        "vigil.hunter",
    ]


def test_plugin_manager_rejects_duplicate_agent_ids(registry):
    duplicate = AgentPlugin("example.duplicate", {"triage": TriageAgent})
    with pytest.raises(PluginLoadError, match="agent id already registered"):
        registry.plugin_manager.register(duplicate)


def test_plugin_manager_rejects_missing_dependencies(registry):
    invalid = AgentPlugin(
        "example.missing",
        {"example": TriageAgent},
        requires=frozenset({"service_that_does_not_exist"}),
    )
    with pytest.raises(PluginLoadError, match="requires unavailable dependencies"):
        registry.plugin_manager.register(invalid)
