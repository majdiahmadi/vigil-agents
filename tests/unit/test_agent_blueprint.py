import inspect

import pytest

from vigil.agents.base import BaseAgent
from vigil.core.models import AgentRequest, AgentResult, AlertEnvelope


@pytest.mark.asyncio
async def test_all_agents_share_template_and_factory(registry):
    fixtures = {
        "orchestrator": {"alert": {"attack": "SSH Brute Force", "ip": "192.0.2.10", "host": "web-01"}},
        "triage": {"alert": {"attack": "SSH Brute Force", "ip": "192.0.2.10", "host": "web-01"}},
        "malware": {"alert": {"category": "suspicious file", "file_path": "synthetic_payload.txt"}},
        "hunter": {"alert": {"category": "multi-host campaign hypothesis", "indicator": "198.51.100.50"}},
    }
    runtime_ids = set()
    for agent_id in registry.list():
        agent = registry.create(agent_id)
        assert isinstance(agent, BaseAgent)
        assert agent.agent_id == agent_id
        assert len(agent.get_skills()) >= 2
        assert type(agent).run is BaseAgent.run
        runtime_ids.add(id(agent.dependencies.runtime))
        result = await agent.run(AgentRequest(alert=AlertEnvelope.from_payload(fixtures[agent_id])))
        assert isinstance(result, AgentResult)
        assert result.case_id
        assert result.agent_id == agent_id
        assert result.skills_used
    assert len(runtime_ids) == 1


def test_tool_permissions_are_isolated(registry):
    assert {t.name for t in registry.create("triage").get_tool_specs()} == {"search_authentication_events", "search_session_events", "search_events"}
    assert "analyze_static_file" not in registry.create("hunter").get_config().allowed_tools
    assert all(not name.startswith("delegate_") for name in registry.create("malware").get_config().allowed_tools)

