from vigil.agents.base import AgentConfig

CONFIG = AgentConfig(
    agent_id="hunter", display_name="Hunter",
    purpose="Hypothesis-driven bounded threat hunting",
    allowed_tools=frozenset({"search_events", "search_by_indicator"}), max_tool_calls=4,
)

