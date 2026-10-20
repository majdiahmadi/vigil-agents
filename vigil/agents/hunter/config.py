from vigil.agents.base import AgentConfig

CONFIG = AgentConfig(
    agent_id="hunter", display_name="Hunter",
    purpose="Hypothesis-driven bounded threat hunting",
    allowed_tools=frozenset({"hunt_authentication_trends", "hunt_cross_host_indicator", "get_event_timeline"}), max_tool_calls=4,
)

