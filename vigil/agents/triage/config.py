from vigil.agents.base import AgentConfig

CONFIG = AgentConfig(
    agent_id="triage", display_name="Triage",
    purpose="Alert, authentication, and session triage",
    allowed_tools=frozenset({"search_authentication_events", "search_session_events", "search_events"}),
    max_tool_calls=4,
)

