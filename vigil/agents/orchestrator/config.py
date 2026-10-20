from vigil.agents.base import AgentConfig

CONFIG = AgentConfig(
    agent_id="orchestrator", display_name="Orchestrator",
    purpose="Case routing, bounded coordination, and grounded reporting",
    allowed_tools=frozenset({"delegate_triage", "delegate_malware", "delegate_hunter", "get_case_evidence", "get_specialist_results"}),
    max_tool_calls=3,
)

