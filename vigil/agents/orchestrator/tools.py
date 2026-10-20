from __future__ import annotations

from pydantic import BaseModel, Field

from vigil.core.models import AgentRequest, CaseContext
from vigil.core.tool_registry import ToolDefinition


class DelegationArgs(BaseModel):
    purpose: str = Field(min_length=3, max_length=300)


def build_tools(dependencies) -> list[ToolDefinition]:
    def make(target: str):
        async def delegate(args: DelegationArgs, context: CaseContext):
            dependencies.store.record_delegation(context.case_id, "orchestrator", target, args.purpose, "running")
            agent = dependencies.agent_registry.create(target)
            result = await agent.run(AgentRequest(alert=context.alert, case_id=context.case_id, purpose=args.purpose, scope=context.scope))
            dependencies.store.record_delegation(context.case_id, "orchestrator", target, args.purpose, result.run_status.value)
            return result
        return delegate

    return [
        ToolDefinition("delegate_triage", "Delegate a scoped alert/session triage task", DelegationArgs, make("triage"), lambda c: {"purpose": "Triage authentication and surrounding evidence"}),
        ToolDefinition("delegate_malware", "Delegate a scoped safe file/IOC task", DelegationArgs, make("malware"), lambda c: {"purpose": "Inspect file and IOC evidence without execution"}),
        ToolDefinition("delegate_hunter", "Delegate a scoped hypothesis-driven hunt", DelegationArgs, make("hunter"), lambda c: {"purpose": "Test the multi-host hypothesis in a bounded window"}),
    ]

