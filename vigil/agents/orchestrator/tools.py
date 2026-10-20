from __future__ import annotations

from pydantic import BaseModel, Field

from vigil.core.models import AgentRequest, CaseContext
from vigil.core.tool_registry import EmptyArgs, ToolDefinition


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

    async def case_evidence(args: EmptyArgs, context: CaseContext):
        return dependencies.store.evidence_for_case(context.case_id)[: dependencies.settings.max_events]

    async def specialist_results(args: EmptyArgs, context: CaseContext):
        return [result for result in dependencies.store.results_for_case(context.case_id) if result.agent_id != "orchestrator"][-10:]

    return [
        ToolDefinition("delegate_triage", "Delegate a scoped alert/session triage task", DelegationArgs, make("triage"), lambda c: {"purpose": "Triage authentication and surrounding evidence"}),
        ToolDefinition("delegate_malware", "Delegate a scoped safe file/IOC task", DelegationArgs, make("malware"), lambda c: {"purpose": "Inspect file and IOC evidence without execution"}),
        ToolDefinition("delegate_hunter", "Delegate a scoped hypothesis-driven hunt", DelegationArgs, make("hunter"), lambda c: {"purpose": "Test the multi-host hypothesis in a bounded window"}),
        ToolDefinition("get_case_evidence", "Read already verified evidence for this case", EmptyArgs, case_evidence, lambda c: {}),
        ToolDefinition("get_specialist_results", "Read structured specialist results for this case", EmptyArgs, specialist_results, lambda c: {}),
    ]

