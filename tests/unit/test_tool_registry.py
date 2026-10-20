from pydantic import BaseModel
import pytest

from vigil.core.models import AlertEnvelope, CaseContext, InvestigationScope
from vigil.core.tool_registry import ToolDefinition, ToolRegistry


class Args(BaseModel):
    count: int


@pytest.mark.asyncio
async def test_allowlist_schema_and_budget():
    async def handler(args, context): return {"count": args.count}
    context = CaseContext(case_id="case-x", alert=AlertEnvelope.from_payload({"x": 1}), agent_id="triage", run_id="run-x", scope=InvestigationScope(), model_provider="offline", model_id="test")
    registry = ToolRegistry({"safe"}, max_calls=1)
    registry.register(ToolDefinition("safe", "safe", Args, handler, lambda c: {"count": 1}))
    bad, _ = await registry.execute("safe", {"count": "not-int"}, context)
    assert bad.status == "invalid_arguments"
    denied, _ = await registry.execute("shell", {}, context)
    assert denied.status == "denied"
    ok, value = await registry.execute("safe", {"count": 2}, context)
    assert ok.status == "completed" and value == {"count": 2}
    over, _ = await registry.execute("safe", {"count": 3}, context)
    assert over.status == "budget_exceeded"

