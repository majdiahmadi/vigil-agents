import json

import pytest

from vigil.core.models import AgentRequest, AlertEnvelope


@pytest.mark.asyncio
async def test_offline_end_to_end_report(registry, project_root):
    payload = json.loads((project_root / "fixtures" / "alerts" / "ssh_bruteforce.json").read_text())
    result = await registry.create("orchestrator").run(AgentRequest(alert=AlertEnvelope.from_payload(payload)))
    report = registry.dependencies.store.get_report(result.case_id)
    assert report.case_id == result.case_id
    assert report.specialist_results[0].agent_id == "triage"
    assert result.run_status == "completed"
    assert report.timeline
    assert report.analyst_review_required
    assert not report.response_executed

