import json

import pytest

from vigil.core.models import AgentRequest, AlertEnvelope


@pytest.mark.asyncio
@pytest.mark.parametrize(("fixture","expected"), [("ssh_bruteforce.json", {"triage"}), ("suspicious_file.json", {"malware"}), ("hunt_scenario.json", {"hunter"}), ("ambiguous.json", {"triage"})])
async def test_selective_real_delegation(registry, project_root, fixture, expected):
    payload = json.loads((project_root / "fixtures" / "alerts" / fixture).read_text())
    result = await registry.create("orchestrator").run(AgentRequest(alert=AlertEnvelope.from_payload(payload)))
    assert {r.agent_id for r in result.specialist_results} == expected
    assert all(r.case_id == result.case_id for r in result.specialist_results)
    assert not any("unknown evidence" in item for item in result.limitations)
    report = registry.dependencies.store.get_report(result.case_id)
    assert report is not None
    assert report.analyst_review_required is True
    assert report.response_executed is False

