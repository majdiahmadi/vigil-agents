from pathlib import Path

import pytest

from vigil.core.models import AgentRequest, AlertEnvelope


def load(project_root: Path, name: str) -> AlertEnvelope:
    import json
    return AlertEnvelope.from_payload(json.loads((project_root / "fixtures" / "alerts" / name).read_text()))


@pytest.mark.asyncio
async def test_specialists_produce_distinct_grounded_results(registry, project_root):
    triage = await registry.create("triage").run(AgentRequest(alert=load(project_root, "ssh_bruteforce.json")))
    malware = await registry.create("malware").run(AgentRequest(alert=load(project_root, "suspicious_file.json")))
    hunter = await registry.create("hunter").run(AgentRequest(alert=load(project_root, "hunt_scenario.json")))
    assert {"log-001", "log-002", "session-001", "session-002"}.issubset({r.native_event_id for r in triage.evidence_refs})
    assert any("not proven" in h.statement for h in triage.hypotheses)
    assert any("not executed" in f.statement for f in malware.observed_facts)
    assert malware.response_executed is False
    assert any("2 hosts" in f.statement for f in hunter.observed_facts)
    assert all("lateral movement" not in f.statement.lower() for f in hunter.observed_facts)

