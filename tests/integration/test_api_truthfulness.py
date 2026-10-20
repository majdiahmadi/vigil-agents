import asyncio
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from vigil.api.app import create_app
from vigil.core.models import AgentResult, AgentStatus
from vigil.workers.investigation_worker import process_one


def test_api_rejects_idempotency_key_reuse_with_different_payload(registry):
    client = TestClient(create_app(registry))
    headers = {"Authorization": "Bearer test-token", "X-Idempotency-Key": "collision"}
    first = client.post("/api/v1/investigations", json={"alert": {"alert_id": "one", "attack": "SSH", "ip": "192.0.2.10"}}, headers=headers)
    second = client.post("/api/v1/investigations", json={"alert": {"alert_id": "two", "attack": "SSH", "ip": "192.0.2.11"}}, headers=headers)
    assert first.status_code == 202
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "idempotency_conflict"


def test_report_not_ready_is_machine_readable(registry):
    client = TestClient(create_app(registry))
    headers = {"Authorization": "Bearer test-token"}
    submitted = client.post("/api/v1/investigations", json={"alert": {"alert_id": "pending", "attack": "SSH", "ip": "192.0.2.10"}}, headers=headers)
    response = client.get(f"/api/v1/investigations/{submitted.json()['case_id']}/report", headers=headers)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "report_not_ready"


def test_worker_propagates_failed_agent_result(registry, monkeypatch):
    client = TestClient(create_app(registry))
    headers = {"Authorization": "Bearer test-token"}
    submitted = client.post("/api/v1/investigations", json={"alert": {"alert_id": "failure", "attack": "SSH", "ip": "192.0.2.10"}}, headers=headers)
    original_create = registry.create

    class FailedAgent:
        async def run(self, request):
            now = datetime.now(timezone.utc)
            return AgentResult(case_id=request.case_id, agent_id="orchestrator", run_id="failed-run", run_status=AgentStatus.FAILED, model_provider="offline", model_id="test", evidence_gaps=["synthetic failure"], started_at=now, completed_at=now)

    monkeypatch.setattr(registry, "create", lambda agent_id: FailedAgent() if agent_id == "orchestrator" else original_create(agent_id))
    assert asyncio.run(process_one(registry)) is True
    status = client.get(f"/api/v1/investigations/{submitted.json()['case_id']}", headers=headers).json()
    assert status["status"] == "failed"
    assert status["job"]["status"] == "failed"
    assert status["terminal"] is True


def test_submission_response_has_version_and_poll_route(registry):
    client = TestClient(create_app(registry))
    response = client.post("/api/v1/investigations", json={"alert": {"alert_id": "versioned", "attack": "SSH", "ip": "192.0.2.10"}}, headers={"Authorization": "Bearer test-token"})
    body = response.json()
    assert response.status_code == 202
    assert body["schema_version"] == "1.0"
    assert body["poll_url"].endswith(body["case_id"])
