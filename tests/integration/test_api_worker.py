import asyncio

from fastapi.testclient import TestClient

from vigil.api.app import create_app
from vigil.workers.investigation_worker import process_one


def test_authenticated_idempotent_api_to_worker_to_report(registry):
    client = TestClient(create_app(registry))
    payload = {"alert": {"attack": "SSH Brute Force", "ip": "192.0.2.10", "attempts": 15, "host": "web-01"}}
    assert client.post("/api/v1/investigations", json=payload).status_code == 401
    headers = {"Authorization": "Bearer test-token", "X-Idempotency-Key": "notification-1"}
    first = client.post("/api/v1/investigations", json=payload, headers=headers)
    second = client.post("/api/v1/investigations", json=payload, headers=headers)
    assert first.status_code == 202
    assert second.json()["case_id"] == first.json()["case_id"]
    assert second.json()["created"] is False
    assert asyncio.run(process_one(registry)) is True
    case_id = first.json()["case_id"]
    status = client.get(f"/api/v1/investigations/{case_id}", headers=headers)
    assert status.status_code == 200
    assert status.json()["status"] in {"completed", "partial"}
    report = client.get(f"/api/v1/investigations/{case_id}/report", headers=headers)
    assert report.status_code == 200
    assert report.json()["response_executed"] is False


def test_validation_and_health(registry):
    client = TestClient(create_app(registry))
    assert client.get("/health").status_code == 200
    headers = {"Authorization": "Bearer test-token"}
    assert client.post("/api/v1/investigations", json={"alert": {}}, headers=headers).status_code == 422

