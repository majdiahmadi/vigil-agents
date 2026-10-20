from datetime import datetime, timedelta, timezone

from vigil.core.models import AlertEnvelope


def test_active_job_is_not_reclaimed_but_expired_lease_is(registry):
    store = registry.dependencies.store
    alert = AlertEnvelope.from_payload({"alert": {"alert_id": "lease-1", "attack": "SSH", "ip": "192.0.2.10"}})
    case_id = store.create_case(alert)
    store.enqueue_job(case_id, {"alert": alert.original_alert}, "lease-key")
    first = store.claim_job(worker_id="worker-a", lease_seconds=120)
    assert first and first["lease_owner"] == "worker-a"
    assert store.claim_job(worker_id="worker-b", lease_seconds=120) is None
    with store.connect() as conn:
        conn.execute("UPDATE jobs SET lease_expires_at=? WHERE job_id=?", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), first["job_id"]))
    recovered = store.claim_job(worker_id="worker-b", lease_seconds=120)
    assert recovered and recovered["job_id"] == first["job_id"]
    assert recovered["lease_owner"] == "worker-b"


def test_idempotency_collision_is_rejected(registry):
    from vigil.core.database import IdempotencyConflict
    store = registry.dependencies.store
    alert = AlertEnvelope.from_payload({"alert": {"alert_id": "idem-1", "attack": "SSH", "ip": "192.0.2.10"}})
    case_id = store.create_case(alert)
    first, created = store.enqueue_job(case_id, {"alert": {"value": 1}}, "same-key")
    second, created_again = store.enqueue_job(case_id, {"alert": {"value": 1}}, "same-key")
    assert first == second and created and not created_again
    try:
        store.enqueue_job(case_id, {"alert": {"value": 2}}, "same-key")
    except IdempotencyConflict:
        pass
    else:
        raise AssertionError("different payload must conflict")
