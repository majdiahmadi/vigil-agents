from __future__ import annotations

import asyncio
import json
from uuid import uuid4

from vigil.agents.registry import build_registry
from vigil.core.models import AgentRequest, AlertEnvelope


async def process_one(registry=None) -> bool:
    registry = registry or build_registry()
    store = registry.dependencies.store
    worker_id = f"worker-{uuid4().hex[:8]}"
    job = store.claim_job(
        worker_id=worker_id,
        lease_seconds=registry.dependencies.settings.worker_lease_seconds,
        max_attempts=registry.dependencies.settings.worker_max_attempts,
    )
    if not job:
        return False
    try:
        payload = json.loads(job["payload_json"])
        alert = AlertEnvelope.from_payload(payload, source="api-worker")
        result = await registry.create("orchestrator").run(AgentRequest(alert=alert, case_id=job["case_id"]))
        store.update_job(job["job_id"], result.run_status.value, None if result.run_status.value in {"completed", "partial"} else "orchestrator run failed")
        store.set_case_status(job["case_id"], result.run_status.value)
    except Exception as exc:
        store.update_job(job["job_id"], "failed", f"{type(exc).__name__}: {exc}")
        store.set_case_status(job["case_id"], "failed")
    return True


async def run_worker(*, once: bool = False, poll_seconds: float = 1.0) -> None:
    registry = build_registry()
    while True:
        worked = await process_one(registry)
        if once:
            return
        if not worked:
            await asyncio.sleep(poll_seconds)


if __name__ == "__main__":
    asyncio.run(run_worker())

