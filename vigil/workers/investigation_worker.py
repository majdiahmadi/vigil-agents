from __future__ import annotations

import asyncio
import json

from vigil.agents.registry import build_registry
from vigil.core.models import AgentRequest, AlertEnvelope


async def process_one(registry=None) -> bool:
    registry = registry or build_registry()
    store = registry.dependencies.store
    job = store.claim_job()
    if not job:
        return False
    try:
        payload = json.loads(job["payload_json"])
        alert = AlertEnvelope.from_payload(payload, source="api-worker")
        await registry.create("orchestrator").run(AgentRequest(alert=alert, case_id=job["case_id"]))
        store.update_job(job["job_id"], "completed")
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

