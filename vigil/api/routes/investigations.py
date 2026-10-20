from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from vigil.api.auth import require_bearer
from vigil.api.schemas import InvestigationStatus, InvestigationSubmission, SubmissionResponse
from vigil.core.models import AlertEnvelope
from vigil.core.database import IdempotencyConflict

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_bearer)])


@router.post("/investigations", response_model=SubmissionResponse, status_code=status.HTTP_202_ACCEPTED, tags=["investigations"])
def submit(body: InvestigationSubmission, request: Request, x_idempotency_key: str | None = Header(default=None, max_length=200)):
    registry = request.app.state.registry
    if x_idempotency_key:
        existing = registry.dependencies.store.get_job_by_idempotency(x_idempotency_key)
        if existing:
            case = registry.dependencies.store.get_case(existing["case_id"])
            requested = json.dumps({"alert": body.alert}, sort_keys=True, separators=(",", ":"), default=str)
            existing_payload = str(existing["payload_json"])
            if json.loads(existing_payload) != json.loads(requested):
                raise HTTPException(409, detail={"code": "idempotency_conflict", "message": "idempotency key was already used with a different alert"})
            return SubmissionResponse(case_id=existing["case_id"], status=case["status"] if case else existing["status"], poll_url=f"/api/v1/investigations/{existing['case_id']}", created=False, schema_version="1.0")
    try:
        envelope = AlertEnvelope.from_payload({"alert": body.alert}, source="api")
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    case_id = registry.dependencies.store.create_case(envelope, reuse_alert=bool(x_idempotency_key))
    try:
        job_id, created = registry.dependencies.store.enqueue_job(case_id, {"alert": body.alert}, x_idempotency_key)
    except IdempotencyConflict as exc:
        raise HTTPException(409, detail={"code": "idempotency_conflict", "message": str(exc)}) from exc
    if not created and x_idempotency_key:
        existing = registry.dependencies.store.get_job_by_idempotency(x_idempotency_key)
        if existing:
            case_id = existing["case_id"]
    case = registry.dependencies.store.get_case(case_id)
    return SubmissionResponse(case_id=case_id, status=case["status"] if case else "queued", poll_url=f"/api/v1/investigations/{case_id}", created=created, schema_version="1.0")


@router.get("/investigations/{case_id}", response_model=InvestigationStatus, tags=["investigations"])
def get_status(case_id: str, request: Request):
    store = request.app.state.registry.dependencies.store
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(404, detail="case not found")
    job = store.get_job_for_case(case_id)
    if job:
        job = {k: v for k, v in job.items() if k != "payload_json"}
    runs = [r.model_dump(mode="json") for r in store.results_for_case(case_id)]
    terminal = case["status"] in {"completed", "partial", "failed", "cancelled"}
    return InvestigationStatus(case_id=case_id, status=case["status"], created_at=case["created_at"], updated_at=case["updated_at"], job=job, agent_runs=runs, terminal=terminal, report_ready=store.get_report(case_id) is not None)


@router.get("/investigations/{case_id}/report", tags=["investigations"])
def get_report(case_id: str, request: Request):
    store = request.app.state.registry.dependencies.store
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(404, detail={"code": "case_not_found"})
    report = store.get_report(case_id)
    if not report:
        code = "report_unavailable" if case["status"] in {"failed", "cancelled"} else "report_not_ready"
        raise HTTPException(409, detail={"code": code, "status": case["status"]})
    return report

