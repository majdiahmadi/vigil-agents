from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from vigil.api.auth import require_bearer
from vigil.api.schemas import InvestigationStatus, InvestigationSubmission, SubmissionResponse
from vigil.core.models import AlertEnvelope

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_bearer)])


@router.post("/investigations", response_model=SubmissionResponse, status_code=status.HTTP_202_ACCEPTED, tags=["investigations"])
def submit(body: InvestigationSubmission, request: Request, x_idempotency_key: str | None = Header(default=None, max_length=200)):
    registry = request.app.state.registry
    if x_idempotency_key:
        existing = registry.dependencies.store.get_job_by_idempotency(x_idempotency_key)
        if existing:
            case = registry.dependencies.store.get_case(existing["case_id"])
            return SubmissionResponse(case_id=existing["case_id"], status=case["status"] if case else existing["status"], poll_url=f"/api/v1/investigations/{existing['case_id']}", created=False)
    try:
        envelope = AlertEnvelope.from_payload({"alert": body.alert}, source="api")
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    case_id = registry.dependencies.store.create_case(envelope, reuse_alert=bool(x_idempotency_key))
    _, created = registry.dependencies.store.enqueue_job(case_id, {"alert": body.alert}, x_idempotency_key)
    case = registry.dependencies.store.get_case(case_id)
    return SubmissionResponse(case_id=case_id, status=case["status"] if case else "queued", poll_url=f"/api/v1/investigations/{case_id}", created=created)


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
    return InvestigationStatus(case_id=case_id, status=case["status"], created_at=case["created_at"], updated_at=case["updated_at"], job=job, agent_runs=runs)


@router.get("/investigations/{case_id}/report", tags=["investigations"])
def get_report(case_id: str, request: Request):
    report = request.app.state.registry.dependencies.store.get_report(case_id)
    if not report:
        raise HTTPException(404, detail="report is not ready")
    return report

