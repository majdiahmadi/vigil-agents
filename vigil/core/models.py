from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AgentStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SecurityAssessment(StrEnum):
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"
    INCONCLUSIVE = "inconclusive"


class NormalizedEventKind(StrEnum):
    AUTH_FAILED = "auth_failed"
    AUTH_SUCCESS = "auth_success"
    SESSION_START = "session_start"
    COMMAND = "command"
    FILE_EVENT = "file_event"
    PROCESS_EVENT = "process_event"
    NETWORK_EVENT = "network_event"
    MALWARE_ALERT = "malware_alert"
    UNKNOWN = "unknown"


class TimeWindow(BaseModel):
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def bounded(self) -> "TimeWindow":
        if self.end <= self.start:
            raise ValueError("time window end must be after start")
        if self.end - self.start > timedelta(days=30):
            raise ValueError("time window cannot exceed 30 days")
        return self


class InvestigationScope(BaseModel):
    source_ips: list[str] = Field(default_factory=list, max_length=50)
    hosts: list[str] = Field(default_factory=list, max_length=50)
    users: list[str] = Field(default_factory=list, max_length=50)
    indicators: list[str] = Field(default_factory=list, max_length=50)
    time_window: TimeWindow | None = None

    @field_validator("source_ips")
    @classmethod
    def validate_ips(cls, values: list[str]) -> list[str]:
        from ipaddress import ip_address

        for value in values:
            ip_address(value)
        return values


class AlertEnvelope(BaseModel):
    schema_version: str = "1.0"
    alert_id: str = Field(default_factory=lambda: f"alert-{uuid4().hex[:12]}")
    source: str = "api"
    received_at: datetime = Field(default_factory=utc_now)
    original_alert: dict[str, Any]
    normalized_fields: dict[str, Any] = Field(default_factory=dict)
    asset_scope: InvestigationScope = Field(default_factory=InvestigationScope)
    evidence_origin: str = "submitted"

    @classmethod
    def from_payload(cls, payload: dict[str, Any], source: str = "cli") -> "AlertEnvelope":
        raw = payload.get("alert", payload)
        if not isinstance(raw, dict) or not raw:
            raise ValueError("alert must be a non-empty JSON object")
        native = raw.get("_source", raw)
        if not isinstance(native, dict):
            native = raw
        data = native.get("data") if isinstance(native.get("data"), dict) else {}
        agent = native.get("agent") if isinstance(native.get("agent"), dict) else {}
        rule = native.get("rule") if isinstance(native.get("rule"), dict) else {}
        alert_id = str(raw.get("alert_id") or raw.get("_id") or native.get("id") or f"alert-{uuid4().hex[:12]}")
        ip = raw.get("ip") or raw.get("source_ip") or raw.get("srcip") or data.get("srcip")
        host_value = raw.get("hosts") or raw.get("host") or raw.get("agent_name") or agent.get("name")
        hosts = [str(x) for x in host_value] if isinstance(host_value, list) else ([str(host_value)] if host_value else [])
        user_value = raw.get("user") or data.get("srcuser") or data.get("dstuser")
        indicator_value = raw.get("sha256") or raw.get("hash") or raw.get("indicator") or data.get("sha256")
        indicators = [str(indicator_value)] if indicator_value else []
        observed_value = raw.get("observed_at") or native.get("timestamp") or native.get("@timestamp")
        received_at = utc_now()
        observed_dt = received_at
        observed_at = received_at.isoformat()
        timestamp_source = "received_at_assumption"
        if observed_value:
            try:
                observed_dt = datetime.fromisoformat(str(observed_value).replace("Z", "+00:00"))
                if observed_dt.tzinfo is None:
                    raise ValueError("timezone is required")
                observed_at = observed_dt.isoformat()
                timestamp_source = "source_alert"
            except ValueError as exc:
                raise ValueError("alert observed_at/timestamp must be timezone-aware ISO 8601") from exc
        scope = InvestigationScope(
            source_ips=[str(ip)] if ip else [], hosts=hosts,
            users=[str(user_value)] if user_value else [], indicators=indicators,
            time_window=TimeWindow(start=observed_dt - timedelta(days=1), end=observed_dt + timedelta(days=1)),
        )
        normalized = {
            "category": str(raw.get("category") or raw.get("attack") or raw.get("type") or rule.get("description") or "unknown"),
            "description": str(raw.get("description") or rule.get("description") or native.get("full_log") or ""),
            "source_ip": ip,
            "host": hosts[0] if hosts else None,
            "user": str(user_value) if user_value else None,
            "sha256": indicators[0] if indicators else None,
            "file_path": raw.get("file_path"),
            "observed_at": observed_at,
            "timestamp_source": timestamp_source,
            "rule_id": raw.get("rule_id") or rule.get("id"),
        }
        return cls(alert_id=alert_id, source=source, received_at=received_at, original_alert=raw, normalized_fields=normalized, asset_scope=scope)


class CaseContext(BaseModel):
    case_id: str
    alert: AlertEnvelope
    agent_id: str
    run_id: str
    scope: InvestigationScope
    model_provider: str
    model_id: str
    purpose: str = "investigate"
    memory: list[dict[str, Any]] = Field(default_factory=list)


class AgentRequest(BaseModel):
    alert: AlertEnvelope
    case_id: str | None = None
    purpose: str = "investigate"
    scope: InvestigationScope | None = None
    force_new_run: bool = False


class EvidenceRecord(BaseModel):
    schema_version: str = "1.0"
    evidence_id: str = Field(default_factory=lambda: f"ev-{uuid4().hex[:12]}")
    case_id: str
    native_event_id: str
    source_type: str
    connector_mode: str
    observed_at: datetime | None = None
    retrieved_at: datetime = Field(default_factory=utc_now)
    index_name: str | None = None
    host: str | None = None
    agent_id: str | None = None
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    rule_id: str | None = None
    normalized_event_kind: NormalizedEventKind = NormalizedEventKind.UNKNOWN
    event_count: int | None = Field(default=None, ge=1)
    command: str | None = None
    file_hash: str | None = None
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    query_scope: dict[str, Any] = Field(default_factory=dict)
    telemetry_coverage: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    simulated: bool = False


class EvidenceReference(BaseModel):
    evidence_id: str
    native_event_id: str
    source_type: str


class EvidenceClaim(BaseModel):
    evidence_id: str
    field_path: str = Field(min_length=1, max_length=200)
    operator: Literal["eq", "contains", "gte", "lte"] = "eq"
    expected_value: Any


class ObservedFact(BaseModel):
    statement: str
    evidence_ids: list[str] = Field(default_factory=list)
    kind: Literal["verified_observation", "analyst_hypothesis", "model_inference", "recommended_action"] = "verified_observation"
    claims: list[EvidenceClaim] = Field(default_factory=list)


class Hypothesis(BaseModel):
    statement: str
    status: str = "inconclusive"
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradictory_evidence_ids: list[str] = Field(default_factory=list)


class ToolCallRecord(BaseModel):
    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    status: str
    evidence_ids: list[str] = Field(default_factory=list)
    error: str | None = None
    duplicate: bool = False


class AgentResult(BaseModel):
    schema_version: str = "1.0"
    case_id: str
    agent_id: str
    run_id: str
    run_status: AgentStatus
    security_assessment: SecurityAssessment = SecurityAssessment.UNKNOWN
    model_provider: str
    model_id: str
    observed_facts: list[ObservedFact] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    evidence_refs: list[EvidenceReference] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    skills_used: list[str] = Field(default_factory=list)
    specialist_results: list["AgentResult"] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime = Field(default_factory=utc_now)
    analyst_review_required: bool = True
    response_executed: bool = False


class SpecialistTask(BaseModel):
    case_id: str
    target_agent: str
    purpose: str
    scoped_targets: InvestigationScope
    constraints: list[str] = Field(default_factory=list)


class CaseReport(BaseModel):
    schema_version: str = "1.0"
    case_id: str
    status: AgentStatus
    security_assessment: SecurityAssessment
    executive_summary: str
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    specialist_results: list[AgentResult] = Field(default_factory=list)
    supported_findings: list[ObservedFact] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    analyst_review_required: bool = True
    response_executed: bool = False


class RuntimeResult(BaseModel):
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    specialist_results: list[AgentResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    narrative: str = ""
    rounds: int = 0
    model_messages: list[dict[str, Any]] = Field(default_factory=list)


class Clock(Protocol):
    def __call__(self) -> datetime: ...


@dataclass(slots=True)
class AgentDependencies:
    runtime: Any
    store: Any
    connector: Any
    validator: Any
    settings: Any
    model_manager: Any
    threat_intel: Any = None
    clock: Clock = utc_now
    agent_registry: Any = None


AgentResult.model_rebuild()

