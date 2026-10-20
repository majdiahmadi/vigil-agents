from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol

from pydantic import BaseModel, Field, model_validator

from vigil.core.models import EvidenceRecord


class SearchFilters(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    host: str | None = None
    rule_id: str | None = None
    indicator: str | None = None
    start: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) - timedelta(days=7))
    end: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=1))
    limit: int = Field(default=100, ge=1, le=500)

    @model_validator(mode="after")
    def validate_window(self) -> "SearchFilters":
        if self.end <= self.start or self.end - self.start > timedelta(days=30):
            raise ValueError("search time window must be positive and at most 30 days")
        return self


class SecurityTelemetryConnector(Protocol):
    mode: str
    async def search_authentication_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]: ...
    async def search_session_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]: ...
    async def search_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]: ...
    async def search_by_indicator(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]: ...
    async def get_agent_context(self, agent_id: str) -> dict: ...

