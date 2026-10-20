from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class InvestigationSubmission(BaseModel):
    alert: dict[str, Any]

    @model_validator(mode="after")
    def bounded(self):
        if not self.alert:
            raise ValueError("alert cannot be empty")
        if len(json.dumps(self.alert, default=str).encode("utf-8")) > 256 * 1024:
            raise ValueError("alert exceeds 256 KiB limit")
        return self


class SubmissionResponse(BaseModel):
    case_id: str
    status: str
    poll_url: str
    created: bool
    schema_version: str = "1.0"


class InvestigationStatus(BaseModel):
    case_id: str
    status: str
    created_at: datetime
    updated_at: datetime
    job: dict[str, Any] | None = None
    agent_runs: list[dict[str, Any]] = Field(default_factory=list)
    terminal: bool = False
    report_ready: bool = False
    schema_version: str = "1.0"

