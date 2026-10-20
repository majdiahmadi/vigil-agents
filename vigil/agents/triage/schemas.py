from pydantic import BaseModel, Field


class TriageSummary(BaseModel):
    failed_auth_events: int = 0
    successful_auth_events: int = 0
    session_events: int = 0
    authorization_status: str = "unknown"
    searched_event_ids: list[str] = Field(default_factory=list)

