from pydantic import BaseModel, Field


class RoutingDecision(BaseModel):
    selected_agents: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    follow_up_limit: int = 1

