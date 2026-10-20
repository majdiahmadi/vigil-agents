from pydantic import BaseModel, Field


class HuntSummary(BaseModel):
    hypothesis: str
    status: str = "inconclusive"
    hosts_observed: list[str] = Field(default_factory=list)
    alternate_explanations: list[str] = Field(default_factory=list)

