class ThreatIntelConnector:
    """Optional interface that degrades to an explicit not-checked result."""

    async def lookup(self, indicator: str) -> dict:
        return {"indicator": indicator, "status": "not_checked", "reason": "no threat-intelligence provider configured"}

