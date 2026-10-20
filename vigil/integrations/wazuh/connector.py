from __future__ import annotations

from vigil.core.models import EvidenceRecord
from vigil.integrations import SearchFilters
from vigil.integrations.wazuh.indexer import WazuhIndexerClient
from vigil.integrations.wazuh.manager import WazuhManagerClient
from vigil.integrations.wazuh.normalizer import normalize_hit


class WazuhTelemetryConnector:
    mode = "wazuh"

    def __init__(self, indexer: WazuhIndexerClient, manager: WazuhManagerClient | None = None) -> None:
        self.indexer = indexer
        self.manager = manager

    async def _search(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        hits = await self.indexer.search(filters)
        scope = filters.model_dump(mode="json")
        return [normalize_hit(case_id, hit, scope) for hit in hits]

    async def search_authentication_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return await self._search(case_id, filters)

    async def search_session_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return await self._search(case_id, filters)

    async def search_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return await self._search(case_id, filters)

    async def search_by_indicator(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return await self._search(case_id, filters)

    async def get_agent_context(self, agent_id: str) -> dict:
        if not self.manager:
            return {"agent_id": agent_id, "status": "manager_not_configured"}
        return await self.manager.get_agent(agent_id)

