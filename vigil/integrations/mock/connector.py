from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from vigil.core.models import EvidenceRecord, NormalizedEventKind
from vigil.integrations import SearchFilters
from vigil.integrations.wazuh.normalizer import normalize_mock_event


class MockTelemetryConnector:
    mode = "mock"

    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = fixture_path
        self._events: list[dict[str, Any]] = json.loads(fixture_path.read_text(encoding="utf-8"))

    def _search(self, case_id: str, filters: SearchFilters, kinds: set[NormalizedEventKind] | None = None) -> list[EvidenceRecord]:
        output: list[EvidenceRecord] = []
        for event in self._events:
            observed = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
            if not (filters.start <= observed <= filters.end):
                continue
            comparisons = {
                "source_ip": filters.source_ip,
                "destination_ip": filters.destination_ip,
                "user": filters.user,
                "host": filters.host,
                "rule_id": filters.rule_id,
            }
            if any(expected and str(event.get(field)) != str(expected) for field, expected in comparisons.items()):
                continue
            if filters.indicator and filters.indicator.lower() not in json.dumps(event).lower():
                continue
            record = normalize_mock_event(case_id, event, filters.model_dump(mode="json"))
            if kinds and record.normalized_event_kind not in kinds:
                continue
            output.append(record)
            if len(output) >= filters.limit:
                break
        return output

    async def search_authentication_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return self._search(case_id, filters, {NormalizedEventKind.AUTH_FAILED, NormalizedEventKind.AUTH_SUCCESS})

    async def search_session_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return self._search(case_id, filters, {NormalizedEventKind.SESSION_START, NormalizedEventKind.COMMAND})

    async def search_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return self._search(case_id, filters)

    async def search_by_indicator(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return self._search(case_id, filters)

    async def get_agent_context(self, agent_id: str) -> dict:
        hosts = [e for e in self._events if str(e.get("agent_id")) == str(agent_id)]
        return {"agent_id": agent_id, "status": "simulated", "events_available": len(hosts)}

