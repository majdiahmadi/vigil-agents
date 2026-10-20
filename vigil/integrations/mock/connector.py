from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from vigil.core.models import EvidenceRecord
from vigil.integrations import SearchFilters


class MockTelemetryConnector:
    mode = "mock"

    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = fixture_path
        self._events: list[dict[str, Any]] = json.loads(fixture_path.read_text(encoding="utf-8"))

    def _search(self, case_id: str, filters: SearchFilters, kinds: set[str] | None = None) -> list[EvidenceRecord]:
        output: list[EvidenceRecord] = []
        for event in self._events:
            observed = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
            if not (filters.start <= observed <= filters.end):
                continue
            if kinds and event.get("kind") not in kinds:
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
            output.append(EvidenceRecord(
                case_id=case_id,
                native_event_id=str(event["event_id"]),
                source_type="mock_wazuh_event",
                connector_mode="mock",
                observed_at=observed,
                host=event.get("host"), user=event.get("user"),
                source_ip=event.get("source_ip"), destination_ip=event.get("destination_ip"),
                rule_id=event.get("rule_id"), raw_fields=event,
                query_scope=filters.model_dump(mode="json"), simulated=True,
            ))
            if len(output) >= filters.limit:
                break
        return output

    async def search_authentication_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return self._search(case_id, filters, {"authentication"})

    async def search_session_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return self._search(case_id, filters, {"session", "command"})

    async def search_events(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return self._search(case_id, filters)

    async def search_by_indicator(self, case_id: str, filters: SearchFilters) -> list[EvidenceRecord]:
        return self._search(case_id, filters)

    async def get_agent_context(self, agent_id: str) -> dict:
        hosts = [e for e in self._events if str(e.get("agent_id")) == str(agent_id)]
        return {"agent_id": agent_id, "status": "simulated", "events_available": len(hosts)}

