from datetime import datetime, timezone

import httpx
import pytest

from vigil.core.models import AgentResult, AgentStatus, EvidenceClaim, EvidenceRecord, ObservedFact
from vigil.core.validation import EvidenceValidator
from vigil.llm.model_catalog import ModelCatalog, ModelCatalogError
from vigil.llm.provider_registry import get_provider


@pytest.mark.asyncio
async def test_catalog_refuses_cross_origin_next_without_sending_secret(tmp_path):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"data": [{"id": "safe-model"}], "next": "https://untrusted.example/models"})

    with pytest.raises(ModelCatalogError, match="changed origin"):
        await ModelCatalog(tmp_path).fetch(get_provider("openai"), "super-secret", refresh=True, transport=httpx.MockTransport(handler))
    assert len(requests) == 1
    assert requests[0].url.host == "api.openai.com"
    assert requests[0].headers["authorization"] == "Bearer super-secret"


def test_field_backed_validator_rejects_fabricated_count():
    now = datetime.now(timezone.utc)
    evidence = EvidenceRecord(evidence_id="ev-1", case_id="case-1", native_event_id="native-1", source_type="test", connector_mode="test", normalized_event_kind="auth_failed", event_count=2)
    result = AgentResult(case_id="case-1", agent_id="triage", run_id="run-1", run_status=AgentStatus.COMPLETED, model_provider="offline", model_id="test", observed_facts=[ObservedFact(statement="Fifteen attempts", evidence_ids=["ev-1"], claims=[EvidenceClaim(evidence_id="ev-1", field_path="event_count", expected_value=15)])], started_at=now, completed_at=now)
    errors = EvidenceValidator().validate(result, [evidence])
    assert any("unsupported claim" in error and "actual 2" in error for error in errors)


def test_stable_evidence_id_deduplicates_repeated_search(registry):
    from vigil.integrations import SearchFilters
    import asyncio
    now = datetime(2026, 10, 19, 10, tzinfo=timezone.utc)
    filters = SearchFilters(source_ip="192.0.2.10", start=now, end=now.replace(hour=11))
    first = asyncio.run(registry.dependencies.connector.search_events("case-stable", filters))
    second = asyncio.run(registry.dependencies.connector.search_events("case-stable", filters))
    assert [item.evidence_id for item in first] == [item.evidence_id for item in second]
