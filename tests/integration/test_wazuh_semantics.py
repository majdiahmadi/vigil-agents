import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from vigil.integrations import SearchFilters
from vigil.integrations.mock.connector import MockTelemetryConnector
from vigil.integrations.wazuh.connector import WazuhTelemetryConnector
from vigil.integrations.wazuh.indexer import WazuhIndexerClient, WazuhUnavailableError


@pytest.mark.asyncio
async def test_mock_and_realistic_wazuh_hits_have_equivalent_ssh_semantics(project_root):
    payload = json.loads((project_root / "fixtures" / "realistic_wazuh_hits" / "ssh_sequence.json").read_text(encoding="utf-8"))
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    wazuh = WazuhTelemetryConnector(WazuhIndexerClient("https://indexer.test", "read", "only", transport=transport))
    mock = MockTelemetryConnector(project_root / "fixtures" / "wazuh_events" / "events.json")
    start = datetime(2026, 10, 19, 9, tzinfo=timezone.utc)
    filters = SearchFilters(source_ip="192.0.2.10", start=start, end=start + timedelta(hours=3), limit=100)
    mock_records = await mock.search_events("case-mock", filters)
    wazuh_records = await wazuh.search_events("case-live", filters)

    def semantics(records):
        return sorted((item.native_event_id, item.normalized_event_kind.value, item.event_count, item.user, item.command) for item in records)

    assert semantics(mock_records) == semantics(wazuh_records)


@pytest.mark.asyncio
@pytest.mark.parametrize(("status_code", "message"), [(401, "authentication failed"), (403, "access was denied"), (503, "unavailable")])
async def test_wazuh_http_failures_are_typed(status_code, message):
    client = WazuhIndexerClient("https://indexer.test", "read", "only", transport=httpx.MockTransport(lambda request: httpx.Response(status_code, json={})))
    now = datetime.now(timezone.utc)
    with pytest.raises(WazuhUnavailableError, match=message):
        await client.search(SearchFilters(start=now - timedelta(minutes=1), end=now, limit=1))


@pytest.mark.asyncio
async def test_wazuh_query_kinds_are_distinct_and_bounded():
    bodies = []
    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"hits": {"hits": []}})
    client = WazuhIndexerClient("https://indexer.test", "read", "only", index_pattern="wazuh-alerts-*", transport=httpx.MockTransport(handler))
    now = datetime.now(timezone.utc)
    filters = SearchFilters(source_ip="192.0.2.10", start=now - timedelta(minutes=5), end=now, limit=7)
    await client.search(filters, "authentication")
    await client.search(filters, "session")
    assert bodies[0] != bodies[1]
    assert bodies[0]["size"] == bodies[1]["size"] == 7
    assert all("192.0.2.10" in json.dumps(body) for body in bodies)
