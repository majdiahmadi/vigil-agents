from datetime import datetime, timedelta, timezone

import httpx
import pytest

from vigil.integrations import SearchFilters
from vigil.integrations.wazuh.connector import WazuhTelemetryConnector
from vigil.integrations.wazuh.indexer import WazuhIndexerClient


@pytest.mark.asyncio
async def test_indexer_http_contract_and_normalization():
    def handler(request: httpx.Request):
        assert request.method == "POST"
        assert "wazuh-alerts-" in str(request.url)
        assert request.headers.get("authorization", "").startswith("Basic ")
        return httpx.Response(200, json={"hits": {"hits": [{"_id": "native-1", "_index": "wazuh-alerts-4.x", "_source": {"timestamp": "2026-10-19T10:00:00Z", "agent": {"name": "host-1"}, "rule": {"id": "5710"}, "data": {"srcip": "192.0.2.10"}}}]}})
    client = WazuhIndexerClient("https://indexer.test", "user", "pass", transport=httpx.MockTransport(handler))
    connector = WazuhTelemetryConnector(client)
    now = datetime(2026, 10, 20, tzinfo=timezone.utc)
    records = await connector.search_events("case-1", SearchFilters(source_ip="192.0.2.10", start=now-timedelta(days=2), end=now))
    assert records[0].native_event_id == "native-1"
    assert records[0].source_ip == "192.0.2.10"
    assert records[0].raw_fields["_index"] == "wazuh-alerts-4.x"
    assert records[0].simulated is False

