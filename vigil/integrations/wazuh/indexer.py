from __future__ import annotations

from typing import Any

import httpx

from vigil.integrations import SearchFilters


class WazuhIndexerClient:
    def __init__(self, base_url: str, username: str, password: str, *, verify: bool | str = True, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.verify = verify
        self.transport = transport

    def build_query(self, filters: SearchFilters) -> dict[str, Any]:
        must: list[dict[str, Any]] = [{"range": {"timestamp": {"gte": filters.start.isoformat(), "lte": filters.end.isoformat()}}}]
        mapping = {"source_ip": "data.srcip", "destination_ip": "data.dstip", "user": "data.srcuser", "host": "agent.name", "rule_id": "rule.id"}
        for attr, field in mapping.items():
            value = getattr(filters, attr)
            if value:
                must.append({"term": {field: value}})
        if filters.indicator:
            must.append({"simple_query_string": {"query": filters.indicator, "fields": ["data.*", "full_log"], "default_operator": "and"}})
        return {"size": filters.limit, "sort": [{"timestamp": "asc"}], "query": {"bool": {"must": must}}}

    async def search(self, filters: SearchFilters) -> list[dict[str, Any]]:
        timeout = httpx.Timeout(15.0, connect=5.0)
        async with httpx.AsyncClient(auth=self.auth, verify=self.verify, timeout=timeout, transport=self.transport) as client:
            response = await client.post(f"{self.base_url}/wazuh-alerts-*/_search", json=self.build_query(filters))
            response.raise_for_status()
            payload = response.json()
            return list(payload.get("hits", {}).get("hits", []))[: filters.limit]

