from __future__ import annotations

import re
from typing import Any, Literal

import httpx

from vigil.integrations import SearchFilters


class WazuhUnavailableError(RuntimeError):
    pass


SearchKind = Literal["authentication", "session", "generic", "indicator"]
_INDEX_PATTERN = re.compile(r"^[a-zA-Z0-9._*-]+$")


class WazuhIndexerClient:
    def __init__(self, base_url: str, username: str, password: str, *, index_pattern: str = "wazuh-alerts-*", verify: bool | str = True, timeout_seconds: float = 15.0, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not base_url.lower().startswith("https://"):
            raise ValueError("Wazuh Indexer URL must use HTTPS")
        if not _INDEX_PATTERN.fullmatch(index_pattern) or ".." in index_pattern or "/" in index_pattern:
            raise ValueError("invalid Wazuh index pattern")
        if verify is False:
            raise ValueError("TLS verification cannot be disabled")
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.index_pattern = index_pattern
        self.verify = verify
        self.timeout_seconds = max(1.0, min(timeout_seconds, 60.0))
        self.transport = transport

    def build_query(self, filters: SearchFilters, kind: SearchKind = "generic") -> dict[str, Any]:
        must: list[dict[str, Any]] = [{"range": {"timestamp": {"gte": filters.start.isoformat(), "lte": filters.end.isoformat()}}}]
        for attr, field in (("source_ip", "data.srcip"), ("destination_ip", "data.dstip"), ("host", "agent.name"), ("rule_id", "rule.id")):
            if value := getattr(filters, attr):
                must.append({"term": {field: value}})
        if filters.user:
            must.append({"bool": {"minimum_should_match": 1, "should": [{"term": {"data.srcuser": filters.user}}, {"term": {"data.dstuser": filters.user}}, {"term": {"user.name": filters.user}}]}})
        if filters.indicator:
            fields = ("data.sha256", "data.hash.sha256", "data.srcip", "data.dstip", "file.hash.sha256")
            must.append({"bool": {"minimum_should_match": 1, "should": [{"term": {field: filters.indicator}} for field in fields]}})
        if kind == "authentication":
            must.append({"bool": {"minimum_should_match": 1, "should": [{"match_phrase": {"rule.description": "authentication"}}, {"match_phrase": {"rule.description": "ssh"}}, {"term": {"decoder.name": "sshd"}}]}})
        elif kind == "session":
            must.append({"bool": {"minimum_should_match": 1, "should": [{"match_phrase": {"rule.description": "session"}}, {"exists": {"field": "data.command"}}, {"exists": {"field": "data.audit.command"}}]}})
        return {"size": min(filters.limit, 500), "track_total_hits": False, "sort": [{"timestamp": "asc"}], "query": {"bool": {"must": must}}}

    async def search(self, filters: SearchFilters, kind: SearchKind = "generic") -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(auth=self.auth, verify=self.verify, timeout=httpx.Timeout(self.timeout_seconds, connect=min(5.0, self.timeout_seconds)), transport=self.transport, follow_redirects=False) as client:
                response = await client.post(f"{self.base_url}/{self.index_pattern}/_search", json=self.build_query(filters, kind))
                if response.status_code == 401:
                    raise WazuhUnavailableError("Wazuh Indexer authentication failed (401)")
                if response.status_code == 403:
                    raise WazuhUnavailableError("Wazuh Indexer read access was denied (403)")
                if 300 <= response.status_code < 400:
                    raise WazuhUnavailableError("Wazuh Indexer redirect was refused")
                if response.status_code >= 500:
                    raise WazuhUnavailableError(f"Wazuh Indexer unavailable ({response.status_code})")
                response.raise_for_status()
                payload = response.json()
                hits = payload.get("hits", {}).get("hits")
                if not isinstance(hits, list):
                    raise WazuhUnavailableError("Wazuh Indexer returned malformed JSON")
                return [hit for hit in hits[: filters.limit] if isinstance(hit, dict)]
        except WazuhUnavailableError:
            raise
        except httpx.TimeoutException as exc:
            raise WazuhUnavailableError("Wazuh Indexer request timed out") from exc
        except httpx.TransportError as exc:
            raise WazuhUnavailableError(f"Wazuh Indexer connection failed: {type(exc).__name__}") from exc
        except (ValueError, TypeError) as exc:
            raise WazuhUnavailableError("Wazuh Indexer returned malformed JSON") from exc
