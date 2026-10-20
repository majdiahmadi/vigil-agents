from __future__ import annotations

import re
from datetime import datetime, timezone

import httpx


class ThreatIntelError(RuntimeError):
    pass


class VirusTotalHashConnector:
    """Hash-only VirusTotal v3 lookup. It never uploads or downloads a sample."""

    base_url = "https://www.virustotal.com/api/v3"
    _hash = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")

    def __init__(self, api_key: str, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not api_key.strip():
            raise ValueError("VirusTotal API key cannot be empty")
        self.api_key = api_key
        self.transport = transport

    async def lookup_hash(self, value: str) -> dict:
        if not self._hash.fullmatch(value):
            raise ValueError("threat-intelligence lookup accepts only MD5, SHA-1, or SHA-256 hashes")
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers={"x-apikey": self.api_key},
                timeout=httpx.Timeout(15, connect=5), transport=self.transport,
                follow_redirects=False,
            ) as client:
                response = await client.get(f"/files/{value.lower()}")
                if response.status_code == 404:
                    return {"provider": "virustotal", "status": "not_found", "hash": value.lower(), "retrieved_at": datetime.now(timezone.utc).isoformat()}
                if response.status_code in (401, 403):
                    raise ThreatIntelError("VirusTotal rejected the configured credential")
                if response.status_code == 429:
                    raise ThreatIntelError("VirusTotal rate limit reached")
                if response.status_code >= 500:
                    raise ThreatIntelError(f"VirusTotal unavailable ({response.status_code})")
                response.raise_for_status()
                attributes = response.json().get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                if not isinstance(stats, dict):
                    raise ThreatIntelError("VirusTotal returned malformed analysis statistics")
                return {
                    "provider": "virustotal", "status": "checked", "hash": value.lower(),
                    "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
                    "harmless": int(stats.get("harmless", 0)), "undetected": int(stats.get("undetected", 0)),
                    "retrieved_at": datetime.now(timezone.utc).isoformat(),
                }
        except ThreatIntelError:
            raise
        except httpx.TimeoutException as exc:
            raise ThreatIntelError("VirusTotal request timed out") from exc
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise ThreatIntelError(f"VirusTotal lookup failed: {type(exc).__name__}") from exc
