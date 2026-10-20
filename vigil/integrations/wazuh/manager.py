from __future__ import annotations

import httpx


class WazuhManagerClient:
    def __init__(self, base_url: str, token: str, *, verify: bool | str = True, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not base_url.lower().startswith("https://"):
            raise ValueError("Wazuh Manager URL must use HTTPS")
        if verify is False:
            raise ValueError("TLS verification cannot be disabled")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify = verify
        self.transport = transport

    async def get_agent(self, agent_id: str) -> dict:
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {self.token}"}, verify=self.verify, timeout=10, transport=self.transport) as client:
            response = await client.get(f"{self.base_url}/agents", params={"agents_list": agent_id, "limit": 1})
            response.raise_for_status()
            return response.json()

