from __future__ import annotations

from typing import Any

import httpx

from vigil.llm.provider_registry import ProviderDefinition


class ProviderInferenceError(RuntimeError):
    pass


class OpenAICompatibleAdapter:
    """OpenAI-compatible chat adapter. Tool execution remains inside VIGIL."""

    def __init__(self, provider: ProviderDefinition, model_id: str, api_key: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.provider = provider
        self.model_id = model_id
        self.api_key = api_key
        self.transport = transport

    async def complete(self, *, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.model_id, "messages": messages}
        if tools:
            body.update({"tools": tools, "tool_choice": "auto"})
        if self.provider.provider_id != "deepseek":
            body["temperature"] = 0
        try:
            async with httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=httpx.Timeout(45, connect=8), transport=self.transport,
                follow_redirects=False,
            ) as client:
                response = await client.post(f"{self.provider.base_url.rstrip('/')}{self.provider.chat_path}", json=body)
                if response.status_code in (401, 403):
                    raise ProviderInferenceError("provider rejected the configured credential or model access")
                if response.status_code == 429:
                    raise ProviderInferenceError("provider rate limit reached")
                if 300 <= response.status_code < 400:
                    raise ProviderInferenceError("provider redirect was refused")
                if response.status_code >= 500:
                    raise ProviderInferenceError(f"provider service unavailable ({response.status_code})")
                response.raise_for_status()
                message = response.json()["choices"][0]["message"]
                if not isinstance(message, dict):
                    raise ValueError("assistant message is not an object")
                return message
        except ProviderInferenceError:
            raise
        except httpx.TimeoutException as exc:
            raise ProviderInferenceError("provider inference timed out") from exc
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise ProviderInferenceError(f"provider inference failed: {type(exc).__name__}") from exc

    async def chat(self, *, messages: list[dict[str, Any]], instructions: str) -> str:
        response = await self.complete(messages=[{"role": "system", "content": instructions}, *messages], tools=[])
        content = response.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ProviderInferenceError("provider returned an empty chat response")
        return content.strip()


OpenAICompatiblePlanner = OpenAICompatibleAdapter
