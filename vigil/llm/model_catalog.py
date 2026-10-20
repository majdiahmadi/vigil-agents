from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from vigil.llm.provider_registry import ProviderDefinition


@dataclass(frozen=True, slots=True)
class ModelInfo:
    model_id: str
    display_name: str
    provider: str
    metadata: dict[str, Any]


class ModelCatalogError(RuntimeError):
    pass


class ModelCatalog:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        cache_dir.mkdir(parents=True, exist_ok=True)

    async def fetch(self, provider: ProviderDefinition, api_key: str, *, refresh: bool = False, transport: httpx.AsyncBaseTransport | None = None) -> tuple[list[ModelInfo], bool]:
        cache = self.cache_dir / f"models-{provider.provider_id}.json"
        if not refresh and cache.exists() and datetime.now(timezone.utc) - datetime.fromtimestamp(cache.stat().st_mtime, timezone.utc) < timedelta(hours=1):
            return self._read_cache(cache, provider), False
        headers = {"Authorization": f"Bearer {api_key}"}
        url = f"{provider.base_url.rstrip('/')}{provider.models_path}"
        models: dict[str, ModelInfo] = {}
        try:
            async with httpx.AsyncClient(headers=headers, timeout=httpx.Timeout(20, connect=5), transport=transport) as client:
                for _ in range(20):
                    response = await client.get(url)
                    if response.status_code in (401, 403):
                        raise ModelCatalogError("provider rejected the API key")
                    if response.status_code == 429:
                        raise ModelCatalogError("provider rate limit reached; retry later")
                    response.raise_for_status()
                    payload = response.json()
                    items = payload.get("data", payload.get("models", []))
                    if not isinstance(items, list):
                        raise ModelCatalogError("provider returned an invalid model catalog")
                    for item in items:
                        if isinstance(item, str):
                            item = {"id": item}
                        model_id = str(item.get("id") or item.get("name") or "").strip()
                        if model_id:
                            models[model_id] = ModelInfo(model_id, str(item.get("name") or model_id), provider.provider_id, item)
                    next_url = payload.get("next")
                    if next_url:
                        url = str(next_url)
                        continue
                    if payload.get("has_more") and items:
                        last = items[-1]
                        last_id = last.get("id") if isinstance(last, dict) else last
                        url = f"{provider.base_url.rstrip('/')}{provider.models_path}?after={last_id}"
                        continue
                    break
        except ModelCatalogError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            if cache.exists():
                return self._read_cache(cache, provider), True
            raise ModelCatalogError(f"could not fetch model catalog: {type(exc).__name__}") from exc
        if not models:
            raise ModelCatalogError("provider returned an empty model catalog")
        ordered = sorted(models.values(), key=lambda x: x.model_id.lower())
        cache.write_text(json.dumps([{"id": x.model_id, "name": x.display_name, "metadata": x.metadata} for x in ordered]), encoding="utf-8")
        return ordered, False

    def _read_cache(self, path: Path, provider: ProviderDefinition) -> list[ModelInfo]:
        return [ModelInfo(str(x["id"]), str(x.get("name") or x["id"]), provider.provider_id, x.get("metadata", {})) for x in json.loads(path.read_text(encoding="utf-8"))]

    @staticmethod
    def search(models: list[ModelInfo], text: str) -> list[ModelInfo]:
        needle = text.lower().strip()
        return [model for model in models if needle in model.model_id.lower() or needle in model.display_name.lower()]

    @staticmethod
    def page(models: list[ModelInfo], page: int, page_size: int = 20) -> list[ModelInfo]:
        start = max(page, 0) * max(1, min(page_size, 100))
        return models[start : start + page_size]

