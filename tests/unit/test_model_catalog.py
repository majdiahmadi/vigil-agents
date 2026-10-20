import httpx
import pytest

from vigil.llm.model_catalog import ModelCatalog, ModelCatalogError
from vigil.llm.provider_registry import get_provider


@pytest.mark.asyncio
async def test_complete_paginated_catalog_and_search(tmp_path):
    calls = 0

    def handler(request: httpx.Request):
        nonlocal calls
        calls += 1
        start = 0 if "after=" not in str(request.url) else 25
        items = [{"id": f"model-{i:02}"} for i in range(start, start + 25)]
        return httpx.Response(200, json={"data": items, "has_more": calls == 1})

    catalog = ModelCatalog(tmp_path)
    models, stale = await catalog.fetch(get_provider("openai"), "secret", refresh=True, transport=httpx.MockTransport(handler))
    assert len(models) == 50
    assert calls == 2
    assert not stale
    assert len(catalog.search(models, "model-4")) == 10
    assert len(catalog.page(models, 1, 20)) == 20


@pytest.mark.asyncio
async def test_catalog_auth_failure_is_actionable(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(401, json={"error": "no"}))
    with pytest.raises(ModelCatalogError, match="rejected"):
        await ModelCatalog(tmp_path).fetch(get_provider("deepseek"), "bad", refresh=True, transport=transport)

