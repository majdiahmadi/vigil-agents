from __future__ import annotations

from vigil.llm.adapter import OpenAICompatiblePlanner
from vigil.llm.credentials import CredentialStore
from vigil.llm.model_catalog import ModelCatalog
from vigil.llm.provider_registry import get_provider


class ModelManager:
    def __init__(self, store, cache_dir) -> None:
        self.store = store
        self.credentials = CredentialStore()
        self.catalog = ModelCatalog(cache_dir)

    def assignment(self, agent_id: str) -> tuple[str, str]:
        return self.store.get_assignment(agent_id)

    def assign(self, agent_id: str, provider: str, model_id: str) -> None:
        if agent_id not in {"orchestrator", "triage", "malware", "hunter"}:
            raise ValueError("unknown agent")
        if provider == "offline":
            if model_id != "deterministic-readonly-v1":
                raise ValueError("unsupported offline model")
        else:
            get_provider(provider)
        self.store.set_assignment(agent_id, provider, model_id)

    async def models(self, provider_id: str, refresh: bool = False, transport=None):
        key = self.credentials.get(provider_id)
        if not key:
            raise RuntimeError(f"missing API key for {provider_id}")
        return await self.catalog.fetch(get_provider(provider_id), key, refresh=refresh, transport=transport)

    def adapter_for(self, agent_id: str):
        provider_id, model_id = self.assignment(agent_id)
        if provider_id == "offline":
            return None
        key = self.credentials.get(provider_id)
        if not key:
            raise RuntimeError(f"missing API key for assigned provider {provider_id}")
        return OpenAICompatiblePlanner(get_provider(provider_id), model_id, key)

