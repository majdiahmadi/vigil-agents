from __future__ import annotations

import os

from vigil.core.database import VigilStore
from vigil.core.models import AgentDependencies
from vigil.core.runtime import AgentRuntime
from vigil.core.settings import Settings, get_settings
from vigil.core.validation import EvidenceValidator
from vigil.integrations.mock.connector import MockTelemetryConnector
from vigil.integrations.wazuh.connector import WazuhTelemetryConnector
from vigil.integrations.wazuh.indexer import WazuhIndexerClient
from vigil.integrations.wazuh.manager import WazuhManagerClient
from vigil.llm.model_manager import ModelManager
from vigil.plugins.manager import PluginManager, build_plugin_manager


class AgentRegistry:
    def __init__(self, dependencies: AgentDependencies, plugin_manager: PluginManager | None = None) -> None:
        self.dependencies = dependencies
        dependencies.agent_registry = self
        self.plugin_manager = plugin_manager or build_plugin_manager(dependencies)

    def create(self, agent_id: str):
        return self.plugin_manager.create(agent_id)

    def list(self) -> list[str]:
        return self.plugin_manager.list_agents()

    def list_plugins(self) -> list[dict[str, object]]:
        return self.plugin_manager.list_plugins()


def _connector(settings: Settings):
    if settings.connector_mode == "mock":
        return MockTelemetryConnector(settings.fixture_dir / "wazuh_events" / "events.json")
    if settings.connector_mode != "wazuh":
        raise ValueError("VIGIL_CONNECTOR_MODE must be mock or wazuh")
    url = os.getenv("VIGIL_WAZUH_INDEXER_URL")
    user = os.getenv("VIGIL_WAZUH_INDEXER_USERNAME")
    password = os.getenv("VIGIL_WAZUH_INDEXER_PASSWORD")
    if not all((url, user, password)):
        raise RuntimeError("Wazuh mode requires Indexer URL, username and password")
    verify: bool | str = os.getenv("VIGIL_WAZUH_CA_BUNDLE") or True
    indexer = WazuhIndexerClient(url, user, password, verify=verify)
    manager = None
    if manager_url := os.getenv("VIGIL_WAZUH_MANAGER_URL"):
        if token := os.getenv("VIGIL_WAZUH_MANAGER_TOKEN"):
            manager = WazuhManagerClient(manager_url, token, verify=verify)
    return WazuhTelemetryConnector(indexer, manager)


def build_registry(
    settings: Settings | None = None,
    store: VigilStore | None = None,
    *,
    load_external_plugins: bool = True,
) -> AgentRegistry:
    settings = settings or get_settings()
    store = store or VigilStore(settings.db_path)
    manager = ModelManager(store, settings.config_dir / "catalogs")
    deps = AgentDependencies(
        runtime=AgentRuntime(), store=store, connector=_connector(settings),
        validator=EvidenceValidator(), settings=settings, model_manager=manager,
    )
    return AgentRegistry(deps, build_plugin_manager(deps, load_external=load_external_plugins))

