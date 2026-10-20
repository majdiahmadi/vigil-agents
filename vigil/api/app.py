from fastapi import FastAPI

from vigil.agents.registry import build_registry
from vigil.api.routes import agents, health, investigations


def create_app(registry=None) -> FastAPI:
    application = FastAPI(
        title="VIGIL API", version="0.1.0",
        description="Authenticated, read-only SOC investigation orchestration. No remediation is executed.",
    )
    application.state.registry = registry or build_registry()
    application.include_router(health.router)
    application.include_router(agents.router)
    application.include_router(investigations.router)
    return application


app = create_app()

