from fastapi import FastAPI
from fastapi.responses import JSONResponse

from vigil.agents.registry import build_registry
from vigil.api.routes import agents, health, investigations


def create_app(registry=None) -> FastAPI:
    application = FastAPI(
        title="VIGIL API", version="0.1.0",
        description="Authenticated, read-only SOC investigation orchestration. No remediation is executed.",
    )
    application.state.registry = registry

    @application.middleware("http")
    async def ensure_registry(request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > 256 * 1024:
            return JSONResponse(status_code=413, content={"detail": {"code": "payload_too_large", "limit_bytes": 256 * 1024}})
        if request.app.state.registry is None:
            request.app.state.registry = build_registry()
        return await call_next(request)
    application.include_router(health.router)
    application.include_router(agents.router)
    application.include_router(investigations.router)
    return application


app = create_app()

