from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health", tags=["service"])
def health():
    return {"status": "ok", "service": "vigil"}


@router.get("/ready", tags=["service"])
def ready(request: Request):
    registry = request.app.state.registry
    registry.dependencies.store.list_cases(limit=1)
    return {"status": "ready", "connector_mode": registry.dependencies.connector.mode}

