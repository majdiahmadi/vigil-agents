from fastapi import HTTPException, Request, status


def require_bearer(request: Request) -> None:
    expected = request.app.state.registry.dependencies.settings.api_token
    if not expected:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="API token is not configured")
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    import secrets
    if scheme.lower() != "bearer" or not token or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"})

