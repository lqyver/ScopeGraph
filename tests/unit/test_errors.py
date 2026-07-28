import httpx
import pytest
from fastapi import FastAPI

from scopegraph.application.errors import ScopeGraphError, install_exception_handlers
from scopegraph.infrastructure.middleware import RequestContextMiddleware


@pytest.mark.asyncio
async def test_application_errors_use_documented_envelope() -> None:
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)
    install_exception_handlers(app)

    @app.get("/failure")
    async def failure() -> None:
        raise ScopeGraphError(
            "SCOPE_VIOLATION",
            "Target is outside authorized scope",
            status_code=403,
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/failure", headers={"X-Request-ID": "test-request"})

    assert response.status_code == 403
    assert response.headers["X-Request-ID"] == "test-request"
    assert response.json() == {
        "error": {
            "code": "SCOPE_VIOLATION",
            "message": "Target is outside authorized scope",
            "details": {},
            "request_id": "test-request",
        }
    }
