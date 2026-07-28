from typing import Any

import httpx


class ScopeGraphApiError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class ScopeGraphApiClient:
    """Small async client used by MCP so business logic stays in the REST services."""

    def __init__(self, base_url: str, *, api_key: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        headers = {"x-scopegraph-api-key": self.api_key} if self.api_key else None
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=httpx.Timeout(30.0),
                follow_redirects=False,
            ) as client:
                response = await client.request(method, path, json=json, params=params)
        except httpx.HTTPError as exc:
            raise ScopeGraphApiError(
                "API_UNREACHABLE",
                "Cannot reach the local ScopeGraph API",
            ) from exc

        if response.is_error:
            code = "API_ERROR"
            message = f"ScopeGraph API returned HTTP {response.status_code}"
            try:
                payload = response.json()
                error = payload.get("error", {}) if isinstance(payload, dict) else {}
                if isinstance(error, dict):
                    code = str(error.get("code") or code)
                    message = str(error.get("message") or message)
            except ValueError:
                pass
            raise ScopeGraphApiError(code, message, status_code=response.status_code)

        if response.status_code == 204:
            return None
        return response.json()
