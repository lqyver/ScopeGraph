from pathlib import Path
from typing import Any

import httpx


class ApiClientError(RuntimeError):
    def __init__(self, message: str, *, code: str = "API_ERROR") -> None:
        super().__init__(message)
        self.code = code


class ApiClient:
    def __init__(self, base_url: str, *, api_key: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        files: dict[str, tuple[str, bytes, str]] | None = None,
    ) -> Any:
        try:
            response = httpx.request(
                method,
                f"{self.base_url}{path}",
                headers=(
                    {"x-scopegraph-api-key": self.api_key} if self.api_key is not None else None
                ),
                json=json,
                params=params,
                files=files,
                timeout=15.0,
            )
        except httpx.HTTPError as exc:
            raise ApiClientError(
                f"Cannot reach ScopeGraph API: {exc}", code="API_UNREACHABLE"
            ) from exc
        if response.is_error:
            try:
                error = response.json().get("error", {})
            except ValueError:
                error = {}
            raise ApiClientError(
                error.get("message") or f"API returned HTTP {response.status_code}",
                code=error.get("code", "API_ERROR"),
            )
        if response.status_code == 204:
            return None
        return response.json()

    def upload(self, path: str, file_path: Path) -> Any:
        content_type = {
            ".txt": "text/plain",
            ".csv": "text/csv",
            ".json": "application/json",
        }.get(file_path.suffix.casefold(), "application/octet-stream")
        return self.request(
            "POST",
            path,
            files={"file": (file_path.name, file_path.read_bytes(), content_type)},
        )
