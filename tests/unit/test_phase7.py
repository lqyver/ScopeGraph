from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

import apps.api.main as api_main
import scopegraph.application.services.storage as storage_service
import scopegraph.application.services.system as system_service
from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.storage import cleanup_storage
from scopegraph.application.services.system import request_tool_update, update_system_settings
from scopegraph.infrastructure.config import Settings
from scopegraph.schemas.system import SystemSettingsPatch
from scopegraph.security import normalize_proxy_url
from scopegraph.tooling.adapters.httpx import HttpxAdapter


def test_proxy_url_is_normalized_and_rejects_credentials_or_paths() -> None:
    assert normalize_proxy_url("HTTP://127.0.0.1:8080/") == "http://127.0.0.1:8080"
    assert normalize_proxy_url("https://[::1]:8081") == "https://[::1]:8081"
    with pytest.raises(ValueError, match="credentials"):
        normalize_proxy_url("http://user:secret@127.0.0.1:8080")
    with pytest.raises(ValueError, match="path"):
        normalize_proxy_url("http://127.0.0.1:8080/admin")


def test_httpx_proxy_is_a_closed_argv_field(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = HttpxAdapter()
    validated = adapter.validate_input(
        {"domains": ["example.com"], "proxy_url": "http://127.0.0.1:8080"}
    )
    command = adapter.build_command(validated)
    assert command[command.index("-proxy") + 1] == "http://127.0.0.1:8080"
    assert all(";" not in item for item in command)


@pytest.mark.asyncio
async def test_public_bind_requires_api_key_and_middleware_enforces_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for unsafe_key in (None, SecretStr(""), SecretStr("   "), SecretStr("too-short")):
        monkeypatch.setattr(
            api_main,
            "get_settings",
            lambda key=unsafe_key: Settings(public_bind=True, api_key=key),
        )
        with pytest.raises(RuntimeError, match="32 bytes"):
            api_main.create_app()

    strong_key = "test-secret-that-is-at-least-32-bytes"
    monkeypatch.setattr(
        api_main,
        "get_settings",
        lambda: Settings(public_bind=True, api_key=SecretStr(strong_key)),
    )
    application = api_main.create_app()
    transport = httpx.ASGITransport(app=application)
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            assert (await client.get("/not-found")).status_code == 401
            assert (
                await client.get(
                    "/not-found", headers={"x-scopegraph-api-key": ""}
                )
            ).status_code == 401
            assert (
                await client.get(
                    "/not-found", headers={"x-scopegraph-api-key": "wrong-key"}
                )
            ).status_code == 401
            assert (
                (
                    await client.get(
                        "/not-found",
                        headers={"x-scopegraph-api-key": strong_key},
                    )
                ).status_code
                == 404
            )


def test_tool_updates_are_never_silent() -> None:
    with pytest.raises(ScopeGraphError, match="confirmation"):
        request_tool_update("httpx", False)
    result = request_tool_update("httpx", True)
    assert result.update_performed is False
    assert result.manual_required is True


def test_proxy_settings_are_atomic_and_credential_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(edition="internal", data_root=tmp_path)
    monkeypatch.setattr(system_service, "get_settings", lambda: settings)
    result = update_system_settings(SystemSettingsPatch(proxy_url="http://127.0.0.1:8080"))
    assert result.proxy_url == "http://127.0.0.1:8080"
    assert result.edition == "internal"
    assert result.proxy_credentials_supported is False
    assert not (tmp_path / "system" / "settings.tmp").exists()


def test_storage_cleanup_removes_files_only_after_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(data_root=tmp_path)
    monkeypatch.setattr(storage_service, "get_settings", lambda: settings)
    raw = tmp_path / "projects" / "p" / "scan_runs" / "r" / "stdout.raw"
    raw.parent.mkdir(parents=True)
    raw.write_bytes(b"evidence")
    with pytest.raises(ScopeGraphError, match="confirmation"):
        cleanup_storage(
            raw_artifacts=True,
            exports=False,
            older_than_days=0,
            confirmation=False,
        )
    result = cleanup_storage(
        raw_artifacts=True,
        exports=False,
        older_than_days=0,
        confirmation=True,
    )
    assert result.deleted_files == 1
    assert result.reclaimed_bytes == len(b"evidence")
    assert result.structured_records_deleted == 0
