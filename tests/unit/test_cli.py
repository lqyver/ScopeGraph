from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from apps.cli import main as cli_module
from apps.cli.client import ApiClient

runner = CliRunner()


class FakeResponse:
    def json(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "version": "1.0.0",
            "environment": "test",
            "checked_at": "2026-07-16T00:00:00Z",
            "checks": {"api": {"status": "healthy"}},
        }


def test_doctor_json_is_machine_readable(monkeypatch: object) -> None:
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: FakeResponse())  # type: ignore[attr-defined]

    result = runner.invoke(cli_module.app, ["doctor", "--json"])

    assert result.exit_code == 0
    assert '"status": "healthy"' in result.stdout


def test_doctor_fails_when_api_is_unreachable(monkeypatch: object) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(httpx, "get", fail)  # type: ignore[attr-defined]

    result = runner.invoke(cli_module.app, ["doctor", "--json"])

    assert result.exit_code == 1
    assert '"status": "unreachable"' in result.stdout


def test_api_client_forwards_configured_server_key(monkeypatch: object) -> None:
    captured: dict[str, object] = {}

    class Response:
        status_code = 200
        is_error = False

        def json(self) -> dict[str, bool]:
            return {"ok": True}

    def request(*args: object, **kwargs: object) -> Response:
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr(httpx, "request", request)  # type: ignore[attr-defined]
    result = ApiClient("http://127.0.0.1:8000", api_key="server-secret").request(
        "GET", "/api/v1/system/settings"
    )
    assert result == {"ok": True}
    assert captured["headers"] == {"x-scopegraph-api-key": "server-secret"}


def test_project_create_requires_explicit_authorization() -> None:
    result = runner.invoke(
        cli_module.app,
        ["project", "create", "--name", "Example", "--company", "Example Ltd."],
    )

    assert result.exit_code == 2
    assert "--authorized is required" in result.stdout


def test_project_create_only_creates_project_and_scope(monkeypatch: object) -> None:
    captured: dict[str, object] = {}

    def request(
        _: ApiClient,
        method: str,
        path: str,
        **kwargs: object,
    ) -> dict[str, object]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"id": "project-id", "name": "Example"}

    monkeypatch.setattr(ApiClient, "request", request)  # type: ignore[attr-defined]
    result = runner.invoke(
        cli_module.app,
        [
            "project",
            "create",
            "--name",
            "Example",
            "--company",
            "Example Ltd.",
            "--root-domain",
            "example.com",
            "--authorized",
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert captured["method"] == "POST"
    assert captured["path"] == "/api/v1/projects"
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert payload["authorization_confirmed"] is True
    assert "scan" not in payload


def test_project_delete_fetches_and_sends_name_confirmation(monkeypatch: object) -> None:
    calls: list[tuple[str, str, dict[str, object]]] = []

    def request(
        _: ApiClient,
        method: str,
        path: str,
        **kwargs: object,
    ) -> dict[str, object]:
        calls.append((method, path, kwargs))
        return {"id": "project-id", "name": "Example"}

    monkeypatch.setattr(ApiClient, "request", request)  # type: ignore[attr-defined]
    result = runner.invoke(cli_module.app, ["project", "delete", "project-id", "--yes"])

    assert result.exit_code == 0
    assert calls == [
        ("GET", "/api/v1/projects/project-id", {}),
        (
            "DELETE",
            "/api/v1/projects/project-id",
            {"json": {"confirmation": "Example"}},
        ),
    ]


def test_scan_start_requires_authorization_and_host_opt_in() -> None:
    missing_auth = runner.invoke(
        cli_module.app,
        ["scan", "start", "project-id", "--root-domain", "example.com"],
    )
    assert missing_auth.exit_code == 2
    assert "--authorized is required" in missing_auth.stdout

    missing_active = runner.invoke(
        cli_module.app,
        [
            "scan",
            "start",
            "project-id",
            "--root-domain",
            "example.com",
            "--authorized",
            "--mode",
            "host",
        ],
    )
    assert missing_active.exit_code == 2
    assert "--allow-active" in missing_active.stdout


def test_scan_start_sends_closed_fixture_payload(monkeypatch: object) -> None:
    captured: dict[str, object] = {}

    def request(
        _: ApiClient,
        method: str,
        path: str,
        **kwargs: object,
    ) -> dict[str, object]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"id": "scan-id", "status": "QUEUED"}

    monkeypatch.setattr(ApiClient, "request", request)  # type: ignore[attr-defined]
    result = runner.invoke(
        cli_module.app,
        [
            "scan",
            "start",
            "project-id",
            "--root-domain",
            "example.com",
            "--authorized",
            "--json",
        ],
    )
    assert result.exit_code == 0
    assert captured["path"] == "/api/v1/projects/project-id/scan-runs"
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert payload == {
        "root_domain": "example.com",
        "profile": "standard",
        "execution_mode": "fixture",
        "authorization_confirmed": True,
        "allow_active_execution": False,
        "deep_confirmation": False,
        "nuclei_enabled": False,
        "nuclei_confirmation": False,
        "proxy_url": None,
    }


def test_scan_full_port_requires_second_cli_confirmation() -> None:
    result = runner.invoke(
        cli_module.app,
        [
            "scan",
            "start",
            "project-id",
            "--root-domain",
            "example.com",
            "--authorized",
            "--full-port",
        ],
    )
    assert result.exit_code == 2
    assert "--confirm-full-port" in result.stdout


def test_scan_nuclei_requires_second_cli_confirmation() -> None:
    result = runner.invoke(
        cli_module.app,
        [
            "scan",
            "start",
            "project-id",
            "--root-domain",
            "example.com",
            "--authorized",
            "--nuclei",
        ],
    )
    assert result.exit_code == 2
    assert "--confirm-nuclei" in result.stdout


def test_scan_deep_and_custom_profiles_require_explicit_configuration(tmp_path: Path) -> None:
    deep = runner.invoke(
        cli_module.app,
        [
            "scan",
            "start",
            "project-id",
            "--root-domain",
            "example.com",
            "--authorized",
            "--profile",
            "deep",
        ],
    )
    assert deep.exit_code == 2
    assert "--confirm-deep" in deep.stdout

    custom = runner.invoke(
        cli_module.app,
        [
            "scan",
            "start",
            "project-id",
            "--root-domain",
            "example.com",
            "--authorized",
            "--profile",
            "custom",
        ],
    )
    assert custom.exit_code == 2
    assert "--custom-config" in custom.stdout

    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json", encoding="utf-8")
    malformed = runner.invoke(
        cli_module.app,
        [
            "scan",
            "start",
            "project-id",
            "--root-domain",
            "example.com",
            "--authorized",
            "--profile",
            "custom",
            "--custom-config",
            str(invalid),
        ],
    )
    assert malformed.exit_code == 2
    assert "Invalid --custom-config" in malformed.stdout


@pytest.mark.parametrize(
    ("args", "expected_method", "expected_path"),
    [
        (
            ["enterprise", "discover", "project-id", "--json"],
            "POST",
            "/api/v1/projects/project-id/enterprise-discovery",
        ),
        (
            ["root-domain", "list", "project-id", "--json"],
            "GET",
            "/api/v1/projects/project-id/candidate-root-domains",
        ),
        (
            ["review", "list", "project-id", "--json"],
            "GET",
            "/api/v1/projects/project-id/review-queue",
        ),
        (
            ["export", "create", "project-id", "--json"],
            "POST",
            "/api/v1/projects/project-id/exports",
        ),
    ],
)
def test_phase_five_and_six_cli_commands_use_expected_api_routes(
    monkeypatch: object,
    args: list[str],
    expected_method: str,
    expected_path: str,
) -> None:
    captured: dict[str, object] = {}

    def request(
        _: ApiClient,
        method: str,
        path: str,
        **kwargs: object,
    ) -> dict[str, object]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"items": []}

    monkeypatch.setattr(ApiClient, "request", request)  # type: ignore[attr-defined]
    result = runner.invoke(cli_module.app, args)
    assert result.exit_code == 0
    assert captured["method"] == expected_method
    assert captured["path"] == expected_path


def test_network_classification_sends_audited_closed_payload(monkeypatch: object) -> None:
    captured: dict[str, object] = {}

    def request(
        _: ApiClient,
        method: str,
        path: str,
        **kwargs: object,
    ) -> dict[str, object]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"asset_id": "asset-id", "classification": "OWNED"}

    monkeypatch.setattr(ApiClient, "request", request)  # type: ignore[attr-defined]
    result = runner.invoke(
        cli_module.app,
        [
            "network",
            "classify",
            "project-id",
            "asset-id",
            "--classification",
            "owned",
            "--reason",
            "Verified allocation record",
            "--json",
        ],
    )
    assert result.exit_code == 0
    assert captured["path"] == "/api/v1/projects/project-id/ips/asset-id"
    assert captured["json"] == {
        "classification": "OWNED",
        "reason": "Verified allocation record",
    }
