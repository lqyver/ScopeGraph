"""Loopback-only Phase 7 release, settings, proxy, and UI acceptance smoke."""

import http.client
import json
import os
import time
from typing import Any
from uuid import uuid4

API_PORT = int(os.getenv("SCOPEGRAPH_API_HOST_PORT", "18000"))
WEB_PORT = int(os.getenv("SCOPEGRAPH_WEB_HOST_PORT", "18080"))


def request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    port: int = API_PORT,
) -> tuple[int, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"content-type": "application/json"} if body is not None else {}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    content_type = response.getheader("content-type") or ""
    connection.close()
    if "application/json" in content_type:
        return response.status, json.loads(raw) if raw else None
    return response.status, raw.decode("utf-8", errors="replace")


def wait_for_run(run_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        status, run = request("GET", f"/api/v1/scan-runs/{run_id}")
        assert status == 200, run
        if run["status"] in {"SUCCESS", "PARTIAL_SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"}:
            return run
        time.sleep(0.2)
    raise AssertionError("Phase 7 proxy fixture scan did not finish within 45 seconds")


def main() -> None:
    status, health = request("GET", "/health")
    assert status == 200 and health["status"] == "healthy", health

    status, tools = request("GET", "/api/v1/system/tools")
    assert status == 200 and len(tools) == 10, tools
    assert all(item["automatic_update"] is False for item in tools)

    status, denied_update = request(
        "POST", "/api/v1/system/tools/httpx/update", {"confirmation": False}
    )
    assert status == 409 and denied_update["error"]["code"] == "TOOL_UPDATE_CONFIRMATION_REQUIRED"
    status, update = request("POST", "/api/v1/system/tools/httpx/update", {"confirmation": True})
    assert status == 200 and update["update_performed"] is False
    assert update["manual_required"] is True

    status, invalid_proxy = request(
        "PATCH",
        "/api/v1/system/settings",
        {"proxy_url": "http://user:secret@127.0.0.1:8080"},
    )
    assert status == 422, invalid_proxy
    proxy = "http://127.0.0.1:18080"
    status, settings = request("PATCH", "/api/v1/system/settings", {"proxy_url": proxy})
    assert status == 200 and settings["proxy_url"] == proxy, settings
    assert settings["proxy_credentials_supported"] is False
    assert settings["public_bind"] is False

    suffix = uuid4().hex[:8]
    project_name = f"CI Phase 7 {suffix}"
    status, project = request(
        "POST",
        "/api/v1/projects",
        {
            "name": project_name,
            "company_name": "Phase 7 Compatibility",
            "authorization_confirmed": True,
            "known_root_domains": ["example.com"],
            "default_scan_profile": "quick",
        },
    )
    assert status == 201, project
    project_id = project["id"]

    status, missing_deep_confirmation = request(
        "POST",
        f"/api/v1/projects/{project_id}/scan-runs",
        {
            "root_domain": "example.com",
            "profile": "deep",
            "execution_mode": "fixture",
            "authorization_confirmed": True,
        },
    )
    assert status == 422, missing_deep_confirmation
    status, deep_queued = request(
        "POST",
        f"/api/v1/projects/{project_id}/scan-runs",
        {
            "root_domain": "example.com",
            "profile": "deep",
            "deep_confirmation": True,
            "execution_mode": "fixture",
            "authorization_confirmed": True,
        },
    )
    assert status == 202, deep_queued
    deep_run = wait_for_run(deep_queued["id"])
    assert deep_run["status"] in {"SUCCESS", "PARTIAL_SUCCESS"}, deep_run

    status, custom_rejected = request(
        "POST",
        f"/api/v1/projects/{project_id}/scan-runs",
        {
            "root_domain": "example.com",
            "profile": "custom",
            "execution_mode": "fixture",
            "authorization_confirmed": True,
            "custom_config": {"shell_command": "nmap -A"},
        },
    )
    assert status == 422, custom_rejected
    status, custom_queued = request(
        "POST",
        f"/api/v1/projects/{project_id}/scan-runs",
        {
            "root_domain": "example.com",
            "profile": "custom",
            "execution_mode": "fixture",
            "authorization_confirmed": True,
            "custom_config": {
                "passive_subdomain": True,
                "dns_enrichment": True,
                "port_scan_enabled": False,
                "http_probe": True,
                "screenshot_enabled": False,
            },
        },
    )
    assert status == 202, custom_queued
    custom_run = wait_for_run(custom_queued["id"])
    assert custom_run["status"] in {"SUCCESS", "PARTIAL_SUCCESS"}, custom_run
    status, queued = request(
        "POST",
        f"/api/v1/projects/{project_id}/scan-runs",
        {
            "root_domain": "example.com",
            "profile": "quick",
            "execution_mode": "fixture",
            "authorization_confirmed": True,
            "allow_active_execution": False,
            "proxy_url": proxy,
        },
    )
    assert status == 202, queued
    run = wait_for_run(queued["id"])
    assert run["status"] in {"SUCCESS", "PARTIAL_SUCCESS"}, run
    assert run["config_snapshot"]["proxy_url"] == proxy

    status, storage = request("GET", "/api/v1/system/storage")
    assert status == 200 and storage["file_count"] >= 1, storage
    status, denied_cleanup = request(
        "POST",
        "/api/v1/system/storage/cleanup",
        {
            "raw_artifacts": True,
            "exports": False,
            "older_than_days": 0,
            "confirmation": False,
        },
    )
    assert status == 409, denied_cleanup

    for path in ("/", "/system", f"/projects/{project_id}/security"):
        ui_status, html = request("GET", path, port=WEB_PORT)
        assert ui_status == 200, (path, ui_status)
        assert "ScopeGraph" in html, path

    status, reset = request("PATCH", "/api/v1/system/settings", {"proxy_url": None})
    assert status == 200 and reset["proxy_url"] is None
    status, deleted = request(
        "DELETE",
        f"/api/v1/projects/{project_id}",
        {"confirmation": project_name},
    )
    assert status == 204, deleted

    print(
        json.dumps(
            {
                "api": health["status"],
                "tools": len(tools),
                "automatic_updates": False,
                "proxy_scan": run["status"],
                "deep_scan": deep_run["status"],
                "custom_scan": custom_run["status"],
                "public_bind": settings["public_bind"],
                "ui_routes": 3,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
