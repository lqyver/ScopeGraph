"""Loopback-only Phase 2 acceptance smoke for Docker Compose and CI."""

import http.client
import json
import time
from typing import Any
from uuid import uuid4


def request(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=10)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"content-type": "application/json"} if body is not None else {}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    return response.status, json.loads(raw) if raw else None


def wait_for_run(scan_run_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status, run = request("GET", f"/api/v1/scan-runs/{scan_run_id}")
        assert status == 200, run
        if run["status"] in {
            "SUCCESS",
            "PARTIAL_SUCCESS",
            "FAILED",
            "TIMEOUT",
            "CANCELLED",
            "SKIPPED",
        }:
            return run
        time.sleep(0.2)
    raise AssertionError("Scan run did not reach a terminal state within 30 seconds")


def main() -> None:
    suffix = uuid4().hex[:8]
    project_name = f"CI Phase 2 {suffix}"
    status, project = request(
        "POST",
        "/api/v1/projects",
        {
            "name": project_name,
            "company_name": "CI Example Ltd.",
            "authorization_confirmed": True,
            "known_root_domains": ["example.com"],
            "default_scan_profile": "standard",
        },
    )
    assert status == 201, project
    project_id = project["id"]
    scan_payload = {
        "root_domain": "example.com",
        "profile": "custom",
        "execution_mode": "fixture",
        "authorization_confirmed": True,
        "allow_active_execution": False,
        "custom_config": {
            "passive_subdomain": True,
            "dns_enrichment": True,
            "http_probe": True,
            "port_scan_enabled": False,
            "screenshot_enabled": False,
        },
    }

    status, first = request("POST", f"/api/v1/projects/{project_id}/scan-runs", scan_payload)
    assert status == 202, first
    first_run = wait_for_run(first["id"])
    assert first_run["status"] == "SUCCESS", first_run
    assert first_run["progress"] == 100

    status, jobs = request("GET", f"/api/v1/scan-runs/{first['id']}/jobs")
    assert status == 200
    assert [(job["sequence"], job["adapter_name"]) for job in jobs] == [
        (0, "subfinder"),
        (1, "dnsx"),
        (2, "httpx"),
    ]
    assert all(job["status"] == "SUCCESS" for job in jobs)
    assert all(job["stdout_path"] for job in jobs)

    status, second = request("POST", f"/api/v1/projects/{project_id}/scan-runs", scan_payload)
    assert status == 202, second
    second_run = wait_for_run(second["id"])
    assert second_run["status"] == "SUCCESS", second_run
    assert second_run["summary"]["assets_created"] == 0
    assert second_run["summary"]["observations_created"] == 9

    status, denied = request(
        "POST",
        f"/api/v1/projects/{project_id}/scan-runs",
        {**scan_payload, "root_domain": "outside.example.net"},
    )
    assert status == 403, denied
    assert denied["error"]["code"] == "SCOPE_VIOLATION"

    status, tools = request("GET", "/api/v1/system/tools")
    assert status == 200, tools
    assert len(tools) == 10
    assert all(tool["installed"] and tool["compatible"] for tool in tools), tools

    status, _ = request(
        "DELETE",
        f"/api/v1/projects/{project_id}",
        {"confirmation": project_name},
    )
    assert status == 204
    print(
        json.dumps(
            {
                "first_run": first_run["status"],
                "jobs": [job["adapter_name"] for job in jobs],
                "out_of_scope": "denied",
                "compatible_tools": len(tools),
                "second_run_assets_created": second_run["summary"]["assets_created"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
