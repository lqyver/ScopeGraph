"""Loopback-only Phase 4 acceptance smoke; all tool executions use recorded fixtures."""

import http.client
import json
import os
import time
from typing import Any
from uuid import uuid4

API_PORT = int(os.getenv("SCOPEGRAPH_API_HOST_PORT", "18000"))


def request(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", API_PORT, timeout=10)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"content-type": "application/json"} if body is not None else {}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    return response.status, json.loads(raw) if raw else None


def request_bytes(path: str) -> tuple[int, str, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", API_PORT, timeout=10)
    connection.request("GET", path)
    response = connection.getresponse()
    body = response.read()
    content_type = response.getheader("content-type") or ""
    connection.close()
    return response.status, content_type, body


def wait_for_run(scan_run_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 45
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
    raise AssertionError("Phase 4 scan did not reach a terminal state within 45 seconds")


def create_fixture_run(project_id: str) -> dict[str, Any]:
    status, run = request(
        "POST",
        f"/api/v1/projects/{project_id}/scan-runs",
        {
            "root_domain": "example.com",
            "profile": "standard",
            "execution_mode": "fixture",
            "authorization_confirmed": True,
            "allow_active_execution": False,
        },
    )
    assert status == 202, run
    return wait_for_run(run["id"])


def main() -> None:
    suffix = uuid4().hex[:8]
    project_name = f"CI Phase 4 {suffix}"
    status, project = request(
        "POST",
        "/api/v1/projects",
        {
            "name": project_name,
            "company_name": "Example Corporation",
            "authorization_confirmed": True,
            "known_root_domains": ["example.com"],
            "default_scan_profile": "standard",
        },
    )
    assert status == 201, project
    project_id = project["id"]
    try:
        status, ip_scope = request(
            "POST",
            f"/api/v1/projects/{project_id}/scope-rules",
            {"rule_type": "IP", "value": "93.184.216.34", "action": "INCLUDE"},
        )
        assert status == 201, ip_scope

        first_run = create_fixture_run(project_id)
        assert first_run["status"] == "SUCCESS", first_run
        expected_chain = [
            "subfinder",
            "puredns",
            "alterx",
            "puredns",
            "dnsx",
            "naabu",
            "nmap",
            "httpx",
            "screenshot",
            "katana",
        ]
        assert first_run["config_snapshot"]["chain"] == expected_chain
        status, jobs = request("GET", f"/api/v1/scan-runs/{first_run['id']}/jobs")
        assert status == 200, jobs
        assert all(job["status"] == "SUCCESS" for job in jobs), jobs

        status, host_websites = request("GET", f"/api/v1/projects/{project_id}/websites")
        assert status == 200 and host_websites["total"] == 0, host_websites
        status, websites = request(
            "GET", f"/api/v1/projects/{project_id}/websites?execution_mode=fixture"
        )
        assert status == 200, websites
        assert websites["total"] == 2, websites
        by_url = {item["url"]: item for item in websites["items"]}
        api = by_url["https://api.example.com/"]
        www = by_url["https://www.example.com/"]
        # A JSON API is not a filing-bearing page; do not spread a website filing to it.
        assert api["icp_status"] == "NOT_APPLICABLE"
        assert www["icp_status"] == "PAGE_DIRECT"
        assert api["screenshot_path"] is None
        assert www["screenshot_path"].endswith("/screenshots/www.example.com.svg")
        assert www["cdn_waf"] == ["vercel"]
        image_status, image_type, image_body = request_bytes(
            f"/api/v1/websites/{www['id']}/screenshot?execution_mode=fixture"
        )
        assert image_status == 200
        assert image_type.startswith("image/svg+xml")
        assert image_body.startswith(b"<svg")

        status, detail = request(
            "GET", f"/api/v1/websites/{www['id']}?execution_mode=fixture"
        )
        assert status == 200, detail
        assert detail["snapshot"]["response_time_ms"] == 350.0
        assert "set-cookie" not in detail["snapshot"]["response_headers"]
        assert detail["snapshot"]["response_headers"]["strict-transport-security"]
        assert {item["name"] for item in detail["technology_details"]} == {
            "Next.js",
            "React",
        }
        assert len(detail["certificates"]) == 1
        assert detail["certificates"][0]["fingerprint_sha256"] == "d" * 64
        assert {item["association_status"] for item in detail["filing_links"]} == {"PAGE_DIRECT"}

        status, filings = request(
            "GET", f"/api/v1/projects/{project_id}/icp-records?execution_mode=fixture"
        )
        assert status == 200, filings
        assert {item["record_kind"] for item in filings} == {"ICP", "PUBLIC_SECURITY"}
        for record in filings:
            associations = {
                website["url"]: website["association_status"] for website in record["websites"]
            }
            assert associations["https://www.example.com/"] == "PAGE_DIRECT"
            assert "https://api.example.com/" not in associations

        status, endpoints = request(
            "GET",
            f"/api/v1/projects/{project_id}/endpoints?scan_run_id={first_run['id']}"
            "&execution_mode=fixture",
        )
        assert status == 200, endpoints
        assert len(endpoints) == 5
        endpoint_by_url = {item["normalized_url"]: item for item in endpoints}
        external = endpoint_by_url["https://vendor.example.net/help"]
        assert external["kind"] == "EXTERNAL_LINK"
        assert external["scope_status"] == "PENDING_REVIEW"
        assert external["actively_visited"] is False
        post = endpoint_by_url["https://www.example.com/api/v1/payment"]
        assert post["method"] == "POST" and post["actively_visited"] is False

        # The operator view must keep each domain's ports and technologies together.
        status, surface = request(
            "GET",
            f"/api/v1/projects/{project_id}/attack-surface?page=1&page_size=100"
            "&execution_mode=fixture",
        )
        assert status == 200, surface
        by_domain = {item["domain"]: item for item in surface["items"]}
        api_surface = by_domain["api.example.com"]
        www_surface = by_domain["www.example.com"]
        assert {port["port"] for port in api_surface["ports"]} == {80, 443}
        assert {"nginx 1.25", "OpenResty"}.issubset(set(api_surface["technologies"]))
        assert {"Next.js 15.1", "React"}.issubset(set(www_surface["technologies"]))
        assert surface["summary"]["open_ports"] == 2

        status, assets = request(
            "GET", f"/api/v1/projects/{project_id}/assets?page=1&page_size=100"
        )
        assert status == 200, assets
        asset_by_value = {item["normalized_value"]: item for item in assets["items"]}
        assert asset_by_value["example.net"]["scope_status"] == "PENDING_REVIEW"
        assert asset_by_value["vendor.example.net"]["scope_status"] == "PENDING_REVIEW"
        assert asset_by_value["d111.cloudfront.net"]["scope_status"] == "CDN_SHARED"
        assert asset_by_value["d111.cloudfront.net"]["ownership_status"] == "THIRD_PARTY"

        # A second run must create history, not duplicate project-level websites or filings.
        second_run = create_fixture_run(project_id)
        assert second_run["status"] == "SUCCESS", second_run
        status, websites_after = request(
            "GET", f"/api/v1/projects/{project_id}/websites?execution_mode=fixture"
        )
        assert status == 200 and websites_after["total"] == 2
        status, filings_after = request(
            "GET", f"/api/v1/projects/{project_id}/icp-records?execution_mode=fixture"
        )
        assert status == 200 and len(filings_after) == 2

        print(
            json.dumps(
                {
                    "chain": expected_chain,
                    "endpoints": len(endpoints),
                    "filings": len(filings),
                    "attack_surface_domains": surface["total"],
                    "screenshot_failure_isolated": api["screenshot_path"] is None,
                    "websites": websites["total"],
                },
                sort_keys=True,
            )
        )
    finally:
        status, deleted = request(
            "DELETE",
            f"/api/v1/projects/{project_id}",
            {"confirmation": project_name},
        )
        assert status == 204, deleted


if __name__ == "__main__":
    main()
