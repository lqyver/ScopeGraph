"""Loopback-only Phase 3 acceptance smoke; every tool execution uses recorded fixtures."""

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


def create_run(project_id: str, **overrides: Any) -> tuple[int, Any]:
    payload = {
        "root_domain": "example.com",
        "profile": "standard",
        "execution_mode": "fixture",
        "authorization_confirmed": True,
        "allow_active_execution": False,
    } | overrides
    return request("POST", f"/api/v1/projects/{project_id}/scan-runs", payload)


def main() -> None:
    suffix = uuid4().hex[:8]
    project_name = f"CI Phase 3 {suffix}"
    status, project = request(
        "POST",
        "/api/v1/projects",
        {
            "name": project_name,
            "company_name": "CI Network Example Ltd.",
            "authorization_confirmed": True,
            "known_root_domains": ["example.com"],
            "default_scan_profile": "standard",
        },
    )
    assert status == 201, project
    project_id = project["id"]
    status, standard = create_run(project_id)
    assert status == 202, standard
    completed = wait_for_run(standard["id"])
    assert completed["status"] == "SUCCESS", completed
    assert completed["config_snapshot"]["chain"] == [
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
    assert completed["config_snapshot"]["profile"]["dns_wordlist_limit"] == 5000

    status, jobs = request("GET", f"/api/v1/scan-runs/{standard['id']}/jobs")
    assert status == 200, jobs
    assert all(job["status"] == "SUCCESS" for job in jobs), jobs
    naabu = next(job for job in jobs if job["adapter_name"] == "naabu")
    nmap = next(job for job in jobs if job["adapter_name"] == "nmap")
    assert naabu["input_ref"]["ports"] == [80, 443, 8080, 8443]
    assert naabu["result_summary"]["authorized_dns_derived_ips"] == 2
    assert naabu["result_summary"]["scan_targets"] == 1
    assert naabu["result_summary"]["ports_tested_per_target"] == 4
    assert naabu["result_summary"]["candidate_socket_checks"] == 4
    assert nmap["input_ref"]["targets"] == [{"ip": "93.184.216.34", "ports": [80, 443]}]

    status, ips = request("GET", f"/api/v1/projects/{project_id}/ips")
    assert status == 200, ips
    owned_candidate = next(item for item in ips if item["ip"] == "93.184.216.34")
    cdn = next(item for item in ips if item["ip"] == "93.184.216.35")
    assert owned_candidate["classification"] == "UNKNOWN"
    assert cdn["classification"] == "CDN_WAF"

    status, ports = request(
        "GET", f"/api/v1/projects/{project_id}/ports?scan_run_id={standard['id']}"
    )
    assert status == 200, ports
    assert {(item["port"], item["service"]["name"]) for item in ports} == {
        (80, "http"),
        (443, "https"),
    }

    status, disabled = create_run(project_id, port_scan_enabled=False)
    assert status == 202, disabled
    assert wait_for_run(disabled["id"])["status"] == "SUCCESS"
    status, disabled_jobs = request("GET", f"/api/v1/scan-runs/{disabled['id']}/jobs")
    assert status == 200
    assert "naabu" not in {job["adapter_name"] for job in disabled_jobs}
    assert "nmap" not in {job["adapter_name"] for job in disabled_jobs}

    status, missing_confirmation = create_run(project_id, full_port_scan=True)
    assert status == 422, missing_confirmation
    status, not_owned = create_run(project_id, full_port_scan=True, full_port_confirmation=True)
    assert status == 202, not_owned
    assert wait_for_run(not_owned["id"])["status"] == "PARTIAL_SUCCESS"
    status, not_owned_jobs = request("GET", f"/api/v1/scan-runs/{not_owned['id']}/jobs")
    assert status == 200
    assert (
        next(job for job in not_owned_jobs if job["adapter_name"] == "naabu")["error_code"]
        == "NO_POLICY_APPROVED_INPUTS"
    )

    status, ip_scope = request(
        "POST",
        f"/api/v1/projects/{project_id}/scope-rules",
        {"rule_type": "IP", "value": "93.184.216.34", "action": "INCLUDE"},
    )
    assert status == 201, ip_scope

    status, classified = request(
        "PATCH",
        f"/api/v1/projects/{project_id}/ips/{owned_candidate['asset_id']}",
        {"classification": "OWNED", "reason": "Explicitly verified CI fixture ownership"},
    )
    assert status == 200, classified
    assert classified["classification"] == "OWNED"

    status, full = create_run(project_id, full_port_scan=True, full_port_confirmation=True)
    assert status == 202, full
    assert wait_for_run(full["id"])["status"] == "SUCCESS"
    status, full_jobs = request("GET", f"/api/v1/scan-runs/{full['id']}/jobs")
    assert status == 200
    full_naabu = next(job for job in full_jobs if job["adapter_name"] == "naabu")
    assert full_naabu["input_ref"]["full_port_scan"] is True
    assert full_naabu["input_ref"]["ports"] == []

    status, _ = request(
        "DELETE",
        f"/api/v1/projects/{project_id}",
        {"confirmation": project_name},
    )
    assert status == 204
    print(
        json.dumps(
            {
                "chain": completed["config_snapshot"]["chain"],
                "full_port_after_owned_confirmation": "allowed",
                "full_port_before_owned_confirmation": "denied",
                "ports_with_services": len(ports),
                "port_scan_disabled": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
