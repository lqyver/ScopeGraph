"""Loopback-only Phase 6 Nuclei, history, and export acceptance smoke."""

import http.client
import json
import os
import time
from io import BytesIO
from typing import Any
from uuid import uuid4
from zipfile import ZipFile

API_PORT = int(os.getenv("SCOPEGRAPH_API_HOST_PORT", "18000"))


def request_raw(
    method: str, path: str, payload: dict[str, Any] | None = None
) -> tuple[int, str, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", API_PORT, timeout=20)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"content-type": "application/json"} if body is not None else {}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    content_type = response.getheader("content-type") or ""
    connection.close()
    return response.status, content_type, raw


def request(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    status, _, raw = request_raw(method, path, payload)
    return status, json.loads(raw) if raw else None


def wait_for_run(run_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        status, run = request("GET", f"/api/v1/scan-runs/{run_id}")
        assert status == 200, run
        if run["status"] in {"SUCCESS", "PARTIAL_SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"}:
            return run
        time.sleep(0.2)
    raise AssertionError("Phase 6 scan did not finish within 45 seconds")


def create_run(project_id: str, *, nuclei: bool) -> dict[str, Any]:
    status, run = request(
        "POST",
        f"/api/v1/projects/{project_id}/scan-runs",
        {
            "root_domain": "example.com",
            "profile": "standard",
            "execution_mode": "fixture",
            "authorization_confirmed": True,
            "allow_active_execution": False,
            "nuclei_enabled": nuclei,
            "nuclei_confirmation": nuclei,
        },
    )
    assert status == 202, run
    return wait_for_run(run["id"])


def create_nuclei_only_run(project_id: str) -> dict[str, Any]:
    status, run = request(
        "POST",
        f"/api/v1/projects/{project_id}/scan-runs",
        {
            "root_domain": "example.com",
            "profile": "custom",
            "execution_mode": "fixture",
            "authorization_confirmed": True,
            "allow_active_execution": False,
            "nuclei_enabled": True,
            "nuclei_confirmation": True,
            "custom_config": {
                "passive_subdomain": False,
                "dns_enrichment": False,
                "http_probe": False,
                "screenshot_enabled": False,
                "nuclei_allowed": True,
            },
        },
    )
    assert status == 202, run
    return wait_for_run(run["id"])


def main() -> None:
    suffix = uuid4().hex[:8]
    project_name = f"CI Phase 6 {suffix}"
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

        status, unsafe = request(
            "POST",
            f"/api/v1/projects/{project_id}/scan-runs",
            {
                "root_domain": "example.com",
                "profile": "standard",
                "execution_mode": "fixture",
                "authorization_confirmed": True,
                "nuclei_enabled": True,
                "nuclei_confirmation": False,
            },
        )
        assert status == 422, unsafe

        first = create_run(project_id, nuclei=True)
        assert first["status"] == "SUCCESS", first
        assert first["config_snapshot"]["chain"][-1] == "nuclei"
        status, jobs = request("GET", f"/api/v1/scan-runs/{first['id']}/jobs")
        assert status == 200
        nuclei_job = next(item for item in jobs if item["adapter_name"] == "nuclei")
        assert nuclei_job["status"] == "SUCCESS"
        assert nuclei_job["result_summary"]["observations_parsed"] == 1

        # Operators can rerun only Nuclei against the project's current live website inventory.
        nuclei_only = create_nuclei_only_run(project_id)
        assert nuclei_only["status"] == "SUCCESS", nuclei_only
        status, nuclei_only_jobs = request("GET", f"/api/v1/scan-runs/{nuclei_only['id']}/jobs")
        assert status == 200
        assert [(item["adapter_name"], item["status"]) for item in nuclei_only_jobs] == [
            ("nuclei", "SUCCESS")
        ]
        assert nuclei_only_jobs[0]["input_ref"]["urls"]

        status, host_findings = request("GET", f"/api/v1/projects/{project_id}/findings")
        assert status == 200 and host_findings == [], host_findings
        status, findings = request(
            "GET", f"/api/v1/projects/{project_id}/findings?execution_mode=fixture"
        )
        assert status == 200 and len(findings) == 1, findings
        finding = findings[0]
        assert finding["status"] == "UNVERIFIED"
        assert finding["severity"] == "low"
        assert finding["evidence"]["confidence"] == 0.5
        status, reviewed = request(
            "POST",
            f"/api/v1/findings/{finding['id']}/review",
            {"status": "POTENTIAL", "reason": "Acceptance test manual review"},
        )
        assert status == 200 and reviewed["status"] == "POTENTIAL"

        second = create_run(project_id, nuclei=False)
        assert second["status"] == "SUCCESS"
        status, diff = request(
            "GET",
            f"/api/v1/projects/{project_id}/diff?from={first['id']}&to={second['id']}",
        )
        assert status == 200, diff
        assert any(item["category"] == "finding" for item in diff["removed"])

        export_results: dict[str, int] = {}
        expected_sheets = {
            "项目总览",
            "根域名",
            "子域名",
            "IP资产",
            "端口服务",
            "Web网站",
            "备案信息",
            "第三方服务",
            "待审核资产",
            "安全发现",
            "扫描历史",
        }
        for export_format in ("xlsx", "csv", "json", "html", "markdown"):
            status, artifact = request(
                "POST",
                f"/api/v1/projects/{project_id}/exports",
                {
                    "export_format": export_format,
                    "export_scope": "all-candidates",
                    "execution_mode": "fixture",
                },
            )
            assert status == 201 and artifact["status"] == "SUCCESS", artifact
            assert set(artifact["row_counts"]) == expected_sheets
            download_status, content_type, body = request_raw(
                "GET", f"/api/v1/exports/{artifact['id']}/download"
            )
            assert download_status == 200 and body
            if export_format == "xlsx":
                assert "spreadsheetml" in content_type
                with ZipFile(BytesIO(body)) as workbook:
                    xml = workbook.read("xl/workbook.xml").decode()
                    assert all(name in xml for name in expected_sheets)
            elif export_format == "csv":
                with ZipFile(BytesIO(body)) as archive:
                    assert {
                        name.removesuffix(".csv") for name in archive.namelist()
                    } == expected_sheets
            elif export_format == "json":
                assert set(json.loads(body)) == expected_sheets
            export_results[export_format] = len(body)

        status, not_confirmed = request(
            "POST",
            "/api/v1/system/storage/cleanup",
            {"raw_artifacts": True, "exports": False, "older_than_days": 30, "confirmation": False},
        )
        assert status == 409, not_confirmed

        print(
            json.dumps(
                {
                    "diff": diff["counts"],
                    "export_bytes": export_results,
                    "finding_status": reviewed["status"],
                    "nuclei_default_safe": unsafe["error"]["code"],
                    "worksheets": len(expected_sheets),
                },
                ensure_ascii=False,
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
