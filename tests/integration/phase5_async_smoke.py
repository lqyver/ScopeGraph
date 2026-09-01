"""Loopback-only acceptance for observable asynchronous enterprise discovery."""

import http.client
import json
import os
import time
from typing import Any
from uuid import uuid4

API_PORT = int(os.getenv("SCOPEGRAPH_API_HOST_PORT", "18000"))


def request(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", API_PORT, timeout=15)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"content-type": "application/json"} if body is not None else {}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    return response.status, json.loads(raw) if raw else None


def main() -> None:
    suffix = uuid4().hex[:8]
    project_name = f"CI Phase 5 async {suffix}"
    status, project = request(
        "POST",
        "/api/v1/projects",
        {
            "name": project_name,
            "company_name": "示例科技有限公司",
            "authorization_confirmed": True,
            "known_root_domains": [],
            "default_scan_profile": "standard",
        },
    )
    assert status == 201, project
    project_id = project["id"]
    try:
        status, queued = request(
            "POST",
            f"/api/v1/projects/{project_id}/enterprise-discovery",
            {"execution_mode": "fixture", "aliases": [], "async_execution": True},
        )
        assert status == 202, queued
        assert queued["status"] == "RUNNING", queued
        assert queued["summary"]["stage"] == "QUEUED", queued
        assert {item["source"] for item in queued["source_results"]} == {
            "local-scope",
            "recorded-public-search",
        }
        run_id = queued["id"]

        deadline = time.monotonic() + 20
        observed_stages = {queued["summary"]["stage"]}
        while time.monotonic() < deadline:
            status, run = request(
                "GET",
                f"/api/v1/projects/{project_id}/enterprise-discovery/{run_id}",
            )
            assert status == 200, run
            observed_stages.add(run["summary"]["stage"])
            if run["status"] != "RUNNING":
                break
            time.sleep(0.1)
        else:
            raise AssertionError("Async enterprise discovery did not finish within 20 seconds")

        assert run["status"] == "SUCCESS", run
        assert run["summary"]["progress_percent"] == 100, run
        assert run["summary"]["candidate_count"] == 1, run
        assert {item["status"] for item in run["source_results"]} == {"COMPLETED"}
        assert "QUEUED" in observed_stages

        print(
            json.dumps(
                {
                    "status": run["status"],
                    "progress": run["summary"]["progress_percent"],
                    "source_count": run["summary"]["source_count"],
                    "observed_stages": sorted(observed_stages),
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
