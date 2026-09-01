"""Queue a fixture scan while the worker is stopped, then verify restart recovery."""

import http.client
import json
import os
import sys
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


def queue() -> None:
    suffix = uuid4().hex[:8]
    status, project = request(
        "POST",
        "/api/v1/projects",
        {
            "name": f"CI restart recovery {suffix}",
            "company_name": "Restart Recovery Fixture",
            "authorization_confirmed": True,
            "known_root_domains": ["example.com"],
            "default_scan_profile": "quick",
        },
    )
    assert status == 201, project
    status, run = request(
        "POST",
        f"/api/v1/projects/{project['id']}/scan-runs",
        {
            "root_domain": "example.com",
            "profile": "quick",
            "execution_mode": "fixture",
            "authorization_confirmed": True,
            "allow_active_execution": False,
        },
    )
    assert status == 202 and run["status"] == "QUEUED", run
    print(run["id"])


def wait(run_id: str) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status, run = request("GET", f"/api/v1/scan-runs/{run_id}")
        assert status == 200, run
        if run["status"] in {"SUCCESS", "PARTIAL_SUCCESS"}:
            print(json.dumps({"run_id": run_id, "recovered_status": run["status"]}))
            return
        if run["status"] in {"FAILED", "TIMEOUT", "CANCELLED"}:
            raise AssertionError(run)
        time.sleep(0.25)
    raise AssertionError("Queued scan was not recovered within 60 seconds after worker restart")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "queue":
        queue()
    elif len(sys.argv) == 3 and sys.argv[1] == "wait":
        wait(sys.argv[2])
    else:
        raise SystemExit("usage: restart_recovery.py queue | wait RUN_ID")
