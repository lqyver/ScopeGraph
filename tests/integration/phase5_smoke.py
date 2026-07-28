"""Loopback-only Phase 5 enterprise discovery and review acceptance smoke."""

import http.client
import json
from typing import Any
from uuid import uuid4


def request(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=15)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"content-type": "application/json"} if body is not None else {}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    return response.status, json.loads(raw) if raw else None


def main() -> None:
    suffix = uuid4().hex[:8]
    project_name = f"CI Phase 5 {suffix}"
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
        # Company-name-only local discovery must fail explicitly rather than inventing assets.
        status, local_run = request(
            "POST",
            f"/api/v1/projects/{project_id}/enterprise-discovery",
            {"execution_mode": "local", "aliases": []},
        )
        assert status == 201, local_run
        assert local_run["status"] == "FAILED"
        assert local_run["summary"]["failure_reason"] == "NO_CANDIDATE_ROOTS"

        # Recorded public evidence gives a deterministic company-name-only acceptance path.
        status, discovery = request(
            "POST",
            f"/api/v1/projects/{project_id}/enterprise-discovery",
            {"execution_mode": "fixture", "aliases": []},
        )
        assert status == 201, discovery
        assert discovery["status"] == "SUCCESS"
        assert discovery["summary"]["candidate_count"] == 1
        assert discovery["summary"]["source_completed_count"] == 2
        assert discovery["summary"]["source_attempted_count"] == 2
        assert discovery["summary"]["source_successful_request_count"] == 2
        assert {item["status"] for item in discovery["source_results"]} == {"COMPLETED"}

        status, candidates = request("GET", f"/api/v1/projects/{project_id}/candidate-root-domains")
        assert status == 200, candidates
        assert len(candidates) == 1
        candidate = candidates[0]
        assert candidate["root_domain"] == "example.com"
        assert candidate["raw_score"] == 35
        assert candidate["status"] == "PENDING_REVIEW"
        assert {item["evidence_type"] for item in candidate["evidence"]} == {
            "OFFICIAL_DIRECT_LINK",
            "BRAND_NAME_MATCH",
            "MULTI_SOURCE",
        }

        # Rerun evidence is idempotent.
        status, rerun = request(
            "POST",
            f"/api/v1/projects/{project_id}/enterprise-discovery",
            {"execution_mode": "fixture", "aliases": []},
        )
        assert status == 201 and rerun["status"] == "SUCCESS"
        status, after_rerun = request(
            "GET", f"/api/v1/projects/{project_id}/candidate-root-domains"
        )
        assert status == 200 and len(after_rerun[0]["evidence"]) == 3

        # Manual add-to-scope is explicit and overrides later automatic scoring.
        status, reviewed = request(
            "POST",
            f"/api/v1/projects/{project_id}/candidate-root-domains/{candidate['id']}/review",
            {
                "decision": "ADD_TO_SCOPE",
                "reason": "Acceptance test verified enterprise ownership",
            },
        )
        assert status == 200, reviewed
        assert reviewed["status"] == "CONFIRMED"
        status, scope_rules = request("GET", f"/api/v1/projects/{project_id}/scope-rules")
        assert status == 200
        assert any(
            item["rule_type"] == "ROOT_DOMAIN"
            and item["value"] == "example.com"
            and item["action"] == "INCLUDE"
            for item in scope_rules
        )
        status, post_override = request(
            "POST",
            f"/api/v1/projects/{project_id}/enterprise-discovery",
            {"execution_mode": "fixture", "aliases": []},
        )
        assert status == 201, post_override
        status, confirmed = request("GET", f"/api/v1/projects/{project_id}/candidate-root-domains")
        assert confirmed[0]["status"] == "CONFIRMED"

        # Task state remains independent from process coverage.
        status, coverage = request("GET", f"/api/v1/projects/{project_id}/coverage")
        assert status == 200, coverage
        assert coverage["task_status"] == "NOT_STARTED"
        assert coverage["task_completed"] is False
        assert coverage["coverage_score"] > 0
        assert coverage["blind_spots"]

        print(
            json.dumps(
                {
                    "candidate": confirmed[0]["root_domain"],
                    "coverage": coverage["coverage_score"],
                    "explicit_failure": local_run["summary"]["failure_reason"],
                    "manual_override": confirmed[0]["status"],
                    "persisted_evidence": len(confirmed[0]["evidence"]),
                    "task_status": coverage["task_status"],
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
