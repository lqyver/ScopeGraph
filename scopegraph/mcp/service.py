import asyncio
from collections.abc import Awaitable
from typing import Any, Literal, Protocol
from uuid import UUID

from scopegraph.mcp.client import ScopeGraphApiClient
from scopegraph.normalizers.assets import registrable_root_domain

AssetTypeName = Literal[
    "company", "domain", "ip", "cidr", "url", "service", "certificate", "icp_record"
]
ScopeStatusName = Literal[
    "IN_SCOPE",
    "OUT_OF_SCOPE",
    "EXCLUDED",
    "PENDING_REVIEW",
    "THIRD_PARTY",
    "CDN_SHARED",
    "UNKNOWN",
]
CollectionProfile = Literal["quick", "standard"]
ExecutionMode = Literal["host", "fixture"]


class ApiTransport(Protocol):
    async def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any: ...


class McpSafetyError(RuntimeError):
    """Raised when an Agent request crosses the MCP safety boundary."""


def _uuid(value: str, field: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid UUID") from exc


def _bounded(value: int, *, minimum: int = 1, maximum: int = 200) -> int:
    if value < minimum or value > maximum:
        raise ValueError(f"value must be between {minimum} and {maximum}")
    return value


def _object_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("ScopeGraph API returned an unexpected non-object response")
    return value


def _compact_job(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "UNKNOWN", "error_message": "Malformed job response"}
    input_ref = value.get("input_ref")
    input_summary: dict[str, Any] = {}
    if isinstance(input_ref, dict):
        for key, item in input_ref.items():
            if isinstance(item, list):
                input_summary[f"{key}_count"] = len(item)
            elif key in {
                "root_domain",
                "rate",
                "concurrency",
                "timeout_seconds",
                "max_redirects",
            }:
                input_summary[key] = item
    return {
        key: value.get(key)
        for key in (
            "id",
            "sequence",
            "job_type",
            "adapter_name",
            "status",
            "attempt",
            "max_attempts",
            "timeout_seconds",
            "started_at",
            "finished_at",
            "error_code",
            "error_message",
            "result_summary",
        )
    } | {"input_summary": input_summary}


class ScopeGraphMcpService:
    def __init__(self, client: ApiTransport, *, allow_scan_start: bool = False) -> None:
        self.client = client
        self.allow_scan_start = allow_scan_start

    @classmethod
    def from_api(
        cls,
        base_url: str,
        *,
        api_key: str | None = None,
        allow_scan_start: bool = False,
    ) -> "ScopeGraphMcpService":
        return cls(
            ScopeGraphApiClient(base_url, api_key=api_key),
            allow_scan_start=allow_scan_start,
        )

    async def system_status(self) -> dict[str, Any]:
        health = await self.client.request("GET", "/health")
        return {"ok": True, "mcp_scan_start_enabled": self.allow_scan_start, "health": health}

    async def get_started(self, project_id: str | None = None) -> dict[str, Any]:
        """Return a live, self-contained operating guide for an attached Agent."""

        async def capture(
            call: Awaitable[dict[str, Any]],
        ) -> tuple[dict[str, Any] | None, str | None]:
            try:
                return await call, None
            except (RuntimeError, ValueError) as exc:
                return None, str(exc)

        (status, status_error), (projects, projects_error) = await asyncio.gather(
            capture(self.system_status()), capture(self.list_projects(page=1, page_size=20))
        )
        project_rows = projects.get("items", []) if projects is not None else []
        if not isinstance(project_rows, list):
            project_rows = []

        selected_project: dict[str, Any] | None = None
        selected_error: str | None = None
        if project_id is not None:
            try:
                selected_project = await self.project_overview(project_id)
            except (RuntimeError, ValueError) as exc:
                selected_error = str(exc)

        if status is None:
            recommended_next = {
                "tool": "scopegraph_system_status",
                "arguments": {},
                "reason": "The local API is not currently reachable; retry health first.",
            }
        elif selected_project is not None:
            recommended_next = {
                "tool": "scopegraph_all_in_one_snapshot",
                "arguments": {"project_id": project_id, "limit": 50},
                "reason": (
                    "Load Scope, assets, websites, network, findings, and scan history in one call."
                ),
            }
        elif project_rows:
            first_project = project_rows[0]
            first_id = first_project.get("id") if isinstance(first_project, dict) else None
            recommended_next = {
                "tool": "scopegraph_all_in_one_snapshot",
                "arguments": {"project_id": first_id, "limit": 50},
                "reason": "Load the selected project's complete bounded intelligence snapshot.",
            }
        else:
            recommended_next = {
                "tool": "scopegraph_list_projects",
                "arguments": {"page": 1, "page_size": 20},
                "reason": (
                    "No project is currently available. Projects and Scope approval are created "
                    "in the Web UI."
                ),
            }

        return {
            "ready": status is not None and projects is not None,
            "workflow_version": "1.0",
            "status": status,
            "status_error": status_error,
            "projects": project_rows,
            "project_count": projects.get("total", len(project_rows)) if projects else 0,
            "projects_error": projects_error,
            "selected_project": selected_project,
            "selected_project_error": selected_error,
            "scan_control": {
                "enabled": self.allow_scan_start,
                "when_disabled": (
                    "Inventory and evidence tools remain immediately usable. A local administrator "
                    "can set SCOPEGRAPH_MCP_ALLOW_SCAN_START=true and restart MCP to allow "
                    "new runs."
                ),
                "allowed": (
                    "Quick or Standard on an exact root domain already approved in ScopeGraph"
                ),
                "always_blocked": ["Scope approval", "Deep", "Custom", "full-port", "Nuclei"],
            },
            "recommended_workflow": [
                {
                    "step": 1,
                    "tool": "scopegraph_all_in_one_snapshot",
                    "purpose": (
                        "Fetch Scope, normalized assets, live websites, IP/ports, findings, "
                        "history, and the latest asset funnel concurrently in one call."
                    ),
                },
                {
                    "step": 2,
                    "tool": "scopegraph_check_scope",
                    "purpose": (
                        "Check the intended domain/IP/URL with the server-side Scope engine."
                    ),
                },
                {
                    "step": 3,
                    "tool": "scopegraph_list_scan_runs",
                    "purpose": "Reuse existing evidence and avoid redundant collection.",
                },
                {
                    "step": 4,
                    "tool": "scopegraph_start_collection",
                    "purpose": "Optionally start a bounded run when scan control is enabled.",
                },
                {
                    "step": 5,
                    "tool": "scopegraph_scan_run_detail",
                    "purpose": "Poll live stages and errors until the run is terminal.",
                },
                {
                    "step": 6,
                    "tools": [
                        "scopegraph_attack_surface_overview",
                        "scopegraph_list_assets",
                        "scopegraph_list_websites",
                        "scopegraph_network_inventory",
                        "scopegraph_list_findings",
                    ],
                    "purpose": (
                        "Collect bounded evidence views and preserve their uncertainty labels."
                    ),
                },
            ],
            "interpretation_rules": [
                "Scan progress measures execution completion, not attack-surface coverage.",
                "Automated findings are unverified leads, not confirmed vulnerabilities.",
                "CDN/shared IP observations do not imply ownership.",
                "PENDING_REVIEW and THIRD_PARTY values must not be actively scanned.",
                "fixture evidence is deterministic test data and must not be reported as "
                "real-world evidence.",
            ],
            "all_in_one_value": {
                "not_just_subfinder": (
                    "Subfinder output is normalized, DNS-validated, resolved, safely port-probed, "
                    "HTTP-verified, crawled, fingerprinted, and correlated with unverified "
                    "security findings."
                ),
                "efficiency": (
                    "Independent DAG branches run concurrently and every ScanRun summary exposes "
                    "the asset funnel plus stage_time_seconds, wall_time_seconds, and "
                    "parallel_time_saved_seconds."
                ),
            },
            "recommended_next": recommended_next,
        }

    async def list_projects(self, *, page: int = 1, page_size: int = 20) -> dict[str, Any]:
        return _object_result(
            await self.client.request(
                "GET",
                "/api/v1/projects",
                params={
                    "page": _bounded(page, maximum=10000),
                    "page_size": _bounded(page_size, maximum=100),
                },
            )
        )

    async def project_overview(self, project_id: str) -> dict[str, Any]:
        project_id = _uuid(project_id, "project_id")
        project, summary, scope_rules = await asyncio.gather(
            self.client.request("GET", f"/api/v1/projects/{project_id}"),
            self.client.request("GET", f"/api/v1/projects/{project_id}/summary"),
            self.client.request("GET", f"/api/v1/projects/{project_id}/scope-rules"),
        )
        return {"project": project, "summary": summary, "scope_rules": scope_rules}

    async def check_scope(
        self,
        project_id: str,
        value: str,
        *,
        asset_type: AssetTypeName = "domain",
    ) -> dict[str, Any]:
        project_id = _uuid(project_id, "project_id")
        return _object_result(
            await self.client.request(
                "POST",
                f"/api/v1/projects/{project_id}/scope/check",
                json={"asset_type": asset_type, "value": value},
            )
        )

    async def list_assets(
        self,
        project_id: str,
        *,
        page: int = 1,
        page_size: int = 50,
        asset_type: AssetTypeName | None = None,
        scope_status: ScopeStatusName | None = None,
    ) -> dict[str, Any]:
        project_id = _uuid(project_id, "project_id")
        params: dict[str, Any] = {
            "page": _bounded(page, maximum=10000),
            "page_size": _bounded(page_size, maximum=100),
        }
        if asset_type is not None:
            params["asset_type"] = asset_type
        if scope_status is not None:
            params["scope_status"] = scope_status
        return _object_result(
            await self.client.request("GET", f"/api/v1/projects/{project_id}/assets", params=params)
        )

    async def list_websites(
        self, project_id: str, *, page: int = 1, page_size: int = 50
    ) -> dict[str, Any]:
        project_id = _uuid(project_id, "project_id")
        return _object_result(
            await self.client.request(
                "GET",
                f"/api/v1/projects/{project_id}/websites",
                params={
                    "page": _bounded(page, maximum=10000),
                    "page_size": _bounded(page_size),
                },
            )
        )

    async def website_detail(self, website_id: str) -> dict[str, Any]:
        website_id = _uuid(website_id, "website_id")
        return _object_result(await self.client.request("GET", f"/api/v1/websites/{website_id}"))

    async def network_inventory(
        self,
        project_id: str,
        *,
        scan_run_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        project_id = _uuid(project_id, "project_id")
        limit = _bounded(limit)
        params: dict[str, Any] = {"page": 1, "page_size": limit}
        if scan_run_id is not None:
            params["scan_run_id"] = _uuid(scan_run_id, "scan_run_id")
        ips, ports = await asyncio.gather(
            self.client.request(
                "GET",
                f"/api/v1/projects/{project_id}/ips-page",
                params={"page": 1, "page_size": limit},
            ),
            self.client.request("GET", f"/api/v1/projects/{project_id}/ports-page", params=params),
        )
        ip_rows = ips.get("items", []) if isinstance(ips, dict) else []
        port_rows = ports.get("items", []) if isinstance(ports, dict) else []
        ip_total = int(ips.get("total", len(ip_rows))) if isinstance(ips, dict) else 0
        port_total = int(ports.get("total", len(port_rows))) if isinstance(ports, dict) else 0
        return {
            "ips": ip_rows,
            "ports": port_rows,
            "counts": {"ips": ip_total, "ports": port_total},
            "truncated": ip_total > limit or port_total > limit,
        }

    async def attack_surface_overview(self, project_id: str, *, limit: int = 50) -> dict[str, Any]:
        """Get the highest-priority domain-centric evidence in one bounded response."""

        project_id = _uuid(project_id, "project_id")
        limit = _bounded(limit, maximum=100)
        result = _object_result(
            await self.client.request(
                "GET",
                f"/api/v1/projects/{project_id}/attack-surface",
                params={"page": 1, "page_size": limit},
            )
        )
        items = result.get("items", [])
        total = int(result.get("total", len(items))) if isinstance(items, list) else 0
        return result | {
            "truncated": total > limit,
            "claim_boundary": (
                "Priority ranks review order from observed ports, web evidence, and unverified "
                "findings; it does not confirm ownership or a vulnerability."
            ),
        }

    async def all_in_one_snapshot(
        self, project_id: str, *, limit: int = 50
    ) -> dict[str, Any]:
        """Return the complete bounded project intelligence view in one MCP roundtrip."""

        project_id = _uuid(project_id, "project_id")
        limit = _bounded(limit)
        overview, assets, websites, network, attack_surface, findings, scans = await asyncio.gather(
            self.project_overview(project_id),
            self.list_assets(project_id, page=1, page_size=limit),
            self.list_websites(project_id, page=1, page_size=limit),
            self.network_inventory(project_id, limit=limit),
            self.attack_surface_overview(project_id, limit=limit),
            self.list_findings(project_id, limit=limit),
            self.list_scan_runs(project_id, page=1, page_size=min(limit, 20)),
        )
        scan_rows = scans.get("items", []) if isinstance(scans, dict) else []
        latest_run = scan_rows[0] if isinstance(scan_rows, list) and scan_rows else None
        asset_total = int(assets.get("total", 0)) if isinstance(assets, dict) else 0
        website_total = int(websites.get("total", 0)) if isinstance(websites, dict) else 0
        network_counts = network.get("counts", {}) if isinstance(network, dict) else {}
        return {
            "project_overview": overview,
            "assets": assets,
            "websites": websites,
            "network": network,
            "attack_surface": attack_surface,
            "findings": findings,
            "scan_runs": scans,
            "latest_run": latest_run,
            "latest_asset_funnel": (
                latest_run.get("summary", {}).get("funnel", {})
                if isinstance(latest_run, dict)
                else {}
            ),
            "counts": {
                "assets": asset_total,
                "websites": website_total,
                "ips": int(network_counts.get("ips", 0)),
                "open_ports": int(network_counts.get("ports", 0)),
                "findings": int(findings.get("total", 0)),
                "scan_runs": int(scans.get("total", len(scan_rows))),
            },
            "bounded_limit": limit,
            "interpretation": {
                "open_ports_are_findings_not_tested_port_count": True,
                "automated_security_hits_are_unverified": True,
                "progress_is_not_coverage": True,
            },
        }

    async def list_findings(self, project_id: str, *, limit: int = 100) -> dict[str, Any]:
        project_id = _uuid(project_id, "project_id")
        limit = _bounded(limit)
        rows = await self.client.request("GET", f"/api/v1/projects/{project_id}/findings")
        findings = rows if isinstance(rows, list) else []
        return {
            "items": findings[:limit],
            "total": len(findings),
            "truncated": len(findings) > limit,
            "claim_boundary": "All automated findings remain unverified until human review.",
        }

    async def list_scan_runs(
        self, project_id: str, *, page: int = 1, page_size: int = 20
    ) -> dict[str, Any]:
        project_id = _uuid(project_id, "project_id")
        return _object_result(
            await self.client.request(
                "GET",
                f"/api/v1/projects/{project_id}/scan-runs",
                params={
                    "page": _bounded(page, maximum=10000),
                    "page_size": _bounded(page_size, maximum=100),
                },
            )
        )

    async def scan_run_detail(self, scan_run_id: str) -> dict[str, Any]:
        scan_run_id = _uuid(scan_run_id, "scan_run_id")
        run, jobs, events = await asyncio.gather(
            self.client.request("GET", f"/api/v1/scan-runs/{scan_run_id}"),
            self.client.request("GET", f"/api/v1/scan-runs/{scan_run_id}/jobs"),
            self.client.request("GET", f"/api/v1/scan-runs/{scan_run_id}/events"),
        )
        job_rows = jobs if isinstance(jobs, list) else []
        event_rows = events if isinstance(events, list) else []
        return {
            "run": run,
            "jobs": [_compact_job(job) for job in job_rows],
            "events": event_rows[-100:],
            "counts": {"jobs": len(job_rows), "events": len(event_rows)},
            "events_truncated": len(event_rows) > 100,
            "interpretation": "progress is execution completion, not attack-surface coverage",
        }

    async def start_collection(
        self,
        project_id: str,
        root_domain: str,
        *,
        profile: CollectionProfile = "quick",
        execution_mode: ExecutionMode = "host",
        port_scan_enabled: bool = False,
        include_screenshots: bool = False,
    ) -> dict[str, Any]:
        if not self.allow_scan_start:
            raise McpSafetyError(
                "Agent-started collection is disabled. A local administrator must set "
                "SCOPEGRAPH_MCP_ALLOW_SCAN_START=true and restart the MCP service."
            )
        if profile not in {"quick", "standard"}:
            raise McpSafetyError("MCP only permits quick or standard collection profiles")
        if execution_mode not in {"host", "fixture"}:
            raise ValueError("execution_mode must be host or fixture")

        project_id = _uuid(project_id, "project_id")
        root_domain = registrable_root_domain(root_domain)
        scope_check, rules = await asyncio.gather(
            self.client.request(
                "POST",
                f"/api/v1/projects/{project_id}/scope/check",
                json={"asset_type": "domain", "value": root_domain},
            ),
            self.client.request("GET", f"/api/v1/projects/{project_id}/scope-rules"),
        )
        if not isinstance(scope_check, dict) or not scope_check.get("active_allowed"):
            raise McpSafetyError("The requested root domain is not approved for active collection")
        confirmed_root = any(
            isinstance(rule, dict)
            and rule.get("rule_type") == "ROOT_DOMAIN"
            and rule.get("action") == "INCLUDE"
            and str(rule.get("value", "")).casefold().rstrip(".") == root_domain.casefold()
            for rule in (rules if isinstance(rules, list) else [])
        )
        if not confirmed_root:
            raise McpSafetyError(
                "MCP cannot approve or expand Scope; the exact root domain must first be confirmed "
                "in ScopeGraph"
            )

        payload = {
            "root_domain": root_domain,
            "profile": profile,
            "execution_mode": execution_mode,
            "authorization_confirmed": True,
            "allow_active_execution": execution_mode == "host",
            "port_scan_enabled": port_scan_enabled,
            "screenshot_enabled": include_screenshots,
            "deep_confirmation": False,
            "full_port_scan": False,
            "full_port_confirmation": False,
            "nuclei_enabled": False,
            "nuclei_confirmation": False,
            "proxy_url": None,
            "custom_config": None,
        }
        run = await self.client.request(
            "POST", f"/api/v1/projects/{project_id}/scan-runs", json=payload
        )
        return {
            "accepted": True,
            "evidence_class": "real" if execution_mode == "host" else "fixture",
            "safety": {
                "scope_preconfirmed": True,
                "deep_disabled": True,
                "full_port_disabled": True,
                "nuclei_disabled": True,
            },
            "run": run,
            "next": "Poll scopegraph_scan_run_detail with the returned run id.",
        }

    async def cancel_collection(self, scan_run_id: str) -> dict[str, Any]:
        if not self.allow_scan_start:
            raise McpSafetyError("Agent scan control is disabled by the local administrator")
        scan_run_id = _uuid(scan_run_id, "scan_run_id")
        run = await self.client.request("POST", f"/api/v1/scan-runs/{scan_run_id}/cancel")
        return {"cancel_requested": True, "run": run}
