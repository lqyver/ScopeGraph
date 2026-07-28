from typing import Any

import pytest

from scopegraph.mcp.service import McpSafetyError, ScopeGraphMcpService

PROJECT_ID = "4a833e5f-e5b5-4f71-86cf-91bcf5fff22b"


class FakeApi:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, dict[str, Any] | None]] = []
        self.scope_allowed = True
        self.root_confirmed = True

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        self.calls.append((method, path, json, params))
        if path.endswith("/scope/check"):
            return {"status": "IN_SCOPE", "active_allowed": self.scope_allowed}
        if path.endswith("/scope-rules"):
            return (
                [{"rule_type": "ROOT_DOMAIN", "action": "INCLUDE", "value": "example.com"}]
                if self.root_confirmed
                else []
            )
        if path.endswith("/scan-runs") and method == "POST":
            return {"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "status": "QUEUED"}
        return {"ok": True, "path": path}


@pytest.mark.asyncio
async def test_agent_scan_start_is_disabled_by_default() -> None:
    service = ScopeGraphMcpService(FakeApi())

    with pytest.raises(McpSafetyError, match="disabled"):
        await service.start_collection(PROJECT_ID, "example.com")


@pytest.mark.asyncio
async def test_get_started_is_live_and_self_contained() -> None:
    class BootstrapApi(FakeApi):
        async def request(
            self,
            method: str,
            path: str,
            *,
            json: dict[str, Any] | None = None,
            params: dict[str, Any] | None = None,
        ) -> Any:
            if path == "/health":
                return {"status": "healthy"}
            if path == "/api/v1/projects":
                return {"items": [{"id": PROJECT_ID, "name": "Example"}], "total": 1}
            return await super().request(method, path, json=json, params=params)

    result = await ScopeGraphMcpService(BootstrapApi()).get_started()

    assert result["ready"] is True
    assert result["project_count"] == 1
    assert result["scan_control"]["enabled"] is False
    assert result["recommended_next"] == {
        "tool": "scopegraph_all_in_one_snapshot",
        "arguments": {"project_id": PROJECT_ID, "limit": 50},
        "reason": "Load the selected project's complete bounded intelligence snapshot.",
    }
    assert len(result["recommended_workflow"]) == 6
    assert result["interpretation_rules"]
    assert result["all_in_one_value"]


@pytest.mark.asyncio
async def test_all_in_one_snapshot_collects_bounded_views_concurrently() -> None:
    class SnapshotApi(FakeApi):
        async def request(
            self,
            method: str,
            path: str,
            *,
            json: dict[str, Any] | None = None,
            params: dict[str, Any] | None = None,
        ) -> Any:
            if path.endswith("/summary"):
                return {"asset_count": 7}
            if path.endswith("/assets"):
                return {"items": [{"normalized_value": "example.com"}], "total": 7}
            if path.endswith("/websites"):
                return {"items": [{"normalized_url": "https://example.com/"}], "total": 3}
            if path.endswith("/ips-page"):
                return {"items": [{"ip": "93.184.216.34"}], "total": 2}
            if path.endswith("/ports-page"):
                return {"items": [{"port": 443}], "total": 1}
            if path.endswith("/findings"):
                return [{"template_id": "tls-version"}]
            if path.endswith("/scan-runs"):
                return {
                    "items": [{"summary": {"funnel": {"websites_alive": 3}}}],
                    "total": 2,
                }
            return await super().request(method, path, json=json, params=params)

    result = await ScopeGraphMcpService(SnapshotApi()).all_in_one_snapshot(
        PROJECT_ID, limit=10
    )

    assert result["counts"] == {
        "assets": 7,
        "websites": 3,
        "ips": 2,
        "open_ports": 1,
        "findings": 1,
        "scan_runs": 2,
    }
    assert result["latest_asset_funnel"] == {"websites_alive": 3}
    assert result["interpretation"]["open_ports_are_findings_not_tested_port_count"] is True


@pytest.mark.asyncio
async def test_agent_cannot_approve_or_expand_scope() -> None:
    api = FakeApi()
    api.root_confirmed = False
    service = ScopeGraphMcpService(api, allow_scan_start=True)

    with pytest.raises(McpSafetyError, match="cannot approve or expand Scope"):
        await service.start_collection(PROJECT_ID, "example.com")


@pytest.mark.asyncio
async def test_agent_scan_payload_keeps_high_risk_features_off() -> None:
    api = FakeApi()
    service = ScopeGraphMcpService(api, allow_scan_start=True)

    result = await service.start_collection(
        PROJECT_ID,
        "www.example.com",
        profile="standard",
        execution_mode="host",
        port_scan_enabled=False,
    )

    request = next(
        call for call in api.calls if call[0] == "POST" and call[1].endswith("/scan-runs")
    )
    payload = request[2]
    assert payload is not None
    assert payload["root_domain"] == "example.com"
    assert payload["allow_active_execution"] is True
    assert payload["port_scan_enabled"] is False
    assert payload["screenshot_enabled"] is False
    assert payload["deep_confirmation"] is False
    assert payload["full_port_scan"] is False
    assert payload["nuclei_enabled"] is False
    assert result["evidence_class"] == "real"


@pytest.mark.asyncio
async def test_network_inventory_is_bounded_for_agent_context() -> None:
    class NetworkApi(FakeApi):
        async def request(
            self,
            method: str,
            path: str,
            *,
            json: dict[str, Any] | None = None,
            params: dict[str, Any] | None = None,
        ) -> Any:
            if path.endswith("/ips-page"):
                return {
                    "items": [{"ip": f"192.0.2.{index}"} for index in range(1, 3)],
                    "total": 5,
                }
            if path.endswith("/ports-page"):
                return {"items": [{"port": index} for index in range(1, 3)], "total": 5}
            return await super().request(method, path, json=json, params=params)

    service = ScopeGraphMcpService(NetworkApi())
    result = await service.network_inventory(PROJECT_ID, limit=2)

    assert len(result["ips"]) == 2
    assert len(result["ports"]) == 2
    assert result["counts"] == {"ips": 5, "ports": 5}
    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_attack_surface_overview_keeps_domain_evidence_together() -> None:
    class SurfaceApi(FakeApi):
        async def request(
            self,
            method: str,
            path: str,
            *,
            json: dict[str, Any] | None = None,
            params: dict[str, Any] | None = None,
        ) -> Any:
            if path.endswith("/attack-surface"):
                return {
                    "items": [
                        {
                            "domain": "www.example.com",
                            "ports": [{"port": 443}],
                            "technologies": ["Next.js 15"],
                        }
                    ],
                    "total": 3,
                    "summary": {"high_priority_targets": 1},
                }
            return await super().request(method, path, json=json, params=params)

    result = await ScopeGraphMcpService(SurfaceApi()).attack_surface_overview(
        PROJECT_ID, limit=2
    )

    assert result["items"][0]["ports"][0]["port"] == 443
    assert result["items"][0]["technologies"] == ["Next.js 15"]
    assert result["truncated"] is True
    assert "does not confirm ownership" in result["claim_boundary"]


@pytest.mark.asyncio
async def test_scan_detail_compacts_large_inputs_for_agent_context() -> None:
    class ScanApi(FakeApi):
        async def request(
            self,
            method: str,
            path: str,
            *,
            json: dict[str, Any] | None = None,
            params: dict[str, Any] | None = None,
        ) -> Any:
            if path.endswith("/jobs"):
                return [
                    {
                        "id": "job-1",
                        "sequence": 0,
                        "adapter_name": "httpx",
                        "status": "RUNNING",
                        "input_ref": {
                            "domains": [f"host-{index}.example.com" for index in range(500)],
                            "concurrency": 30,
                        },
                    }
                ]
            if path.endswith("/events"):
                return [{"event_type": str(index)} for index in range(150)]
            if "/scan-runs/" in path:
                return {"id": path.rsplit("/", 1)[-1], "status": "RUNNING"}
            return await super().request(method, path, json=json, params=params)

    service = ScopeGraphMcpService(ScanApi())
    result = await service.scan_run_detail("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")

    assert result["jobs"][0]["input_summary"] == {"domains_count": 500, "concurrency": 30}
    assert "input_ref" not in result["jobs"][0]
    assert len(result["events"]) == 100
    assert result["events_truncated"] is True
