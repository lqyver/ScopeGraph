import json
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from scopegraph.mcp.service import (
    AssetTypeName,
    CollectionProfile,
    ExecutionMode,
    ScopeGraphMcpService,
    ScopeStatusName,
)

SERVER_INSTRUCTIONS = """
ScopeGraph is a self-describing MCP server for authorized public attack-surface
information collection. Call scopegraph_get_started first: it returns live health,
available projects, scan-control state, the recommended tool sequence, interpretation
rules, and a ready-to-call next action. No local documentation is required. Before any
collection, load scopegraph_all_in_one_snapshot and check the exact target with check_scope. Reuse
existing scan evidence where possible. Poll scan_run_detail for long work. Progress is
execution completion, not coverage, and automated findings are never confirmed
vulnerabilities. This MCP cannot
approve or expand Scope and never offers Deep, Custom, full-port, or Nuclei execution.
""".strip()
READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
START_COLLECTION = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)
CANCEL_COLLECTION = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)


def create_mcp_server(
    service: ScopeGraphMcpService,
    *,
    host: str = "127.0.0.1",
    port: int = 8001,
) -> FastMCP:
    server = FastMCP(
        "ScopeGraph",
        instructions=SERVER_INSTRUCTIONS,
        host=host,
        port=port,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )

    @server.resource("scopegraph://about")
    async def about() -> str:
        """ScopeGraph MCP capability and safety contract."""
        return json.dumps(
            {
                "name": "ScopeGraph",
                "purpose": "Authorized public attack-surface information collection",
                "scan_start_enabled": service.allow_scan_start,
                "write_boundary": "No Scope approval, Deep, full-port, custom, or Nuclei tools",
                "coverage_boundary": "Execution completion is not attack-surface coverage",
                "start_here": "Call scopegraph_get_started; local documentation is not required",
            },
            ensure_ascii=False,
        )

    @server.prompt(
        name="scopegraph_information_collection",
        title="Operate ScopeGraph safely without local documentation",
        description="A self-contained workflow prompt for an Agent attached to ScopeGraph.",
    )
    async def information_collection_prompt() -> str:
        return (
            "Call scopegraph_get_started first and follow its recommended_next value. "
            "Load scopegraph_all_in_one_snapshot and check Scope before collection. Reuse existing "
            "scan runs when possible; otherwise start only a permitted bounded collection. Poll "
            "scopegraph_scan_run_detail to a terminal state, then refresh the All-in-One snapshot. "
            "Preserve uncertainty, ownership, evidence-class, and "
            "Scope labels."
        )

    @server.tool(
        title="Start here: live ScopeGraph guide",
        description=(
            "CALL THIS FIRST after connecting. Returns live health, visible projects, MCP "
            "permissions, "
            "the complete recommended workflow, evidence rules, and a ready-to-call next action. "
            "Optionally pass a project UUID to include its live overview."
        ),
        annotations=READ_ONLY,
    )
    async def scopegraph_get_started(project_id: str | None = None) -> dict[str, Any]:
        """Bootstrap an Agent without requiring any local ScopeGraph documentation."""
        return await service.get_started(project_id)

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_system_status() -> dict[str, Any]:
        """Check API/database/Redis/storage health and whether Agent scan start is enabled."""
        return await service.system_status()

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_list_projects(page: int = 1, page_size: int = 20) -> dict[str, Any]:
        """List local ScopeGraph projects. This is read-only."""
        return await service.list_projects(page=page, page_size=page_size)

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_project_overview(project_id: str) -> dict[str, Any]:
        """Get project metadata, summary counts, and the exact include/exclude Scope rules."""
        return await service.project_overview(project_id)

    @server.tool(
        title="All-in-One project intelligence snapshot",
        description=(
            "Fetch exact Scope, normalized assets, a domain-centric priority view, live websites, "
            "IP/open ports, findings, scan history, and the latest asset funnel concurrently "
            "in one bounded call."
        ),
        annotations=READ_ONLY,
    )
    async def scopegraph_all_in_one_snapshot(
        project_id: str, limit: int = 50
    ) -> dict[str, Any]:
        """Use this after bootstrap when an Agent needs the complete current intelligence view."""
        return await service.all_in_one_snapshot(project_id, limit=limit)

    @server.tool(
        title="Domain attack-surface overview",
        description=(
            "Return domains ordered by evidence-based review priority. Each domain includes its "
            "resolved IPs, open ports/services, live websites, technology fingerprints, endpoint "
            "count, and unverified findings."
        ),
        annotations=READ_ONLY,
    )
    async def scopegraph_attack_surface_overview(
        project_id: str, limit: int = 50
    ) -> dict[str, Any]:
        """Use this when an Agent needs ports and technologies correlated to each domain."""
        return await service.attack_surface_overview(project_id, limit=limit)

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_check_scope(
        project_id: str,
        value: str,
        asset_type: AssetTypeName = "domain",
    ) -> dict[str, Any]:
        """Evaluate a value with ScopeGraph's server-side Scope engine without changing Scope."""
        return await service.check_scope(project_id, value, asset_type=asset_type)

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_list_assets(
        project_id: str,
        page: int = 1,
        page_size: int = 50,
        asset_type: AssetTypeName | None = None,
        scope_status: ScopeStatusName | None = None,
    ) -> dict[str, Any]:
        """List normalized assets with evidence-derived Scope and ownership fields."""
        return await service.list_assets(
            project_id,
            page=page,
            page_size=page_size,
            asset_type=asset_type,
            scope_status=scope_status,
        )

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_list_websites(
        project_id: str, page: int = 1, page_size: int = 50
    ) -> dict[str, Any]:
        """List observed websites, status, title, technologies, and evidence metadata."""
        return await service.list_websites(project_id, page=page, page_size=page_size)

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_website_detail(website_id: str) -> dict[str, Any]:
        """Get one website's latest snapshot, technologies, certificates, filings, and endpoints."""
        return await service.website_detail(website_id)

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_network_inventory(
        project_id: str,
        scan_run_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Get bounded IP and port inventory. Shared/CDN IP ownership is not implied."""
        return await service.network_inventory(project_id, scan_run_id=scan_run_id, limit=limit)

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_list_findings(project_id: str, limit: int = 100) -> dict[str, Any]:
        """List low-risk discovery findings; every automated finding remains unverified."""
        return await service.list_findings(project_id, limit=limit)

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_list_scan_runs(
        project_id: str, page: int = 1, page_size: int = 20
    ) -> dict[str, Any]:
        """List scan history and execution summaries for one project."""
        return await service.list_scan_runs(project_id, page=page, page_size=page_size)

    @server.tool(annotations=READ_ONLY)
    async def scopegraph_scan_run_detail(scan_run_id: str) -> dict[str, Any]:
        """Get live run status, per-stage results, errors, and progress events."""
        return await service.scan_run_detail(scan_run_id)

    @server.tool(annotations=START_COLLECTION)
    async def scopegraph_start_collection(
        project_id: str,
        root_domain: str,
        profile: CollectionProfile = "quick",
        execution_mode: ExecutionMode = "host",
        port_scan_enabled: bool = False,
        include_screenshots: bool = False,
    ) -> dict[str, Any]:
        """Start Quick/Standard collection for an exact, preconfirmed root domain.

        Disabled by default. A local administrator must enable Agent scan start. This tool cannot
        approve Scope and never enables Deep, full-port, custom profiles, or Nuclei.
        """
        return await service.start_collection(
            project_id,
            root_domain,
            profile=profile,
            execution_mode=execution_mode,
            port_scan_enabled=port_scan_enabled,
            include_screenshots=include_screenshots,
        )

    @server.tool(annotations=CANCEL_COLLECTION)
    async def scopegraph_cancel_collection(scan_run_id: str) -> dict[str, Any]:
        """Cancel an Agent-controlled scan while preserving all evidence already collected."""
        return await service.cancel_collection(scan_run_id)

    return server
