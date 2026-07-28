import argparse
import asyncio
import json

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def smoke(url: str) -> dict[str, object]:
    async with streamable_http_client(url) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            bootstrap = await session.call_tool("scopegraph_get_started", arguments={})
            status = await session.call_tool("scopegraph_system_status", arguments={})
            projects = await session.call_tool(
                "scopegraph_list_projects", arguments={"page": 1, "page_size": 5}
            )
            status_payload = status.structuredContent or {}
            if "result" in status_payload and isinstance(status_payload["result"], dict):
                status_payload = status_payload["result"]
            write_enabled = bool(status_payload.get("mcp_scan_start_enabled"))
            blocked_start = None
            if not write_enabled:
                blocked_start = await session.call_tool(
                    "scopegraph_start_collection",
                    arguments={
                        "project_id": "00000000-0000-4000-8000-000000000000",
                        "root_domain": "example.com",
                    },
                )
            names = [tool.name for tool in tools.tools]
            required = {
                "scopegraph_system_status",
                "scopegraph_get_started",
                "scopegraph_list_projects",
                "scopegraph_all_in_one_snapshot",
                "scopegraph_start_collection",
                "scopegraph_scan_run_detail",
            }
            missing = sorted(required.difference(names))
            write_gate_failed = blocked_start is not None and not blocked_start.isError
            if (
                missing
                or bootstrap.isError
                or status.isError
                or projects.isError
                or write_gate_failed
            ):
                raise RuntimeError(
                    f"MCP smoke failed; missing={missing}, status_error={status.isError}, "
                    f"projects_error={projects.isError}, "
                    f"bootstrap_error={bootstrap.isError}, "
                    f"write_gate_failed={write_gate_failed}"
                )
            return {
                "ok": True,
                "url": url,
                "tool_count": len(names),
                "tools": names,
                "status_content_blocks": len(status.content),
                "bootstrap_content_blocks": len(bootstrap.content),
                "project_content_blocks": len(projects.content),
                "write_enabled": write_enabled,
                "default_write_gate_verified": (
                    blocked_start.isError if blocked_start is not None else None
                ),
            }


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke-test a ScopeGraph MCP HTTP endpoint")
    parser.add_argument("--url", default="http://127.0.0.1:8001/mcp")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(smoke(args.url)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
