import argparse
import asyncio
import json
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from apps.mcp_server.collection_smoke import TERMINAL, _payload


async def poll_run(url: str, run_id: str, *, timeout_seconds: int) -> dict[str, Any]:
    async with streamable_http_client(url) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            deadline = asyncio.get_running_loop().time() + timeout_seconds
            while asyncio.get_running_loop().time() < deadline:
                detail = await session.call_tool(
                    "scopegraph_scan_run_detail", arguments={"scan_run_id": run_id}
                )
                if detail.isError:
                    raise RuntimeError(f"MCP run polling failed: {detail.content}")
                payload = _payload(detail)
                run = payload.get("run", {})
                status = str(run.get("status", "")) if isinstance(run, dict) else ""
                if status in TERMINAL:
                    return {
                        "ok": status in {"SUCCESS", "PARTIAL_SUCCESS"},
                        "run_id": run_id,
                        "status": status,
                        "progress": run.get("progress"),
                        "summary": run.get("summary"),
                        "jobs": payload.get("jobs", []),
                    }
                await asyncio.sleep(1)
            raise TimeoutError(f"MCP run did not finish within {timeout_seconds} seconds")


def main() -> None:
    parser = argparse.ArgumentParser(description="Poll an existing ScopeGraph run through MCP")
    parser.add_argument("--url", default="http://127.0.0.1:8001/mcp")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()
    result = asyncio.run(poll_run(args.url, args.run_id, timeout_seconds=args.timeout_seconds))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
