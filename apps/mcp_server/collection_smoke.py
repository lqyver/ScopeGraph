import argparse
import asyncio
import json
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

TERMINAL = {"SUCCESS", "PARTIAL_SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"}


def _payload(result: Any) -> dict[str, Any]:
    payload = result.structuredContent or {}
    if "result" in payload and isinstance(payload["result"], dict):
        return payload["result"]
    return payload


async def run_collection(
    url: str,
    project_id: str,
    root_domain: str,
    *,
    profile: str,
    execution_mode: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    async with streamable_http_client(url) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            started = await session.call_tool(
                "scopegraph_start_collection",
                arguments={
                    "project_id": project_id,
                    "root_domain": root_domain,
                    "profile": profile,
                    "execution_mode": execution_mode,
                    "port_scan_enabled": False,
                    "include_screenshots": False,
                },
            )
            if started.isError:
                raise RuntimeError(f"MCP rejected collection: {started.content}")
            started_payload = _payload(started)
            run = started_payload.get("run", {})
            run_id = str(run.get("id", "")) if isinstance(run, dict) else ""
            if not run_id:
                raise RuntimeError(f"MCP response did not include a scan run id: {started_payload}")

            deadline = asyncio.get_running_loop().time() + timeout_seconds
            latest: dict[str, Any] = {}
            while asyncio.get_running_loop().time() < deadline:
                detail = await session.call_tool(
                    "scopegraph_scan_run_detail", arguments={"scan_run_id": run_id}
                )
                if detail.isError:
                    raise RuntimeError(f"MCP run polling failed: {detail.content}")
                latest = _payload(detail)
                run_detail = latest.get("run", {})
                status = str(run_detail.get("status", "")) if isinstance(run_detail, dict) else ""
                if status in TERMINAL:
                    return {
                        "ok": status in {"SUCCESS", "PARTIAL_SUCCESS"},
                        "evidence_class": started_payload.get("evidence_class"),
                        "run_id": run_id,
                        "status": status,
                        "progress": run_detail.get("progress"),
                        "summary": run_detail.get("summary"),
                        "jobs": latest.get("jobs", []),
                    }
                await asyncio.sleep(1)
            raise TimeoutError(f"MCP collection did not finish within {timeout_seconds} seconds")


def main() -> None:
    parser = argparse.ArgumentParser(description="Start and poll a collection through MCP")
    parser.add_argument("--url", default="http://127.0.0.1:8001/mcp")
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--root-domain", required=True)
    parser.add_argument("--profile", choices=("quick", "standard"), default="quick")
    parser.add_argument("--execution-mode", choices=("host", "fixture"), default="fixture")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--confirm-start", action="store_true")
    args = parser.parse_args()
    if not args.confirm_start:
        parser.error("--confirm-start is required because this command creates a scan run")
    result = asyncio.run(
        run_collection(
            args.url,
            args.project_id,
            args.root_domain,
            profile=args.profile,
            execution_mode=args.execution_mode,
            timeout_seconds=args.timeout_seconds,
        )
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
