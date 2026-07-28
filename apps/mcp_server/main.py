import argparse
from typing import Literal, cast

from scopegraph.infrastructure.config import get_settings
from scopegraph.infrastructure.logging import configure_logging
from scopegraph.mcp.server import create_mcp_server
from scopegraph.mcp.service import ScopeGraphMcpService

Transport = Literal["stdio", "streamable-http"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ScopeGraph MCP server")
    parser.add_argument("--transport", choices=("stdio", "streamable-http"))
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    return parser


def main() -> None:
    settings = get_settings()
    args = _parser().parse_args()
    transport = cast(Transport, args.transport or settings.mcp_transport)
    host = str(args.host or settings.mcp_host)
    port = int(args.port or settings.mcp_port)
    configure_logging(settings.log_level)
    service = ScopeGraphMcpService.from_api(
        settings.api_url,
        api_key=settings.api_key.get_secret_value() if settings.api_key else None,
        allow_scan_start=settings.mcp_allow_scan_start,
    )
    server = create_mcp_server(service, host=host, port=port)
    server.run(transport=transport)


if __name__ == "__main__":
    main()
