import pytest

from scopegraph.mcp.server import create_mcp_server
from scopegraph.mcp.service import ScopeGraphMcpService


@pytest.mark.asyncio
async def test_mcp_exposes_bounded_tool_contract_and_annotations() -> None:
    server = create_mcp_server(ScopeGraphMcpService(None))  # type: ignore[arg-type]

    tools = {tool.name: tool for tool in await server.list_tools()}

    assert len(tools) == 16
    bootstrap = tools["scopegraph_get_started"]
    assert bootstrap.annotations is not None
    assert bootstrap.annotations.readOnlyHint is True
    assert "CALL THIS FIRST" in (bootstrap.description or "")
    assert tools["scopegraph_list_assets"].annotations is not None
    assert tools["scopegraph_list_assets"].annotations.readOnlyHint is True
    assert tools["scopegraph_all_in_one_snapshot"].annotations is not None
    assert tools["scopegraph_all_in_one_snapshot"].annotations.readOnlyHint is True
    assert tools["scopegraph_attack_surface_overview"].annotations is not None
    assert tools["scopegraph_attack_surface_overview"].annotations.readOnlyHint is True
    start = tools["scopegraph_start_collection"]
    assert start.annotations is not None
    assert start.annotations.readOnlyHint is False
    assert start.annotations.openWorldHint is True
    profile = start.inputSchema["properties"]["profile"]
    assert profile["enum"] == ["quick", "standard"]
    assert "deep" not in str(start.inputSchema).casefold()
    assert "nuclei" not in str(start.inputSchema).casefold()

    prompts = {prompt.name: prompt for prompt in await server.list_prompts()}
    assert "scopegraph_information_collection" in prompts
