from fastapi import APIRouter

from scopegraph.application.services.system import (
    check_tool,
    list_tools,
    read_system_settings,
    request_tool_update,
    update_system_settings,
)
from scopegraph.schemas.system import (
    SystemSettingsPatch,
    SystemSettingsRead,
    ToolStatusRead,
    ToolUpdateRead,
    ToolUpdateRequest,
)

router = APIRouter(prefix="/api/v1/system", tags=["system"])


@router.get("/tools", response_model=list[ToolStatusRead])
async def tools_endpoint() -> list[ToolStatusRead]:
    return await list_tools()


@router.post("/tools/{name}/check-update", response_model=ToolStatusRead)
async def check_tool_endpoint(name: str) -> ToolStatusRead:
    return await check_tool(name)


@router.post("/tools/{name}/update", response_model=ToolUpdateRead)
async def update_tool_endpoint(name: str, payload: ToolUpdateRequest) -> ToolUpdateRead:
    return request_tool_update(name, payload.confirmation)


@router.get("/settings", response_model=SystemSettingsRead)
async def settings_endpoint() -> SystemSettingsRead:
    return read_system_settings()


@router.patch("/settings", response_model=SystemSettingsRead)
async def update_settings_endpoint(payload: SystemSettingsPatch) -> SystemSettingsRead:
    return update_system_settings(payload)
