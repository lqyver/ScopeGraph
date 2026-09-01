from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.services.web_inventory import (
    get_website_detail,
    get_website_screenshot_path,
    list_endpoints,
    list_icp_records,
    list_websites,
)
from scopegraph.infrastructure.database import get_session
from scopegraph.schemas.web import (
    EndpointRead,
    ICPRecordRead,
    WebsiteDetailRead,
    WebsitePage,
)

router = APIRouter(prefix="/api/v1", tags=["web-inventory"])
Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/projects/{project_id}/websites", response_model=WebsitePage)
async def project_websites(
    project_id: UUID,
    session: Session,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    execution_mode: Literal["host", "fixture"] = "host",
) -> WebsitePage:
    return await list_websites(
        session,
        project_id,
        page=page,
        page_size=page_size,
        execution_mode=execution_mode,
    )


@router.get("/websites/{website_id}", response_model=WebsiteDetailRead)
async def website_detail(
    website_id: UUID,
    session: Session,
    execution_mode: Literal["host", "fixture"] = "host",
) -> WebsiteDetailRead:
    return await get_website_detail(session, website_id, execution_mode=execution_mode)


@router.get("/websites/{website_id}/screenshot", response_class=FileResponse)
async def website_screenshot(
    website_id: UUID,
    session: Session,
    execution_mode: Literal["host", "fixture"] = "host",
) -> FileResponse:
    path, media_type = await get_website_screenshot_path(
        session, website_id, execution_mode=execution_mode
    )
    return FileResponse(
        path,
        media_type=media_type,
        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
    )


@router.get("/projects/{project_id}/icp-records", response_model=list[ICPRecordRead])
async def project_icp_records(
    project_id: UUID,
    session: Session,
    execution_mode: Literal["host", "fixture"] = "host",
) -> list[ICPRecordRead]:
    return await list_icp_records(session, project_id, execution_mode=execution_mode)


@router.get("/projects/{project_id}/endpoints", response_model=list[EndpointRead])
async def project_endpoints(
    project_id: UUID,
    session: Session,
    scan_run_id: UUID | None = None,
    execution_mode: Literal["host", "fixture"] = "host",
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[EndpointRead]:
    return await list_endpoints(
        session,
        project_id,
        scan_run_id=scan_run_id,
        execution_mode=execution_mode,
        limit=limit,
    )
