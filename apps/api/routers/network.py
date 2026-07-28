from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.services.network import (
    list_ip_inventory,
    list_port_inventory,
    page_ip_inventory,
    page_port_inventory,
    update_ip_classification,
)
from scopegraph.infrastructure.database import get_session
from scopegraph.schemas.network import (
    IPClassificationUpdate,
    IPInventoryPage,
    IPInventoryRead,
    PortInventoryPage,
    PortInventoryRead,
)

router = APIRouter(prefix="/api/v1", tags=["network-inventory"])
Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/projects/{project_id}/ips", response_model=list[IPInventoryRead])
async def project_ips(project_id: UUID, session: Session) -> list[IPInventoryRead]:
    return await list_ip_inventory(session, project_id)


@router.get("/projects/{project_id}/ips-page", response_model=IPInventoryPage)
async def project_ips_page(
    project_id: UUID,
    session: Session,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
) -> IPInventoryPage:
    return await page_ip_inventory(session, project_id, page=page, page_size=page_size)


@router.patch("/projects/{project_id}/ips/{asset_id}", response_model=IPInventoryRead)
async def classify_project_ip(
    project_id: UUID,
    asset_id: UUID,
    payload: IPClassificationUpdate,
    session: Session,
) -> IPInventoryRead:
    return await update_ip_classification(session, project_id, asset_id, payload)


@router.get("/projects/{project_id}/ports", response_model=list[PortInventoryRead])
async def project_ports(
    project_id: UUID,
    session: Session,
    scan_run_id: UUID | None = None,
) -> list[PortInventoryRead]:
    return await list_port_inventory(session, project_id, scan_run_id=scan_run_id)


@router.get("/projects/{project_id}/ports-page", response_model=PortInventoryPage)
async def project_ports_page(
    project_id: UUID,
    session: Session,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    scan_run_id: UUID | None = None,
) -> PortInventoryPage:
    return await page_port_inventory(
        session,
        project_id,
        page=page,
        page_size=page_size,
        scan_run_id=scan_run_id,
    )
