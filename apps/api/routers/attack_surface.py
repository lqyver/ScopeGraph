from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.services.attack_surface import page_attack_surface
from scopegraph.infrastructure.database import get_session
from scopegraph.schemas.attack_surface import AttackSurfacePage

router = APIRouter(prefix="/api/v1", tags=["attack-surface"])
Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/projects/{project_id}/attack-surface", response_model=AttackSurfacePage)
async def attack_surface_endpoint(
    project_id: UUID,
    session: Session,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> AttackSurfacePage:
    return await page_attack_surface(session, project_id, page=page, page_size=page_size)
