from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, File, Query, Response, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.projects import (
    add_scope_rule,
    check_scope,
    create_project,
    get_project_or_404,
    import_assets,
    list_assets,
    list_projects,
    list_scope_rules,
    project_summary,
    remove_scope_rule,
    soft_delete_project,
    update_project,
)
from scopegraph.domain.enums import AssetType, ProjectStatus, ScopeStatus
from scopegraph.domain.models import Asset
from scopegraph.infrastructure.database import get_session
from scopegraph.normalizers.imports import parse_import_file
from scopegraph.schemas.projects import (
    AssetImportResult,
    AssetPage,
    AssetRead,
    ProjectCreate,
    ProjectDeleteRequest,
    ProjectPage,
    ProjectRead,
    ProjectSummary,
    ProjectUpdate,
    ScopeCheckRequest,
    ScopeCheckResponse,
    ScopeRuleCreate,
    ScopeRuleRead,
)

router = APIRouter(prefix="/api/v1", tags=["projects"])
Session = Annotated[AsyncSession, Depends(get_session)]
MAX_IMPORT_BYTES = 10 * 1024 * 1024


@router.post("/projects", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
async def create_project_endpoint(payload: ProjectCreate, session: Session) -> ProjectRead:
    return ProjectRead.model_validate(await create_project(session, payload))


@router.get("/projects", response_model=ProjectPage)
async def list_projects_endpoint(
    session: Session,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    project_status: Annotated[ProjectStatus | None, Query(alias="status")] = None,
) -> ProjectPage:
    projects, total = await list_projects(
        session, page=page, page_size=page_size, status=project_status
    )
    return ProjectPage(
        items=[ProjectRead.model_validate(item) for item in projects],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get("/projects/{project_id}", response_model=ProjectRead)
async def get_project_endpoint(project_id: UUID, session: Session) -> ProjectRead:
    return ProjectRead.model_validate(await get_project_or_404(session, project_id))


@router.patch("/projects/{project_id}", response_model=ProjectRead)
async def update_project_endpoint(
    project_id: UUID,
    payload: ProjectUpdate,
    session: Session,
) -> ProjectRead:
    return ProjectRead.model_validate(await update_project(session, project_id, payload))


@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project_endpoint(
    project_id: UUID,
    payload: ProjectDeleteRequest,
    session: Session,
) -> Response:
    await soft_delete_project(session, project_id, payload.confirmation)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/projects/{project_id}/summary", response_model=ProjectSummary)
async def project_summary_endpoint(project_id: UUID, session: Session) -> ProjectSummary:
    return await project_summary(session, project_id)


@router.post(
    "/projects/{project_id}/scope-rules",
    response_model=ScopeRuleRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_scope_rule_endpoint(
    project_id: UUID,
    payload: ScopeRuleCreate,
    session: Session,
) -> ScopeRuleRead:
    return ScopeRuleRead.model_validate(await add_scope_rule(session, project_id, payload))


@router.get("/projects/{project_id}/scope-rules", response_model=list[ScopeRuleRead])
async def list_scope_rules_endpoint(project_id: UUID, session: Session) -> list[ScopeRuleRead]:
    return [
        ScopeRuleRead.model_validate(rule) for rule in await list_scope_rules(session, project_id)
    ]


@router.delete(
    "/projects/{project_id}/scope-rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_scope_rule_endpoint(
    project_id: UUID,
    rule_id: UUID,
    session: Session,
) -> Response:
    await remove_scope_rule(session, project_id, rule_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/projects/{project_id}/scope/check", response_model=ScopeCheckResponse)
async def check_scope_endpoint(
    project_id: UUID,
    payload: ScopeCheckRequest,
    session: Session,
) -> ScopeCheckResponse:
    return await check_scope(session, project_id, payload.asset_type, payload.value)


@router.get("/projects/{project_id}/assets", response_model=AssetPage)
async def list_assets_endpoint(
    project_id: UUID,
    session: Session,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 50,
    asset_type: AssetType | None = None,
    scope_status: ScopeStatus | None = None,
    execution_mode: Literal["host", "fixture"] | None = None,
) -> AssetPage:
    assets, total = await list_assets(
        session,
        project_id,
        page=page,
        page_size=page_size,
        asset_type=asset_type,
        scope_status=scope_status,
        execution_mode=execution_mode,
    )
    return AssetPage(
        items=[AssetRead.model_validate(asset) for asset in assets],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get("/assets/{asset_id}", response_model=AssetRead)
async def get_asset_endpoint(asset_id: UUID, session: Session) -> AssetRead:
    asset = await session.scalar(select(Asset).where(Asset.id == asset_id))
    if asset is None:
        raise ScopeGraphError("ASSET_NOT_FOUND", "Asset was not found", status_code=404)
    return AssetRead.model_validate(asset)


@router.post("/projects/{project_id}/assets/import", response_model=AssetImportResult)
async def import_assets_endpoint(
    project_id: UUID,
    session: Session,
    file: Annotated[UploadFile, File(description="UTF-8 TXT, CSV, or JSON asset file")],
) -> AssetImportResult:
    filename = file.filename or ""
    content = await file.read(MAX_IMPORT_BYTES + 1)
    await file.close()
    if len(content) > MAX_IMPORT_BYTES:
        raise ScopeGraphError(
            "IMPORT_TOO_LARGE",
            "Import file exceeds the 10 MiB limit",
            status_code=413,
        )
    items = parse_import_file(filename, content)
    return await import_assets(session, project_id, items)
