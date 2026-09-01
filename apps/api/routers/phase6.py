from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.services.exports import (
    create_export,
    get_export_or_404,
    resolve_export_path,
)
from scopegraph.application.services.findings import list_findings, page_findings, review_finding
from scopegraph.application.services.history import compare_scan_runs
from scopegraph.application.services.storage import cleanup_storage, storage_status
from scopegraph.infrastructure.database import get_session
from scopegraph.schemas.phase6 import (
    ExportCreate,
    ExportRead,
    FindingPage,
    FindingRead,
    FindingReviewRequest,
    ScanDiffRead,
    StorageCleanupRead,
    StorageCleanupRequest,
    StorageRead,
)

router = APIRouter(prefix="/api/v1", tags=["findings-history-exports"])
Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/projects/{project_id}/findings", response_model=list[FindingRead])
async def findings_endpoint(
    project_id: UUID,
    session: Session,
    execution_mode: Literal["host", "fixture"] = "host",
    limit: int = Query(default=100, ge=1, le=200),
) -> list[FindingRead]:
    return [
        FindingRead.model_validate(item)
        for item in await list_findings(
            session, project_id, execution_mode=execution_mode, limit=limit
        )
    ]


@router.get("/projects/{project_id}/findings-page", response_model=FindingPage)
async def findings_page_endpoint(
    project_id: UUID,
    session: Session,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    execution_mode: Literal["host", "fixture"] = "host",
) -> FindingPage:
    items, total = await page_findings(
        session,
        project_id,
        page=page,
        page_size=page_size,
        execution_mode=execution_mode,
    )
    return FindingPage(
        items=[FindingRead.model_validate(item) for item in items],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.post("/findings/{finding_id}/review", response_model=FindingRead)
async def review_finding_endpoint(
    finding_id: UUID, payload: FindingReviewRequest, session: Session
) -> FindingRead:
    return FindingRead.model_validate(
        await review_finding(session, finding_id, payload.status, payload.reason)
    )


@router.get("/projects/{project_id}/diff", response_model=ScanDiffRead)
async def scan_diff_endpoint(
    project_id: UUID,
    session: Session,
    from_run: Annotated[UUID, Query(alias="from")],
    to_run: Annotated[UUID, Query(alias="to")],
) -> ScanDiffRead:
    return await compare_scan_runs(session, project_id, from_run, to_run)


@router.post(
    "/projects/{project_id}/exports",
    response_model=ExportRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_export_endpoint(
    project_id: UUID, payload: ExportCreate, session: Session
) -> ExportRead:
    return ExportRead.model_validate(
        await create_export(
            session,
            project_id,
            payload.export_format,
            payload.export_scope,
            payload.execution_mode,
        )
    )


@router.get("/exports/{export_id}", response_model=ExportRead)
async def get_export_endpoint(export_id: UUID, session: Session) -> ExportRead:
    return ExportRead.model_validate(await get_export_or_404(session, export_id))


@router.get("/exports/{export_id}/download", response_class=FileResponse)
async def download_export_endpoint(export_id: UUID, session: Session) -> FileResponse:
    artifact = await get_export_or_404(session, export_id)
    path = resolve_export_path(artifact)
    return FileResponse(
        path,
        media_type=artifact.media_type,
        filename=path.name,
    )


@router.get("/system/storage", response_model=StorageRead)
async def storage_endpoint() -> StorageRead:
    return storage_status()


@router.post("/system/storage/cleanup", response_model=StorageCleanupRead)
async def cleanup_endpoint(payload: StorageCleanupRequest) -> StorageCleanupRead:
    return cleanup_storage(**payload.model_dump())
