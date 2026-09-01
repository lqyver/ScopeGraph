from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.services.scans import (
    cancel_scan_run,
    create_scan_run,
    get_scan_run_or_404,
    list_scan_jobs,
    list_scan_overview,
    list_scan_runs,
    pause_scan_run,
    resume_scan_run,
    retry_scan_job,
    scan_events,
)
from scopegraph.infrastructure.database import get_session
from scopegraph.schemas.scans import (
    ScanEvent,
    ScanJobRead,
    ScanRunCreate,
    ScanRunOverviewItem,
    ScanRunOverviewPage,
    ScanRunPage,
    ScanRunRead,
)

router = APIRouter(prefix="/api/v1", tags=["scans"])
Session = Annotated[AsyncSession, Depends(get_session)]


def _enqueue(scan_run_id: UUID) -> None:
    from apps.worker.tasks import execute_scan_run

    execute_scan_run.send(str(scan_run_id))


@router.post(
    "/projects/{project_id}/scan-runs",
    response_model=ScanRunRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_run(
    project_id: UUID,
    payload: ScanRunCreate,
    session: Session,
) -> ScanRunRead:
    run = await create_scan_run(session, project_id, payload)
    _enqueue(run.id)
    return ScanRunRead.model_validate(run)


@router.get("/projects/{project_id}/scan-runs", response_model=ScanRunPage)
async def project_runs(
    project_id: UUID,
    session: Session,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    execution_mode: Literal["host", "fixture"] | None = None,
) -> ScanRunPage:
    items, total = await list_scan_runs(
        session,
        project_id,
        page=page,
        page_size=page_size,
        execution_mode=execution_mode,
    )
    return ScanRunPage(items=items, page=page, page_size=page_size, total=total)


@router.get(
    "/projects/{project_id}/scan-runs-overview",
    response_model=ScanRunOverviewPage,
)
async def project_runs_overview(
    project_id: UUID,
    session: Session,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=50),
    execution_mode: Literal["host", "fixture"] | None = None,
) -> ScanRunOverviewPage:
    runs, jobs_by_run, total = await list_scan_overview(
        session,
        project_id,
        page=page,
        page_size=page_size,
        execution_mode=execution_mode,
    )
    return ScanRunOverviewPage(
        items=[
            ScanRunOverviewItem(
                run=ScanRunRead.model_validate(run),
                jobs=[ScanJobRead.model_validate(job) for job in jobs_by_run[run.id]],
            )
            for run in runs
        ],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get("/scan-runs/{scan_run_id}", response_model=ScanRunRead)
async def run_detail(scan_run_id: UUID, session: Session) -> ScanRunRead:
    return ScanRunRead.model_validate(await get_scan_run_or_404(session, scan_run_id))


@router.get("/scan-runs/{scan_run_id}/jobs", response_model=list[ScanJobRead])
async def run_jobs(scan_run_id: UUID, session: Session) -> list[ScanJobRead]:
    return [ScanJobRead.model_validate(job) for job in await list_scan_jobs(session, scan_run_id)]


@router.get("/scan-runs/{scan_run_id}/events", response_model=list[ScanEvent])
async def run_events(scan_run_id: UUID, session: Session) -> list[ScanEvent]:
    return await scan_events(session, scan_run_id)


@router.post("/scan-runs/{scan_run_id}/pause", response_model=ScanRunRead)
async def pause_run(scan_run_id: UUID, session: Session) -> ScanRunRead:
    return ScanRunRead.model_validate(await pause_scan_run(session, scan_run_id))


@router.post("/scan-runs/{scan_run_id}/resume", response_model=ScanRunRead)
async def resume_run(scan_run_id: UUID, session: Session) -> ScanRunRead:
    run = await resume_scan_run(session, scan_run_id)
    _enqueue(run.id)
    return ScanRunRead.model_validate(run)


@router.post("/scan-runs/{scan_run_id}/cancel", response_model=ScanRunRead)
async def cancel_run(scan_run_id: UUID, session: Session) -> ScanRunRead:
    return ScanRunRead.model_validate(await cancel_scan_run(session, scan_run_id))


@router.post("/scan-jobs/{scan_job_id}/retry", response_model=ScanJobRead)
async def retry_job(scan_job_id: UUID, session: Session) -> ScanJobRead:
    job, run = await retry_scan_job(session, scan_job_id)
    _enqueue(run.id)
    return ScanJobRead.model_validate(job)
