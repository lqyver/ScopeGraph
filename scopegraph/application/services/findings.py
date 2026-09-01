from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.enums import FindingStatus
from scopegraph.domain.models import AuditLog, Finding


def _finding_conditions(
    project_id: UUID, execution_mode: str
) -> tuple[ColumnElement[bool], ...]:
    return Finding.project_id == project_id, Finding.execution_mode == execution_mode


async def list_findings(
    session: AsyncSession,
    project_id: UUID,
    *,
    execution_mode: str = "host",
    limit: int = 100,
) -> list[Finding]:
    await get_project_or_404(session, project_id)
    return list(
        await session.scalars(
            select(Finding)
            .where(*_finding_conditions(project_id, execution_mode))
            .order_by(
                Finding.is_active.desc(), Finding.severity.desc(), Finding.last_seen_at.desc()
            )
            .limit(limit)
        )
    )


async def page_findings(
    session: AsyncSession,
    project_id: UUID,
    *,
    page: int,
    page_size: int,
    execution_mode: str = "host",
) -> tuple[list[Finding], int]:
    await get_project_or_404(session, project_id)
    conditions = _finding_conditions(project_id, execution_mode)
    total = int(await session.scalar(select(func.count(Finding.id)).where(*conditions)) or 0)
    items = list(
        await session.scalars(
            select(Finding)
            .where(*conditions)
            .order_by(
                Finding.is_active.desc(), Finding.severity.desc(), Finding.last_seen_at.desc()
            )
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return items, total


async def review_finding(
    session: AsyncSession,
    finding_id: UUID,
    status: FindingStatus,
    reason: str,
) -> Finding:
    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise ScopeGraphError("FINDING_NOT_FOUND", "Finding was not found", status_code=404)
    previous = finding.status
    finding.status = status
    finding.updated_by = "local-admin"
    session.add(
        AuditLog(
            project_id=finding.project_id,
            actor="local-admin",
            action="FINDING_STATUS_REVIEWED",
            resource_type="finding",
            resource_id=str(finding.id),
            details={"previous": previous.value, "status": status.value, "reason": reason},
        )
    )
    await session.commit()
    await session.refresh(finding)
    return finding
