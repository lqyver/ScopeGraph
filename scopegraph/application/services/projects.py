from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import exists, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from scopegraph.application.errors import ScopeGraphError
from scopegraph.domain.enums import (
    AssetType,
    CandidateRootStatus,
    OwnershipStatus,
    ProjectStatus,
    ScopeStatus,
)
from scopegraph.domain.models import (
    Asset,
    AuditLog,
    CandidateRootDomain,
    Observation,
    Project,
    ScanRun,
    ScopeRule,
)
from scopegraph.normalizers import NormalizationError, normalize_asset, normalize_company_name
from scopegraph.normalizers.assets import normalize_scope_value
from scopegraph.normalizers.imports import ImportItem
from scopegraph.scanning.state_machine import TERMINAL_STATUSES
from scopegraph.schemas.projects import (
    AssetImportResult,
    ImportIssue,
    ProjectCreate,
    ProjectSummary,
    ProjectUpdate,
    ScopeCheckResponse,
    ScopeRuleCreate,
)
from scopegraph.scope_engine import ScopeRuleValue, evaluate_scope


async def get_project_or_404(session: AsyncSession, project_id: UUID) -> Project:
    project = await session.scalar(
        select(Project).where(Project.id == project_id, Project.deleted_at.is_(None))
    )
    if project is None:
        raise ScopeGraphError("PROJECT_NOT_FOUND", "Project was not found", status_code=404)
    return project


def _audit(
    *,
    project_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: UUID | str | None,
    details: dict[str, object] | None = None,
) -> AuditLog:
    return AuditLog(
        project_id=project_id,
        actor="local-admin",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        details=details or {},
    )


async def create_project(session: AsyncSession, payload: ProjectCreate) -> Project:
    now = datetime.now(UTC)
    project = Project(
        name=payload.name.strip(),
        company_name=payload.company_name.strip(),
        company_normalized_name=normalize_company_name(payload.company_name),
        status=ProjectStatus.ACTIVE if payload.known_root_domains else ProjectStatus.DRAFT,
        default_scan_profile=payload.default_scan_profile,
        authorization_confirmed_at=now,
        retention_policy=payload.retention_policy,
        created_by="local-admin",
        updated_by="local-admin",
    )
    session.add(project)
    await session.flush()

    seen_rules: set[tuple[str, str, str]] = set()
    for rule_payload in [
        *[
            ScopeRuleCreate(rule_type="ROOT_DOMAIN", value=value, action="INCLUDE")
            for value in payload.known_root_domains
        ],
        *[
            ScopeRuleCreate(rule_type="DOMAIN", value=value, action="EXCLUDE")
            for value in payload.excluded_domains
        ],
    ]:
        normalized = normalize_scope_value(rule_payload.rule_type, rule_payload.value)
        identity = (rule_payload.rule_type.value, normalized, rule_payload.action.value)
        if identity in seen_rules:
            continue
        seen_rules.add(identity)
        session.add(
            ScopeRule(
                project_id=project.id,
                rule_type=rule_payload.rule_type,
                value=normalized,
                action=rule_payload.action,
                source=rule_payload.source,
                created_by="local-admin",
                updated_by="local-admin",
            )
        )
    session.add(
        _audit(
            project_id=project.id,
            action="PROJECT_CREATED",
            resource_type="project",
            resource_id=project.id,
            details={"authorization_confirmed_at": now.isoformat()},
        )
    )
    await session.commit()
    await session.refresh(project)
    return project


async def list_projects(
    session: AsyncSession,
    *,
    page: int,
    page_size: int,
    status: ProjectStatus | None,
) -> tuple[list[Project], int]:
    conditions: list[ColumnElement[bool]] = [Project.deleted_at.is_(None)]
    if status is not None:
        conditions.append(Project.status == status)
    total = await session.scalar(select(func.count(Project.id)).where(*conditions))
    projects = list(
        (
            await session.scalars(
                select(Project)
                .where(*conditions)
                .order_by(Project.updated_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    return projects, int(total or 0)


async def update_project(
    session: AsyncSession,
    project_id: UUID,
    payload: ProjectUpdate,
) -> Project:
    project = await get_project_or_404(session, project_id)
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    if "company_name" in changes:
        project.company_normalized_name = normalize_company_name(changes["company_name"])
    for field, value in changes.items():
        setattr(project, field, value.strip() if isinstance(value, str) else value)
    project.updated_by = "local-admin"
    session.add(
        _audit(
            project_id=project.id,
            action="PROJECT_UPDATED",
            resource_type="project",
            resource_id=project.id,
            details={"fields": sorted(changes)},
        )
    )
    await session.commit()
    await session.refresh(project)
    return project


async def soft_delete_project(
    session: AsyncSession,
    project_id: UUID,
    confirmation: str,
) -> None:
    project = await get_project_or_404(session, project_id)
    if confirmation != project.name:
        raise ScopeGraphError(
            "PROJECT_DELETE_CONFIRMATION_MISMATCH",
            "Project name confirmation did not match",
            status_code=409,
            details={"expected": project.name},
        )

    active_runs = list(
        (
            await session.scalars(
                select(ScanRun).where(
                    ScanRun.project_id == project_id,
                    ScanRun.status.not_in(tuple(TERMINAL_STATUSES)),
                )
            )
        ).all()
    )
    for run in active_runs:
        run.cancellation_requested = True

    deleted_at = datetime.now(UTC)
    project.deleted_at = deleted_at
    project.status = ProjectStatus.ARCHIVED
    project.updated_by = "local-admin"
    session.add(
        _audit(
            project_id=project.id,
            action="PROJECT_SOFT_DELETED",
            resource_type="project",
            resource_id=project.id,
            details={
                "deleted_at": deleted_at.isoformat(),
                "scan_cancellation_requests": len(active_runs),
            },
        )
    )
    await session.commit()


async def project_summary(session: AsyncSession, project_id: UUID) -> ProjectSummary:
    await get_project_or_404(session, project_id)
    type_rows = (
        await session.execute(
            select(Asset.asset_type, func.count(Asset.id))
            .where(Asset.project_id == project_id)
            .group_by(Asset.asset_type)
        )
    ).all()
    scope_rows = (
        await session.execute(
            select(Asset.scope_status, func.count(Asset.id))
            .where(Asset.project_id == project_id)
            .group_by(Asset.scope_status)
        )
    ).all()
    rule_count = await session.scalar(
        select(func.count(ScopeRule.id)).where(ScopeRule.project_id == project_id)
    )
    assets_by_type = {row[0].value: row[1] for row in type_rows}
    assets_by_scope = {row[0].value: row[1] for row in scope_rows}
    return ProjectSummary(
        project_id=project_id,
        asset_count=sum(assets_by_type.values()),
        scope_rule_count=int(rule_count or 0),
        assets_by_type=assets_by_type,
        assets_by_scope=assets_by_scope,
    )


async def list_scope_rules(session: AsyncSession, project_id: UUID) -> list[ScopeRule]:
    await get_project_or_404(session, project_id)
    return list(
        (
            await session.scalars(
                select(ScopeRule)
                .where(ScopeRule.project_id == project_id)
                .order_by(ScopeRule.action.desc(), ScopeRule.created_at.asc())
            )
        ).all()
    )


async def _confirm_candidate_for_manual_root(
    session: AsyncSession, project_id: UUID, root_domain: str
) -> bool:
    candidate = await session.scalar(
        select(CandidateRootDomain).where(
            CandidateRootDomain.project_id == project_id,
            CandidateRootDomain.root_domain == root_domain,
        )
    )
    if candidate is None or candidate.status is CandidateRootStatus.CONFIRMED:
        return False
    now = datetime.now(UTC)
    candidate.status = CandidateRootStatus.CONFIRMED
    candidate.confirmed_at = now
    candidate.rejected_at = None
    candidate.updated_by = "local-admin"
    asset = await session.get(Asset, candidate.asset_id)
    if asset is not None:
        asset.ownership_status = OwnershipStatus.CONFIRMED
        asset.scope_status = ScopeStatus.IN_SCOPE
        asset.confidence_score = 100
        asset.updated_by = "local-admin"
    session.add(
        _audit(
            project_id=project_id,
            action="CANDIDATE_CONFIRMED_BY_SCOPE_RULE",
            resource_type="candidate_root_domain",
            resource_id=candidate.id,
            details={"root_domain": root_domain},
        )
    )
    return True


async def add_scope_rule(
    session: AsyncSession,
    project_id: UUID,
    payload: ScopeRuleCreate,
) -> ScopeRule:
    project = await get_project_or_404(session, project_id)
    normalized = normalize_scope_value(payload.rule_type, payload.value)
    candidate_changed = False
    asset_scope_changed = False
    if payload.rule_type.value == "ROOT_DOMAIN" and payload.action.value == "INCLUDE":
        candidate_changed = await _confirm_candidate_for_manual_root(
            session, project_id, normalized
        )
    if payload.rule_type.value == "IP" and payload.action.value == "INCLUDE":
        existing_ip = await session.scalar(
            select(Asset).where(
                Asset.project_id == project_id,
                Asset.asset_type == AssetType.IP,
                Asset.normalized_value == normalized,
            )
        )
        if existing_ip is not None and existing_ip.scope_status is not ScopeStatus.IN_SCOPE:
            existing_ip.scope_status = ScopeStatus.IN_SCOPE
            existing_ip.ownership_status = OwnershipStatus.CONFIRMED
            existing_ip.confidence_score = 100
            existing_ip.updated_by = "local-admin"
            asset_scope_changed = True
    existing = await session.scalar(
        select(ScopeRule).where(
            ScopeRule.project_id == project_id,
            ScopeRule.rule_type == payload.rule_type,
            ScopeRule.value == normalized,
            ScopeRule.action == payload.action,
        )
    )
    if existing is not None:
        if candidate_changed or asset_scope_changed:
            await session.commit()
        return existing
    rule = ScopeRule(
        project_id=project_id,
        rule_type=payload.rule_type,
        value=normalized,
        action=payload.action,
        source=payload.source,
        created_by="local-admin",
        updated_by="local-admin",
    )
    session.add(rule)
    if payload.action.value == "INCLUDE":
        project.status = ProjectStatus.ACTIVE
        project.updated_by = "local-admin"
    await session.flush()
    session.add(
        _audit(
            project_id=project_id,
            action="SCOPE_RULE_ADDED",
            resource_type="scope_rule",
            resource_id=rule.id,
            details={
                "rule_type": rule.rule_type.value,
                "value": rule.value,
                "action": rule.action.value,
            },
        )
    )
    await session.commit()
    await session.refresh(rule)
    return rule


async def remove_scope_rule(session: AsyncSession, project_id: UUID, rule_id: UUID) -> None:
    await get_project_or_404(session, project_id)
    rule = await session.scalar(
        select(ScopeRule).where(ScopeRule.id == rule_id, ScopeRule.project_id == project_id)
    )
    if rule is None:
        raise ScopeGraphError("SCOPE_RULE_NOT_FOUND", "Scope rule was not found", status_code=404)
    session.add(
        _audit(
            project_id=project_id,
            action="SCOPE_RULE_REMOVED",
            resource_type="scope_rule",
            resource_id=rule.id,
            details={"rule_type": rule.rule_type.value, "value": rule.value},
        )
    )
    await session.delete(rule)
    await session.commit()


async def check_scope(
    session: AsyncSession,
    project_id: UUID,
    asset_type: AssetType,
    value: str,
) -> ScopeCheckResponse:
    rules = await list_scope_rules(session, project_id)
    decision = evaluate_scope(
        asset_type,
        value,
        [ScopeRuleValue(rule.rule_type, rule.value, rule.action, rule.id) for rule in rules],
    )
    return ScopeCheckResponse(
        status=decision.status,
        normalized_value=decision.normalized_value,
        reason=decision.reason,
        matched_rule_id=decision.matched_rule_id,
        active_allowed=decision.active_allowed,
    )


async def list_assets(
    session: AsyncSession,
    project_id: UUID,
    *,
    page: int,
    page_size: int,
    asset_type: AssetType | None,
    scope_status: ScopeStatus | None,
    execution_mode: str | None = None,
) -> tuple[list[Asset], int]:
    await get_project_or_404(session, project_id)
    conditions = [Asset.project_id == project_id]
    if asset_type is not None:
        conditions.append(Asset.asset_type == asset_type)
    if scope_status is not None:
        conditions.append(Asset.scope_status == scope_status)
    if execution_mode is not None:
        matching_runs = select(ScanRun.id).where(
        ScanRun.project_id == project_id,
        ScanRun.execution_mode == execution_mode,
        )
        observed = exists(
            select(Observation.id).where(
                Observation.project_id == project_id,
                Observation.scan_run_id.in_(matching_runs),
                or_(
                    Observation.subject_value == Asset.normalized_value,
                    Observation.object_value == Asset.normalized_value,
                ),
            )
        )
        conditions.append(or_(Asset.created_by != "scan-worker", observed))
    total = await session.scalar(select(func.count(Asset.id)).where(*conditions))
    assets = list(
        (
            await session.scalars(
                select(Asset)
                .where(*conditions)
                .order_by(Asset.last_seen_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    return assets, int(total or 0)


async def import_assets(
    session: AsyncSession,
    project_id: UUID,
    items: list[ImportItem],
) -> AssetImportResult:
    await get_project_or_404(session, project_id)
    rules = await list_scope_rules(session, project_id)
    scope_values = [
        ScopeRuleValue(rule.rule_type, rule.value, rule.action, rule.id) for rule in rules
    ]
    normalized: dict[tuple[AssetType, str], tuple[str, ScopeStatus]] = {}
    rejected: list[ImportIssue] = []
    for index, item in enumerate(items, start=1):
        try:
            asset = normalize_asset(item.asset_type, item.value)
            if asset.asset_type in {AssetType.DOMAIN, AssetType.IP, AssetType.URL}:
                status = evaluate_scope(
                    asset.asset_type, asset.normalized_value, scope_values
                ).status
            else:
                status = ScopeStatus.UNKNOWN
            normalized[(asset.asset_type, asset.normalized_value)] = (asset.display_value, status)
        except NormalizationError as exc:
            rejected.append(ImportIssue(index=index, value=item.value, error=str(exc)))

    existing_keys: set[tuple[AssetType, str]] = set()
    if normalized:
        rows = (
            await session.execute(
                select(Asset.asset_type, Asset.normalized_value).where(
                    Asset.project_id == project_id,
                    Asset.normalized_key.in_(
                        [f"{kind.value}:{value}" for kind, value in normalized]
                    ),
                )
            )
        ).all()
        existing_keys = {(row[0], row[1]) for row in rows}

    created_count = 0
    for (kind, value), (display, status) in normalized.items():
        if (kind, value) in existing_keys:
            continue
        statement = (
            pg_insert(Asset)
            .values(
                project_id=project_id,
                asset_type=kind,
                normalized_value=value,
                display_value=display,
                normalized_key=f"{kind.value}:{value}",
                scope_status=status,
                ownership_status=(
                    OwnershipStatus.CONFIRMED
                    if status is ScopeStatus.IN_SCOPE
                    else OwnershipStatus.PENDING_REVIEW
                ),
                confidence_score=100 if status is ScopeStatus.IN_SCOPE else 0,
                metadata_json={},
                created_by="local-admin",
                updated_by="local-admin",
            )
            .on_conflict_do_nothing(index_elements=["project_id", "asset_type", "normalized_value"])
            .returning(Asset.id)
        )
        inserted_id = await session.scalar(statement)
        if inserted_id is not None:
            created_count += 1

    session.add(
        _audit(
            project_id=project_id,
            action="ASSETS_IMPORTED",
            resource_type="asset",
            resource_id=None,
            details={
                "input_count": len(items),
                "normalized_count": len(normalized),
                "created_count": created_count,
                "rejected_count": len(rejected),
            },
        )
    )
    await session.commit()
    valid_input_count = len(items) - len(rejected)
    duplicate_count = valid_input_count - created_count
    return AssetImportResult(
        input_count=len(items),
        normalized_count=len(normalized),
        created_count=created_count,
        duplicate_count=duplicate_count,
        rejected_count=len(rejected),
        rejected=rejected,
    )
