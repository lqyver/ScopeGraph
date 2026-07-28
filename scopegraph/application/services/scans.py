from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.enums import AssetType, ScanStatus
from scopegraph.domain.models import AuditLog, ScanJob, ScanRun, ScopeRule
from scopegraph.scanning.profiles import ScanProfileConfig, load_profile
from scopegraph.scanning.state_machine import (
    InvalidStateTransition,
    make_idempotency_key,
    transition,
)
from scopegraph.schemas.scans import ScanEvent, ScanRunCreate
from scopegraph.scope_engine import ScopeRuleValue, evaluate_scope, require_active_scope
from scopegraph.tooling.adapters import ADAPTERS


def _stage_timeout_seconds(adapter_name: str, profile: ScanProfileConfig) -> int:
    manifest_timeout = ADAPTERS[adapter_name].manifest.timeout_seconds
    if adapter_name == "katana":
        return min(manifest_timeout, profile.crawler_max_duration_seconds + 60)
    if adapter_name == "screenshot":
        return min(manifest_timeout, profile.job_timeout_seconds)
    interactive_caps = {
        "subfinder": 180,
        "puredns": 180,
        "alterx": 120,
        "dnsx": 180,
        "naabu": 300,
        "nmap": 300,
        "httpx": 300,
        "nuclei": 1_200,
    }
    return min(manifest_timeout, profile.job_timeout_seconds, interactive_caps[adapter_name])


async def get_scan_run_or_404(session: AsyncSession, scan_run_id: UUID) -> ScanRun:
    run = await session.get(ScanRun, scan_run_id)
    if run is None:
        raise ScopeGraphError("SCAN_RUN_NOT_FOUND", "Scan run was not found", status_code=404)
    return run


async def get_scan_job_or_404(session: AsyncSession, scan_job_id: UUID) -> ScanJob:
    job = await session.get(ScanJob, scan_job_id)
    if job is None:
        raise ScopeGraphError("SCAN_JOB_NOT_FOUND", "Scan job was not found", status_code=404)
    return job


def _audit(run: ScanRun, action: str, resource_type: str, resource_id: UUID) -> AuditLog:
    return AuditLog(
        project_id=run.project_id,
        actor="local-admin",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        details={"scan_run_id": str(run.id)},
    )


async def _scope_values(session: AsyncSession, project_id: UUID) -> list[ScopeRuleValue]:
    rules = list(await session.scalars(select(ScopeRule).where(ScopeRule.project_id == project_id)))
    return [ScopeRuleValue(rule.rule_type, rule.value, rule.action, rule.id) for rule in rules]


async def create_scan_run(
    session: AsyncSession, project_id: UUID, payload: ScanRunCreate
) -> ScanRun:
    await get_project_or_404(session, project_id)
    decision = evaluate_scope(
        AssetType.DOMAIN, payload.root_domain, await _scope_values(session, project_id)
    )
    require_active_scope(decision)
    if payload.execution_mode == "host" and not payload.allow_active_execution:
        raise ScopeGraphError(
            "ACTIVE_EXECUTION_CONFIRMATION_REQUIRED",
            "Host execution requires explicit active-execution confirmation",
            status_code=409,
        )

    custom_config = payload.custom_config.model_dump(mode="json") if payload.custom_config else None
    try:
        profile_config = load_profile(payload.profile, custom_config)
    except ValueError as exc:
        raise ScopeGraphError("INVALID_SCAN_PROFILE", str(exc), status_code=422) from exc
    if payload.screenshot_enabled is not None:
        profile_config = profile_config.model_copy(
            update={"screenshot_enabled": payload.screenshot_enabled}
        )
    if payload.port_scan_enabled is True and not profile_config.port_scan_enabled:
        raise ScopeGraphError(
            "PROFILE_PORT_SCAN_DISABLED",
            "The selected profile does not permit port scanning",
            status_code=409,
        )
    effective_port_scan = (
        profile_config.port_scan_enabled and payload.port_scan_enabled is not False
    )
    if payload.full_port_scan and not effective_port_scan:
        raise ScopeGraphError(
            "FULL_PORT_SCAN_DISABLED",
            "Full-port scanning requires a port-enabled profile",
            status_code=409,
        )
    if payload.nuclei_enabled and not profile_config.nuclei_allowed:
        raise ScopeGraphError(
            "PROFILE_NUCLEI_DISABLED",
            "The selected profile does not permit Nuclei security discovery",
            status_code=409,
        )

    stages: list[tuple[str, str, dict[str, object]]] = []
    if profile_config.passive_subdomain:
        stages.append(
            ("passive_subdomain", "subfinder", {"root_domain": decision.normalized_value})
        )
    if profile_config.dns_bruteforce:
        stages.append(
            (
                "dns_bruteforce_validation",
                "puredns",
                {"root_domain": decision.normalized_value, "candidates": []},
            )
        )
    if profile_config.domain_variants:
        stages.append(
            ("domain_variants", "alterx", {"domains": [], "limit": profile_config.variant_limit})
        )
        stages.append(
            (
                "dns_permutation_validation",
                "puredns",
                {"root_domain": decision.normalized_value, "candidates": []},
            )
        )
    if profile_config.dns_enrichment:
        stages.append(("dns_enrichment", "dnsx", {"domains": []}))
    if effective_port_scan:
        stages.append(("port_discovery", "naabu", {"ips": [], "ports": []}))
    if effective_port_scan and profile_config.service_detection:
        stages.append(("service_detection", "nmap", {"targets": []}))
    if profile_config.http_probe:
        stages.append(("http_probe", "httpx", {"domains": []}))
    if profile_config.http_probe and profile_config.screenshot_enabled:
        stages.append(("website_screenshot", "screenshot", {"urls": []}))
    if profile_config.http_probe and profile_config.crawler_enabled:
        stages.append(("web_crawl", "katana", {"urls": []}))
    if payload.nuclei_enabled:
        stages.append(("safe_security_discovery", "nuclei", {"urls": []}))

    config_snapshot = {
        "chain": [adapter_name for _, adapter_name, _ in stages],
        "execution_strategy": "parallel_dag_v1",
        "max_parallel_stages": 4,
        "execution_mode": payload.execution_mode,
        "root_domain": decision.normalized_value,
        "profile": profile_config.model_dump(mode="json"),
        "port_scan_enabled": effective_port_scan,
        "deep_confirmation": payload.deep_confirmation,
        "full_port_scan": payload.full_port_scan,
        "full_port_confirmation": payload.full_port_confirmation,
        "nuclei_enabled": payload.nuclei_enabled,
        "nuclei_confirmation": payload.nuclei_confirmation,
        "proxy_url": payload.proxy_url,
        "scope_checked_at": datetime.now(UTC).isoformat(),
        "active_execution_confirmed": payload.allow_active_execution,
    }
    run = ScanRun(
        project_id=project_id,
        profile=payload.profile,
        config_snapshot=config_snapshot,
        status=ScanStatus.QUEUED,
        progress=0,
        summary={"observations": 0, "assets_created": 0},
        created_by="local-admin",
        updated_by="local-admin",
    )
    session.add(run)
    await session.flush()

    for index, (job_type, adapter_name, input_ref) in enumerate(stages):
        session.add(
            ScanJob(
                scan_run_id=run.id,
                sequence=index,
                job_type=job_type,
                adapter_name=adapter_name,
                input_ref=input_ref,
                idempotency_key=make_idempotency_key(
                    job_type, adapter_name, {"root_domain": decision.normalized_value}
                ),
                status=ScanStatus.QUEUED if index == 0 else ScanStatus.PENDING,
                timeout_seconds=_stage_timeout_seconds(adapter_name, profile_config),
                max_attempts=2,
                created_by="local-admin",
                updated_by="local-admin",
            )
        )
    session.add(_audit(run, "SCAN_RUN_CREATED", "scan_run", run.id))
    await session.commit()
    await session.refresh(run)
    return run


async def list_scan_runs(
    session: AsyncSession, project_id: UUID, *, page: int, page_size: int
) -> tuple[list[ScanRun], int]:
    await get_project_or_404(session, project_id)
    total = await session.scalar(
        select(func.count(ScanRun.id)).where(ScanRun.project_id == project_id)
    )
    items = list(
        await session.scalars(
            select(ScanRun)
            .where(ScanRun.project_id == project_id)
            .order_by(ScanRun.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return items, int(total or 0)


async def list_scan_jobs(session: AsyncSession, scan_run_id: UUID) -> list[ScanJob]:
    await get_scan_run_or_404(session, scan_run_id)
    return list(
        await session.scalars(
            select(ScanJob)
            .where(ScanJob.scan_run_id == scan_run_id)
            .order_by(ScanJob.sequence.asc())
        )
    )


async def list_scan_overview(
    session: AsyncSession, project_id: UUID, *, page: int, page_size: int
) -> tuple[list[ScanRun], dict[UUID, list[ScanJob]], int]:
    runs, total = await list_scan_runs(session, project_id, page=page, page_size=page_size)
    jobs_by_run: dict[UUID, list[ScanJob]] = {run.id: [] for run in runs}
    if runs:
        jobs = list(
            await session.scalars(
                select(ScanJob)
                .where(ScanJob.scan_run_id.in_([run.id for run in runs]))
                .order_by(ScanJob.scan_run_id, ScanJob.sequence)
            )
        )
        for job in jobs:
            jobs_by_run[job.scan_run_id].append(job)
    return runs, jobs_by_run, total


async def pause_scan_run(session: AsyncSession, scan_run_id: UUID) -> ScanRun:
    run = await get_scan_run_or_404(session, scan_run_id)
    try:
        run.status = transition(run.status, ScanStatus.PAUSED)
    except InvalidStateTransition as exc:
        raise ScopeGraphError("INVALID_SCAN_STATE", str(exc), status_code=409) from exc
    jobs = await list_scan_jobs(session, run.id)
    for job in jobs:
        if job.status is ScanStatus.QUEUED:
            job.status = ScanStatus.PAUSED
    session.add(_audit(run, "SCAN_RUN_PAUSED", "scan_run", run.id))
    await session.commit()
    await session.refresh(run)
    return run


async def resume_scan_run(session: AsyncSession, scan_run_id: UUID) -> ScanRun:
    run = await get_scan_run_or_404(session, scan_run_id)
    try:
        run.status = transition(run.status, ScanStatus.QUEUED)
    except InvalidStateTransition as exc:
        raise ScopeGraphError("INVALID_SCAN_STATE", str(exc), status_code=409) from exc
    jobs = await list_scan_jobs(session, run.id)
    for job in jobs:
        if job.status is ScanStatus.PAUSED:
            job.status = ScanStatus.QUEUED
            break
    session.add(_audit(run, "SCAN_RUN_RESUMED", "scan_run", run.id))
    await session.commit()
    await session.refresh(run)
    return run


async def cancel_scan_run(session: AsyncSession, scan_run_id: UUID) -> ScanRun:
    run = await get_scan_run_or_404(session, scan_run_id)
    if run.status in {ScanStatus.SUCCESS, ScanStatus.CANCELLED}:
        raise ScopeGraphError(
            "INVALID_SCAN_STATE", f"Cannot cancel a {run.status} scan run", status_code=409
        )
    run.cancellation_requested = True
    jobs = await list_scan_jobs(session, run.id)
    for job in jobs:
        if job.status in {ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.PAUSED}:
            job.status = ScanStatus.CANCELLED
            job.finished_at = datetime.now(UTC)
    if all(job.status is not ScanStatus.RUNNING for job in jobs):
        run.status = ScanStatus.CANCELLED
        run.finished_at = datetime.now(UTC)
    session.add(_audit(run, "SCAN_RUN_CANCEL_REQUESTED", "scan_run", run.id))
    await session.commit()
    await session.refresh(run)
    return run


async def retry_scan_job(session: AsyncSession, scan_job_id: UUID) -> tuple[ScanJob, ScanRun]:
    job = await get_scan_job_or_404(session, scan_job_id)
    run = await get_scan_run_or_404(session, job.scan_run_id)
    if job.attempt >= job.max_attempts:
        raise ScopeGraphError(
            "RETRY_LIMIT_REACHED", "Scan job retry limit reached", status_code=409
        )
    try:
        job.status = transition(job.status, ScanStatus.QUEUED)
    except InvalidStateTransition as exc:
        raise ScopeGraphError("INVALID_SCAN_STATE", str(exc), status_code=409) from exc
    job.error_code = None
    job.error_message = None
    job.finished_at = None
    run.status = ScanStatus.QUEUED
    run.finished_at = None
    run.cancellation_requested = False
    session.add(_audit(run, "SCAN_JOB_RETRIED", "scan_job", job.id))
    await session.commit()
    await session.refresh(job)
    await session.refresh(run)
    return job, run


async def scan_events(session: AsyncSession, scan_run_id: UUID) -> list[ScanEvent]:
    run = await get_scan_run_or_404(session, scan_run_id)
    jobs = await list_scan_jobs(session, scan_run_id)
    events = [
        ScanEvent(
            event_type="scan_run",
            scan_run_id=run.id,
            status=run.status,
            progress=run.progress,
            message=f"Scan run is {run.status}",
            occurred_at=run.updated_at,
        )
    ]
    events.extend(
        ScanEvent(
            event_type="scan_job",
            scan_run_id=run.id,
            scan_job_id=job.id,
            status=job.status,
            progress=run.progress,
            message=f"{job.adapter_name} is {job.status}",
            occurred_at=job.updated_at,
        )
        for job in jobs
    )
    return events
