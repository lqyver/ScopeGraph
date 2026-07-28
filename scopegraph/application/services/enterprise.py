import asyncio
import hashlib
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.enums import (
    AssetType,
    CandidateRootStatus,
    EnterpriseDiscoveryStatus,
    OwnershipStatus,
    ScopeAction,
    ScopeRuleType,
)
from scopegraph.domain.models import (
    Asset,
    AuditLog,
    CandidateRootDomain,
    EnterpriseDiscoveryRun,
    Evidence,
    ScopeRule,
)
from scopegraph.enterprise.names import build_company_profile
from scopegraph.enterprise.ownership import OwnershipRules, score_signals
from scopegraph.enterprise.sources import (
    BingSearchSource,
    CandidateSignal,
    CertificateTransparencyDomainSource,
    PublicSearchSource,
    RdapRegistrantSource,
    RecordedSource,
    SourceResult,
    denied_source_domains,
)
from scopegraph.infrastructure.config import get_settings
from scopegraph.normalizers import NormalizationError, registrable_root_domain
from scopegraph.schemas.enterprise import EnterpriseDiscoveryRequest, ManualCandidateRequest

_MAX_ENRICHMENT_SEEDS = 4


async def _local_scope_source(session: AsyncSession, project_id: UUID) -> SourceResult:
    roots = list(
        (
            await session.scalars(
                select(ScopeRule).where(
                    ScopeRule.project_id == project_id,
                    ScopeRule.rule_type == ScopeRuleType.ROOT_DOMAIN,
                    ScopeRule.action == ScopeAction.INCLUDE,
                )
            )
        ).all()
    )
    return SourceResult(
        "local-scope",
        tuple(
            CandidateSignal(
                rule.value,
                "local-scope",
                "scopegraph://scope-rule",
                ("CONFIRMED_ROOT",),
                "local-scope",
            )
            for rule in roots
        ),
        category="local",
    )


async def _asset_for_candidate(session: AsyncSession, project_id: UUID, domain: str) -> Asset:
    asset = await session.scalar(
        select(Asset).where(
            Asset.project_id == project_id,
            Asset.asset_type == AssetType.DOMAIN,
            Asset.normalized_value == domain,
        )
    )
    if asset is not None:
        return asset
    asset = Asset(
        project_id=project_id,
        asset_type=AssetType.DOMAIN,
        normalized_value=domain,
        display_value=domain,
        normalized_key=f"domain:{domain}",
        scope_status="PENDING_REVIEW",
        ownership_status=OwnershipStatus.PENDING_REVIEW,
        confidence_score=0,
        metadata_json={"discovery_source": "enterprise"},
        created_by="local-admin",
        updated_by="local-admin",
    )
    session.add(asset)
    await session.flush()
    return asset


def _evidence_hash(project_id: UUID, domain: str, signal: str, source: str, url: str) -> str:
    raw = f"{project_id}|{domain}|{signal}|{source}|{url}".encode()
    return hashlib.sha256(raw).hexdigest()


async def _persist_candidate(
    session: AsyncSession,
    *,
    run: EnterpriseDiscoveryRun,
    domain: str,
    rows: list[CandidateSignal],
    rules: OwnershipRules,
) -> CandidateRootDomain:
    asset = await _asset_for_candidate(session, run.project_id, domain)
    candidate = await session.scalar(
        select(CandidateRootDomain).where(
            CandidateRootDomain.project_id == run.project_id,
            CandidateRootDomain.root_domain == domain,
        )
    )
    signals = [signal for row in rows for signal in row.signals]
    source_families = {row.source_family or row.source for row in rows}
    if len(source_families) > 1:
        signals.append("MULTI_SOURCE")
    result = score_signals(signals, rules)
    summary = [
        {"signal": signal, "weight": weight, "rule_version": rules.version}
        for signal, weight in result.applied
    ]
    if candidate is None:
        candidate = CandidateRootDomain(
            project_id=run.project_id,
            discovery_run_id=run.id,
            asset_id=asset.id,
            root_domain=domain,
            display_domain=domain,
            score=result.score,
            raw_score=result.raw_score,
            status=result.status,
            source_count=len(source_families),
            evidence_summary=summary,
            source_failures=[],
            created_by="system",
            updated_by="system",
        )
        session.add(candidate)
    elif candidate.status not in {CandidateRootStatus.CONFIRMED, CandidateRootStatus.REJECTED}:
        candidate.discovery_run_id = run.id
        candidate.score = result.score
        candidate.raw_score = result.raw_score
        candidate.status = result.status
        candidate.source_count = len(source_families)
        candidate.evidence_summary = summary
        candidate.updated_by = "system"
    if candidate.status not in {CandidateRootStatus.CONFIRMED, CandidateRootStatus.REJECTED}:
        asset.confidence_score = result.score
        asset.ownership_status = result.ownership_status
        asset.updated_by = "system"
    await session.flush()

    now = datetime.now(UTC)
    for row in rows:
        for signal in dict.fromkeys(row.signals):
            weight = rules.weights.get(signal)
            if weight is None:
                continue
            statement = (
                pg_insert(Evidence)
                .values(
                    evidence_hash=_evidence_hash(
                        run.project_id, domain, signal, row.source, row.source_url
                    ),
                    project_id=run.project_id,
                    asset_id=asset.id,
                    evidence_type=signal,
                    value=domain,
                    score_delta=weight,
                    source_tool=row.source,
                    source_url=row.source_url,
                    observed_at=now,
                    is_manual=False,
                    metadata_json={
                        "rule_version": rules.version,
                        "discovery_run_id": str(run.id),
                        "source_family": row.source_family or row.source,
                    },
                )
                .on_conflict_do_nothing(index_elements=["project_id", "evidence_hash"])
            )
            await session.execute(statement)
    return candidate


_SOURCE_CATEGORIES = {
    "local-scope": "local",
    "recorded-public-search": "fixture",
    "duckduckgo-html": "public-search",
    "bing-html": "public-search",
    "crtsh-domain-verify": "certificate-transparency",
    "rdap-registrant": "registration",
}
_TERMINAL_SOURCE_STATUSES = {"COMPLETED", "PARTIAL", "UNAVAILABLE", "SKIPPED"}


def _planned_source_records(
    execution_mode: str, search_keyword_count: int
) -> list[dict[str, Any]]:
    names = ["local-scope"]
    if execution_mode == "fixture":
        names.append("recorded-public-search")
    elif execution_mode == "public":
        names.extend(
            [
                "duckduckgo-html",
                "bing-html",
                "crtsh-domain-verify",
                "rdap-registrant",
            ]
        )
    query_count = min(search_keyword_count, 2)
    records: list[dict[str, Any]] = []
    for name in names:
        records.append(
            {
                "source": name,
                "category": _SOURCE_CATEGORIES[name],
                "status": "PENDING",
                "candidate_count": 0,
                "attempted_count": query_count if name in {"duckduckgo-html", "bing-html"} else 0,
                "completed_count": 0,
                "skipped_reason": None,
                "error": None,
            }
        )
    return records


def _source_record(result: SourceResult) -> dict[str, Any]:
    return {
        "source": result.source,
        "category": result.category,
        "status": result.status,
        "candidate_count": len(result.candidates),
        "attempted_count": result.attempted_count,
        "completed_count": result.completed_count,
        "skipped_reason": result.skipped_reason,
        "error": result.error,
    }


def _group_candidate_signals(
    results: list[SourceResult], denied: set[str]
) -> tuple[dict[str, list[CandidateSignal]], list[str]]:
    grouped: dict[str, list[CandidateSignal]] = defaultdict(list)
    rejected_values: list[str] = []
    for result in results:
        for row in result.candidates:
            try:
                root = registrable_root_domain(row.domain)
            except NormalizationError:
                rejected_values.append(row.domain)
                continue
            if root in denied:
                continue
            grouped[root].append(
                CandidateSignal(
                    root,
                    row.source,
                    row.source_url,
                    row.signals,
                    row.source_family,
                )
            )
    return grouped, rejected_values


def _enrichment_seeds(results: list[SourceResult], denied: set[str]) -> list[str]:
    source_families: dict[str, set[str]] = defaultdict(set)
    for result in results:
        for row in result.candidates:
            try:
                root = registrable_root_domain(row.domain)
            except NormalizationError:
                continue
            if root not in denied:
                source_families[root].add(row.source_family or row.source)
    return sorted(
        source_families,
        key=lambda domain: (-len(source_families[domain]), domain),
    )[:_MAX_ENRICHMENT_SEEDS]


def _progress_summary(
    records: list[dict[str, Any]],
    *,
    stage: str,
    candidate_count: int = 0,
    corroborated_candidate_count: int = 0,
    enrichment_seed_count: int = 0,
    rejected_value_count: int = 0,
    failure_reason: str | None = None,
) -> dict[str, Any]:
    total = len(records)
    completed = sum(item["status"] == "COMPLETED" for item in records)
    partial = sum(item["status"] == "PARTIAL" for item in records)
    unavailable = sum(item["status"] == "UNAVAILABLE" for item in records)
    skipped = sum(item["status"] == "SKIPPED" for item in records)
    running = sum(item["status"] == "RUNNING" for item in records)
    pending = sum(item["status"] == "PENDING" for item in records)
    terminal = completed + partial + unavailable + skipped
    return {
        "candidate_count": candidate_count,
        "source_count": total,
        "source_failure_count": sum(bool(item.get("error")) for item in records),
        "source_completed_count": completed,
        "source_partial_count": partial,
        "source_unavailable_count": unavailable,
        "source_skipped_count": skipped,
        "source_running_count": running,
        "source_pending_count": pending,
        "source_attempted_count": sum(int(item.get("attempted_count") or 0) for item in records),
        "source_successful_request_count": sum(
            int(item.get("completed_count") or 0) for item in records
        ),
        "corroborated_candidate_count": corroborated_candidate_count,
        "enrichment_seed_count": enrichment_seed_count,
        "rejected_value_count": rejected_value_count,
        "failure_reason": failure_reason,
        "stage": stage,
        "progress_percent": int((terminal / total) * 100) if total else 100,
    }


async def _commit_progress(
    session: AsyncSession,
    run: EnterpriseDiscoveryRun,
    records: list[dict[str, Any]],
    *,
    stage: str,
    results: list[SourceResult | None],
    denied: set[str],
    enrichment_seed_count: int,
) -> None:
    grouped, rejected_values = _group_candidate_signals(
        [result for result in results if result is not None], denied
    )
    run.source_results = [dict(item) for item in records]
    run.summary = _progress_summary(
        records,
        stage=stage,
        candidate_count=len(grouped),
        enrichment_seed_count=enrichment_seed_count,
        rejected_value_count=len(rejected_values),
    )
    run.updated_by = "system"
    await session.commit()


async def _safe_discover(source: Any, profile: Any) -> SourceResult:
    try:
        return cast(SourceResult, await source.discover(profile))
    except Exception as exc:  # Source-specific failures must not strand the run.
        return SourceResult(
            source.name,
            (),
            f"INTERNAL_SOURCE_ERROR: {type(exc).__name__}",
            category=getattr(source, "category", "passive"),
            attempted_count=1,
            completed_count=0,
        )


async def _create_enterprise_discovery_run(
    session: AsyncSession,
    project_id: UUID,
    payload: EnterpriseDiscoveryRequest,
) -> EnterpriseDiscoveryRun:
    project = await get_project_or_404(session, project_id)
    profile = build_company_profile(project.company_name, payload.aliases)
    now = datetime.now(UTC)
    records = _planned_source_records(payload.execution_mode, len(profile.search_keywords))
    run = EnterpriseDiscoveryRun(
        project_id=project_id,
        status=EnterpriseDiscoveryStatus.RUNNING,
        company_normalized_name=profile.normalized_name,
        aliases=list(profile.aliases),
        search_keywords=list(profile.search_keywords),
        execution_mode=payload.execution_mode,
        source_results=records,
        summary=_progress_summary(records, stage="QUEUED"),
        started_at=now,
        created_by="local-admin",
        updated_by="local-admin",
    )
    session.add(run)
    await session.flush()
    session.add(
        AuditLog(
            project_id=project_id,
            actor="local-admin",
            action="ENTERPRISE_DISCOVERY_STARTED",
            resource_type="enterprise_discovery_run",
            resource_id=str(run.id),
            details={"execution_mode": payload.execution_mode, "source_count": len(records)},
        )
    )
    return run


async def start_enterprise_discovery(
    session: AsyncSession,
    project_id: UUID,
    payload: EnterpriseDiscoveryRequest,
) -> EnterpriseDiscoveryRun:
    """Persist a RUNNING discovery record before a worker begins source collection."""

    run = await _create_enterprise_discovery_run(session, project_id, payload)
    await session.commit()
    await session.refresh(run)
    return run


async def get_enterprise_discovery_run(
    session: AsyncSession,
    project_id: UUID,
    run_id: UUID,
) -> EnterpriseDiscoveryRun:
    await get_project_or_404(session, project_id)
    run = await session.get(EnterpriseDiscoveryRun, run_id)
    if run is None or run.project_id != project_id:
        raise ScopeGraphError(
            "ENTERPRISE_DISCOVERY_NOT_FOUND",
            "Enterprise discovery run was not found",
            status_code=404,
        )
    return run


async def _finalize_enterprise_discovery(
    session: AsyncSession,
    run: EnterpriseDiscoveryRun,
    records: list[dict[str, Any]],
    results: list[SourceResult | None],
    denied: set[str],
    enrichment_seed_count: int,
) -> EnterpriseDiscoveryRun:
    completed_results = [result for result in results if result is not None]
    grouped, rejected_values = _group_candidate_signals(completed_results, denied)
    rules = OwnershipRules.load()
    for domain, rows in grouped.items():
        await _persist_candidate(session, run=run, domain=domain, rows=rows, rules=rules)

    failures = [item for item in records if item.get("error")]
    corroborated_candidate_count = sum(
        1 for rows in grouped.values() if len({row.source_family or row.source for row in rows}) > 1
    )
    run.source_results = [dict(item) for item in records]
    run.summary = _progress_summary(
        records,
        stage="COMPLETED",
        candidate_count=len(grouped),
        corroborated_candidate_count=corroborated_candidate_count,
        enrichment_seed_count=enrichment_seed_count,
        rejected_value_count=len(rejected_values),
        failure_reason="NO_CANDIDATE_ROOTS" if not grouped else None,
    )
    run.status = (
        EnterpriseDiscoveryStatus.FAILED
        if not grouped
        else EnterpriseDiscoveryStatus.PARTIAL_SUCCESS
        if failures
        else EnterpriseDiscoveryStatus.SUCCESS
    )
    run.finished_at = datetime.now(UTC)
    run.updated_by = "system"
    session.add(
        AuditLog(
            project_id=run.project_id,
            actor="local-admin",
            action="ENTERPRISE_DISCOVERY_COMPLETED",
            resource_type="enterprise_discovery_run",
            resource_id=str(run.id),
            details={"status": run.status.value, **run.summary},
        )
    )
    await session.commit()
    await session.refresh(run)
    return run


async def _mark_enterprise_discovery_failed(
    session: AsyncSession,
    run: EnterpriseDiscoveryRun,
    exc: Exception,
) -> EnterpriseDiscoveryRun:
    records = [dict(item) for item in run.source_results]
    run.status = EnterpriseDiscoveryStatus.FAILED
    run.summary = _progress_summary(
        records,
        stage="FAILED",
        failure_reason=f"INTERNAL_EXECUTION_ERROR: {type(exc).__name__}",
    )
    run.finished_at = datetime.now(UTC)
    run.updated_by = "system"
    session.add(
        AuditLog(
            project_id=run.project_id,
            actor="local-admin",
            action="ENTERPRISE_DISCOVERY_FAILED",
            resource_type="enterprise_discovery_run",
            resource_id=str(run.id),
            details={"error_type": type(exc).__name__},
        )
    )
    await session.commit()
    await session.refresh(run)
    return run


async def _execute_enterprise_discovery_in_session(
    session: AsyncSession, run: EnterpriseDiscoveryRun
) -> EnterpriseDiscoveryRun:
    project = await get_project_or_404(session, run.project_id)
    profile = build_company_profile(project.company_name, run.aliases)
    denied = denied_source_domains()
    records = [dict(item) for item in run.source_results]
    results: list[SourceResult | None] = [None] * len(records)
    index_by_source = {str(item["source"]): index for index, item in enumerate(records)}
    enrichment_seed_count = 0

    async def publish(stage: str) -> None:
        await _commit_progress(
            session,
            run,
            records,
            stage=stage,
            results=results,
            denied=denied,
            enrichment_seed_count=enrichment_seed_count,
        )

    async def mark_running(source_names: list[str], stage: str) -> None:
        for source_name in source_names:
            record = records[index_by_source[source_name]]
            record["status"] = "RUNNING"
            record["error"] = None
            record["skipped_reason"] = None
        await publish(stage)

    async def save_result(index: int, result: SourceResult) -> None:
        results[index] = result
        records[index] = _source_record(result)
        await publish(f"{result.source}: {result.status}")

    await mark_running(["local-scope"], "local-scope")
    await save_result(
        index_by_source["local-scope"],
        await _local_scope_source(session, run.project_id),
    )

    if run.execution_mode == "fixture":
        await mark_running(["recorded-public-search"], "recorded-public-search")
        await save_result(
            index_by_source["recorded-public-search"],
            await _safe_discover(RecordedSource(), profile),
        )
    elif run.execution_mode == "public":
        search_sources = [
            ("duckduckgo-html", PublicSearchSource()),
            ("bing-html", BingSearchSource()),
        ]
        await mark_running([name for name, _ in search_sources], "public-search")

        async def collect(index: int, source: Any) -> tuple[int, SourceResult]:
            return index, await _safe_discover(source, profile)

        search_tasks = [
            asyncio.create_task(collect(index_by_source[name], source))
            for name, source in search_sources
        ]
        for task in asyncio.as_completed(search_tasks):
            index, result = await task
            await save_result(index, result)

        seed_roots = _enrichment_seeds(
            [result for result in results if result is not None], denied
        )
        enrichment_seed_count = len(seed_roots)
        enrichment_sources = [
            ("crtsh-domain-verify", CertificateTransparencyDomainSource(seed_roots)),
            ("rdap-registrant", RdapRegistrantSource(seed_roots)),
        ]
        await mark_running([name for name, _ in enrichment_sources], "candidate-corroboration")
        enrichment_tasks = [
            asyncio.create_task(collect(index_by_source[name], source))
            for name, source in enrichment_sources
        ]
        for task in asyncio.as_completed(enrichment_tasks):
            index, result = await task
            await save_result(index, result)

    return await _finalize_enterprise_discovery(
        session,
        run,
        records,
        results,
        denied,
        enrichment_seed_count,
    )


async def run_enterprise_discovery(
    session: AsyncSession,
    project_id: UUID,
    payload: EnterpriseDiscoveryRequest,
) -> EnterpriseDiscoveryRun:
    """Run discovery inline for CLI and existing synchronous API clients."""

    run = await _create_enterprise_discovery_run(session, project_id, payload)
    try:
        return await _execute_enterprise_discovery_in_session(session, run)
    except Exception as exc:
        return await _mark_enterprise_discovery_failed(session, run, exc)


async def execute_enterprise_discovery(run_id: UUID) -> None:
    """Worker entrypoint for the observable asynchronous enterprise flow."""

    settings = get_settings()
    execution_engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    session_factory = async_sessionmaker(execution_engine, expire_on_commit=False)
    try:
        async with session_factory() as session:
            run = await session.get(EnterpriseDiscoveryRun, run_id)
            if run is None or run.status != EnterpriseDiscoveryStatus.RUNNING:
                return
            try:
                await _execute_enterprise_discovery_in_session(session, run)
            except Exception as exc:
                await _mark_enterprise_discovery_failed(session, run, exc)
    finally:
        await execution_engine.dispose()


async def list_candidates(session: AsyncSession, project_id: UUID) -> list[CandidateRootDomain]:
    await get_project_or_404(session, project_id)
    return list(
        (
            await session.scalars(
                select(CandidateRootDomain)
                .where(CandidateRootDomain.project_id == project_id)
                .order_by(CandidateRootDomain.score.desc(), CandidateRootDomain.root_domain)
            )
        ).all()
    )


async def candidate_evidence(
    session: AsyncSession, candidate: CandidateRootDomain
) -> list[Evidence]:
    return list(
        (
            await session.scalars(
                select(Evidence)
                .where(
                    Evidence.project_id == candidate.project_id,
                    Evidence.asset_id == candidate.asset_id,
                )
                .order_by(Evidence.score_delta.desc(), Evidence.observed_at.desc())
            )
        ).all()
    )


async def add_manual_candidate(
    session: AsyncSession,
    project_id: UUID,
    payload: ManualCandidateRequest,
) -> CandidateRootDomain:
    await get_project_or_404(session, project_id)
    try:
        domain = registrable_root_domain(payload.domain)
    except NormalizationError as exc:
        raise ScopeGraphError("INVALID_CANDIDATE_DOMAIN", str(exc), status_code=422) from exc
    run = EnterpriseDiscoveryRun(
        project_id=project_id,
        status=EnterpriseDiscoveryStatus.SUCCESS,
        company_normalized_name="manual",
        aliases=[],
        search_keywords=[],
        execution_mode="local",
        source_results=[{"source": "manual", "candidate_count": 1, "error": None}],
        summary={"candidate_count": 1, "manual": True},
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        created_by="local-admin",
        updated_by="local-admin",
    )
    session.add(run)
    await session.flush()
    candidate = await _persist_candidate(
        session,
        run=run,
        domain=domain,
        rows=[
            CandidateSignal(
                domain,
                "manual",
                "scopegraph://manual",
                ("CONFIRMED_ROOT",),
                "manual",
            )
        ],
        rules=OwnershipRules.load(),
    )
    session.add(
        AuditLog(
            project_id=project_id,
            actor="local-admin",
            action="MANUAL_CANDIDATE_ADDED",
            resource_type="candidate_root_domain",
            resource_id=str(candidate.id),
            details={"domain": domain, "reason": payload.reason},
        )
    )
    await session.commit()
    await session.refresh(candidate)
    return candidate
