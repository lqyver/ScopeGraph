import asyncio
import logging
import math
import shutil
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import delete, exists, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.sql.elements import ColumnElement

from scopegraph.application.services.web_persistence import (
    infer_root_icp_links,
    persist_web_observation,
)
from scopegraph.domain.enums import (
    AssetType,
    DNSRecordType,
    FindingSeverity,
    FindingStatus,
    IPClassification,
    OwnershipStatus,
    PortState,
    RelationType,
    ScanStatus,
    ScopeStatus,
    TransportProtocol,
)
from scopegraph.domain.models import (
    Asset,
    AssetRelation,
    DNSRecord,
    FileArtifact,
    Finding,
    IPDetail,
    Observation,
    Port,
    ScanJob,
    ScanRun,
    ScopeRule,
    Service,
    Website,
    WebSnapshot,
)
from scopegraph.infrastructure.config import get_settings
from scopegraph.normalizers.assets import normalize_asset, normalize_domain
from scopegraph.scanning.observations import ObservationPayload
from scopegraph.scanning.port_policy import classify_ip, decide_port_scan
from scopegraph.scanning.profiles import ScanProfileConfig
from scopegraph.scanning.state_machine import TERMINAL_STATUSES, aggregate_run_state
from scopegraph.scanning.third_party import classify_cname
from scopegraph.scope_engine import ScopeRuleValue, evaluate_scope, require_active_scope
from scopegraph.tooling.adapters import ADAPTERS
from scopegraph.tooling.artifacts import ArtifactStore, StoredArtifact
from scopegraph.tooling.base import (
    AdapterContext,
    OutputParseError,
    ToolUnavailableError,
    clean_tool_output,
    detected_tool_version,
    version_output_is_compatible,
)
from scopegraph.tooling.process import ProcessOutcome, SafeProcessRunner

_fixtures = Path(__file__).parents[2] / "tooling" / "fixtures"
_dns_wordlist = Path(__file__).parents[3] / "configs" / "dns_wordlist.txt"
_relation_types = {
    "HAS_SUBDOMAIN": RelationType.HAS_SUBDOMAIN,
    "RESOLVES_TO": RelationType.RESOLVES_TO,
    "CNAME_TO": RelationType.CNAME_TO,
    "SERVES_WEBSITE": RelationType.SERVES_WEBSITE,
    "HOSTS_SERVICE": RelationType.HOSTS_SERVICE,
    "HAS_ICP_RECORD": RelationType.HAS_ICP_RECORD,
    "DISCOVERED_ENDPOINT": RelationType.DISCOVERED_FROM,
}

_JOB_DEPENDENCIES: dict[str, set[str]] = {
    "passive_subdomain": set(),
    "dns_bruteforce_validation": {"passive_subdomain"},
    "domain_variants": {"passive_subdomain"},
    "dns_permutation_validation": {"dns_bruteforce_validation", "domain_variants"},
    "dns_enrichment": {
        "passive_subdomain",
        "dns_bruteforce_validation",
        "domain_variants",
        "dns_permutation_validation",
    },
    "port_discovery": {"dns_enrichment"},
    "service_detection": {"port_discovery"},
    "http_probe": {"dns_enrichment"},
    "website_screenshot": {"http_probe"},
    "web_crawl": {"http_probe"},
    "safe_security_discovery": {"http_probe"},
}


def _job_waves(jobs: list[ScanJob]) -> list[list[UUID]]:
    """Return dependency-safe execution waves while preserving stage order."""

    present = {job.job_type for job in jobs}
    remaining = sorted(jobs, key=lambda item: item.sequence)
    completed_types: set[str] = set()
    waves: list[list[UUID]] = []
    while remaining:
        ready = [
            job
            for job in remaining
            if (_JOB_DEPENDENCIES.get(job.job_type, set()) & present) <= completed_types
        ]
        if not ready:
            # Custom/legacy runs must remain executable even if they contain an
            # unknown dependency shape. Falling back to one ordered stage is
            # safer than stranding the run.
            ready = [remaining[0]]
        waves.append([job.id for job in ready])
        ready_ids = {job.id for job in ready}
        completed_types.update(job.job_type for job in ready)
        remaining = [job for job in remaining if job.id not in ready_ids]
    return waves


logger = logging.getLogger(__name__)


def _run_should_stop(run: ScanRun) -> bool:
    return run.cancellation_requested or run.status is ScanStatus.PAUSED


def _should_retire_nuclei_findings(
    adapter_name: str,
    outcome_status: ScanStatus,
    preserve_budgeted_output: bool,
    asset_budget_dropped: int = 0,
) -> bool:
    """Retire stale findings only after a complete Nuclei refresh."""

    return (
        adapter_name == "nuclei"
        and outcome_status is ScanStatus.SUCCESS
        and not preserve_budgeted_output
        and asset_budget_dropped == 0
    )


def _scan_run_lock_key(scan_run_id: UUID) -> int:
    """Map a run UUID to PostgreSQL's signed 64-bit advisory-lock namespace."""

    return int.from_bytes(scan_run_id.bytes[:8], byteorder="big", signed=True)


async def _rules(session: AsyncSession, project_id: UUID) -> list[ScopeRuleValue]:
    values = list(
        await session.scalars(select(ScopeRule).where(ScopeRule.project_id == project_id))
    )
    return [ScopeRuleValue(item.rule_type, item.value, item.action, item.id) for item in values]


async def _cancel_monitor(
    scan_run_id: UUID,
    event: asyncio.Event,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    while not event.is_set():
        async with session_factory() as session:
            requested = await session.scalar(
                select(ScanRun.cancellation_requested).where(ScanRun.id == scan_run_id)
            )
        if requested:
            event.set()
            return
        await asyncio.sleep(0.5)


async def _job_progress_monitor(
    scan_job_id: UUID,
    stdout_path: Path,
    stop: asyncio.Event,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Publish bounded live output counters without parsing incomplete tool output."""

    while not stop.is_set():
        try:
            size = await asyncio.to_thread(
                lambda: stdout_path.stat().st_size if stdout_path.is_file() else 0
            )
            async with session_factory() as session:
                job = await session.get(ScanJob, scan_job_id)
                if job is None or job.status is not ScanStatus.RUNNING:
                    return
                job.result_summary = {
                    **job.result_summary,
                    "phase": "running",
                    "live_output_bytes": size,
                    "heartbeat_at": datetime.now(UTC).isoformat(),
                }
                await session.commit()
        except OSError:
            logger.debug("Unable to read live output size for job %s", scan_job_id)
        try:
            await asyncio.wait_for(stop.wait(), timeout=2)
        except TimeoutError:
            continue


def _fixture_outcome(store: ArtifactStore, directory: Path, adapter_name: str) -> ProcessOutcome:
    stdout_path = store.path_for(directory, "stdout.raw")
    stderr_path = store.path_for(directory, "stderr.log")
    shutil.copyfile(_fixtures / f"{adapter_name}.jsonl", stdout_path)
    side_artifacts: tuple[StoredArtifact, ...] = ()
    if adapter_name == "screenshot":
        screenshot_directory = directory / "screenshots"
        screenshot_directory.mkdir(parents=True, exist_ok=True)
        screenshot_path = screenshot_directory / "www.example.com.svg"
        shutil.copyfile(_fixtures / "screenshot.svg", screenshot_path)
        side_artifacts = (store.describe(screenshot_path),)
    stderr_path.write_bytes(b"")
    return ProcessOutcome(
        status=ScanStatus.SUCCESS,
        exit_code=0,
        duration_seconds=0,
        stdout=store.describe(stdout_path),
        stderr=store.describe(stderr_path),
        side_artifacts=side_artifacts,
    )


async def _record_artifact(
    session: AsyncSession,
    run: ScanRun,
    job: ScanJob,
    artifact: StoredArtifact,
    artifact_type: str,
    media_type: str,
) -> None:
    await session.execute(
        pg_insert(FileArtifact)
        .values(
            project_id=run.project_id,
            scan_run_id=run.id,
            scan_job_id=job.id,
            artifact_type=artifact_type,
            path=artifact.relative_path,
            sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
            media_type=media_type,
        )
        .on_conflict_do_nothing(index_elements=[FileArtifact.path])
    )


async def _asset_id(
    session: AsyncSession,
    run: ScanRun,
    asset_type: AssetType,
    value: str,
    rules: list[ScopeRuleValue],
) -> UUID:
    normalized = normalize_asset(asset_type, value)
    decision = evaluate_scope(asset_type, normalized.normalized_value, rules)
    created = await session.scalar(
        pg_insert(Asset)
        .values(
            project_id=run.project_id,
            asset_type=normalized.asset_type,
            normalized_value=normalized.normalized_value,
            display_value=normalized.display_value,
            normalized_key=normalized.normalized_key,
            scope_status=decision.status,
            ownership_status=(
                OwnershipStatus.CONFIRMED
                if decision.status is ScopeStatus.IN_SCOPE
                else OwnershipStatus.PENDING_REVIEW
            ),
            confidence_score=100 if decision.status is ScopeStatus.IN_SCOPE else 0,
            metadata_json={},
            created_by="scan-worker",
            updated_by="scan-worker",
        )
        .on_conflict_do_nothing(
            index_elements=[Asset.project_id, Asset.asset_type, Asset.normalized_value]
        )
        .returning(Asset.id)
    )
    if created is not None:
        return created
    existing = await session.scalar(
        select(Asset.id).where(
            Asset.project_id == run.project_id,
            Asset.asset_type == normalized.asset_type,
            Asset.normalized_value == normalized.normalized_value,
        )
    )
    if existing is None:
        raise RuntimeError("Asset upsert did not return or locate an asset")
    return existing


async def _persist_observations(
    session: AsyncSession,
    run: ScanRun,
    payloads: list[ObservationPayload],
    rules: list[ScopeRuleValue],
) -> tuple[int, int]:
    observations_created = 0
    saw_filing_observation = False
    assets_before = int(
        await session.scalar(select(func.count(Asset.id)).where(Asset.project_id == run.project_id))
        or 0
    )
    for payload in payloads:
        subject_id = await _asset_id(
            session, run, payload.subject.type, payload.subject.value, rules
        )
        object_id = None
        if payload.object is not None:
            object_id = await _asset_id(
                session, run, payload.object.type, payload.object.value, rules
            )
        for item, asset_id in ((payload.subject, subject_id), (payload.object, object_id)):
            if item is not None and asset_id is not None and item.type is AssetType.IP:
                cname_value = payload.attributes.get("cname")
                cname = (
                    cname_value[0]
                    if isinstance(cname_value, list) and cname_value
                    else cname_value
                    if isinstance(cname_value, str)
                    else None
                )
                classification = classify_ip(item.value, cname=cname)
                await session.execute(
                    pg_insert(IPDetail)
                    .values(
                        project_id=run.project_id,
                        asset_id=asset_id,
                        classification=classification,
                        classification_source="network_safety_classifier",
                        is_private=classification is IPClassification.PRIVATE_RESERVED,
                        is_cdn=classification is IPClassification.CDN_WAF,
                        metadata_json={},
                        created_by="scan-worker",
                        updated_by="scan-worker",
                    )
                    .on_conflict_do_nothing(index_elements=[IPDetail.project_id, IPDetail.asset_id])
                )
        inserted = await session.scalar(
            pg_insert(Observation)
            .values(
                project_id=run.project_id,
                scan_run_id=run.id,
                source_tool=payload.source_tool,
                source_version=payload.source_version,
                subject_type=payload.subject.type.value,
                subject_value=payload.subject.value,
                predicate=payload.predicate,
                object_type=payload.object.type.value if payload.object else None,
                object_value=payload.object.value if payload.object else None,
                attributes={**payload.attributes, "confidence": payload.confidence},
                raw_artifact_path=payload.raw_artifact_path,
                observed_at=payload.observed_at,
                observation_hash=payload.observation_hash(),
            )
            .on_conflict_do_nothing(
                index_elements=[Observation.project_id, Observation.observation_hash]
            )
            .returning(Observation.id)
        )
        observations_created += inserted is not None
        if (
            payload.predicate == "CNAME_TO"
            and payload.object is not None
            and payload.object.type is AssetType.DOMAIN
            and object_id is not None
        ):
            cname_classification = classify_cname(payload.object.value)
            if cname_classification is not None:
                derived_status = (
                    ScopeStatus.CDN_SHARED
                    if cname_classification.category == "CDN"
                    else ScopeStatus.THIRD_PARTY
                )
                await session.execute(
                    update(Asset)
                    .where(
                        Asset.id == object_id,
                        Asset.scope_status.notin_([ScopeStatus.IN_SCOPE, ScopeStatus.EXCLUDED]),
                    )
                    .values(
                        scope_status=derived_status,
                        ownership_status=OwnershipStatus.THIRD_PARTY,
                        metadata_json={
                            "cname_provider": cname_classification.provider,
                            "cname_category": cname_classification.category,
                            "cname_matched_suffix": cname_classification.matched_suffix,
                            "cname_rules_version": cname_classification.rules_version,
                        },
                        updated_by="scan-worker",
                        updated_at=func.now(),
                    )
                )
                await session.execute(
                    pg_insert(AssetRelation)
                    .values(
                        project_id=run.project_id,
                        source_asset_id=subject_id,
                        target_asset_id=object_id,
                        relation_type=RelationType.THIRD_PARTY_HOSTED_BY,
                        confidence=1.0,
                        evidence_count=1,
                    )
                    .on_conflict_do_nothing(
                        index_elements=[
                            AssetRelation.project_id,
                            AssetRelation.source_asset_id,
                            AssetRelation.target_asset_id,
                            AssetRelation.relation_type,
                        ]
                    )
                )
        record_type = payload.attributes.get("record_type")
        record_value = payload.attributes.get("record_value")
        if (
            payload.subject.type is AssetType.DOMAIN
            and isinstance(record_type, str)
            and isinstance(record_value, str)
            and record_type in DNSRecordType
        ):
            await session.execute(
                pg_insert(DNSRecord)
                .values(
                    project_id=run.project_id,
                    scan_run_id=run.id,
                    domain_asset_id=subject_id,
                    record_type=DNSRecordType(record_type),
                    value=record_value,
                    ttl=(
                        payload.attributes.get("ttl")
                        if isinstance(payload.attributes.get("ttl"), int)
                        else None
                    ),
                    resolver=(
                        payload.attributes.get("resolver")
                        if isinstance(payload.attributes.get("resolver"), str)
                        else None
                    ),
                    source_tool=payload.source_tool,
                    observed_at=payload.observed_at,
                )
                .on_conflict_do_nothing(
                    index_elements=[
                        DNSRecord.scan_run_id,
                        DNSRecord.domain_asset_id,
                        DNSRecord.record_type,
                        DNSRecord.value,
                    ]
                )
            )
        if payload.source_tool == "naabu" and payload.subject.type is AssetType.IP:
            port_value = payload.attributes.get("port")
            protocol_value = payload.attributes.get("protocol")
            if isinstance(port_value, int) and isinstance(protocol_value, str):
                await session.execute(
                    pg_insert(Port)
                    .values(
                        project_id=run.project_id,
                        scan_run_id=run.id,
                        ip_asset_id=subject_id,
                        port=port_value,
                        protocol=TransportProtocol(protocol_value),
                        state=PortState.OPEN,
                        source_tool=payload.source_tool,
                    )
                    .on_conflict_do_update(
                        index_elements=[
                            Port.scan_run_id,
                            Port.ip_asset_id,
                            Port.port,
                            Port.protocol,
                        ],
                        set_={"state": PortState.OPEN, "last_seen_at": func.now()},
                    )
                )
        if payload.source_tool == "nmap" and payload.subject.type is AssetType.SERVICE:
            ip_value = payload.attributes.get("ip")
            port_value = payload.attributes.get("port")
            protocol_value = payload.attributes.get("protocol")
            if (
                isinstance(ip_value, str)
                and isinstance(port_value, int)
                and isinstance(protocol_value, str)
            ):
                ip_normalized = normalize_asset(AssetType.IP, ip_value).normalized_value
                ip_id = await session.scalar(
                    select(Asset.id).where(
                        Asset.project_id == run.project_id,
                        Asset.asset_type == AssetType.IP,
                        Asset.normalized_value == ip_normalized,
                    )
                )
                port_id = await session.scalar(
                    select(Port.id).where(
                        Port.scan_run_id == run.id,
                        Port.ip_asset_id == ip_id,
                        Port.port == port_value,
                        Port.protocol == TransportProtocol(protocol_value),
                    )
                )
                if port_id is not None:
                    await session.execute(
                        pg_insert(Service)
                        .values(
                            project_id=run.project_id,
                            scan_run_id=run.id,
                            port_id=port_id,
                            name=payload.attributes.get("name"),
                            product=payload.attributes.get("product"),
                            version=payload.attributes.get("version"),
                            tunnel=payload.attributes.get("tunnel"),
                            cpe=payload.attributes.get("cpe"),
                            tls=payload.attributes.get("tunnel") == "ssl",
                            source_tool=payload.source_tool,
                            attributes=payload.attributes,
                            observed_at=payload.observed_at,
                        )
                        .on_conflict_do_nothing(
                            index_elements=[Service.scan_run_id, Service.port_id]
                        )
                    )
        if payload.source_tool == "nuclei" and payload.predicate == "HAS_FINDING":
            template_id = payload.attributes.get("template_id")
            template_name = payload.attributes.get("template_name")
            severity_value = payload.attributes.get("severity")
            if (
                isinstance(template_id, str)
                and isinstance(template_name, str)
                and isinstance(severity_value, str)
                and severity_value in FindingSeverity
            ):
                await session.execute(
                    pg_insert(Finding)
                    .values(
                        project_id=run.project_id,
                        first_scan_run_id=run.id,
                        last_scan_run_id=run.id,
                        asset_id=subject_id,
                        execution_mode=str(run.config_snapshot["execution_mode"]),
                        template_id=template_id,
                        template_name=template_name,
                        tool_version=payload.source_version,
                        target=payload.subject.value,
                        matched_at=payload.attributes.get("matched_at"),
                        severity=FindingSeverity(severity_value),
                        status=FindingStatus.UNVERIFIED,
                        evidence={
                            "matcher_name": payload.attributes.get("matcher_name"),
                            "tags": payload.attributes.get("tags", []),
                            "confidence": payload.confidence,
                        },
                        raw_artifact_path=payload.raw_artifact_path,
                        first_seen_at=payload.observed_at,
                        last_seen_at=payload.observed_at,
                        is_active=True,
                        created_by="scan-worker",
                        updated_by="scan-worker",
                    )
                    .on_conflict_do_update(
                        index_elements=[
                            Finding.project_id,
                            Finding.execution_mode,
                            Finding.template_id,
                            Finding.target,
                        ],
                        set_={
                            "last_scan_run_id": run.id,
                            "tool_version": payload.source_version,
                            "matched_at": payload.attributes.get("matched_at"),
                            "severity": FindingSeverity(severity_value),
                            "evidence": {
                                "matcher_name": payload.attributes.get("matcher_name"),
                                "tags": payload.attributes.get("tags", []),
                                "confidence": payload.confidence,
                            },
                            "raw_artifact_path": payload.raw_artifact_path,
                            "last_seen_at": payload.observed_at,
                            "is_active": True,
                            "updated_by": "scan-worker",
                            "updated_at": func.now(),
                        },
                    )
                )
        await persist_web_observation(
            session,
            run,
            payload,
            subject_id,
            object_id,
            rules,
            _asset_id,
        )
        saw_filing_observation = saw_filing_observation or payload.predicate == "HAS_ICP_RECORD"
        relation_type = _relation_types.get(payload.predicate)
        if object_id is not None and relation_type is not None and subject_id != object_id:
            await session.execute(
                pg_insert(AssetRelation)
                .values(
                    project_id=run.project_id,
                    source_asset_id=subject_id,
                    target_asset_id=object_id,
                    relation_type=relation_type,
                    confidence=payload.confidence,
                    evidence_count=1,
                )
                .on_conflict_do_nothing(
                    index_elements=[
                        AssetRelation.project_id,
                        AssetRelation.source_asset_id,
                        AssetRelation.target_asset_id,
                        AssetRelation.relation_type,
                    ]
                )
            )
    if saw_filing_observation:
        await infer_root_icp_links(session, run)
    assets_after = int(
        await session.scalar(select(func.count(Asset.id)).where(Asset.project_id == run.project_id))
        or 0
    )
    return observations_created, assets_after - assets_before


async def _apply_asset_budget(
    session: AsyncSession,
    run: ScanRun,
    payloads: list[ObservationPayload],
    max_assets: int,
) -> tuple[list[ObservationPayload], int]:
    """Keep known-asset evidence while preventing unbounded new asset creation."""

    existing = {
        (asset_type, normalized_value)
        for asset_type, normalized_value in (
            await session.execute(
                select(Asset.asset_type, Asset.normalized_value).where(
                    Asset.project_id == run.project_id
                )
            )
        ).all()
    }
    accepted: list[ObservationPayload] = []
    dropped = 0
    for payload in payloads:
        identities: set[tuple[AssetType, str]] = set()
        for item in (payload.subject, payload.object):
            if item is None:
                continue
            normalized = normalize_asset(item.type, item.value)
            identities.add((normalized.asset_type, normalized.normalized_value))
        new_identities = identities - existing
        if len(existing) + len(new_identities) > max_assets:
            dropped += 1
            continue
        existing.update(new_identities)
        accepted.append(payload)
    return accepted, dropped


def _naabu_output_looks_intercepted(
    result_summary: dict[str, object], unique_open_endpoints: int
) -> tuple[bool, float]:
    """Detect the characteristic all-open result produced by local proxy/TUN interception."""

    def summary_int(key: str) -> int:
        value = result_summary.get(key, 0)
        return int(value) if isinstance(value, int | str) else 0

    targets = summary_int("scan_targets")
    ports_per_target = summary_int("ports_tested_per_target")
    candidate_checks = summary_int("candidate_socket_checks")
    saturation = unique_open_endpoints / candidate_checks if candidate_checks else 0.0
    suspicious = (
        targets >= 1
        and ports_per_target >= 2
        and candidate_checks >= 4
        and saturation >= 0.95
    )
    return suspicious, round(saturation, 4)


async def _clear_naabu_results_for_run(session: AsyncSession, run: ScanRun) -> int:
    """Replace retried Naabu results and remove orphan service assets from quarantined output."""

    service_values = set(
        await session.scalars(
            select(Observation.object_value).where(
                Observation.project_id == run.project_id,
                Observation.scan_run_id == run.id,
                Observation.source_tool == "naabu",
                Observation.object_type == AssetType.SERVICE.value,
                Observation.object_value.is_not(None),
            )
        )
    )
    await session.execute(delete(Port).where(Port.scan_run_id == run.id))
    await session.execute(
        delete(Observation).where(
            Observation.project_id == run.project_id,
            Observation.scan_run_id == run.id,
            Observation.source_tool == "naabu",
        )
    )
    await session.flush()
    if not service_values:
        return 0
    still_observed = exists(
        select(Observation.id).where(
            Observation.project_id == run.project_id,
            or_(
                (Observation.subject_type == AssetType.SERVICE.value)
                & (Observation.subject_value == Asset.normalized_value),
                (Observation.object_type == AssetType.SERVICE.value)
                & (Observation.object_value == Asset.normalized_value),
            ),
        )
    )
    result = await session.execute(
        delete(Asset).where(
            Asset.project_id == run.project_id,
            Asset.asset_type == AssetType.SERVICE,
            Asset.normalized_value.in_(service_values),
            Asset.created_by == "scan-worker",
            ~still_observed,
        )
    )
    rowcount = getattr(result, "rowcount", 0)
    return int(rowcount) if isinstance(rowcount, int) else 0


def _observed_in_run(run: ScanRun, asset_type: AssetType) -> ColumnElement[bool]:
    return exists(
        select(Observation.id).where(
            Observation.project_id == run.project_id,
            Observation.scan_run_id == run.id,
            or_(
                (Observation.subject_type == asset_type.value)
                & (Observation.subject_value == Asset.normalized_value),
                (Observation.object_type == asset_type.value)
                & (Observation.object_value == Asset.normalized_value),
            ),
        )
    )


async def _active_domains(
    session: AsyncSession, run: ScanRun, rules: list[ScopeRuleValue]
) -> list[str]:
    run_root = normalize_domain(str(run.config_snapshot["root_domain"]))
    domains = [run_root]
    domains.extend(
        await session.scalars(
            select(Asset.normalized_value).where(
                Asset.project_id == run.project_id,
                Asset.asset_type == AssetType.DOMAIN,
                Asset.scope_status == ScopeStatus.IN_SCOPE,
                Asset.is_active.is_(True),
                or_(
                    Asset.created_by != "scan-worker",
                    _observed_in_run(run, AssetType.DOMAIN),
                ),
            )
        )
    )
    allowed: list[str] = []
    for domain in domains:
        normalized = normalize_domain(domain)
        if normalized != run_root and not normalized.endswith(f".{run_root}"):
            continue
        decision = evaluate_scope(AssetType.DOMAIN, domain, rules)
        require_active_scope(decision)
        allowed.append(decision.normalized_value)
    return sorted(set(allowed))


async def _active_websites(
    session: AsyncSession,
    run: ScanRun,
    rules: list[ScopeRuleValue],
    *,
    one_per_host: bool = False,
    allow_project_fallback: bool = False,
) -> list[str]:
    run_root = normalize_domain(str(run.config_snapshot["root_domain"]))
    current_run_statement = (
        select(Website.normalized_url)
        .join(WebSnapshot, WebSnapshot.website_id == Website.id)
        .where(
            Website.project_id == run.project_id,
            Website.is_alive.is_(True),
            WebSnapshot.scan_run_id == run.id,
        )
        .distinct()
    )
    values = list(await session.scalars(current_run_statement))
    if not values and allow_project_fallback:
        values = list(
            await session.scalars(
                select(Website.normalized_url)
                .where(
                    Website.project_id == run.project_id,
                    Website.is_alive.is_(True),
                )
                .distinct()
            )
        )
    allowed: list[str] = []
    for value in values:
        hostname = urlsplit(value).hostname
        if hostname is None:
            continue
        try:
            normalized_host = normalize_domain(hostname)
        except ValueError:
            continue
        if normalized_host != run_root and not normalized_host.endswith(f".{run_root}"):
            continue
        decision = evaluate_scope(AssetType.URL, value, rules)
        require_active_scope(decision)
        allowed.append(decision.normalized_value)
    unique = sorted(set(allowed))
    return _preferred_crawl_urls(unique) if one_per_host else unique


def _preferred_crawl_urls(urls: list[str]) -> list[str]:
    """Select one stable crawl seed per host, preferring HTTPS and root paths."""

    selected: dict[str, str] = {}
    for url in sorted(urls):
        parsed = urlsplit(url)
        if parsed.hostname is None:
            continue
        key = parsed.hostname.casefold()
        current = selected.get(key)
        candidate_rank = (parsed.scheme != "https", parsed.path not in {"", "/"}, len(url))
        if current is None:
            selected[key] = url
            continue
        current_parsed = urlsplit(current)
        current_rank = (
            current_parsed.scheme != "https",
            current_parsed.path not in {"", "/"},
            len(current),
        )
        if candidate_rank < current_rank:
            selected[key] = url
    return sorted(selected.values())


async def _puredns_candidates(
    session: AsyncSession,
    run: ScanRun,
    rules: list[ScopeRuleValue],
    profile: ScanProfileConfig,
) -> list[str]:
    candidates = set(await _active_domains(session, run, rules))
    if profile.dns_bruteforce and profile.dns_wordlist_limit:
        labels = [
            line.strip().casefold()
            for line in _dns_wordlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ][: profile.dns_wordlist_limit]
        root = str(run.config_snapshot["root_domain"])
        candidates.update(f"{label}.{root}" for label in labels)
    return sorted(candidates)


async def _naabu_input(
    session: AsyncSession,
    run: ScanRun,
    rules: list[ScopeRuleValue],
    profile: ScanProfileConfig,
) -> dict[str, object] | None:
    # An authorized root-domain rule does not syntactically match an IP. The
    # DNS edge is the missing provenance: permit only IPs resolved from a
    # currently observed, in-scope domain. The normal IP classifier still
    # blocks private/CDN nodes and restricts unknown/shared nodes to safe web
    # ports, so this does not turn domain authorization into arbitrary IP scope.
    resolved_pairs = list(
        (
            await session.execute(
                select(Observation.subject_value, Observation.object_value).where(
                    Observation.scan_run_id == run.id,
                    Observation.predicate == "RESOLVES_TO",
                    Observation.subject_type == AssetType.DOMAIN.value,
                    Observation.object_type == AssetType.IP.value,
                )
            )
        ).all()
    )
    authorized_derived_ips = {
        ip_value
        for domain_value, ip_value in resolved_pairs
        if isinstance(ip_value, str)
        and evaluate_scope(AssetType.DOMAIN, domain_value, rules).status is ScopeStatus.IN_SCOPE
    }
    rows = list(
        (
            await session.execute(
                select(Asset, IPDetail)
                .outerjoin(IPDetail, IPDetail.asset_id == Asset.id)
                .where(
                    Asset.project_id == run.project_id,
                    Asset.asset_type == AssetType.IP,
                    Asset.is_active.is_(True),
                    or_(
                        Asset.created_by != "scan-worker",
                        _observed_in_run(run, AssetType.IP),
                    ),
                )
            )
        ).all()
    )
    allowed: list[tuple[str, tuple[int, ...], bool]] = []
    policy_counts = {
        "discovered_ips": len(rows),
        "authorized_dns_derived_ips": len(authorized_derived_ips),
        "direct_ip_scope": 0,
        "blocked_cdn_or_private": 0,
        "blocked_without_authorized_provenance": 0,
    }
    for asset, detail in rows:
        current_scope = evaluate_scope(AssetType.IP, asset.normalized_value, rules)
        classification = (
            detail.classification if detail is not None else classify_ip(asset.normalized_value)
        )
        derived_from_authorized_domain = asset.normalized_value in authorized_derived_ips
        effective_scope = (
            ScopeStatus.IN_SCOPE if derived_from_authorized_domain else current_scope.status
        )
        if current_scope.status is ScopeStatus.IN_SCOPE:
            policy_counts["direct_ip_scope"] += 1
        decision = decide_port_scan(
            classification=classification,
            scope_status=effective_scope,
            profile=profile,
            port_scan_enabled=bool(run.config_snapshot.get("port_scan_enabled")),
            full_port_scan=bool(run.config_snapshot.get("full_port_scan")),
            full_port_confirmation=bool(run.config_snapshot.get("full_port_confirmation")),
        )
        if decision.allowed:
            allowed.append(
                (asset.normalized_value, decision.effective_ports, decision.full_port_scan)
            )
        elif classification in {IPClassification.CDN_WAF, IPClassification.PRIVATE_RESERVED}:
            policy_counts["blocked_cdn_or_private"] += 1
        else:
            policy_counts["blocked_without_authorized_provenance"] += 1
    if not allowed:
        return None
    if all(item[2] for item in allowed):
        return {
            "ips": [item[0] for item in allowed],
            "ports": [],
            "full_port_scan": True,
            "rate": profile.port_rate,
            "concurrency": profile.port_concurrency,
            "policy_summary": {**policy_counts, "scan_targets": len(allowed)},
        }
    effective = set(allowed[0][1])
    for _, ports, _ in allowed[1:]:
        effective.intersection_update(ports)
    if not effective:
        return None
    return {
        "ips": [item[0] for item in allowed],
        "ports": sorted(effective),
        "full_port_scan": False,
        "rate": profile.port_rate,
        "concurrency": profile.port_concurrency,
        "policy_summary": {
            **policy_counts,
            "scan_targets": len(allowed),
            "ports_tested_per_target": len(effective),
            "candidate_socket_checks": len(allowed) * len(effective),
        },
    }


async def _nmap_input(
    session: AsyncSession, run: ScanRun, job: ScanJob
) -> dict[str, object] | None:
    rows = list(
        (
            await session.execute(
                select(Asset.normalized_value, Port.port)
                .join(Port, Port.ip_asset_id == Asset.id)
                .where(Port.scan_run_id == run.id, Port.state == PortState.OPEN)
                .order_by(Asset.normalized_value, Port.port)
            )
        ).all()
    )
    by_ip: dict[str, set[int]] = {}
    for ip, port in rows:
        by_ip.setdefault(ip, set()).add(port)
    if not by_ip:
        return None
    return {"targets": [{"ip": ip, "ports": sorted(ports)} for ip, ports in sorted(by_ip.items())]}


def _crawler_parallelism(target_count: int) -> int:
    return min(8, max(1, target_count))


def _crawler_per_site_limit(profile: ScanProfileConfig, target_count: int) -> int:
    raw_record_budget = min(profile.max_assets, 3_000)
    distributed = raw_record_budget // max(1, target_count)
    return min(profile.crawler_max_urls_per_site, max(5, distributed))


def _crawler_target_duration_seconds(
    profile: ScanProfileConfig, target_count: int, parallelism: int
) -> int:
    batches = max(1, math.ceil(target_count / max(1, parallelism)))
    wall_budget = min(profile.crawler_max_duration_seconds, 240)
    distributed = wall_budget // batches
    return min(120, max(15, distributed))


async def _build_job_input(
    session: AsyncSession,
    run: ScanRun,
    job: ScanJob,
    rules: list[ScopeRuleValue],
) -> dict[str, object] | None:
    profile = ScanProfileConfig.model_validate(run.config_snapshot["profile"])
    if job.adapter_name == "subfinder":
        return {"root_domain": run.config_snapshot["root_domain"]}
    if job.adapter_name == "alterx":
        domains = await _active_domains(session, run, rules)
        return {"domains": domains, "limit": profile.variant_limit} if domains else None
    if job.adapter_name == "puredns":
        candidates = await _puredns_candidates(session, run, rules, profile)
        return (
            {
                "root_domain": run.config_snapshot["root_domain"],
                "candidates": candidates,
                "rate": profile.dns_rate,
            }
            if candidates
            else None
        )
    if job.adapter_name == "dnsx":
        domains = await _active_domains(session, run, rules)
        return {"domains": domains} if domains else None
    if job.adapter_name == "httpx":
        domains = await _active_domains(session, run, rules)
        return (
            {
                "domains": domains,
                "concurrency": profile.http_concurrency,
                "rate": profile.http_rate,
                "timeout_seconds": profile.http_timeout_seconds,
                "max_redirects": profile.max_redirects,
                "max_response_body_bytes": profile.max_response_body_bytes,
                "extract_icp": profile.icp_extraction,
                "proxy_url": run.config_snapshot.get("proxy_url"),
            }
            if domains
            else None
        )
    if job.adapter_name in {"katana", "screenshot"}:
        urls = await _active_websites(
            session,
            run,
            rules,
            one_per_host=job.adapter_name == "katana",
        )
        if not urls:
            return None
        if job.adapter_name == "screenshot":
            return {
                "urls": urls,
                "concurrency": min(profile.http_concurrency, 5),
                "rate": min(profile.http_rate, 10),
                "timeout_seconds": min(max(profile.http_timeout_seconds, 5), 60),
                "max_redirects": profile.max_redirects,
                "proxy_url": run.config_snapshot.get("proxy_url"),
            }
        parallelism = _crawler_parallelism(len(urls))
        return {
            "urls": urls,
            "depth": profile.crawler_depth,
            "max_urls_per_site": _crawler_per_site_limit(profile, len(urls)),
            "duration_seconds": _crawler_target_duration_seconds(profile, len(urls), parallelism),
            "rate": profile.crawler_rate,
            "concurrency": min(profile.http_concurrency, 3),
            "parallelism": parallelism,
            "timeout_seconds": profile.http_timeout_seconds,
            "max_response_body_bytes": profile.max_response_body_bytes,
            "proxy_url": run.config_snapshot.get("proxy_url"),
        }
    if job.adapter_name == "nuclei":
        chain = run.config_snapshot.get("chain", [])
        urls = await _active_websites(
            session,
            run,
            rules,
            allow_project_fallback=(isinstance(chain, list) and "httpx" not in chain),
        )
        return (
            {
                "urls": urls,
                "concurrency": profile.nuclei_concurrency,
                "rate": profile.nuclei_rate,
                "timeout_seconds": profile.nuclei_timeout_seconds,
                "strategy": profile.nuclei_strategy,
                "proxy_url": run.config_snapshot.get("proxy_url"),
            }
            if urls
            else None
        )
    if job.adapter_name == "naabu":
        return await _naabu_input(session, run, rules, profile)
    if job.adapter_name == "nmap":
        return await _nmap_input(session, run, job)
    raise RuntimeError(f"No input planner exists for adapter {job.adapter_name}")


async def _execute_job(
    session: AsyncSession,
    run: ScanRun,
    job: ScanJob,
    rules: list[ScopeRuleValue],
    store: ArtifactStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    adapter = ADAPTERS[job.adapter_name]
    input_ref = await _build_job_input(session, run, job, rules)
    if input_ref is None:
        job.status = ScanStatus.SKIPPED
        job.error_code = "NO_POLICY_APPROVED_INPUTS"
        job.error_message = "No in-scope inputs passed this stage's safety policy"
        job.result_summary = {"phase": "skipped", "input_count": 0}
        job.finished_at = datetime.now(UTC)
        await session.commit()
        return
    job.input_ref = {**job.input_ref, **input_ref}

    if job.adapter_name == "subfinder":
        require_active_scope(evaluate_scope(AssetType.DOMAIN, str(input_ref["root_domain"]), rules))
    validated = adapter.validate_input(input_ref)
    job.status = ScanStatus.RUNNING
    job.attempt += 1
    job.started_at = datetime.now(UTC)
    input_count = next(
        (
            len(value)
            for key in ("candidates", "domains", "ips", "targets", "urls")
            if isinstance((value := input_ref.get(key)), list)
        ),
        1,
    )
    job.result_summary = {
        **job.result_summary,
        "phase": "running",
        "input_count": input_count,
    }
    if job.adapter_name == "naabu":
        policy_summary = input_ref.get("policy_summary")
        if isinstance(policy_summary, dict):
            job.result_summary = {**job.result_summary, **policy_summary}
    if job.adapter_name == "nuclei":
        job.result_summary = {
            **job.result_summary,
            "scan_strategy": input_ref.get("strategy", "automatic"),
        }
    run.status = ScanStatus.RUNNING
    run.started_at = run.started_at or datetime.now(UTC)
    await session.commit()

    job_directory = store.job_directory(run.project_id, run.id, job.id)
    directory = store.attempt_directory(job_directory, job.attempt)
    if run.config_snapshot["execution_mode"] == "fixture":
        outcome = _fixture_outcome(store, directory, job.adapter_name)
    else:
        try:
            adapter.require_installed()
        except ToolUnavailableError as exc:
            stdout = store.path_for(directory, "stdout.raw")
            stderr = store.path_for(directory, "stderr.log")
            stdout.write_bytes(b"")
            stderr.write_text(str(exc), encoding="utf-8")
            outcome = ProcessOutcome(
                status=ScanStatus.SKIPPED,
                exit_code=None,
                duration_seconds=0,
                stdout=store.describe(stdout),
                stderr=store.describe(stderr),
                error_code=exc.code,
                error_message=str(exc),
            )
        else:
            cancellation = asyncio.Event()
            monitor = asyncio.create_task(_cancel_monitor(run.id, cancellation, session_factory))
            try:
                runner = SafeProcessRunner(store)
                version_outcome = await runner.run(
                    adapter.manifest.version_command,
                    job_directory=directory,
                    timeout_seconds=30,
                    cancellation=cancellation,
                )
                version_text = clean_tool_output(
                    version_outcome.stdout.absolute_path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    + version_outcome.stderr.absolute_path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                )
                compatible = (
                    version_outcome.status is ScanStatus.SUCCESS
                    and version_output_is_compatible(adapter.manifest, version_text)
                )
                if version_outcome.status is ScanStatus.CANCELLED:
                    outcome = version_outcome
                elif not compatible:
                    outcome = ProcessOutcome(
                        status=ScanStatus.SKIPPED,
                        exit_code=version_outcome.exit_code,
                        duration_seconds=version_outcome.duration_seconds,
                        stdout=version_outcome.stdout,
                        stderr=version_outcome.stderr,
                        error_code="TOOL_INCOMPATIBLE",
                        error_message=(
                            f"{adapter.manifest.name} executable did not match its supported "
                            "tool signature"
                        ),
                    )
                else:
                    job.result_summary = {
                        **job.result_summary,
                        "detected_version": detected_tool_version(version_text),
                    }
                    progress_stop = asyncio.Event()
                    progress_monitor = asyncio.create_task(
                        _job_progress_monitor(
                            job.id,
                            store.path_for(directory, "stdout.raw"),
                            progress_stop,
                            session_factory,
                        )
                    )
                    try:
                        outcome = await runner.run(
                            adapter.build_command(validated),
                            job_directory=directory,
                            timeout_seconds=job.timeout_seconds,
                            stdin=adapter.stdin_bytes(validated),
                            cancellation=cancellation,
                            working_directory=(
                                directory if job.adapter_name == "screenshot" else None
                            ),
                            side_artifact_directory=(
                                directory / "screenshots"
                                if job.adapter_name == "screenshot"
                                else None
                            ),
                        )
                    finally:
                        progress_stop.set()
                        await asyncio.gather(progress_monitor, return_exceptions=True)
            finally:
                monitor.cancel()
                await asyncio.gather(monitor, return_exceptions=True)

    media_types = {
        "json": "application/json",
        "jsonl": "application/x-ndjson",
        "text": "text/plain",
        "xml": "application/xml",
    }
    await _record_artifact(
        session,
        run,
        job,
        outcome.stdout,
        "stdout",
        media_types[adapter.manifest.preferred_output],
    )
    await _record_artifact(session, run, job, outcome.stderr, "stderr", "text/plain")
    if job.adapter_name == "screenshot":
        for screenshot in outcome.side_artifacts:
            media_type = {
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".png": "image/png",
                ".svg": "image/svg+xml",
                ".webp": "image/webp",
            }.get(screenshot.absolute_path.suffix.casefold(), "application/octet-stream")
            await _record_artifact(
                session,
                run,
                job,
                screenshot,
                "screenshot",
                media_type,
            )
    job.stdout_path = outcome.stdout.relative_path
    job.stderr_path = outcome.stderr.relative_path
    job.status = outcome.status
    job.error_code = outcome.error_code
    job.error_message = outcome.error_message
    job.finished_at = datetime.now(UTC)
    job.result_summary = {
        **job.result_summary,
        "phase": "finished",
        "duration_seconds": outcome.duration_seconds,
        "exit_code": outcome.exit_code,
        "stdout_bytes": outcome.stdout.size_bytes,
        "stderr_bytes": outcome.stderr.size_bytes,
    }
    preserve_budgeted_output = (
        job.adapter_name in {"katana", "screenshot", "nuclei"}
        and outcome.status is ScanStatus.TIMEOUT
        and outcome.stdout.absolute_path.stat().st_size > 0
    )
    if preserve_budgeted_output:
        job.status = ScanStatus.PARTIAL_SUCCESS
        budget_codes = {
            "katana": "CRAWL_BUDGET_REACHED",
            "screenshot": "SCREENSHOT_BUDGET_REACHED",
            "nuclei": "SECURITY_SCAN_BUDGET_REACHED",
        }
        job.error_code = budget_codes[job.adapter_name]
        job.error_message = (
            "The configured stage time budget was reached; complete results written before "
            "the deadline were preserved"
        )
    if outcome.status is ScanStatus.SUCCESS or preserve_budgeted_output:
        source_version = (
            "fixture-1"
            if run.config_snapshot["execution_mode"] == "fixture"
            else str(job.result_summary.get("detected_version", "unknown"))[:100]
        )
        context = AdapterContext(
            project_id=run.project_id,
            scan_run_id=run.id,
            source_version=source_version,
            raw_artifact_path=outcome.stdout.relative_path,
        )
        try:
            payloads = adapter.parse_output(outcome.stdout.absolute_path, context)
            parse_diagnostics = getattr(payloads, "diagnostics", {})
            profile = ScanProfileConfig.model_validate(run.config_snapshot["profile"])
            if job.adapter_name == "naabu":
                removed_assets = await _clear_naabu_results_for_run(session, run)
                suspicious, saturation = _naabu_output_looks_intercepted(
                    job.result_summary, len(payloads)
                )
                if suspicious:
                    job.status = ScanStatus.PARTIAL_SUCCESS
                    job.error_code = "PORT_SCAN_INTERCEPTION_SUSPECTED"
                    job.error_message = (
                        "Nearly every candidate port appeared open. Results were quarantined "
                        "because a local proxy or TUN interception is likely."
                    )
                    job.result_summary = {
                        **job.result_summary,
                        **parse_diagnostics,
                        "observations_parsed": 0,
                        "observations_created": 0,
                        "assets_created": 0,
                        "quarantined_open_endpoints": len(payloads),
                        "open_port_saturation_ratio": saturation,
                        "removed_stale_service_assets": removed_assets,
                    }
                    await session.commit()
                    return
            payloads, budget_dropped = await _apply_asset_budget(
                session, run, payloads, profile.max_assets
            )
        except OutputParseError as exc:
            job.status = ScanStatus.PARTIAL_SUCCESS
            job.error_code = exc.code
            job.error_message = str(exc)
        else:
            if _should_retire_nuclei_findings(
                job.adapter_name,
                outcome.status,
                preserve_budgeted_output,
                budget_dropped,
            ):
                await session.execute(
                    update(Finding)
                    .where(
                        Finding.project_id == run.project_id,
                        Finding.execution_mode == str(run.config_snapshot["execution_mode"]),
                        Finding.is_active.is_(True),
                    )
                    .values(is_active=False, updated_by="scan-worker", updated_at=func.now())
                )
            observations, assets = await _persist_observations(session, run, payloads, rules)
            job.result_summary = {
                **job.result_summary,
                "assets_created": assets,
                "observations_created": observations,
                "observations_parsed": len(payloads),
                "asset_budget_dropped": budget_dropped,
                "asset_budget_limit": profile.max_assets,
                **parse_diagnostics,
            }
            if budget_dropped:
                job.status = ScanStatus.PARTIAL_SUCCESS
                job.error_code = "ASSET_LIMIT_REACHED"
                job.error_message = (
                    f"Asset limit {profile.max_assets} reached; "
                    f"{budget_dropped} observations requiring new assets were skipped"
                )
    await session.commit()


async def _record_stage_exception(
    session: AsyncSession,
    scan_run_id: UUID,
    scan_job_id: UUID,
    error: Exception,
) -> tuple[ScanRun, ScanJob]:
    await session.rollback()
    run = await session.get(ScanRun, scan_run_id)
    job = await session.get(ScanJob, scan_job_id)
    if run is None or job is None:
        raise RuntimeError("Scan stage disappeared while recording its failure") from error
    now = datetime.now(UTC)
    if job.status not in TERMINAL_STATUSES:
        job.status = ScanStatus.CANCELLED if run.cancellation_requested else ScanStatus.FAILED
        job.attempt = max(job.attempt, 1)
        job.started_at = job.started_at or now
        job.finished_at = now
        job.error_code = (
            "INPUT_VALIDATION_FAILED" if isinstance(error, ValueError) else "STAGE_EXECUTION_FAILED"
        )
        job.error_message = str(error)[:2000] or error.__class__.__name__
        job.result_summary = {
            **job.result_summary,
            "phase": "failed",
            "exception_type": error.__class__.__name__,
        }
        await session.commit()
    return run, job


async def _refresh_run_aggregate(
    session: AsyncSession,
    scan_run_id: UUID,
    *,
    finalize: bool = False,
) -> ScanRun:
    run = await session.get(ScanRun, scan_run_id, populate_existing=True)
    if run is None:
        raise RuntimeError("Scan run disappeared while aggregating progress")
    jobs = list(
        await session.scalars(
            select(ScanJob)
            .where(ScanJob.scan_run_id == scan_run_id)
            .order_by(ScanJob.sequence.asc())
            .execution_options(populate_existing=True)
        )
    )
    aggregate = aggregate_run_state(
        [job.status for job in jobs],
        cancellation_requested=run.cancellation_requested,
    )
    paused = run.status is ScanStatus.PAUSED and not run.cancellation_requested
    run.status = ScanStatus.PAUSED if paused else aggregate.status
    run.progress = aggregate.progress
    if finalize and aggregate.progress == 100 and not paused:
        run.finished_at = datetime.now(UTC)
    stage_seconds = round(
        sum(float(job.result_summary.get("duration_seconds", 0) or 0) for job in jobs), 3
    )
    now = datetime.now(UTC)
    intervals = sorted(
        (job.started_at, job.finished_at or now)
        for job in jobs
        if job.started_at is not None
    )
    merged_intervals: list[tuple[datetime, datetime]] = []
    for start, end in intervals:
        if not merged_intervals or start > merged_intervals[-1][1]:
            merged_intervals.append((start, end))
            continue
        previous_start, previous_end = merged_intervals[-1]
        merged_intervals[-1] = (previous_start, max(previous_end, end))
    wall_seconds = round(
        sum(max(0.0, (end - start).total_seconds()) for start, end in merged_intervals), 3
    )
    lifecycle_seconds = (
        round(max(0.0, ((run.finished_at or now) - run.started_at).total_seconds()), 3)
        if run.started_at is not None
        else 0.0
    )

    def _stage_total(adapter_name: str, key: str) -> int:
        return sum(
            int(job.result_summary.get(key, 0) or 0)
            for job in jobs
            if job.adapter_name == adapter_name
        )

    funnel = {
        "subdomains_discovered": _stage_total("subfinder", "observations_parsed"),
        "domains_validated": _stage_total("dnsx", "input_count"),
        "websites_alive": _stage_total("httpx", "observations_parsed"),
        "candidate_port_checks": _stage_total("naabu", "candidate_socket_checks"),
        "open_ports": _stage_total("naabu", "observations_parsed"),
        "services_fingerprinted": _stage_total("nmap", "observations_parsed"),
        "web_endpoints_discovered": _stage_total("katana", "observations_parsed"),
        "unverified_security_hits": _stage_total("nuclei", "observations_parsed"),
    }
    run.summary = {
        "assets_created": sum(int(job.result_summary.get("assets_created", 0)) for job in jobs),
        "completed_jobs": aggregate.completed_jobs,
        "observations_created": sum(
            int(job.result_summary.get("observations_created", 0)) for job in jobs
        ),
        "running_jobs": sum(job.status is ScanStatus.RUNNING for job in jobs),
        "total_jobs": aggregate.total_jobs,
        "funnel": funnel,
        "stage_time_seconds": stage_seconds,
        "wall_time_seconds": wall_seconds,
        "lifecycle_elapsed_seconds": lifecycle_seconds,
        "parallel_time_saved_seconds": round(max(0.0, stage_seconds - wall_seconds), 3),
        "execution_strategy": "parallel_dag_v1",
    }
    await session.commit()
    return run


async def _execute_job_isolated(
    session_factory: async_sessionmaker[AsyncSession],
    store: ArtifactStore,
    scan_run_id: UUID,
    scan_job_id: UUID,
) -> None:
    """Execute one DAG stage in its own database session."""

    async with session_factory() as session:
        run = await session.get(ScanRun, scan_run_id)
        job = await session.get(ScanJob, scan_job_id)
        if run is None or job is None or job.status in TERMINAL_STATUSES:
            return
        if _run_should_stop(run):
            return
        if job.status in {ScanStatus.PENDING, ScanStatus.PAUSED}:
            job.status = ScanStatus.QUEUED
            await session.commit()
        rules = await _rules(session, run.project_id)
        try:
            await _execute_job(session, run, job, rules, store, session_factory)
        except Exception as exc:  # A stage failure must never strand the whole run.
            logger.exception("Scan stage %s failed for run %s", job.adapter_name, scan_run_id)
            await _record_stage_exception(session, run.id, job.id, exc)
        await _refresh_run_aggregate(session, scan_run_id)


async def execute_scan_run(scan_run_id: UUID) -> None:
    settings = get_settings()
    store = ArtifactStore(settings.data_root)
    execution_engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    session_factory = async_sessionmaker(execution_engine, expire_on_commit=False)
    try:
        lock_key = _scan_run_lock_key(scan_run_id)
        async with execution_engine.connect() as lock_connection:
            await lock_connection.execute(
                text("SELECT pg_advisory_lock(:lock_key)"), {"lock_key": lock_key}
            )
            await lock_connection.commit()
            try:
                async with session_factory() as session:
                    run = await session.get(ScanRun, scan_run_id)
                    if run is None or run.status in {ScanStatus.SUCCESS, ScanStatus.CANCELLED}:
                        return
                    if run.status is ScanStatus.PAUSED:
                        return
                    jobs = list(
                        await session.scalars(
                            select(ScanJob)
                            .where(ScanJob.scan_run_id == run.id)
                            .order_by(ScanJob.sequence.asc())
                        )
                    )
                    for wave in _job_waves(jobs):
                        run = await session.get(ScanRun, scan_run_id, populate_existing=True)
                        if run is None:
                            return
                        if _run_should_stop(run):
                            break
                        runnable: list[UUID] = []
                        for job_id in wave:
                            job = await session.get(ScanJob, job_id, populate_existing=True)
                            if job is not None and job.status not in TERMINAL_STATUSES:
                                runnable.append(job_id)
                        if runnable:
                            await asyncio.gather(
                                *(
                                    _execute_job_isolated(
                                        session_factory, store, scan_run_id, job_id
                                    )
                                    for job_id in runnable
                                )
                            )
                        await _refresh_run_aggregate(session, scan_run_id)

                    await _refresh_run_aggregate(session, scan_run_id, finalize=True)
            finally:
                await lock_connection.execute(
                    text("SELECT pg_advisory_unlock(:lock_key)"), {"lock_key": lock_key}
                )
                await lock_connection.commit()
    finally:
        await execution_engine.dispose()
