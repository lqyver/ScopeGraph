import asyncio
from collections import defaultdict
from pathlib import Path
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.models import (
    Asset,
    Certificate,
    Endpoint,
    ICPRecord,
    ScanRun,
    Technology,
    Website,
    WebsiteICPLink,
    WebSnapshot,
)
from scopegraph.infrastructure.config import get_settings
from scopegraph.schemas.web import (
    CertificateRead,
    EndpointRead,
    ICPRecordRead,
    ICPWebsiteRead,
    TechnologyRead,
    WebsiteDetailRead,
    WebsiteICPLinkRead,
    WebsitePage,
    WebsiteSummaryRead,
    WebSnapshotRead,
)
from scopegraph.tooling.network_policy import is_environment_mapping_ip


async def _website_rows(
    session: AsyncSession,
    project_id: UUID,
    *,
    offset: int = 0,
    limit: int | None = None,
    website_id: UUID | None = None,
    execution_mode: str | None = None,
) -> list[tuple[Website, Asset, Asset | None]]:
    url_asset = aliased(Asset)
    ip_asset = aliased(Asset)
    statement = (
        select(Website, url_asset, ip_asset)
        .join(url_asset, url_asset.id == Website.asset_id)
        .outerjoin(ip_asset, ip_asset.id == Website.ip_asset_id)
        .where(Website.project_id == project_id)
        .order_by(Website.is_alive.desc(), Website.normalized_url)
        .offset(offset)
    )
    if website_id is not None:
        statement = statement.where(Website.id == website_id)
    if execution_mode is not None:
        matching_runs = select(ScanRun.id).where(
            ScanRun.project_id == project_id,
            ScanRun.config_snapshot["execution_mode"].astext == execution_mode,
        )
        statement = statement.where(
            Website.id.in_(
                select(WebSnapshot.website_id).where(
                    WebSnapshot.scan_run_id.in_(matching_runs)
                )
            )
        )
    if limit is not None:
        statement = statement.limit(limit)
    rows = (await session.execute(statement)).all()
    return [(website, url, ip) for website, url, ip in rows]


async def _related_maps(
    session: AsyncSession,
    project_id: UUID,
    website_ids: list[UUID],
    execution_mode: str | None = None,
) -> tuple[
    dict[UUID, WebSnapshot],
    dict[UUID, str],
    dict[UUID, list[Technology]],
    dict[UUID, int],
]:
    if not website_ids:
        return {}, {}, {}, {}
    matching_runs = None
    if execution_mode is not None:
        matching_runs = select(ScanRun.id).where(
            ScanRun.project_id == project_id,
            ScanRun.config_snapshot["execution_mode"].astext == execution_mode,
        )
    snapshot_statement = (
        select(WebSnapshot)
        .where(
            WebSnapshot.project_id == project_id,
            WebSnapshot.website_id.in_(website_ids),
        )
        .order_by(WebSnapshot.website_id, WebSnapshot.observed_at.desc())
    )
    if matching_runs is not None:
        snapshot_statement = snapshot_statement.where(
            WebSnapshot.scan_run_id.in_(matching_runs)
        )
    snapshots = list(
        await session.scalars(
            snapshot_statement
        )
    )
    latest_snapshots: dict[UUID, WebSnapshot] = {}
    latest_screenshots: dict[UUID, str] = {}
    for snapshot in snapshots:
        latest_snapshots.setdefault(snapshot.website_id, snapshot)
        if snapshot.screenshot_path:
            latest_screenshots.setdefault(snapshot.website_id, snapshot.screenshot_path)
    technology_statement = (
        select(Technology)
        .where(
            Technology.project_id == project_id,
            Technology.website_id.in_(website_ids),
        )
        .order_by(Technology.name, Technology.version)
    )
    if matching_runs is not None:
        technology_statement = technology_statement.where(
            Technology.scan_run_id.in_(matching_runs)
        )
    technologies = list(
        await session.scalars(
            technology_statement
        )
    )
    by_website: dict[UUID, list[Technology]] = defaultdict(list)
    seen: dict[UUID, set[tuple[str, str]]] = defaultdict(set)
    for technology in technologies:
        identity = (technology.name, technology.version)
        if identity not in seen[technology.website_id]:
            seen[technology.website_id].add(identity)
            by_website[technology.website_id].append(technology)
    endpoint_conditions = [Endpoint.website_id.in_(website_ids)]
    if matching_runs is not None:
        endpoint_conditions.append(Endpoint.scan_run_id.in_(matching_runs))
    count_rows = (
        await session.execute(
            select(Endpoint.website_id, func.count(Endpoint.id))
            .where(*endpoint_conditions)
            .group_by(Endpoint.website_id)
        )
    ).all()
    counts: dict[UUID, int] = {
        website_id: int(count) for website_id, count in count_rows if website_id is not None
    }
    return latest_snapshots, latest_screenshots, by_website, counts


def _technology_label(item: Technology) -> str:
    return f"{item.name} {item.version}".strip()


def _summary(
    website: Website,
    url_asset: Asset,
    ip_asset: Asset | None,
    snapshot: WebSnapshot | None,
    screenshot_path: str | None,
    technologies: list[Technology],
    endpoint_count: int,
) -> WebsiteSummaryRead:
    return WebsiteSummaryRead(
        id=website.id,
        project_id=website.project_id,
        asset_id=website.asset_id,
        url=website.normalized_url,
        final_url=website.final_url,
        title=website.title,
        status_code=website.status_code,
        content_type=website.content_type,
        ip=(
            ip_asset.normalized_value
            if ip_asset and not is_environment_mapping_ip(ip_asset.normalized_value)
            else None
        ),
        port=website.port,
        is_alive=website.is_alive,
        scope_status=url_asset.scope_status,
        ownership_status=website.ownership_status,
        icp_status=website.icp_status,
        technologies=[_technology_label(item) for item in technologies],
        cdn_waf=snapshot.cdn_waf if snapshot else [],
        screenshot_path=screenshot_path,
        endpoint_count=endpoint_count,
        first_seen_at=website.first_seen_at,
        last_seen_at=website.last_seen_at,
    )


async def list_websites(
    session: AsyncSession,
    project_id: UUID,
    *,
    page: int,
    page_size: int,
    execution_mode: str | None = None,
) -> WebsitePage:
    await get_project_or_404(session, project_id)
    count_statement = select(func.count(Website.id)).where(Website.project_id == project_id)
    if execution_mode is not None:
        matching_runs = select(ScanRun.id).where(
            ScanRun.project_id == project_id,
            ScanRun.config_snapshot["execution_mode"].astext == execution_mode,
        )
        count_statement = count_statement.where(
            Website.id.in_(
                select(WebSnapshot.website_id).where(
                    WebSnapshot.scan_run_id.in_(matching_runs)
                )
            )
        )
    total = int(await session.scalar(count_statement) or 0)
    rows = await _website_rows(
        session,
        project_id,
        offset=(page - 1) * page_size,
        limit=page_size,
        execution_mode=execution_mode,
    )
    ids = [website.id for website, _, _ in rows]
    snapshots, screenshots, technologies, endpoint_counts = await _related_maps(
        session, project_id, ids, execution_mode
    )
    return WebsitePage(
        items=[
            _summary(
                website,
                url_asset,
                ip_asset,
                snapshots.get(website.id),
                screenshots.get(website.id),
                technologies.get(website.id, []),
                endpoint_counts.get(website.id, 0),
            )
            for website, url_asset, ip_asset in rows
        ],
        page=page,
        page_size=page_size,
        total=total,
    )


def _snapshot_read(snapshot: WebSnapshot) -> WebSnapshotRead:
    return WebSnapshotRead(
        id=snapshot.id,
        scan_run_id=snapshot.scan_run_id,
        input_url=snapshot.input_url,
        final_url=snapshot.final_url,
        redirect_chain=snapshot.redirect_chain,
        response_time_ms=snapshot.response_time_ms,
        content_length=snapshot.content_length,
        server_header=snapshot.server_header,
        response_headers=snapshot.response_headers,
        cdn_waf=snapshot.cdn_waf,
        tls_summary=snapshot.tls_summary,
        favicon_hash=snapshot.favicon_hash,
        body_hash=snapshot.body_hash,
        screenshot_path=snapshot.screenshot_path,
        error=snapshot.error,
        observed_at=snapshot.observed_at,
    )


async def get_website_detail(session: AsyncSession, website_id: UUID) -> WebsiteDetailRead:
    website = await session.get(Website, website_id)
    if website is None:
        raise ScopeGraphError("WEBSITE_NOT_FOUND", "Website was not found", status_code=404)
    rows = await _website_rows(session, website.project_id, website_id=website_id)
    if not rows:
        raise ScopeGraphError("WEBSITE_NOT_FOUND", "Website was not found", status_code=404)
    snapshots, screenshots, technologies, endpoint_counts = await _related_maps(
        session, website.project_id, [website.id]
    )
    current_snapshot = snapshots.get(website.id)
    summary = _summary(
        *rows[0],
        current_snapshot,
        screenshots.get(website.id),
        technologies.get(website.id, []),
        endpoint_counts.get(website.id, 0),
    )
    certificates = list(
        await session.scalars(
            select(Certificate)
            .where(Certificate.website_id == website.id)
            .order_by(Certificate.observed_at.desc())
        )
    )
    filing_rows = list(
        (
            await session.execute(
                select(WebsiteICPLink, ICPRecord)
                .join(ICPRecord, ICPRecord.id == WebsiteICPLink.icp_record_id)
                .where(WebsiteICPLink.website_id == website.id)
                .order_by(ICPRecord.record_kind, ICPRecord.normalized_number)
            )
        ).all()
    )
    endpoint_rows = list(
        await session.scalars(
            select(Endpoint)
            .where(Endpoint.website_id == website.id)
            .order_by(Endpoint.normalized_url, Endpoint.method)
        )
    )
    return WebsiteDetailRead(
        **summary.model_dump(),
        snapshot=_snapshot_read(current_snapshot) if current_snapshot else None,
        technology_details=[
            TechnologyRead(
                name=item.name,
                version=item.version,
                category=item.category,
                confidence=item.confidence,
                source_tool=item.source_tool,
            )
            for item in technologies.get(website.id, [])
        ],
        certificates=[
            CertificateRead(
                id=item.id,
                subject=item.subject,
                issuer=item.issuer,
                serial_number=item.serial_number,
                not_before=item.not_before,
                not_after=item.not_after,
                san=item.san,
                fingerprint_sha256=item.fingerprint_sha256,
                validation_errors=item.validation_errors,
                observed_at=item.observed_at,
            )
            for item in certificates
        ],
        filing_links=[
            WebsiteICPLinkRead(
                record_id=record.id,
                record_kind=record.record_kind,
                normalized_number=record.normalized_number,
                display_number=record.display_number,
                subject_name=record.subject_name,
                association_status=link.association_status,
                source_url=link.source_url,
                evidence_excerpt=link.evidence_excerpt,
                official_confirmed=record.official_confirmed,
            )
            for link, record in filing_rows
        ],
        endpoints=[
            EndpointRead(
                id=item.id,
                scan_run_id=item.scan_run_id,
                website_id=item.website_id,
                normalized_url=item.normalized_url,
                method=item.method,
                kind=item.kind,
                scope_status=item.scope_status,
                actively_visited=item.actively_visited,
                source_tool=item.source_tool,
                status_code=item.status_code,
                discovered_at=item.discovered_at,
            )
            for item in endpoint_rows
        ],
    )


async def get_website_screenshot_path(session: AsyncSession, website_id: UUID) -> tuple[Path, str]:
    website = await session.get(Website, website_id)
    if website is None:
        raise ScopeGraphError("WEBSITE_NOT_FOUND", "Website was not found", status_code=404)
    snapshot = await session.scalar(
        select(WebSnapshot)
        .where(
            WebSnapshot.website_id == website.id,
            WebSnapshot.screenshot_path.is_not(None),
        )
        .order_by(WebSnapshot.observed_at.desc())
        .limit(1)
    )
    if snapshot is None or not snapshot.screenshot_path:
        raise ScopeGraphError(
            "SCREENSHOT_NOT_FOUND", "Website screenshot is not available", status_code=404
        )
    root = await asyncio.to_thread(get_settings().data_root.resolve)
    candidate = await asyncio.to_thread((root / snapshot.screenshot_path).resolve)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ScopeGraphError(
            "INVALID_SCREENSHOT_PATH", "Stored screenshot path is invalid", status_code=409
        ) from exc
    if not await asyncio.to_thread(candidate.is_file):
        raise ScopeGraphError(
            "SCREENSHOT_NOT_FOUND", "Website screenshot file is missing", status_code=404
        )
    media_type = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".svg": "image/svg+xml",
        ".webp": "image/webp",
    }.get(candidate.suffix.casefold(), "application/octet-stream")
    return candidate, media_type


async def list_icp_records(session: AsyncSession, project_id: UUID) -> list[ICPRecordRead]:
    await get_project_or_404(session, project_id)
    records = list(
        await session.scalars(
            select(ICPRecord)
            .where(ICPRecord.project_id == project_id)
            .order_by(ICPRecord.record_kind, ICPRecord.normalized_number)
        )
    )
    links = list(
        (
            await session.execute(
                select(WebsiteICPLink, Website)
                .join(Website, Website.id == WebsiteICPLink.website_id)
                .where(WebsiteICPLink.project_id == project_id)
            )
        ).all()
    )
    by_record: dict[UUID, list[ICPWebsiteRead]] = defaultdict(list)
    for link, website in links:
        by_record[link.icp_record_id].append(
            ICPWebsiteRead(
                website_id=website.id,
                url=website.normalized_url,
                association_status=link.association_status,
            )
        )
    return [
        ICPRecordRead(
            id=record.id,
            record_kind=record.record_kind,
            normalized_number=record.normalized_number,
            display_number=record.display_number,
            subject_name=record.subject_name,
            website_name=record.website_name,
            source_url=record.source_url,
            excerpt=record.excerpt,
            official_confirmed=record.official_confirmed,
            observed_at=record.observed_at,
            websites=by_record.get(record.id, []),
        )
        for record in records
    ]


async def list_endpoints(
    session: AsyncSession,
    project_id: UUID,
    *,
    scan_run_id: UUID | None = None,
    execution_mode: str | None = None,
    limit: int = 200,
) -> list[EndpointRead]:
    await get_project_or_404(session, project_id)
    statement = (
        select(Endpoint)
        .where(Endpoint.project_id == project_id)
        .order_by(Endpoint.scope_status, Endpoint.normalized_url, Endpoint.method)
    )
    if scan_run_id is not None:
        statement = statement.where(Endpoint.scan_run_id == scan_run_id)
    if execution_mode is not None:
        matching_runs = select(ScanRun.id).where(
            ScanRun.project_id == project_id,
            ScanRun.config_snapshot["execution_mode"].astext == execution_mode,
        )
        statement = statement.where(Endpoint.scan_run_id.in_(matching_runs))
    statement = statement.limit(limit)
    endpoints = list(await session.scalars(statement))
    return [
        EndpointRead(
            id=item.id,
            scan_run_id=item.scan_run_id,
            website_id=item.website_id,
            normalized_url=item.normalized_url,
            method=item.method,
            kind=item.kind,
            scope_status=item.scope_status,
            actively_visited=item.actively_visited,
            source_tool=item.source_tool,
            status_code=item.status_code,
            discovered_at=item.discovered_at,
        )
        for item in endpoints
    ]
