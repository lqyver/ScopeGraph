import re
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import case, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.domain.enums import (
    AssetType,
    EndpointKind,
    ICPAssociationStatus,
    ICPRecordKind,
    OwnershipStatus,
    RelationType,
    ScopeStatus,
)
from scopegraph.domain.models import (
    Asset,
    AssetRelation,
    Certificate,
    Endpoint,
    ICPRecord,
    ScanRun,
    Technology,
    Website,
    WebsiteICPLink,
    WebSnapshot,
)
from scopegraph.normalizers.assets import (
    NormalizationError,
    normalize_domain,
    normalize_ip,
    normalize_url,
    registrable_root_domain,
)
from scopegraph.scanning.observations import ObservationPayload
from scopegraph.scope_engine import ScopeRuleValue, evaluate_scope

AssetIdFactory = Callable[
    [AsyncSession, ScanRun, AssetType, str, list[ScopeRuleValue]], Awaitable[UUID]
]
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


def _string(value: object, limit: int) -> str | None:
    return str(value)[:limit] if value is not None and str(value).strip() else None


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _mapping(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _timestamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _first_ip(value: object) -> str | None:
    candidates = value if isinstance(value, list) else [value]
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        try:
            return normalize_ip(candidate)
        except NormalizationError:
            continue
    return None


def _technology_identity(value: str) -> tuple[str, str]:
    name, separator, version = value.rpartition(":")
    if separator and name and version[:1].isdigit():
        return name[:300], version[:300]
    return value[:300], ""


def _tls_fingerprint(tls: dict[str, object]) -> str | None:
    nested = _mapping(tls.get("fingerprint_hash"))
    value = tls.get("fingerprint_sha256") or nested.get("sha256")
    if not isinstance(value, str):
        return None
    normalized = value.casefold().replace(":", "")
    return normalized if _FINGERPRINT.fullmatch(normalized) else None


async def _website_for_asset(
    session: AsyncSession, project_id: UUID, asset_id: UUID
) -> Website | None:
    return cast(
        Website | None,
        await session.scalar(
            select(Website).where(Website.project_id == project_id, Website.asset_id == asset_id)
        ),
    )


async def _persist_website(
    session: AsyncSession,
    run: ScanRun,
    payload: ObservationPayload,
    domain_asset_id: UUID,
    url_asset_id: UUID,
    asset_factory: AssetIdFactory,
    rules: list[ScopeRuleValue],
) -> None:
    attrs = payload.attributes
    if payload.object is None:
        return
    input_url = normalize_url(str(attrs.get("input_url") or payload.object.value))
    final_url = normalize_url(str(attrs.get("final_url") or input_url))
    status_code = _integer(attrs.get("status_code"))
    ip_value = _first_ip(attrs.get("ip"))
    ip_asset_id = (
        await asset_factory(session, run, AssetType.IP, ip_value, rules) if ip_value else None
    )
    url_asset = await session.get(Asset, url_asset_id)
    ownership = (
        url_asset.ownership_status if url_asset is not None else OwnershipStatus.PENDING_REVIEW
    )
    headers = _mapping(attrs.get("response_headers"))
    content_type = _string(attrs.get("content_type"), 300)
    location = _string(headers.get("location"), 2_000)
    input_host = urlsplit(input_url).hostname
    redirect_host = urlsplit(location).hostname if location else None
    if (
        status_code is not None
        and 300 <= status_code < 400
        and input_host
        and redirect_host
        and input_host.casefold() != redirect_host.casefold()
    ):
        initial_icp_status = ICPAssociationStatus.PENDING_MANUAL_VERIFY
    elif content_type and "html" not in content_type.casefold():
        initial_icp_status = ICPAssociationStatus.NOT_APPLICABLE
    elif status_code is None or attrs.get("error") is not None:
        initial_icp_status = ICPAssociationStatus.PENDING_MANUAL_VERIFY
    else:
        initial_icp_status = ICPAssociationStatus.NOT_FOUND
    port = _integer(attrs.get("port"))
    if port is None:
        parsed = urlsplit(final_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    website_id = await session.scalar(
        pg_insert(Website)
        .values(
            project_id=run.project_id,
            asset_id=url_asset_id,
            domain_asset_id=domain_asset_id,
            ip_asset_id=ip_asset_id,
            normalized_url=input_url,
            final_url=final_url,
            title=_string(attrs.get("title"), 1_000),
            status_code=status_code,
            content_type=content_type,
            port=port,
            is_alive=status_code is not None and attrs.get("error") is None,
            ownership_status=ownership,
            icp_status=initial_icp_status,
            created_by="scan-worker",
            updated_by="scan-worker",
        )
        .on_conflict_do_update(
            index_elements=[Website.project_id, Website.asset_id],
            set_={
                "domain_asset_id": domain_asset_id,
                "ip_asset_id": ip_asset_id,
                "final_url": final_url,
                "title": _string(attrs.get("title"), 1_000),
                "status_code": status_code,
                "content_type": content_type,
                "port": port,
                "is_alive": status_code is not None and attrs.get("error") is None,
                "ownership_status": ownership,
                "icp_status": case(
                    (
                        Website.icp_status.in_(
                            [
                                ICPAssociationStatus.NOT_FOUND,
                                ICPAssociationStatus.NOT_APPLICABLE,
                                ICPAssociationStatus.PENDING_MANUAL_VERIFY,
                            ]
                        ),
                        initial_icp_status,
                    ),
                    else_=Website.icp_status,
                ),
                "last_seen_at": func.now(),
                "updated_at": func.now(),
                "updated_by": "scan-worker",
            },
        )
        .returning(Website.id)
    )
    if website_id is None:
        raise RuntimeError("Website upsert did not return an id")

    tls = _mapping(attrs.get("tls"))
    cdn_waf = [str(item)[:200] for item in _list(attrs.get("cdn_waf"))]
    await session.execute(
        pg_insert(WebSnapshot)
        .values(
            project_id=run.project_id,
            scan_run_id=run.id,
            website_id=website_id,
            input_url=input_url,
            final_url=final_url,
            redirect_chain=_list(attrs.get("redirect_chain")),
            response_time_ms=attrs.get("response_time_ms"),
            content_length=_integer(attrs.get("content_length")),
            server_header=_string(attrs.get("webserver"), 500),
            response_headers=headers,
            cdn_waf=cdn_waf,
            tls_summary=tls,
            favicon_hash=_string(attrs.get("favicon_hash"), 128),
            body_hash=_string(attrs.get("body_hash"), 128),
            screenshot_path=None,
            error=_string(attrs.get("error"), 4_096),
            observed_at=payload.observed_at,
        )
        .on_conflict_do_update(
            index_elements=[WebSnapshot.scan_run_id, WebSnapshot.website_id],
            set_={
                "final_url": final_url,
                "redirect_chain": _list(attrs.get("redirect_chain")),
                "response_time_ms": attrs.get("response_time_ms"),
                "content_length": _integer(attrs.get("content_length")),
                "server_header": _string(attrs.get("webserver"), 500),
                "response_headers": headers,
                "cdn_waf": cdn_waf,
                "tls_summary": tls,
                "favicon_hash": _string(attrs.get("favicon_hash"), 128),
                "body_hash": _string(attrs.get("body_hash"), 128),
                "error": _string(attrs.get("error"), 4_096),
                "observed_at": payload.observed_at,
            },
        )
    )

    for raw_technology in _list(attrs.get("technologies")):
        if not isinstance(raw_technology, str) or not raw_technology.strip():
            continue
        name, version = _technology_identity(raw_technology.strip())
        await session.execute(
            pg_insert(Technology)
            .values(
                project_id=run.project_id,
                scan_run_id=run.id,
                website_id=website_id,
                name=name,
                version=version,
                confidence=1.0,
                source_tool=payload.source_tool,
            )
            .on_conflict_do_nothing(
                index_elements=[
                    Technology.scan_run_id,
                    Technology.website_id,
                    Technology.name,
                    Technology.version,
                ]
            )
        )

    fingerprint = _tls_fingerprint(tls)
    if fingerprint:
        san = tls.get("subject_an") or tls.get("san")
        await session.execute(
            pg_insert(Certificate)
            .values(
                project_id=run.project_id,
                scan_run_id=run.id,
                website_id=website_id,
                subject=_string(tls.get("subject_dn") or tls.get("subject"), 2_000),
                issuer=_string(tls.get("issuer_dn") or tls.get("issuer"), 2_000),
                serial_number=_string(tls.get("serial") or tls.get("serial_number"), 300),
                not_before=_timestamp(tls.get("not_before")),
                not_after=_timestamp(tls.get("not_after")),
                san=[str(item)[:253] for item in _list(san)],
                fingerprint_sha256=fingerprint,
                validation_errors=[str(item)[:500] for item in _list(tls.get("validation_errors"))],
                observed_at=payload.observed_at,
            )
            .on_conflict_do_nothing(
                index_elements=[
                    Certificate.scan_run_id,
                    Certificate.website_id,
                    Certificate.fingerprint_sha256,
                ]
            )
        )


async def _persist_icp(
    session: AsyncSession,
    run: ScanRun,
    payload: ObservationPayload,
    website_asset_id: UUID,
    icp_asset_id: UUID,
) -> None:
    website = await _website_for_asset(session, run.project_id, website_asset_id)
    if website is None:
        return
    attrs = payload.attributes
    try:
        kind = ICPRecordKind(str(attrs.get("record_kind")))
    except ValueError:
        return
    number = payload.object.value if payload.object else ""
    if not number:
        return
    subjects = [str(item)[:500] for item in _list(attrs.get("copyright_subjects"))]
    source_url = _string(attrs.get("source_url"), 4_096) or website.normalized_url
    excerpt = _string(attrs.get("excerpt"), 2_000) or number
    display_number = _string(attrs.get("display_number"), 200) or number
    record_id = await session.scalar(
        pg_insert(ICPRecord)
        .values(
            project_id=run.project_id,
            record_kind=kind,
            normalized_number=number,
            display_number=display_number,
            subject_name=subjects[0] if subjects else None,
            website_name=website.title,
            source_url=source_url,
            excerpt=excerpt,
            official_confirmed=False,
            observed_at=payload.observed_at,
            created_by="scan-worker",
            updated_by="scan-worker",
        )
        .on_conflict_do_update(
            index_elements=[
                ICPRecord.project_id,
                ICPRecord.record_kind,
                ICPRecord.normalized_number,
            ],
            set_={
                "display_number": display_number,
                "subject_name": subjects[0] if subjects else None,
                "website_name": website.title,
                "source_url": source_url,
                "excerpt": excerpt,
                "observed_at": payload.observed_at,
                "updated_at": func.now(),
                "updated_by": "scan-worker",
            },
        )
        .returning(ICPRecord.id)
    )
    if record_id is None:
        return
    await session.execute(
        pg_insert(WebsiteICPLink)
        .values(
            project_id=run.project_id,
            website_id=website.id,
            icp_record_id=record_id,
            association_status=ICPAssociationStatus.PAGE_DIRECT,
            source_url=source_url,
            evidence_excerpt=excerpt,
        )
        .on_conflict_do_update(
            index_elements=[WebsiteICPLink.website_id, WebsiteICPLink.icp_record_id],
            set_={
                "association_status": ICPAssociationStatus.PAGE_DIRECT,
                "source_url": source_url,
                "evidence_excerpt": excerpt,
            },
        )
    )
    website.icp_status = ICPAssociationStatus.PAGE_DIRECT
    await session.execute(
        update(Asset)
        .where(Asset.id == icp_asset_id)
        .values(scope_status=ScopeStatus.IN_SCOPE, ownership_status=website.ownership_status)
    )


async def _mark_pending_asset(session: AsyncSession, asset_id: UUID) -> None:
    await session.execute(
        update(Asset)
        .where(
            Asset.id == asset_id,
            Asset.scope_status.notin_([ScopeStatus.IN_SCOPE, ScopeStatus.EXCLUDED]),
        )
        .values(
            scope_status=ScopeStatus.PENDING_REVIEW,
            ownership_status=OwnershipStatus.PENDING_REVIEW,
            confidence_score=0,
            updated_at=func.now(),
            updated_by="scan-worker",
        )
    )


async def _persist_endpoint(
    session: AsyncSession,
    run: ScanRun,
    payload: ObservationPayload,
    source_asset_id: UUID,
    endpoint_asset_id: UUID,
    asset_factory: AssetIdFactory,
    rules: list[ScopeRuleValue],
) -> None:
    if payload.object is None:
        return
    attrs = payload.attributes
    endpoint_url = normalize_url(payload.object.value)
    method = str(attrs.get("method") or "GET").upper()[:10]
    try:
        kind = EndpointKind(str(attrs.get("kind") or EndpointKind.PAGE.value))
    except ValueError:
        kind = EndpointKind.PAGE
    decision = evaluate_scope(AssetType.URL, endpoint_url, rules)
    external = bool(attrs.get("external_candidate"))
    scope_status = decision.status
    if external and scope_status not in {ScopeStatus.IN_SCOPE, ScopeStatus.EXCLUDED}:
        scope_status = ScopeStatus.PENDING_REVIEW
        await _mark_pending_asset(session, endpoint_asset_id)

    hostname = urlsplit(endpoint_url).hostname
    domain_asset_id: UUID | None = None
    if hostname:
        try:
            domain = normalize_domain(hostname)
            root = registrable_root_domain(domain)
        except NormalizationError:
            domain = None
            root = None
        if domain and root:
            domain_asset_id = await asset_factory(session, run, AssetType.DOMAIN, domain, rules)
            root_asset_id = await asset_factory(session, run, AssetType.DOMAIN, root, rules)
            if external and scope_status is ScopeStatus.PENDING_REVIEW:
                await _mark_pending_asset(session, domain_asset_id)
                await _mark_pending_asset(session, root_asset_id)
            if domain_asset_id != root_asset_id:
                await session.execute(
                    pg_insert(AssetRelation)
                    .values(
                        project_id=run.project_id,
                        source_asset_id=root_asset_id,
                        target_asset_id=domain_asset_id,
                        relation_type=RelationType.HAS_SUBDOMAIN,
                        confidence=0.6 if external else 1.0,
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

    website = await _website_for_asset(session, run.project_id, source_asset_id)
    if website is None and domain_asset_id is not None:
        website = await session.scalar(
            select(Website).where(
                Website.project_id == run.project_id,
                Website.domain_asset_id == domain_asset_id,
            )
        )
    active = (
        bool(attrs.get("actively_visited"))
        and method in {"GET", "HEAD"}
        and scope_status is ScopeStatus.IN_SCOPE
    )
    await session.execute(
        pg_insert(Endpoint)
        .values(
            project_id=run.project_id,
            scan_run_id=run.id,
            website_id=website.id if website else None,
            normalized_url=endpoint_url,
            method=method,
            kind=kind,
            scope_status=scope_status,
            actively_visited=active,
            source_tool=payload.source_tool,
            status_code=_integer(attrs.get("status_code")),
            discovered_at=payload.observed_at,
        )
        .on_conflict_do_update(
            index_elements=[Endpoint.scan_run_id, Endpoint.normalized_url, Endpoint.method],
            set_={
                "website_id": website.id if website else None,
                "kind": kind,
                "scope_status": scope_status,
                "actively_visited": case((Endpoint.actively_visited.is_(True), True), else_=active),
                "status_code": _integer(attrs.get("status_code")),
            },
        )
    )


async def persist_web_observation(
    session: AsyncSession,
    run: ScanRun,
    payload: ObservationPayload,
    subject_asset_id: UUID,
    object_asset_id: UUID | None,
    rules: list[ScopeRuleValue],
    asset_factory: AssetIdFactory,
) -> None:
    if payload.predicate == "SERVES_WEBSITE" and object_asset_id is not None:
        await _persist_website(
            session,
            run,
            payload,
            subject_asset_id,
            object_asset_id,
            asset_factory,
            rules,
        )
    elif payload.predicate == "HAS_ICP_RECORD" and object_asset_id is not None:
        await _persist_icp(session, run, payload, subject_asset_id, object_asset_id)
    elif payload.predicate == "DISCOVERED_ENDPOINT" and object_asset_id is not None:
        await _persist_endpoint(
            session,
            run,
            payload,
            subject_asset_id,
            object_asset_id,
            asset_factory,
            rules,
        )
    elif payload.predicate in {"SCREENSHOT_CAPTURED", "SCREENSHOT_FAILED"}:
        website = await _website_for_asset(session, run.project_id, subject_asset_id)
        if website is None:
            return
        screenshot_path = payload.attributes.get("screenshot_path")
        stored_path: str | None = None
        if isinstance(screenshot_path, str):
            raw_parent = payload.raw_artifact_path.replace("\\", "/").rsplit("/", 1)[0]
            stored_path = f"{raw_parent}/{screenshot_path}"
        if stored_path is None:
            return
        await session.execute(
            update(WebSnapshot)
            .where(
                WebSnapshot.scan_run_id == run.id,
                WebSnapshot.website_id == website.id,
            )
            .values(screenshot_path=stored_path)
        )


async def infer_root_icp_links(session: AsyncSession, run: ScanRun) -> int:
    direct_rows = list(
        (
            await session.execute(
                select(Website, WebsiteICPLink, ICPRecord)
                .join(WebsiteICPLink, WebsiteICPLink.website_id == Website.id)
                .join(ICPRecord, ICPRecord.id == WebsiteICPLink.icp_record_id)
                .where(
                    Website.project_id == run.project_id,
                    WebsiteICPLink.association_status == ICPAssociationStatus.PAGE_DIRECT,
                )
            )
        ).all()
    )
    by_root: dict[str, list[tuple[WebsiteICPLink, ICPRecord]]] = {}
    for website, link, record in direct_rows:
        hostname = urlsplit(website.normalized_url).hostname
        if not hostname:
            continue
        try:
            root = registrable_root_domain(hostname)
        except NormalizationError:
            continue
        by_root.setdefault(root, []).append((link, record))

    candidates = list(
        await session.scalars(
            select(Website).where(
                Website.project_id == run.project_id,
                Website.icp_status == ICPAssociationStatus.NOT_FOUND,
            )
        )
    )
    created = 0
    for website in candidates:
        hostname = urlsplit(website.normalized_url).hostname
        if not hostname:
            continue
        try:
            root = registrable_root_domain(hostname)
        except NormalizationError:
            continue
        for direct_link, record in by_root.get(root, []):
            inserted = await session.scalar(
                pg_insert(WebsiteICPLink)
                .values(
                    project_id=run.project_id,
                    website_id=website.id,
                    icp_record_id=record.id,
                    association_status=ICPAssociationStatus.ROOT_DOMAIN_INFERRED,
                    source_url=direct_link.source_url,
                    evidence_excerpt=(
                        f"Root-domain inference from direct evidence at {direct_link.source_url}"
                    )[:2_000],
                )
                .on_conflict_do_nothing(
                    index_elements=[WebsiteICPLink.website_id, WebsiteICPLink.icp_record_id]
                )
                .returning(WebsiteICPLink.id)
            )
            created += inserted is not None
        if by_root.get(root):
            website.icp_status = ICPAssociationStatus.ROOT_DOMAIN_INFERRED
    return created
