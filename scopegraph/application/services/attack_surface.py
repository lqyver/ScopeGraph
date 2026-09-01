"""Read-only domain-centric aggregation for the project intelligence views."""

from collections import defaultdict
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.enums import AssetType, FindingSeverity, PortState, RelationType
from scopegraph.domain.models import (
    Asset,
    AssetRelation,
    Endpoint,
    Finding,
    Observation,
    Port,
    ScanRun,
    Service,
    Technology,
    Website,
    WebSnapshot,
)
from scopegraph.schemas.attack_surface import (
    AttackSurfaceFindingRead,
    AttackSurfaceItemRead,
    AttackSurfacePage,
    AttackSurfacePortRead,
    AttackSurfaceServiceRead,
    AttackSurfaceSummaryRead,
    AttackSurfaceWebsiteRead,
)
from scopegraph.tooling.network_policy import is_environment_mapping_ip

_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 5,
    FindingSeverity.HIGH: 4,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.LOW: 2,
    FindingSeverity.INFO: 1,
    FindingSeverity.UNKNOWN: 0,
}
_WEB_COMMON_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888}


def _technology_label(item: Technology) -> str:
    return f"{item.name} {item.version}".strip()


def _priority(
    item: AttackSurfaceItemRead,
) -> tuple[int, Literal["urgent", "high", "review", "observed"], list[str]]:
    """Rank review order from observable signals, never a vulnerability verdict."""

    score = 0
    reasons: list[str] = []
    active = [finding for finding in item.findings if finding.is_active]
    severity_counts = {
        severity: sum(1 for finding in active if finding.severity is severity)
        for severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM)
    }
    if severity_counts[FindingSeverity.CRITICAL]:
        count = severity_counts[FindingSeverity.CRITICAL]
        score += min(60, count * 60)
        reasons.append(f"{count} 条严重级自动化命中（仍待人工验证）")
    if severity_counts[FindingSeverity.HIGH]:
        count = severity_counts[FindingSeverity.HIGH]
        score += min(40, count * 40)
        reasons.append(f"{count} 条高危级自动化命中（仍待人工验证）")
    if severity_counts[FindingSeverity.MEDIUM]:
        count = severity_counts[FindingSeverity.MEDIUM]
        score += min(20, count * 10)
        reasons.append(f"{count} 条中危级自动化命中（仍待人工验证）")

    non_web_ports = [port for port in item.ports if port.port not in _WEB_COMMON_PORTS]
    if non_web_ports:
        score += min(24, len(non_web_ports) * 8)
        reasons.append(f"发现 {len(non_web_ports)} 个非 Web 常见端口")
    identified_services = [port for port in item.ports if port.service and port.service.name]
    if identified_services:
        score += min(8, len(identified_services) * 2)
        reasons.append(f"{len(identified_services)} 个端口已完成服务指纹")
    alive_websites = [website for website in item.websites if website.is_alive]
    if alive_websites:
        score += 5
        reasons.append(f"{len(alive_websites)} 个存活网站")
    if item.endpoint_count >= 10:
        score += min(12, item.endpoint_count // 10 * 3)
        reasons.append(f"已发现 {item.endpoint_count} 个站点端点")
    if item.technologies:
        score += min(6, len(item.technologies))
    if item.scope_status.value == "IN_SCOPE":
        score += 3
    if item.ownership_status.value in {"CONFIRMED", "HIGH_CONFIDENCE"}:
        score += 3

    score = min(100, score)
    tier: Literal["urgent", "high", "review", "observed"]
    if score >= 75:
        tier = "urgent"
    elif score >= 45:
        tier = "high"
    elif score >= 20:
        tier = "review"
    else:
        tier = "observed"
    if not reasons:
        reasons.append("已收集资产，尚无额外优先复核信号")
    return score, tier, reasons[:6]


def _latest_timestamp(values: list[datetime]) -> datetime:
    return max(values)


def _website_read(
    website: Website,
    observation: Observation | None,
    snapshot: WebSnapshot | None,
    endpoint_count: int,
) -> AttackSurfaceWebsiteRead:
    attributes = observation.attributes if observation is not None else {}
    status_value = attributes.get("status_code")
    status_code = (
        status_value
        if isinstance(status_value, int) and not isinstance(status_value, bool)
        else None
    )
    title_value = attributes.get("title")
    title = str(title_value)[:1000] if title_value is not None else None
    final_url = snapshot.final_url if snapshot is not None else website.normalized_url
    port_value = attributes.get("port")
    port = port_value if isinstance(port_value, int) and not isinstance(port_value, bool) else None
    if port is None:
        parsed = urlsplit(final_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    last_seen_at = (
        observation.observed_at
        if observation is not None
        else snapshot.observed_at
        if snapshot is not None
        else website.last_seen_at
    )
    return AttackSurfaceWebsiteRead(
        id=website.id,
        url=website.normalized_url,
        final_url=final_url,
        title=title,
        status_code=status_code,
        port=port,
        is_alive=status_code is not None and attributes.get("error") is None,
        endpoint_count=endpoint_count,
        last_seen_at=last_seen_at,
    )


async def page_attack_surface(
    session: AsyncSession,
    project_id: UUID,
    *,
    page: int,
    page_size: int,
    execution_mode: str = "host",
) -> AttackSurfacePage:
    """Return a bounded attack-surface inventory centered on each domain.

    The source tables remain independently queryable for auditability.  This
    service only joins their already-recorded evidence so an operator can see
    the ports, websites, technology signals, and unverified findings belonging
    to the same domain in one place.
    """

    await get_project_or_404(session, project_id)
    matching_runs = select(ScanRun.id).where(
        ScanRun.project_id == project_id,
        ScanRun.execution_mode == execution_mode,
    )
    domains = list(
        (
            await session.scalars(
                select(Asset)
                .where(
                    Asset.project_id == project_id,
                    Asset.asset_type == AssetType.DOMAIN,
                    exists(
                        select(Observation.id).where(
                            Observation.project_id == project_id,
                            Observation.scan_run_id.in_(matching_runs),
                            or_(
                                (Observation.subject_type == AssetType.DOMAIN.value)
                                & (Observation.subject_value == Asset.normalized_value),
                                (Observation.object_type == AssetType.DOMAIN.value)
                                & (Observation.object_value == Asset.normalized_value),
                            ),
                        )
                    ),
                )
                .order_by(Asset.normalized_value)
            )
        ).all()
    )
    if not domains:
        return AttackSurfacePage(
            items=[],
            page=page,
            page_size=page_size,
            total=0,
            summary=AttackSurfaceSummaryRead(),
        )

    domain_by_id = {item.id: item for item in domains}
    domain_by_value = {item.normalized_value: item for item in domains}
    domain_ids = list(domain_by_id)
    dns_observations = (
        await session.execute(
            select(Observation.subject_value, Observation.object_value).where(
                Observation.project_id == project_id,
                Observation.scan_run_id.in_(matching_runs),
                Observation.predicate == "RESOLVES_TO",
                Observation.subject_type == AssetType.DOMAIN.value,
                Observation.object_type == AssetType.IP.value,
            )
        )
    ).all()
    ip_values = {value for _, value in dns_observations if value is not None}
    ip_assets = list(
        await session.scalars(
            select(Asset).where(
                Asset.project_id == project_id,
                Asset.asset_type == AssetType.IP,
                Asset.normalized_value.in_(ip_values),
            )
        )
    )
    ip_by_value = {item.normalized_value: item for item in ip_assets}
    ips_by_domain: dict[UUID, dict[UUID, Asset]] = defaultdict(dict)
    domains_by_ip: dict[UUID, set[UUID]] = defaultdict(set)
    excluded_mappings: set[str] = set()
    for domain_value, ip_value in dns_observations:
        domain = domain_by_value.get(domain_value)
        ip = ip_by_value.get(ip_value or "")
        if domain is None or ip is None:
            continue
        if is_environment_mapping_ip(ip.normalized_value):
            excluded_mappings.add(ip.normalized_value)
            continue
        ips_by_domain[domain.id][ip.id] = ip
        domains_by_ip[ip.id].add(domain.id)

    website_rows = list(
        (
            await session.scalars(
                select(Website).where(
                    Website.project_id == project_id,
                    Website.id.in_(
                        select(WebSnapshot.website_id).where(
                            WebSnapshot.scan_run_id.in_(matching_runs)
                        )
                    ),
                )
            )
        ).all()
    )
    url_domain_rows = (
        await session.execute(
            select(AssetRelation.source_asset_id, AssetRelation.target_asset_id)
            .where(
                AssetRelation.project_id == project_id,
                AssetRelation.source_asset_id.in_(domain_ids),
                AssetRelation.relation_type == RelationType.SERVES_WEBSITE,
            )
        )
    ).all()
    domain_by_url_asset = {
        target_asset_id: source_asset_id
        for source_asset_id, target_asset_id in url_domain_rows
        if source_asset_id in domain_by_id
    }
    domain_by_website: dict[UUID, UUID] = {}
    websites_by_domain: dict[UUID, list[Website]] = defaultdict(list)
    for website in website_rows:
        domain_id = website.domain_asset_id or domain_by_url_asset.get(website.asset_id)
        if domain_id not in domain_by_id:
            continue
        domain_by_website[website.id] = domain_id
        websites_by_domain[domain_id].append(website)

    website_ids = list(domain_by_website)
    web_observation_by_url: dict[str, Observation] = {}
    web_snapshot_by_website: dict[UUID, WebSnapshot] = {}
    if website_ids:
        website_urls = [
            website.normalized_url
            for website in website_rows
            if website.id in domain_by_website
        ]
        for observation in await session.scalars(
            select(Observation)
            .where(
                Observation.project_id == project_id,
                Observation.scan_run_id.in_(matching_runs),
                Observation.predicate == "SERVES_WEBSITE",
                Observation.object_value.in_(website_urls),
            )
            .order_by(Observation.observed_at.desc())
        ):
            if observation.object_value is not None:
                web_observation_by_url.setdefault(observation.object_value, observation)
        for snapshot in await session.scalars(
            select(WebSnapshot)
            .where(
                WebSnapshot.website_id.in_(website_ids),
                WebSnapshot.scan_run_id.in_(matching_runs),
            )
            .order_by(WebSnapshot.observed_at.desc())
        ):
            web_snapshot_by_website.setdefault(snapshot.website_id, snapshot)
    endpoint_counts: dict[UUID, int] = {}
    technologies_by_domain: dict[UUID, set[str]] = defaultdict(set)
    if website_ids:
        endpoint_rows = (
            await session.execute(
                select(Endpoint.website_id, func.count(func.distinct(Endpoint.normalized_url)))
                .where(
                    Endpoint.project_id == project_id,
                    Endpoint.website_id.in_(website_ids),
                    Endpoint.scan_run_id.in_(matching_runs),
                )
                .group_by(Endpoint.website_id)
            )
        ).all()
        endpoint_counts = {
            website_id: int(count)
            for website_id, count in endpoint_rows
            if website_id is not None
        }
        technologies = list(
            (
                await session.scalars(
                    select(Technology).where(
                        Technology.project_id == project_id,
                        Technology.website_id.in_(website_ids),
                        Technology.scan_run_id.in_(matching_runs),
                    )
                )
            ).all()
        )
        for technology in technologies:
            domain_id = domain_by_website.get(technology.website_id)
            if domain_id is not None:
                technologies_by_domain[domain_id].add(_technology_label(technology))

    visible_ip_ids = list(domains_by_ip)
    ports_by_domain: dict[UUID, dict[tuple[str, int, str], AttackSurfacePortRead]] = (
        defaultdict(dict)
    )
    if visible_ip_ids:
        port_ip_asset = aliased(Asset)
        port_rows = (
            await session.execute(
                select(Port, port_ip_asset, Service)
                .join(port_ip_asset, port_ip_asset.id == Port.ip_asset_id)
                .outerjoin(Service, Service.port_id == Port.id)
                .where(
                    Port.project_id == project_id,
                    Port.ip_asset_id.in_(visible_ip_ids),
                    Port.state == PortState.OPEN,
                    Port.scan_run_id.in_(matching_runs),
                )
            )
        ).all()
        for port, ip, service in port_rows:
            candidate = AttackSurfacePortRead(
                ip=ip.normalized_value,
                port=port.port,
                protocol=port.protocol,
                state=port.state,
                source_tool=port.source_tool,
                last_seen_at=port.last_seen_at,
                service=(
                    AttackSurfaceServiceRead(
                        name=service.name,
                        product=service.product,
                        version=service.version,
                        tls=service.tls,
                    )
                    if service is not None
                    else None
                ),
            )
            key = (candidate.ip, candidate.port, candidate.protocol.value)
            for domain_id in domains_by_ip.get(port.ip_asset_id, set()):
                previous = ports_by_domain[domain_id].get(key)
                if previous is None or candidate.last_seen_at > previous.last_seen_at:
                    ports_by_domain[domain_id][key] = candidate

    domains_by_finding_asset: dict[UUID, set[UUID]] = defaultdict(set)
    for domain_id in domain_by_id:
        domains_by_finding_asset[domain_id].add(domain_id)
    for ip_id, related_domains in domains_by_ip.items():
        domains_by_finding_asset[ip_id].update(related_domains)
    for website in website_rows:
        domain_id = domain_by_website.get(website.id)
        if domain_id is not None:
            domains_by_finding_asset[website.asset_id].add(domain_id)

    findings_by_domain: dict[UUID, dict[UUID, Finding]] = defaultdict(dict)
    relevant_finding_asset_ids = list(domains_by_finding_asset)
    findings = list(
        (
            await session.scalars(
                select(Finding).where(
                    Finding.project_id == project_id,
                    Finding.execution_mode == execution_mode,
                    Finding.asset_id.in_(relevant_finding_asset_ids),
                )
            )
        ).all()
    )
    for finding in findings:
        for domain_id in domains_by_finding_asset.get(finding.asset_id, set()):
            findings_by_domain[domain_id][finding.id] = finding

    items: list[AttackSurfaceItemRead] = []
    for domain in domains:
        domain_id = domain.id
        ports = sorted(
            ports_by_domain.get(domain_id, {}).values(),
            key=lambda value: (value.ip, value.port, value.protocol.value),
        )[:30]
        website_values = sorted(
            websites_by_domain.get(domain_id, []),
            key=lambda value: (
                not _website_read(
                    value,
                    web_observation_by_url.get(value.normalized_url),
                    web_snapshot_by_website.get(value.id),
                    endpoint_counts.get(value.id, 0),
                ).is_alive,
                value.normalized_url,
            ),
        )
        websites = [
            _website_read(
                website,
                web_observation_by_url.get(website.normalized_url),
                web_snapshot_by_website.get(website.id),
                endpoint_counts.get(website.id, 0),
            )
            for website in website_values[:20]
        ]
        finding_values = sorted(
            findings_by_domain.get(domain_id, {}).values(),
            key=lambda value: (
                not value.is_active,
                -_SEVERITY_RANK[value.severity],
                value.template_name,
                value.target,
            ),
        )
        finding_rows = [
            AttackSurfaceFindingRead(
                id=finding.id,
                template_id=finding.template_id,
                template_name=finding.template_name,
                severity=finding.severity,
                status=finding.status,
                target=finding.target,
                is_active=finding.is_active,
                last_seen_at=finding.last_seen_at,
            )
            for finding in finding_values[:10]
        ]
        timestamps = [domain.last_seen_at]
        timestamps.extend(port.last_seen_at for port in ports)
        timestamps.extend(website.last_seen_at for website in websites)
        timestamps.extend(finding.last_seen_at for finding in finding_rows)
        item = AttackSurfaceItemRead(
            domain_asset_id=domain.id,
            domain=domain.normalized_value,
            scope_status=domain.scope_status,
            ownership_status=domain.ownership_status,
            resolved_ips=sorted(
                asset.normalized_value for asset in ips_by_domain.get(domain_id, {}).values()
            ),
            ports=ports,
            websites=websites,
            technologies=sorted(
                technologies_by_domain.get(domain_id, set()), key=str.casefold
            )[:30],
            endpoint_count=sum(endpoint_counts.get(website.id, 0) for website in website_values),
            findings=finding_rows,
            active_finding_count=sum(1 for finding in finding_values if finding.is_active),
            high_finding_count=sum(
                1
                for finding in finding_values
                if finding.is_active
                and finding.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}
            ),
            priority_score=0,
            priority_tier="observed",
            priority_reasons=[],
            last_seen_at=_latest_timestamp(timestamps),
        )
        score, tier, reasons = _priority(item)
        item.priority_score = score
        item.priority_tier = tier
        item.priority_reasons = reasons
        items.append(item)

    items.sort(
        key=lambda value: (
            -value.priority_score,
            -value.high_finding_count,
            -value.active_finding_count,
            value.domain,
        )
    )
    all_ports = {
        (port.ip, port.port, port.protocol.value)
        for item in items
        for port in item.ports
    }
    all_technologies = {technology for item in items for technology in item.technologies}
    all_findings = {
        finding.id: finding
        for item in items
        for finding in item.findings
    }.values()
    active_findings = [finding for finding in all_findings if finding.is_active]
    summary = AttackSurfaceSummaryRead(
        domains=len(items),
        active_websites=sum(
            1 for item in items for website in item.websites if website.is_alive
        ),
        domains_with_ports=sum(1 for item in items if item.ports),
        open_ports=len(all_ports),
        technologies=len(all_technologies),
        active_findings=len(active_findings),
        high_findings=sum(
            1
            for finding in active_findings
            if finding.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}
        ),
        high_priority_targets=sum(
            1 for item in items if item.priority_tier in {"urgent", "high"}
        ),
    )
    offset = (page - 1) * page_size
    return AttackSurfacePage(
        items=items[offset : offset + page_size],
        page=page,
        page_size=page_size,
        total=len(items),
        summary=summary,
        environment_mappings_excluded=len(excluded_mappings),
    )
