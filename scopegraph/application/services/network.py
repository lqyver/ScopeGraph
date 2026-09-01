import ipaddress
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select
from sqlalchemy.sql.elements import ColumnElement

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.enums import AssetType, IPClassification, ScopeStatus
from scopegraph.domain.models import Asset, AuditLog, IPDetail, Observation, Port, ScanRun, Service
from scopegraph.scanning.port_policy import classify_ip
from scopegraph.schemas.network import (
    IPClassificationUpdate,
    IPInventoryPage,
    IPInventoryRead,
    PortInventoryPage,
    PortInventoryRead,
    ServiceRead,
)

_BENCHMARK_NETWORK = ipaddress.ip_network("198.18.0.0/15")


def _visible_ip_condition() -> ColumnElement[bool]:
    return and_(
        Asset.normalized_value.not_like("198.18.%"),
        Asset.normalized_value.not_like("198.19.%"),
    )


def _matching_run_ids(project_id: UUID, execution_mode: str) -> Select[tuple[UUID]]:
    return select(ScanRun.id).where(
        ScanRun.project_id == project_id,
        ScanRun.execution_mode == execution_mode,
    )


def _observed_ip_condition(project_id: UUID, execution_mode: str) -> ColumnElement[bool]:
    matching_runs = _matching_run_ids(project_id, execution_mode)
    return exists(
        select(Observation.id).where(
            Observation.project_id == project_id,
            Observation.scan_run_id.in_(matching_runs),
            or_(
                (Observation.subject_type == AssetType.IP.value)
                & (Observation.subject_value == Asset.normalized_value),
                (Observation.object_type == AssetType.IP.value)
                & (Observation.object_value == Asset.normalized_value),
            ),
        )
    )


def _environment_warning(value: str) -> str | None:
    address = ipaddress.ip_address(value)
    if address in _BENCHMARK_NETWORK:
        return (
            "该地址属于网络基准测试保留段 198.18.0.0/15；当前运行环境可能进行了 "
            "DNS/HTTP 代理映射，不能把它当作目标真实公网 IP。"
        )
    return None


def _ip_read(asset: Asset, detail: IPDetail | None) -> IPInventoryRead:
    return IPInventoryRead(
        asset_id=asset.id,
        ip=asset.normalized_value,
        scope_status=asset.scope_status,
        classification=(detail.classification if detail else classify_ip(asset.normalized_value)),
        classification_source=(detail.classification_source if detail else "derived_on_read"),
        asn=detail.asn if detail else None,
        organization=detail.organization if detail else None,
        provider=detail.provider if detail else None,
        reverse_dns=detail.reverse_dns if detail else None,
        is_private=(
            detail.is_private
            if detail
            else not ipaddress.ip_address(asset.normalized_value).is_global
        ),
        is_cdn=detail.is_cdn if detail else False,
        environment_warning=_environment_warning(asset.normalized_value),
        updated_at=detail.updated_at if detail else None,
    )


async def list_ip_inventory(
    session: AsyncSession,
    project_id: UUID,
    *,
    execution_mode: str = "host",
) -> list[IPInventoryRead]:
    await get_project_or_404(session, project_id)
    rows = (
        await session.execute(
            select(Asset, IPDetail)
            .outerjoin(IPDetail, IPDetail.asset_id == Asset.id)
            .where(
                Asset.project_id == project_id,
                Asset.asset_type == AssetType.IP,
                _visible_ip_condition(),
                _observed_ip_condition(project_id, execution_mode),
            )
            .order_by(Asset.normalized_value)
            .limit(1000)
        )
    ).all()
    return [_ip_read(asset, detail) for asset, detail in rows]


async def page_ip_inventory(
    session: AsyncSession,
    project_id: UUID,
    *,
    page: int,
    page_size: int,
    execution_mode: str = "host",
) -> IPInventoryPage:
    await get_project_or_404(session, project_id)
    visible_condition = _visible_ip_condition()
    observed_condition = _observed_ip_condition(project_id, execution_mode)
    total = int(
        await session.scalar(
            select(func.count(Asset.id)).where(
                Asset.project_id == project_id,
                Asset.asset_type == AssetType.IP,
                visible_condition,
                observed_condition,
            )
        )
        or 0
    )
    ignored = int(
        await session.scalar(
            select(func.count(Asset.id)).where(
                Asset.project_id == project_id,
                Asset.asset_type == AssetType.IP,
                ~visible_condition,
                observed_condition,
            )
        )
        or 0
    )
    rows = (
        await session.execute(
            select(Asset, IPDetail)
            .outerjoin(IPDetail, IPDetail.asset_id == Asset.id)
            .where(
                Asset.project_id == project_id,
                Asset.asset_type == AssetType.IP,
                visible_condition,
                observed_condition,
            )
            .order_by(Asset.normalized_value)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    return IPInventoryPage(
        items=[_ip_read(asset, detail) for asset, detail in rows],
        page=page,
        page_size=page_size,
        total=total,
        ignored_environment_mappings=ignored,
    )


async def update_ip_classification(
    session: AsyncSession,
    project_id: UUID,
    asset_id: UUID,
    payload: IPClassificationUpdate,
) -> IPInventoryRead:
    await get_project_or_404(session, project_id)
    asset = await session.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.project_id == project_id,
            Asset.asset_type == AssetType.IP,
        )
    )
    if asset is None:
        raise ScopeGraphError("IP_ASSET_NOT_FOUND", "IP asset was not found", status_code=404)
    if (
        payload.classification is IPClassification.OWNED
        and asset.scope_status is not ScopeStatus.IN_SCOPE
    ):
        raise ScopeGraphError(
            "OWNED_IP_REQUIRES_SCOPE",
            "An IP must be explicitly in active Scope before it can be classified as OWNED",
            status_code=409,
        )
    address_class = classify_ip(asset.normalized_value)
    if (
        address_class is IPClassification.PRIVATE_RESERVED
        and payload.classification is not address_class
    ):
        raise ScopeGraphError(
            "RESERVED_IP_CLASSIFICATION_LOCKED",
            "Private and reserved addresses cannot be reclassified for active scanning",
            status_code=409,
        )

    await session.execute(
        pg_insert(IPDetail)
        .values(
            project_id=project_id,
            asset_id=asset.id,
            classification=payload.classification,
            classification_source="manual",
            is_private=payload.classification is IPClassification.PRIVATE_RESERVED,
            is_cdn=payload.classification is IPClassification.CDN_WAF,
            metadata_json={"classification_reason": payload.reason},
            created_by="local-admin",
            updated_by="local-admin",
        )
        .on_conflict_do_update(
            index_elements=[IPDetail.project_id, IPDetail.asset_id],
            set_={
                "classification": payload.classification,
                "classification_source": "manual",
                "is_private": payload.classification is IPClassification.PRIVATE_RESERVED,
                "is_cdn": payload.classification is IPClassification.CDN_WAF,
                "metadata": {"classification_reason": payload.reason},
                "updated_by": "local-admin",
                "updated_at": datetime.now(UTC),
            },
        )
    )
    session.add(
        AuditLog(
            project_id=project_id,
            actor="local-admin",
            action="IP_CLASSIFICATION_UPDATED",
            resource_type="asset",
            resource_id=str(asset.id),
            details={
                "classification": payload.classification.value,
                "reason": payload.reason,
            },
        )
    )
    await session.commit()
    await session.refresh(asset)
    detail = await session.scalar(select(IPDetail).where(IPDetail.asset_id == asset.id))
    return _ip_read(asset, detail)


async def list_port_inventory(
    session: AsyncSession,
    project_id: UUID,
    *,
    scan_run_id: UUID | None = None,
    execution_mode: str = "host",
) -> list[PortInventoryRead]:
    await get_project_or_404(session, project_id)
    statement = (
        select(Port, Asset, Service)
        .join(Asset, Asset.id == Port.ip_asset_id)
        .outerjoin(Service, Service.port_id == Port.id)
        .where(Port.project_id == project_id)
        .where(_visible_ip_condition())
        .where(Port.scan_run_id.in_(_matching_run_ids(project_id, execution_mode)))
        .order_by(Asset.normalized_value, Port.port, Port.protocol)
        .limit(1000)
    )
    if scan_run_id is not None:
        statement = statement.where(Port.scan_run_id == scan_run_id)
    rows = (await session.execute(statement)).all()
    return [
        PortInventoryRead(
            id=port.id,
            scan_run_id=port.scan_run_id,
            ip_asset_id=port.ip_asset_id,
            ip=asset.normalized_value,
            port=port.port,
            protocol=port.protocol,
            state=port.state,
            source_tool=port.source_tool,
            first_seen_at=port.first_seen_at,
            last_seen_at=port.last_seen_at,
            service=(
                ServiceRead(
                    id=service.id,
                    name=service.name,
                    product=service.product,
                    version=service.version,
                    tunnel=service.tunnel,
                    cpe=service.cpe,
                    tls=service.tls,
                    observed_at=service.observed_at,
                )
                if service
                else None
            ),
        )
        for port, asset, service in rows
    ]


async def page_port_inventory(
    session: AsyncSession,
    project_id: UUID,
    *,
    page: int,
    page_size: int,
    scan_run_id: UUID | None = None,
    execution_mode: str = "host",
) -> PortInventoryPage:
    await get_project_or_404(session, project_id)
    conditions = [
        Port.project_id == project_id,
        _visible_ip_condition(),
        Port.scan_run_id.in_(_matching_run_ids(project_id, execution_mode)),
    ]
    if scan_run_id is not None:
        conditions.append(Port.scan_run_id == scan_run_id)
    total = int(
        await session.scalar(
            select(func.count(Port.id))
            .join(Asset, Asset.id == Port.ip_asset_id)
            .where(*conditions)
        )
        or 0
    )
    statement = (
        select(Port, Asset, Service)
        .join(Asset, Asset.id == Port.ip_asset_id)
        .outerjoin(Service, Service.port_id == Port.id)
        .where(*conditions)
        .order_by(Asset.normalized_value, Port.port, Port.protocol)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await session.execute(statement)).all()
    items = [
        PortInventoryRead(
            id=port.id,
            scan_run_id=port.scan_run_id,
            ip_asset_id=port.ip_asset_id,
            ip=asset.normalized_value,
            port=port.port,
            protocol=port.protocol,
            state=port.state,
            source_tool=port.source_tool,
            first_seen_at=port.first_seen_at,
            last_seen_at=port.last_seen_at,
            service=(
                ServiceRead(
                    id=service.id,
                    name=service.name,
                    product=service.product,
                    version=service.version,
                    tunnel=service.tunnel,
                    cpe=service.cpe,
                    tls=service.tls,
                    observed_at=service.observed_at,
                )
                if service
                else None
            ),
        )
        for port, asset, service in rows
    ]
    return PortInventoryPage(items=items, page=page, page_size=page_size, total=total)
