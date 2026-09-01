import asyncio
import csv
import html
import io
import json
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID
from zipfile import ZIP_DEFLATED, ZipFile

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.enums import (
    AssetType,
    ExportFormat,
    ExportScope,
    ExportStatus,
    OwnershipStatus,
    ScopeAction,
    ScopeRuleType,
    ScopeStatus,
)
from scopegraph.domain.models import (
    Asset,
    AuditLog,
    CandidateRootDomain,
    ExportArtifact,
    Finding,
    ICPRecord,
    IPDetail,
    Observation,
    Port,
    Project,
    ScanRun,
    ScopeRule,
    Service,
    Website,
    WebSnapshot,
)
from scopegraph.exporting import write_xlsx
from scopegraph.infrastructure.config import get_settings
from scopegraph.tooling.artifacts import ArtifactStore

Dataset = OrderedDict[str, tuple[list[str], list[dict[str, Any]]]]


def _enum(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _allowed_asset(asset: Asset, export_scope: ExportScope) -> bool:
    if export_scope is ExportScope.ALL_CANDIDATES:
        return True
    allowed = {OwnershipStatus.CONFIRMED}
    if export_scope is ExportScope.CONFIRMED_AND_HIGH:
        allowed.add(OwnershipStatus.HIGH_CONFIDENCE)
    return asset.ownership_status in allowed


def _asset_rows(items: list[Asset]) -> list[dict[str, Any]]:
    return [
        {
            "ID": str(item.id),
            "值": item.normalized_value,
            "Scope状态": item.scope_status.value,
            "归属状态": item.ownership_status.value,
            "置信分": item.confidence_score,
            "首次发现": item.first_seen_at,
            "最后发现": item.last_seen_at,
        }
        for item in items
    ]


def _attribute(mapping: dict[Any, Any], key: Any, name: str, default: Any = None) -> Any:
    value = mapping.get(key)
    return getattr(value, name, default) if value is not None else default


async def _datasets(
    session: AsyncSession,
    project: Project,
    export_scope: ExportScope,
    execution_mode: str,
) -> Dataset:
    project_id = project.id
    matching_runs = select(ScanRun.id).where(
        ScanRun.project_id == project_id,
        ScanRun.execution_mode == execution_mode,
    )
    observations = list(
        await session.scalars(
            select(Observation).where(
                Observation.project_id == project_id,
                Observation.scan_run_id.in_(matching_runs),
            )
        )
    )
    observed_identities = {
        (asset_type, value)
        for observation in observations
        for asset_type, value in (
            (observation.subject_type, observation.subject_value),
            (observation.object_type, observation.object_value),
        )
        if asset_type is not None and value is not None
    }
    assets = list(await session.scalars(select(Asset).where(Asset.project_id == project_id)))
    evidence_assets = [
        item
        for item in assets
        if (item.asset_type.value, item.normalized_value) in observed_identities
    ]
    selected_assets = [item for item in evidence_assets if _allowed_asset(item, export_scope)]
    selected_ids = {item.id for item in selected_assets}
    root_rules = list(
        await session.scalars(
            select(ScopeRule).where(
                ScopeRule.project_id == project_id,
                ScopeRule.rule_type == ScopeRuleType.ROOT_DOMAIN,
                ScopeRule.action == ScopeAction.INCLUDE,
            )
        )
    )
    root_values = {item.value for item in root_rules}
    domains = [item for item in selected_assets if item.asset_type is AssetType.DOMAIN]
    roots = [item for item in domains if item.normalized_value in root_values]
    subdomains = [item for item in domains if item.normalized_value not in root_values]
    ip_details = list(
        await session.scalars(select(IPDetail).where(IPDetail.project_id == project_id))
    )
    detail_by_asset = {item.asset_id: item for item in ip_details}
    ports = list(
        await session.scalars(
            select(Port).where(
                Port.project_id == project_id,
                Port.scan_run_id.in_(matching_runs),
            )
        )
    )
    services = list(
        await session.scalars(
            select(Service).where(
                Service.project_id == project_id,
                Service.scan_run_id.in_(matching_runs),
            )
        )
    )
    service_by_port = {item.port_id: item for item in services}
    asset_by_id = {item.id: item for item in assets}
    websites = list(
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
    )
    snapshots = list(
        await session.scalars(
            select(WebSnapshot)
            .where(
                WebSnapshot.project_id == project_id,
                WebSnapshot.scan_run_id.in_(matching_runs),
            )
            .order_by(WebSnapshot.observed_at.desc())
        )
    )
    snapshot_by_website: dict[UUID, WebSnapshot] = {}
    for snapshot in snapshots:
        snapshot_by_website.setdefault(snapshot.website_id, snapshot)
    web_observation_by_url: dict[str, Observation] = {}
    for observation in sorted(observations, key=lambda item: item.observed_at, reverse=True):
        if observation.predicate == "SERVES_WEBSITE" and observation.object_value is not None:
            web_observation_by_url.setdefault(observation.object_value, observation)

    def website_values(item: Website) -> dict[str, Any]:
        observation = web_observation_by_url.get(item.normalized_url)
        attributes = observation.attributes if observation is not None else {}
        snapshot = snapshot_by_website.get(item.id)
        status_value = attributes.get("status_code")
        status_code = (
            status_value
            if isinstance(status_value, int) and not isinstance(status_value, bool)
            else None
        )
        title_value = attributes.get("title")
        content_type_value = attributes.get("content_type")
        observed_at = observation.observed_at if observation is not None else item.last_seen_at
        return {
            "final_url": snapshot.final_url if snapshot is not None else item.normalized_url,
            "title": str(title_value)[:1000] if title_value is not None else None,
            "status_code": status_code,
            "content_type": (
                str(content_type_value)[:300] if content_type_value is not None else None
            ),
            "is_alive": status_code is not None and attributes.get("error") is None,
            "observed_at": observed_at,
        }

    if export_scope is ExportScope.LIVE_WEBSITES:
        websites = [item for item in websites if website_values(item)["is_alive"]]
    elif export_scope is not ExportScope.ALL_CANDIDATES:
        websites = [item for item in websites if item.asset_id in selected_ids]
    filings = list(
        await session.scalars(
            select(ICPRecord).where(
                ICPRecord.project_id == project_id,
                ICPRecord.normalized_number.in_(
                    select(Observation.object_value).where(
                        Observation.project_id == project_id,
                        Observation.scan_run_id.in_(matching_runs),
                        Observation.predicate == "HAS_ICP_RECORD",
                    )
                ),
            )
        )
    )
    candidates = list(
        await session.scalars(
            select(CandidateRootDomain).where(CandidateRootDomain.project_id == project_id)
        )
    )
    findings = list(
        await session.scalars(
            select(Finding).where(
                Finding.project_id == project_id,
                Finding.execution_mode == execution_mode,
            )
        )
    )
    scan_runs = list(
        await session.scalars(
            select(ScanRun)
            .where(
                ScanRun.project_id == project_id,
                ScanRun.execution_mode == execution_mode,
            )
            .order_by(ScanRun.created_at.desc())
        )
    )

    asset_headers = ["ID", "值", "Scope状态", "归属状态", "置信分", "首次发现", "最后发现"]
    datasets: Dataset = OrderedDict()
    datasets["项目总览"] = (
        [
            "项目ID",
            "项目名称",
            "企业名称",
            "生成时间",
            "导出范围",
            "证据模式",
            "授权确认时间",
            "资产数",
        ],
        [
            {
                "项目ID": str(project.id),
                "项目名称": project.name,
                "企业名称": project.company_name,
                "生成时间": datetime.now(UTC),
                "导出范围": export_scope.value,
                "证据模式": execution_mode,
                "授权确认时间": project.authorization_confirmed_at,
                "资产数": len(selected_assets),
            }
        ],
    )
    datasets["根域名"] = (asset_headers, _asset_rows(roots))
    datasets["子域名"] = (asset_headers, _asset_rows(subdomains))
    datasets["IP资产"] = (
        ["ID", "IP", "Scope状态", "归属状态", "分类", "ASN", "组织", "提供商", "反向DNS"],
        [
            {
                "ID": str(item.id),
                "IP": item.normalized_value,
                "Scope状态": item.scope_status.value,
                "归属状态": item.ownership_status.value,
                "分类": _enum(_attribute(detail_by_asset, item.id, "classification", "UNKNOWN")),
                "ASN": _attribute(detail_by_asset, item.id, "asn"),
                "组织": _attribute(detail_by_asset, item.id, "organization"),
                "提供商": _attribute(detail_by_asset, item.id, "provider"),
                "反向DNS": _attribute(detail_by_asset, item.id, "reverse_dns"),
            }
            for item in selected_assets
            if item.asset_type is AssetType.IP
        ],
    )
    datasets["端口服务"] = (
        ["扫描ID", "IP", "端口", "协议", "状态", "服务", "产品", "版本", "TLS", "来源"],
        [
            {
                "扫描ID": str(item.scan_run_id),
                "IP": _attribute(asset_by_id, item.ip_asset_id, "normalized_value", ""),
                "端口": item.port,
                "协议": item.protocol.value,
                "状态": item.state.value,
                "服务": _attribute(service_by_port, item.id, "name"),
                "产品": _attribute(service_by_port, item.id, "product"),
                "版本": _attribute(service_by_port, item.id, "version"),
                "TLS": _attribute(service_by_port, item.id, "tls", False),
                "来源": item.source_tool,
            }
            for item in ports
            if item.ip_asset_id in selected_ids
        ],
    )
    datasets["Web网站"] = (
        [
            "ID",
            "URL",
            "最终URL",
            "标题",
            "状态码",
            "内容类型",
            "存活",
            "归属状态",
            "备案关联",
            "首次发现",
            "最后发现",
        ],
        [
            {
                "ID": str(item.id),
                "URL": item.normalized_url,
                "最终URL": website_values(item)["final_url"],
                "标题": website_values(item)["title"],
                "状态码": website_values(item)["status_code"],
                "内容类型": website_values(item)["content_type"],
                "存活": website_values(item)["is_alive"],
                "归属状态": item.ownership_status.value,
                "备案关联": item.icp_status.value,
                "首次发现": website_values(item)["observed_at"],
                "最后发现": website_values(item)["observed_at"],
            }
            for item in websites
        ],
    )
    datasets["备案信息"] = (
        ["类型", "备案号", "主体", "网站名称", "来源URL", "官方确认", "观察时间"],
        [
            {
                "类型": item.record_kind.value,
                "备案号": item.display_number,
                "主体": item.subject_name,
                "网站名称": item.website_name,
                "来源URL": item.source_url,
                "官方确认": item.official_confirmed,
                "观察时间": item.observed_at,
            }
            for item in filings
        ],
    )
    datasets["第三方服务"] = (
        ["ID", "值", "资产类型", "Scope状态", "归属状态", "证据"],
        [
            {
                "ID": str(item.id),
                "值": item.normalized_value,
                "资产类型": item.asset_type.value,
                "Scope状态": item.scope_status.value,
                "归属状态": item.ownership_status.value,
                "证据": json.dumps(item.metadata_json, ensure_ascii=False, default=str),
            }
            for item in assets
            if item.scope_status in {ScopeStatus.THIRD_PARTY, ScopeStatus.CDN_SHARED}
        ],
    )
    datasets["待审核资产"] = (
        ["候选ID", "根域", "分数", "原始分", "状态", "来源数", "评分证据"],
        [
            {
                "候选ID": str(item.id),
                "根域": item.root_domain,
                "分数": item.score,
                "原始分": item.raw_score,
                "状态": item.status.value,
                "来源数": item.source_count,
                "评分证据": json.dumps(item.evidence_summary, ensure_ascii=False),
            }
            for item in candidates
        ],
    )
    datasets["安全发现"] = (
        [
            "ID",
            "模板ID",
            "名称",
            "目标",
            "严重性",
            "状态",
            "存活",
            "首次发现",
            "最后发现",
            "证据",
            "原始路径",
        ],
        [
            {
                "ID": str(item.id),
                "模板ID": item.template_id,
                "名称": item.template_name,
                "目标": item.target,
                "严重性": item.severity.value,
                "状态": item.status.value,
                "存活": item.is_active,
                "首次发现": item.first_seen_at,
                "最后发现": item.last_seen_at,
                "证据": json.dumps(item.evidence, ensure_ascii=False),
                "原始路径": item.raw_artifact_path,
            }
            for item in findings
        ],
    )
    datasets["扫描历史"] = (
        ["扫描ID", "模式", "状态", "进度", "开始时间", "结束时间", "覆盖分", "覆盖等级", "工具链"],
        [
            {
                "扫描ID": str(item.id),
                "模式": item.profile.value,
                "状态": item.status.value,
                "进度": item.progress,
                "开始时间": item.started_at,
                "结束时间": item.finished_at,
                "覆盖分": item.coverage_score,
                "覆盖等级": item.coverage_level,
                "工具链": ", ".join(str(value) for value in item.config_snapshot.get("chain", [])),
            }
            for item in scan_runs
        ],
    )
    if export_scope is ExportScope.FINDINGS_ONLY:
        for name in list(datasets):
            if name not in {"项目总览", "安全发现"}:
                headers, _ = datasets[name]
                datasets[name] = (headers, [])
    return datasets


def _safe_csv(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def _write_csv_zip(path: Path, datasets: Dataset) -> None:
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        for name, (headers, rows) in datasets.items():
            buffer = io.StringIO(newline="")
            writer = csv.DictWriter(buffer, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            writer.writerows({key: _safe_csv(value) for key, value in row.items()} for row in rows)
            archive.writestr(f"{name}.csv", "\ufeff" + buffer.getvalue())


def _html_table(headers: list[str], rows: list[dict[str, Any]]) -> str:
    head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
    body = "".join(
        "<tr>"
        + "".join(f"<td>{html.escape(str(row.get(header, '') or ''))}</td>" for header in headers)
        + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _write_text_export(path: Path, export_format: ExportFormat, datasets: Dataset) -> None:
    if export_format is ExportFormat.JSON:
        payload = {name: rows for name, (_, rows) in datasets.items()}
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
        )
        return
    if export_format is ExportFormat.HTML:
        html_sections = "".join(
            f"<h2>{html.escape(name)}</h2>{_html_table(headers, rows)}"
            for name, (headers, rows) in datasets.items()
        )
        document = (
            '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
            "<title>ScopeGraph 导出</title><style>"
            "body{font:14px system-ui;margin:32px;color:#172b2d}"
            "table{border-collapse:collapse;width:100%;margin:12px 0 36px}"
            "th{background:#0f766e;color:white;position:sticky;top:0}"
            "th,td{padding:8px;border-bottom:1px solid #d5e3e3;text-align:left;"
            "vertical-align:top}h2{margin-top:36px}</style><body>"
            f"<h1>ScopeGraph 结构化导出</h1>{html_sections}</body></html>"
        )
        path.write_text(document, encoding="utf-8")
        return
    markdown_sections: list[str] = []
    for name, (headers, rows) in datasets.items():
        lines = [
            f"## {name}",
            "",
            "| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
        ]
        lines.extend(
            "| "
            + " | ".join(
                str(row.get(header, "") or "").replace("|", "\\|").replace("\n", " ")
                for header in headers
            )
            + " |"
            for row in rows
        )
        markdown_sections.append("\n".join(lines))
    path.write_text(
        "# ScopeGraph 结构化导出\n\n" + "\n\n".join(markdown_sections),
        encoding="utf-8",
    )


def _write_export_file(path: Path, export_format: ExportFormat, datasets: Dataset) -> None:
    """Serialize an export outside the async event loop."""

    if export_format is ExportFormat.XLSX:
        write_xlsx(path, datasets)
    elif export_format is ExportFormat.CSV:
        _write_csv_zip(path, datasets)
    else:
        _write_text_export(path, export_format, datasets)


async def create_export(
    session: AsyncSession,
    project_id: UUID,
    export_format: ExportFormat,
    export_scope: ExportScope,
    execution_mode: str = "host",
) -> ExportArtifact:
    project = await get_project_or_404(session, project_id)
    artifact = ExportArtifact(
        project_id=project_id,
        export_format=export_format,
        export_scope=export_scope,
        execution_mode=execution_mode,
        status=ExportStatus.PENDING,
        row_counts={},
        created_by="local-admin",
        updated_by="local-admin",
    )
    session.add(artifact)
    await session.flush()
    store = ArtifactStore(get_settings().data_root)
    directory = store.export_directory(project_id, artifact.id)
    extension = "zip" if export_format is ExportFormat.CSV else export_format.value
    path = store.path_for(directory, f"scopegraph-export.{extension}")
    media_types = {
        ExportFormat.XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ExportFormat.CSV: "application/zip",
        ExportFormat.JSON: "application/json",
        ExportFormat.HTML: "text/html; charset=utf-8",
        ExportFormat.MARKDOWN: "text/markdown; charset=utf-8",
    }
    try:
        datasets = await _datasets(session, project, export_scope, execution_mode)
        await asyncio.to_thread(_write_export_file, path, export_format, datasets)
        stored = store.describe(path)
        artifact.status = ExportStatus.SUCCESS
        artifact.path = stored.relative_path
        artifact.media_type = media_types[export_format]
        artifact.size_bytes = stored.size_bytes
        artifact.sha256 = stored.sha256
        artifact.row_counts = {name: len(rows) for name, (_, rows) in datasets.items()}
    except (OSError, ValueError, TypeError) as exc:
        artifact.status = ExportStatus.FAILED
        artifact.error_message = f"{type(exc).__name__}: {exc}"[:2000]
    session.add(
        AuditLog(
            project_id=project_id,
            actor="local-admin",
            action="EXPORT_CREATED",
            resource_type="export",
            resource_id=str(artifact.id),
            details={
                "format": export_format.value,
                "scope": export_scope.value,
                "execution_mode": execution_mode,
                "status": artifact.status.value,
            },
        )
    )
    await session.commit()
    await session.refresh(artifact)
    return artifact


async def get_export_or_404(session: AsyncSession, export_id: UUID) -> ExportArtifact:
    artifact = await session.get(ExportArtifact, export_id)
    if artifact is None:
        raise ScopeGraphError("EXPORT_NOT_FOUND", "Export was not found", status_code=404)
    return artifact


def resolve_export_path(artifact: ExportArtifact) -> Path:
    if artifact.status is not ExportStatus.SUCCESS or artifact.path is None:
        raise ScopeGraphError("EXPORT_NOT_READY", "Export is not available", status_code=409)
    root = get_settings().data_root.resolve()
    path = (root / artifact.path).resolve()
    if not path.is_file() or not path.is_relative_to(root):
        raise ScopeGraphError("EXPORT_FILE_MISSING", "Export file is missing", status_code=404)
    return path
