from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.enums import ScanStatus, ScopeAction, ScopeRuleType
from scopegraph.domain.models import (
    Certificate,
    EnterpriseDiscoveryRun,
    ICPRecord,
    ReviewAction,
    ScanJob,
    ScanRun,
    ScopeRule,
)
from scopegraph.schemas.enterprise import CoverageAssessment, CoverageFactor


async def _exists(session: AsyncSession, statement: Select[tuple[int]]) -> bool:
    return bool(await session.scalar(statement))


async def assess_coverage(session: AsyncSession, project_id: UUID) -> CoverageAssessment:
    project = await get_project_or_404(session, project_id)
    latest_scan = await session.scalar(
        select(ScanRun).where(ScanRun.project_id == project_id).order_by(ScanRun.created_at.desc())
    )
    checks = {
        "root_confirmed": await _exists(
            session,
            select(func.count(ScopeRule.id)).where(
                ScopeRule.project_id == project_id,
                ScopeRule.rule_type == ScopeRuleType.ROOT_DOMAIN,
                ScopeRule.action == ScopeAction.INCLUDE,
            ),
        ),
        "filing": await _exists(
            session, select(func.count(ICPRecord.id)).where(ICPRecord.project_id == project_id)
        ),
        "brand_profile": bool(project.company_normalized_name),
        "subfinder": await _exists(
            session,
            select(func.count(ScanJob.id))
            .join(ScanRun, ScanRun.id == ScanJob.scan_run_id)
            .where(
                ScanRun.project_id == project_id,
                ScanJob.adapter_name == "subfinder",
                ScanJob.status == ScanStatus.SUCCESS,
            ),
        ),
        "dns_brute": await _exists(
            session,
            select(func.count(ScanJob.id))
            .join(ScanRun, ScanRun.id == ScanJob.scan_run_id)
            .where(
                ScanRun.project_id == project_id,
                ScanJob.adapter_name == "puredns",
                ScanJob.status == ScanStatus.SUCCESS,
            ),
        ),
        "tls_san": await _exists(
            session, select(func.count(Certificate.id)).where(Certificate.project_id == project_id)
        ),
        "web_js": await _exists(
            session,
            select(func.count(ScanJob.id))
            .join(ScanRun, ScanRun.id == ScanJob.scan_run_id)
            .where(
                ScanRun.project_id == project_id,
                ScanJob.adapter_name == "katana",
                ScanJob.status == ScanStatus.SUCCESS,
            ),
        ),
        "history_urls": False,
        "source_feedback": await _exists(
            session,
            select(func.count(EnterpriseDiscoveryRun.id)).where(
                EnterpriseDiscoveryRun.project_id == project_id,
                EnterpriseDiscoveryRun.status.in_(["SUCCESS", "PARTIAL_SUCCESS"]),
            ),
        ),
        "reviewed_candidates": await _exists(
            session,
            select(func.count(ReviewAction.id)).where(ReviewAction.project_id == project_id),
        ),
    }
    definitions = [
        ("root_confirmed", "已确认根域", 15.0),
        ("filing", "备案信息", 10.0),
        ("brand_profile", "企业名与别名", 5.0),
        ("subfinder", "被动子域发现", 10.0),
        ("dns_brute", "DNS 字典与变体", 10.0),
        ("tls_san", "TLS/SAN 证书覆盖", 10.0),
        ("web_js", "Web/JS 抓取", 10.0),
        ("history_urls", "历史 URL 数据源", 10.0),
        ("source_feedback", "多来源企业发现", 10.0),
        ("reviewed_candidates", "高优先级人工复核", 10.0),
    ]
    factors = [
        CoverageFactor(
            key=key,
            label=label,
            weight=weight,
            completed=checks[key],
            evidence="已完成" if checks[key] else "尚无可验证证据",
        )
        for key, label, weight in definitions
    ]
    score = sum(item.weight for item in factors if item.completed)
    level = (
        "HIGH" if score >= 85 else "HIGHER" if score >= 70 else "MEDIUM" if score >= 45 else "LOW"
    )
    task_status = latest_scan.status.value if latest_scan else "NOT_STARTED"
    task_completed = bool(
        latest_scan and latest_scan.status in {ScanStatus.SUCCESS, ScanStatus.PARTIAL_SUCCESS}
    )
    blind_spots = [item.label for item in factors if not item.completed]
    if latest_scan is not None:
        latest_scan.coverage_score = score
        latest_scan.coverage_level = level
        latest_scan.summary = {**latest_scan.summary, "coverage_blind_spots": blind_spots}
        await session.commit()
    return CoverageAssessment(
        project_id=project_id,
        task_status=task_status,
        task_completed=task_completed,
        coverage_score=score,
        coverage_level=level,
        factors=factors,
        blind_spots=blind_spots,
        assessed_at=datetime.now(UTC),
    )
