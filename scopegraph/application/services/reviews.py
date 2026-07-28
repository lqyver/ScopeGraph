from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.enums import (
    AssetType,
    CandidateRootStatus,
    OwnershipStatus,
    ProjectStatus,
    ReviewDecision,
    ReviewResourceType,
    ScopeAction,
    ScopeRuleType,
    ScopeSource,
    ScopeStatus,
)
from scopegraph.domain.models import (
    Asset,
    AuditLog,
    CandidateRootDomain,
    ReviewAction,
    ScopeRule,
)
from scopegraph.normalizers import registrable_root_domain
from scopegraph.schemas.enterprise import BatchReviewItem, ReviewQueueItem


async def _ensure_scope_rule(
    session: AsyncSession,
    *,
    project_id: UUID,
    domain: str,
    action: ScopeAction,
) -> None:
    root = registrable_root_domain(domain)
    existing = await session.scalar(
        select(ScopeRule).where(
            ScopeRule.project_id == project_id,
            ScopeRule.rule_type == ScopeRuleType.ROOT_DOMAIN,
            ScopeRule.value == root,
            ScopeRule.action == action,
        )
    )
    if existing is None:
        session.add(
            ScopeRule(
                project_id=project_id,
                rule_type=ScopeRuleType.ROOT_DOMAIN,
                value=root,
                action=action,
                source=(
                    ScopeSource.AUTO_CONFIRMED
                    if action is ScopeAction.INCLUDE
                    else ScopeSource.USER
                ),
                created_by="local-admin",
                updated_by="local-admin",
            )
        )


def _apply_asset_decision(asset: Asset, decision: ReviewDecision) -> str:
    if decision in {ReviewDecision.CONFIRM, ReviewDecision.ADD_TO_SCOPE}:
        asset.ownership_status = OwnershipStatus.CONFIRMED
        asset.confidence_score = 100
        if decision is ReviewDecision.ADD_TO_SCOPE:
            asset.scope_status = ScopeStatus.IN_SCOPE
    elif decision is ReviewDecision.EXCLUDE:
        asset.ownership_status = OwnershipStatus.REJECTED
        asset.scope_status = ScopeStatus.EXCLUDED
    elif decision is ReviewDecision.MARK_THIRD_PARTY:
        asset.ownership_status = OwnershipStatus.THIRD_PARTY
        asset.scope_status = ScopeStatus.THIRD_PARTY
    asset.updated_by = "local-admin"
    return asset.ownership_status.value


async def apply_review(
    session: AsyncSession,
    project_id: UUID,
    item: BatchReviewItem,
    *,
    commit: bool = True,
) -> ReviewAction:
    project = await get_project_or_404(session, project_id)
    asset: Asset
    candidate: CandidateRootDomain | None = None
    if item.resource_type is ReviewResourceType.CANDIDATE_ROOT_DOMAIN:
        candidate = await session.scalar(
            select(CandidateRootDomain).where(
                CandidateRootDomain.id == item.resource_id,
                CandidateRootDomain.project_id == project_id,
            )
        )
        if candidate is None:
            raise ScopeGraphError(
                "CANDIDATE_NOT_FOUND", "Candidate root was not found", status_code=404
            )
        candidate_asset = await session.get(Asset, candidate.asset_id)
        if candidate_asset is None:
            raise ScopeGraphError(
                "ASSET_NOT_FOUND", "Candidate asset was not found", status_code=404
            )
        asset = candidate_asset
        previous = candidate.status.value
    else:
        reviewed_asset = await session.scalar(
            select(Asset).where(Asset.id == item.resource_id, Asset.project_id == project_id)
        )
        if reviewed_asset is None:
            raise ScopeGraphError("ASSET_NOT_FOUND", "Asset was not found", status_code=404)
        asset = reviewed_asset
        previous = asset.ownership_status.value

    now = datetime.now(UTC)
    if item.decision is ReviewDecision.DEFER:
        resulting = previous
    else:
        resulting = _apply_asset_decision(asset, item.decision)
        if asset.asset_type is AssetType.DOMAIN and item.decision is ReviewDecision.ADD_TO_SCOPE:
            await _ensure_scope_rule(
                session,
                project_id=project_id,
                domain=asset.normalized_value,
                action=ScopeAction.INCLUDE,
            )
            project.status = ProjectStatus.ACTIVE
            project.updated_by = "local-admin"
        elif asset.asset_type is AssetType.DOMAIN and item.decision is ReviewDecision.EXCLUDE:
            await _ensure_scope_rule(
                session,
                project_id=project_id,
                domain=asset.normalized_value,
                action=ScopeAction.EXCLUDE,
            )
        if candidate is not None:
            if item.decision in {ReviewDecision.CONFIRM, ReviewDecision.ADD_TO_SCOPE}:
                candidate.status = CandidateRootStatus.CONFIRMED
                candidate.confirmed_at = now
                candidate.rejected_at = None
            elif item.decision is ReviewDecision.EXCLUDE:
                candidate.status = CandidateRootStatus.REJECTED
                candidate.rejected_at = now
            elif item.decision is ReviewDecision.MARK_THIRD_PARTY:
                candidate.status = CandidateRootStatus.THIRD_PARTY
                candidate.rejected_at = now
            candidate.updated_by = "local-admin"
            resulting = candidate.status.value

    review = ReviewAction(
        project_id=project_id,
        resource_type=item.resource_type,
        resource_id=item.resource_id,
        decision=item.decision,
        previous_status=previous,
        resulting_status=resulting,
        reason=item.reason,
        actor="local-admin",
        details={"manual_override": item.decision is not ReviewDecision.DEFER},
    )
    session.add(review)
    session.add(
        AuditLog(
            project_id=project_id,
            actor="local-admin",
            action="REVIEW_DECISION_APPLIED",
            resource_type=item.resource_type.value,
            resource_id=str(item.resource_id),
            details={
                "decision": item.decision.value,
                "previous_status": previous,
                "resulting_status": resulting,
                "reason": item.reason,
            },
        )
    )
    if commit:
        await session.commit()
        await session.refresh(review)
    else:
        await session.flush()
    return review


async def list_review_queue(session: AsyncSession, project_id: UUID) -> list[ReviewQueueItem]:
    await get_project_or_404(session, project_id)
    candidates = list(
        (
            await session.scalars(
                select(CandidateRootDomain).where(
                    CandidateRootDomain.project_id == project_id,
                    CandidateRootDomain.status.notin_(
                        [CandidateRootStatus.CONFIRMED, CandidateRootStatus.REJECTED]
                    ),
                )
            )
        ).all()
    )
    candidate_asset_ids = {item.asset_id for item in candidates}
    assets = list(
        (
            await session.scalars(
                select(Asset).where(
                    Asset.project_id == project_id,
                    Asset.id.notin_(candidate_asset_ids),
                    Asset.ownership_status.in_(
                        [
                            OwnershipStatus.PENDING_REVIEW,
                            OwnershipStatus.WEAK_RELATION,
                            OwnershipStatus.THIRD_PARTY,
                        ]
                    ),
                )
            )
        ).all()
    )
    rows = [
        ReviewQueueItem(
            resource_type=ReviewResourceType.CANDIDATE_ROOT_DOMAIN,
            resource_id=item.id,
            value=item.root_domain,
            status=item.status.value,
            score=item.score,
            reasons=[str(row.get("signal", "unknown")) for row in item.evidence_summary],
        )
        for item in candidates
    ]
    rows.extend(
        ReviewQueueItem(
            resource_type=ReviewResourceType.ASSET,
            resource_id=item.id,
            value=item.display_value,
            status=item.ownership_status.value,
            score=item.confidence_score,
            reasons=[item.scope_status.value],
        )
        for item in assets
    )
    return sorted(rows, key=lambda row: (-row.score, row.value))
