from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.coverage import assess_coverage
from scopegraph.application.services.enterprise import (
    add_manual_candidate,
    candidate_evidence,
    get_enterprise_discovery_run,
    list_candidates,
    run_enterprise_discovery,
    start_enterprise_discovery,
)
from scopegraph.application.services.reviews import apply_review, list_review_queue
from scopegraph.domain.enums import ReviewDecision, ReviewResourceType
from scopegraph.domain.models import CandidateRootDomain
from scopegraph.infrastructure.database import get_session
from scopegraph.schemas.enterprise import (
    BatchReviewItem,
    BatchReviewRequest,
    BatchReviewResult,
    CandidateRootRead,
    CoverageAssessment,
    EnterpriseDiscoveryRead,
    EnterpriseDiscoveryRequest,
    EvidenceRead,
    ManualCandidateRequest,
    ReviewQueueItem,
    ReviewRequest,
)

router = APIRouter(prefix="/api/v1", tags=["enterprise-discovery"])
Session = Annotated[AsyncSession, Depends(get_session)]


def _enqueue_enterprise_discovery(run_id: UUID) -> None:
    from apps.worker.tasks import execute_enterprise_discovery

    execute_enterprise_discovery.send(str(run_id))


async def _candidate_read(
    session: AsyncSession, candidate: CandidateRootDomain
) -> CandidateRootRead:
    result = CandidateRootRead.model_validate(candidate)
    evidence = await candidate_evidence(session, candidate)
    return result.model_copy(
        update={"evidence": [EvidenceRead.model_validate(item) for item in evidence]}
    )


@router.post(
    "/projects/{project_id}/enterprise-discovery",
    response_model=EnterpriseDiscoveryRead,
    status_code=status.HTTP_201_CREATED,
)
async def enterprise_discovery_endpoint(
    project_id: UUID,
    payload: EnterpriseDiscoveryRequest,
    session: Session,
    response: Response,
) -> EnterpriseDiscoveryRead:
    if payload.async_execution:
        run = await start_enterprise_discovery(session, project_id, payload)
        _enqueue_enterprise_discovery(run.id)
        response.status_code = status.HTTP_202_ACCEPTED
        return EnterpriseDiscoveryRead.model_validate(run)
    return EnterpriseDiscoveryRead.model_validate(
        await run_enterprise_discovery(session, project_id, payload)
    )


@router.get(
    "/projects/{project_id}/enterprise-discovery/{run_id}",
    response_model=EnterpriseDiscoveryRead,
)
async def enterprise_discovery_run_endpoint(
    project_id: UUID,
    run_id: UUID,
    session: Session,
) -> EnterpriseDiscoveryRead:
    return EnterpriseDiscoveryRead.model_validate(
        await get_enterprise_discovery_run(session, project_id, run_id)
    )


@router.get("/projects/{project_id}/candidate-root-domains", response_model=list[CandidateRootRead])
async def candidate_roots_endpoint(project_id: UUID, session: Session) -> list[CandidateRootRead]:
    return [
        await _candidate_read(session, candidate)
        for candidate in await list_candidates(session, project_id)
    ]


@router.post(
    "/projects/{project_id}/candidate-root-domains",
    response_model=CandidateRootRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_candidate_endpoint(
    project_id: UUID, payload: ManualCandidateRequest, session: Session
) -> CandidateRootRead:
    return await _candidate_read(session, await add_manual_candidate(session, project_id, payload))


@router.post(
    "/projects/{project_id}/candidate-root-domains/{candidate_id}/review",
    response_model=CandidateRootRead,
)
async def review_candidate_endpoint(
    project_id: UUID,
    candidate_id: UUID,
    payload: ReviewRequest,
    session: Session,
) -> CandidateRootRead:
    await apply_review(
        session,
        project_id,
        BatchReviewItem(
            resource_type=ReviewResourceType.CANDIDATE_ROOT_DOMAIN,
            resource_id=candidate_id,
            decision=payload.decision,
            reason=payload.reason,
        ),
    )
    candidates = await list_candidates(session, project_id)
    candidate = next((item for item in candidates if item.id == candidate_id), None)
    if candidate is None:
        raise ScopeGraphError(
            "CANDIDATE_NOT_FOUND", "Candidate root was not found", status_code=404
        )
    return await _candidate_read(session, candidate)


@router.post(
    "/projects/{project_id}/candidate-root-domains/{candidate_id}/confirm",
    response_model=CandidateRootRead,
)
async def confirm_candidate_endpoint(
    project_id: UUID, candidate_id: UUID, session: Session
) -> CandidateRootRead:
    return await review_candidate_endpoint(
        project_id,
        candidate_id,
        ReviewRequest(
            decision=ReviewDecision.ADD_TO_SCOPE, reason="Confirmed by local administrator"
        ),
        session,
    )


@router.post(
    "/projects/{project_id}/candidate-root-domains/{candidate_id}/reject",
    response_model=CandidateRootRead,
)
async def reject_candidate_endpoint(
    project_id: UUID, candidate_id: UUID, session: Session
) -> CandidateRootRead:
    return await review_candidate_endpoint(
        project_id,
        candidate_id,
        ReviewRequest(decision=ReviewDecision.EXCLUDE, reason="Rejected by local administrator"),
        session,
    )


@router.get("/projects/{project_id}/review-queue", response_model=list[ReviewQueueItem])
async def review_queue_endpoint(project_id: UUID, session: Session) -> list[ReviewQueueItem]:
    return await list_review_queue(session, project_id)


@router.post("/projects/{project_id}/reviews/batch", response_model=BatchReviewResult)
async def batch_review_endpoint(
    project_id: UUID, payload: BatchReviewRequest, session: Session
) -> BatchReviewResult:
    completed = 0
    failed: list[dict[str, str]] = []
    for item in payload.items:
        try:
            await apply_review(session, project_id, item)
            completed += 1
        except ScopeGraphError as exc:
            failed.append(
                {"resource_id": str(item.resource_id), "code": exc.code, "message": exc.message}
            )
    return BatchReviewResult(completed=completed, failed=failed)


@router.get("/projects/{project_id}/coverage", response_model=CoverageAssessment)
async def coverage_endpoint(project_id: UUID, session: Session) -> CoverageAssessment:
    return await assess_coverage(session, project_id)
