from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from scopegraph.domain.enums import (
    CandidateRootStatus,
    EnterpriseDiscoveryStatus,
    ReviewDecision,
    ReviewResourceType,
)


class EnterpriseDiscoveryRequest(BaseModel):
    execution_mode: str = Field(default="local", pattern="^(local|fixture|public)$")
    aliases: list[str] = Field(default_factory=list, max_length=50)
    async_execution: bool = False


class EnterpriseDiscoveryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    project_id: UUID
    status: EnterpriseDiscoveryStatus
    company_normalized_name: str
    aliases: list[str]
    search_keywords: list[str]
    execution_mode: str
    source_results: list[dict[str, Any]]
    summary: dict[str, Any]
    started_at: datetime
    finished_at: datetime | None


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    evidence_type: str
    value: str
    score_delta: float
    source_tool: str | None
    source_url: str | None
    observed_at: datetime
    is_manual: bool
    metadata_json: dict[str, Any]


class CandidateRootRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    project_id: UUID
    root_domain: str
    display_domain: str
    score: float
    raw_score: float
    status: CandidateRootStatus
    source_count: int
    evidence_summary: list[dict[str, Any]]
    source_failures: list[dict[str, Any]]
    confirmed_at: datetime | None
    rejected_at: datetime | None
    evidence: list[EvidenceRead] = Field(default_factory=list)


class ManualCandidateRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    reason: str = Field(min_length=3, max_length=1000)


class ReviewRequest(BaseModel):
    decision: ReviewDecision
    reason: str = Field(min_length=3, max_length=2000)


class BatchReviewItem(BaseModel):
    resource_type: ReviewResourceType
    resource_id: UUID
    decision: ReviewDecision
    reason: str = Field(min_length=3, max_length=2000)


class BatchReviewRequest(BaseModel):
    items: list[BatchReviewItem] = Field(min_length=1, max_length=100)


class ReviewQueueItem(BaseModel):
    resource_type: ReviewResourceType
    resource_id: UUID
    value: str
    status: str
    score: float
    reasons: list[str]


class BatchReviewResult(BaseModel):
    completed: int
    failed: list[dict[str, str]]


class CoverageFactor(BaseModel):
    key: str
    label: str
    weight: float
    completed: bool
    evidence: str


class CoverageAssessment(BaseModel):
    project_id: UUID
    task_status: str
    task_completed: bool
    coverage_score: float
    coverage_level: str
    factors: list[CoverageFactor]
    blind_spots: list[str]
    assessed_at: datetime
