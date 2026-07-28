from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from scopegraph.domain.enums import (
    AssetType,
    OwnershipStatus,
    ProjectStatus,
    ScanProfile,
    ScopeAction,
    ScopeRuleType,
    ScopeSource,
    ScopeStatus,
)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    company_name: str = Field(min_length=1, max_length=300)
    default_scan_profile: ScanProfile = ScanProfile.STANDARD
    authorization_confirmed: bool
    known_root_domains: list[str] = Field(default_factory=list, max_length=100)
    excluded_domains: list[str] = Field(default_factory=list, max_length=100)
    retention_policy: dict[str, Any] = Field(default_factory=lambda: {"raw_artifacts": "PERMANENT"})

    @model_validator(mode="after")
    def authorization_is_required(self) -> "ProjectCreate":
        if not self.authorization_confirmed:
            raise ValueError("Authorization confirmation is required")
        return self


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    company_name: str | None = Field(default=None, min_length=1, max_length=300)
    status: ProjectStatus | None = None
    default_scan_profile: ScanProfile | None = None
    retention_policy: dict[str, Any] | None = None


class ProjectDeleteRequest(BaseModel):
    confirmation: str = Field(min_length=1, max_length=200)


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    company_name: str
    company_normalized_name: str
    status: ProjectStatus
    default_scan_profile: ScanProfile
    authorization_confirmed_at: datetime
    retention_policy: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ProjectPage(BaseModel):
    items: list[ProjectRead]
    page: int
    page_size: int
    total: int


class ProjectSummary(BaseModel):
    project_id: UUID
    asset_count: int
    scope_rule_count: int
    assets_by_type: dict[str, int]
    assets_by_scope: dict[str, int]


class ScopeRuleCreate(BaseModel):
    rule_type: ScopeRuleType
    value: str = Field(min_length=1, max_length=2048)
    action: ScopeAction = ScopeAction.INCLUDE
    source: ScopeSource = ScopeSource.USER


class ScopeRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    rule_type: ScopeRuleType
    value: str
    action: ScopeAction
    source: ScopeSource
    created_at: datetime


class ScopeCheckRequest(BaseModel):
    asset_type: AssetType
    value: str = Field(min_length=1, max_length=4096)


class ScopeCheckResponse(BaseModel):
    status: ScopeStatus
    normalized_value: str
    reason: str
    matched_rule_id: UUID | None
    active_allowed: bool


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    asset_type: AssetType
    normalized_value: str
    display_value: str
    normalized_key: str
    scope_status: ScopeStatus
    ownership_status: OwnershipStatus
    confidence_score: float
    first_seen_at: datetime
    last_seen_at: datetime
    is_active: bool
    metadata_json: dict[str, Any]


class AssetPage(BaseModel):
    items: list[AssetRead]
    page: int
    page_size: int
    total: int


class ImportIssue(BaseModel):
    index: int
    value: str
    error: str


class AssetImportResult(BaseModel):
    input_count: int
    normalized_count: int
    created_count: int
    duplicate_count: int
    rejected_count: int
    rejected: list[ImportIssue]
