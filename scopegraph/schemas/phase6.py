from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from scopegraph.domain.enums import (
    ExportFormat,
    ExportScope,
    ExportStatus,
    FindingSeverity,
    FindingStatus,
)


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    project_id: UUID
    first_scan_run_id: UUID
    last_scan_run_id: UUID
    execution_mode: Literal["host", "fixture"]
    template_id: str
    template_name: str
    tool_version: str
    target: str
    matched_at: str | None
    severity: FindingSeverity
    status: FindingStatus
    evidence: dict[str, Any]
    raw_artifact_path: str
    first_seen_at: datetime
    last_seen_at: datetime
    is_active: bool


class FindingPage(BaseModel):
    items: list[FindingRead]
    page: int
    page_size: int
    total: int


class FindingReviewRequest(BaseModel):
    status: FindingStatus
    reason: str = Field(min_length=3, max_length=2000)


class DiffItem(BaseModel):
    category: str
    identity: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None


class ScanDiffRead(BaseModel):
    project_id: UUID
    from_scan_run_id: UUID
    to_scan_run_id: UUID
    added: list[DiffItem]
    removed: list[DiffItem]
    changed: list[DiffItem]
    counts: dict[str, int]


class ExportCreate(BaseModel):
    export_format: ExportFormat
    export_scope: ExportScope = ExportScope.CONFIRMED_AND_HIGH
    execution_mode: Literal["host", "fixture"] = "host"


class ExportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    project_id: UUID
    export_format: ExportFormat
    export_scope: ExportScope
    execution_mode: str
    status: ExportStatus
    media_type: str | None
    size_bytes: int | None
    sha256: str | None
    row_counts: dict[str, int]
    error_message: str | None
    created_at: datetime


class StorageRead(BaseModel):
    total_bytes: int
    raw_artifact_bytes: int
    export_bytes: int
    file_count: int


class StorageCleanupRequest(BaseModel):
    raw_artifacts: bool = True
    exports: bool = False
    older_than_days: int = Field(default=30, ge=0, le=3650)
    confirmation: bool


class StorageCleanupRead(BaseModel):
    deleted_files: int
    reclaimed_bytes: int
    structured_records_deleted: int = 0
