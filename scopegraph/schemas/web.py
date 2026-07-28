from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from scopegraph.domain.enums import (
    EndpointKind,
    ICPAssociationStatus,
    ICPRecordKind,
    OwnershipStatus,
    ScopeStatus,
)


class TechnologyRead(BaseModel):
    name: str
    version: str
    category: str | None
    confidence: float
    source_tool: str


class CertificateRead(BaseModel):
    id: UUID
    subject: str | None
    issuer: str | None
    serial_number: str | None
    not_before: datetime | None
    not_after: datetime | None
    san: list[str]
    fingerprint_sha256: str
    validation_errors: list[str]
    observed_at: datetime


class WebSnapshotRead(BaseModel):
    id: UUID
    scan_run_id: UUID
    input_url: str
    final_url: str
    redirect_chain: list[Any]
    response_time_ms: float | None
    content_length: int | None
    server_header: str | None
    response_headers: dict[str, Any]
    cdn_waf: list[str]
    tls_summary: dict[str, Any]
    favicon_hash: str | None
    body_hash: str | None
    screenshot_path: str | None
    error: str | None
    observed_at: datetime


class WebsiteSummaryRead(BaseModel):
    id: UUID
    project_id: UUID
    asset_id: UUID
    url: str
    final_url: str | None
    title: str | None
    status_code: int | None
    content_type: str | None
    ip: str | None
    port: int | None
    is_alive: bool
    scope_status: ScopeStatus
    ownership_status: OwnershipStatus
    icp_status: ICPAssociationStatus
    technologies: list[str]
    cdn_waf: list[str]
    screenshot_path: str | None
    endpoint_count: int
    finding_count: int = 0
    first_seen_at: datetime
    last_seen_at: datetime


class WebsitePage(BaseModel):
    items: list[WebsiteSummaryRead]
    page: int
    page_size: int
    total: int


class WebsiteICPLinkRead(BaseModel):
    record_id: UUID
    record_kind: ICPRecordKind
    normalized_number: str
    display_number: str
    subject_name: str | None
    association_status: ICPAssociationStatus
    source_url: str
    evidence_excerpt: str
    official_confirmed: bool


class EndpointRead(BaseModel):
    id: UUID
    scan_run_id: UUID
    website_id: UUID | None
    normalized_url: str
    method: str
    kind: EndpointKind
    scope_status: ScopeStatus
    actively_visited: bool
    source_tool: str
    status_code: int | None
    discovered_at: datetime


class WebsiteDetailRead(WebsiteSummaryRead):
    snapshot: WebSnapshotRead | None
    technology_details: list[TechnologyRead]
    certificates: list[CertificateRead]
    filing_links: list[WebsiteICPLinkRead]
    endpoints: list[EndpointRead]


class ICPWebsiteRead(BaseModel):
    website_id: UUID
    url: str
    association_status: ICPAssociationStatus


class ICPRecordRead(BaseModel):
    id: UUID
    record_kind: ICPRecordKind
    normalized_number: str
    display_number: str
    subject_name: str | None
    website_name: str | None
    source_url: str
    excerpt: str
    official_confirmed: bool
    observed_at: datetime
    websites: list[ICPWebsiteRead]
