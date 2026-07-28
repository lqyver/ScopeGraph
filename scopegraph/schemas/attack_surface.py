from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from scopegraph.domain.enums import (
    FindingSeverity,
    FindingStatus,
    OwnershipStatus,
    PortState,
    ScopeStatus,
    TransportProtocol,
)


class AttackSurfaceServiceRead(BaseModel):
    name: str | None = None
    product: str | None = None
    version: str | None = None
    tls: bool = False


class AttackSurfacePortRead(BaseModel):
    ip: str
    port: int = Field(ge=1, le=65535)
    protocol: TransportProtocol
    state: PortState
    source_tool: str
    last_seen_at: datetime
    service: AttackSurfaceServiceRead | None = None


class AttackSurfaceWebsiteRead(BaseModel):
    id: UUID
    url: str
    final_url: str | None = None
    title: str | None = None
    status_code: int | None = None
    port: int | None = None
    is_alive: bool
    endpoint_count: int = 0
    last_seen_at: datetime


class AttackSurfaceFindingRead(BaseModel):
    id: UUID
    template_id: str
    template_name: str
    severity: FindingSeverity
    status: FindingStatus
    target: str
    is_active: bool
    last_seen_at: datetime


class AttackSurfaceItemRead(BaseModel):
    domain_asset_id: UUID
    domain: str
    scope_status: ScopeStatus
    ownership_status: OwnershipStatus
    resolved_ips: list[str] = Field(default_factory=list)
    ports: list[AttackSurfacePortRead] = Field(default_factory=list)
    websites: list[AttackSurfaceWebsiteRead] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    endpoint_count: int = 0
    findings: list[AttackSurfaceFindingRead] = Field(default_factory=list)
    active_finding_count: int = 0
    high_finding_count: int = 0
    priority_score: int = Field(ge=0, le=100)
    priority_tier: Literal["urgent", "high", "review", "observed"]
    priority_reasons: list[str] = Field(default_factory=list)
    last_seen_at: datetime


class AttackSurfaceSummaryRead(BaseModel):
    domains: int = 0
    active_websites: int = 0
    domains_with_ports: int = 0
    open_ports: int = 0
    technologies: int = 0
    active_findings: int = 0
    high_findings: int = 0
    high_priority_targets: int = 0


class AttackSurfacePage(BaseModel):
    items: list[AttackSurfaceItemRead]
    page: int
    page_size: int
    total: int
    summary: AttackSurfaceSummaryRead
    environment_mappings_excluded: int = 0
