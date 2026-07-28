from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from scopegraph.domain.enums import (
    IPClassification,
    PortState,
    ScopeStatus,
    TransportProtocol,
)


class IPClassificationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: IPClassification
    reason: str = Field(min_length=3, max_length=1000)


class IPInventoryRead(BaseModel):
    asset_id: UUID
    ip: str
    scope_status: ScopeStatus
    classification: IPClassification
    classification_source: str
    asn: int | None = None
    organization: str | None = None
    provider: str | None = None
    reverse_dns: str | None = None
    is_private: bool = False
    is_cdn: bool = False
    environment_warning: str | None = None
    updated_at: datetime | None = None


class IPInventoryPage(BaseModel):
    items: list[IPInventoryRead]
    page: int
    page_size: int
    total: int
    ignored_environment_mappings: int = 0


class ServiceRead(BaseModel):
    id: UUID
    name: str | None
    product: str | None
    version: str | None
    tunnel: str | None
    cpe: str | None
    tls: bool
    observed_at: datetime


class PortInventoryRead(BaseModel):
    id: UUID
    scan_run_id: UUID
    ip_asset_id: UUID
    ip: str
    port: int
    protocol: TransportProtocol
    state: PortState
    source_tool: str
    first_seen_at: datetime
    last_seen_at: datetime
    service: ServiceRead | None = None


class PortInventoryPage(BaseModel):
    items: list[PortInventoryRead]
    page: int
    page_size: int
    total: int
