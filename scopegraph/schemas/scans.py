from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scopegraph.domain.enums import ScanProfile, ScanStatus
from scopegraph.normalizers.assets import registrable_root_domain
from scopegraph.scanning.profiles import ScanProfileConfig
from scopegraph.security import normalize_proxy_url


class ScanRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_domain: str = Field(min_length=1, max_length=253)
    profile: ScanProfile = ScanProfile.STANDARD
    execution_mode: Literal["fixture", "host"] = "fixture"
    authorization_confirmed: bool
    allow_active_execution: bool = False
    port_scan_enabled: bool | None = None
    screenshot_enabled: bool | None = None
    deep_confirmation: bool = False
    full_port_scan: bool = False
    full_port_confirmation: bool = False
    nuclei_enabled: bool = False
    nuclei_confirmation: bool = False
    proxy_url: str | None = None
    custom_config: ScanProfileConfig | None = None

    @field_validator("root_domain")
    @classmethod
    def normalize_root(cls, value: str) -> str:
        return registrable_root_domain(value)

    @field_validator("authorization_confirmed")
    @classmethod
    def require_authorization(cls, value: bool) -> bool:
        if not value:
            raise ValueError("Scan authorization must be explicitly confirmed")
        return value

    @field_validator("proxy_url")
    @classmethod
    def validate_proxy(cls, value: str | None) -> str | None:
        return normalize_proxy_url(value) if value else None

    @model_validator(mode="after")
    def validate_execution_safety(self) -> "ScanRunCreate":
        if self.execution_mode == "host" and not self.allow_active_execution:
            raise ValueError("Host execution requires explicit active-execution opt-in")
        if self.profile is ScanProfile.CUSTOM and self.custom_config is None:
            raise ValueError("custom_config is required for the custom profile")
        if self.profile is not ScanProfile.CUSTOM and self.custom_config is not None:
            raise ValueError("custom_config is only valid for the custom profile")
        if self.profile is ScanProfile.DEEP and not self.deep_confirmation:
            raise ValueError("Deep scanning requires explicit second confirmation")
        if self.profile is not ScanProfile.DEEP and self.deep_confirmation:
            raise ValueError("Deep confirmation is only valid for the deep profile")
        if self.full_port_scan and not self.full_port_confirmation:
            raise ValueError("Full-port scanning requires explicit second confirmation")
        if self.full_port_confirmation and not self.full_port_scan:
            raise ValueError("Full-port confirmation is only valid for a full-port scan")
        if self.full_port_scan and self.port_scan_enabled is False:
            raise ValueError("Full-port scanning cannot be requested while port scans are disabled")
        if self.nuclei_enabled and not self.nuclei_confirmation:
            raise ValueError("Nuclei security discovery requires explicit second confirmation")
        if self.nuclei_confirmation and not self.nuclei_enabled:
            raise ValueError("Nuclei confirmation is only valid when Nuclei is enabled")
        return self


class ScanRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    profile: ScanProfile
    execution_mode: str
    config_snapshot: dict[str, Any]
    status: ScanStatus
    progress: float
    started_at: datetime | None
    finished_at: datetime | None
    coverage_score: float | None
    coverage_level: str | None
    summary: dict[str, Any]
    cancellation_requested: bool
    created_at: datetime
    updated_at: datetime


class ScanRunPage(BaseModel):
    items: list[ScanRunRead]
    page: int
    page_size: int
    total: int


class ScanJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_run_id: UUID
    sequence: int
    job_type: str
    adapter_name: str
    input_ref: dict[str, Any]
    idempotency_key: str
    status: ScanStatus
    attempt: int
    max_attempts: int
    timeout_seconds: int
    started_at: datetime | None
    finished_at: datetime | None
    stdout_path: str | None
    stderr_path: str | None
    error_code: str | None
    error_message: str | None
    result_summary: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ScanRunOverviewItem(BaseModel):
    run: ScanRunRead
    jobs: list[ScanJobRead]


class ScanRunOverviewPage(BaseModel):
    items: list[ScanRunOverviewItem]
    page: int
    page_size: int
    total: int


class ScanEvent(BaseModel):
    event_type: str
    scan_run_id: UUID
    scan_job_id: UUID | None = None
    status: ScanStatus
    progress: float
    message: str
    occurred_at: datetime
