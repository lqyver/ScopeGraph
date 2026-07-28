from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from scopegraph.domain.enums import (
    AssetType,
    CandidateRootStatus,
    DNSRecordType,
    EndpointKind,
    EnterpriseDiscoveryStatus,
    ExportFormat,
    ExportScope,
    ExportStatus,
    FindingSeverity,
    FindingStatus,
    ICPAssociationStatus,
    ICPRecordKind,
    IPClassification,
    OwnershipStatus,
    PortState,
    ProjectStatus,
    RelationType,
    ReviewDecision,
    ReviewResourceType,
    ScanProfile,
    ScanStatus,
    ScopeAction,
    ScopeRuleType,
    ScopeSource,
    ScopeStatus,
    TransportProtocol,
)
from scopegraph.infrastructure.database import Base


class TimestampActorMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    created_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


class Project(TimestampActorMixin, Base):
    __tablename__ = "projects"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    company_name: Mapped[str] = mapped_column(String(300), nullable=False)
    company_normalized_name: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    status: Mapped[ProjectStatus] = mapped_column(
        Enum(ProjectStatus, native_enum=False, length=20),
        default=ProjectStatus.DRAFT,
        nullable=False,
    )
    default_scan_profile: Mapped[ScanProfile] = mapped_column(
        Enum(ScanProfile, native_enum=False, length=20),
        default=ScanProfile.STANDARD,
        nullable=False,
    )
    authorization_confirmed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    proxy_config_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    retention_policy: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=lambda: {"raw_artifacts": "PERMANENT"}, nullable=False
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )


class ScopeRule(TimestampActorMixin, Base):
    __tablename__ = "scope_rules"
    __table_args__ = (
        UniqueConstraint(
            "project_id", "rule_type", "value", "action", name="uq_scope_rule_identity"
        ),
        Index("ix_scope_rules_project_action", "project_id", "action"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_type: Mapped[ScopeRuleType] = mapped_column(
        Enum(ScopeRuleType, native_enum=False, length=20), nullable=False
    )
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    action: Mapped[ScopeAction] = mapped_column(
        Enum(ScopeAction, native_enum=False, length=20), nullable=False
    )
    source: Mapped[ScopeSource] = mapped_column(
        Enum(ScopeSource, native_enum=False, length=20), default=ScopeSource.USER, nullable=False
    )


class Asset(TimestampActorMixin, Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint(
            "project_id", "asset_type", "normalized_value", name="uq_asset_normalized"
        ),
        CheckConstraint("confidence_score >= 0 AND confidence_score <= 100", name="ck_asset_score"),
        Index("ix_assets_project_scope", "project_id", "scope_status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_type: Mapped[AssetType] = mapped_column(
        Enum(AssetType, native_enum=False, length=30), nullable=False
    )
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    display_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    normalized_key: Mapped[str] = mapped_column(String(2100), nullable=False)
    scope_status: Mapped[ScopeStatus] = mapped_column(
        Enum(ScopeStatus, native_enum=False, length=30), default=ScopeStatus.UNKNOWN, nullable=False
    )
    ownership_status: Mapped[OwnershipStatus] = mapped_column(
        Enum(OwnershipStatus, native_enum=False, length=30),
        default=OwnershipStatus.PENDING_REVIEW,
        nullable=False,
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )


class AssetRelation(Base):
    __tablename__ = "asset_relations"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "source_asset_id",
            "target_asset_id",
            "relation_type",
            name="uq_asset_relation_identity",
        ),
        CheckConstraint("source_asset_id <> target_asset_id", name="ck_relation_not_self"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relation_type: Mapped[RelationType] = mapped_column(
        Enum(RelationType, native_enum=False, length=40), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    evidence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (
        UniqueConstraint("project_id", "observation_hash", name="uq_observation_hash"),
        Index("ix_observations_subject", "project_id", "subject_type", "subject_value"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    source_version: Mapped[str] = mapped_column(String(100), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(30), nullable=False)
    subject_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    predicate: Mapped[str] = mapped_column(String(100), nullable=False)
    object_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    object_value: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    raw_artifact_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observation_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("project_id", "evidence_hash", name="uq_evidence_hash"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    score_delta: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    source_tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    source_observation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("observations.id", ondelete="SET NULL"), nullable=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_manual: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )


class EnterpriseDiscoveryRun(TimestampActorMixin, Base):
    __tablename__ = "enterprise_discovery_runs"
    __table_args__ = (Index("ix_enterprise_discovery_project_status", "project_id", "status"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[EnterpriseDiscoveryStatus] = mapped_column(
        Enum(EnterpriseDiscoveryStatus, native_enum=False, length=30), nullable=False
    )
    company_normalized_name: Mapped[str] = mapped_column(String(300), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    search_keywords: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    execution_mode: Mapped[str] = mapped_column(String(20), nullable=False)
    source_results: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CandidateRootDomain(TimestampActorMixin, Base):
    __tablename__ = "candidate_root_domains"
    __table_args__ = (
        UniqueConstraint("project_id", "root_domain", name="uq_candidate_root_domain"),
        Index("ix_candidate_root_project_status", "project_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    discovery_run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("enterprise_discovery_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    root_domain: Mapped[str] = mapped_column(String(253), nullable=False)
    display_domain: Mapped[str] = mapped_column(String(253), nullable=False)
    score: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    raw_score: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    status: Mapped[CandidateRootStatus] = mapped_column(
        Enum(CandidateRootStatus, native_enum=False, length=30), nullable=False
    )
    source_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    evidence_summary: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    source_failures: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReviewAction(Base):
    __tablename__ = "review_actions"
    __table_args__ = (Index("ix_review_actions_resource", "resource_type", "resource_id"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    resource_type: Mapped[ReviewResourceType] = mapped_column(
        Enum(ReviewResourceType, native_enum=False, length=40), nullable=False
    )
    resource_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    decision: Mapped[ReviewDecision] = mapped_column(
        Enum(ReviewDecision, native_enum=False, length=30), nullable=False
    )
    previous_status: Mapped[str] = mapped_column(String(50), nullable=False)
    resulting_status: Mapped[str] = mapped_column(String(50), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(String(100), default="local-admin", nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class Finding(TimestampActorMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_id", "template_id", "target", name="uq_finding_identity"),
        Index("ix_findings_project_status", "project_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    first_scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    last_scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    template_id: Mapped[str] = mapped_column(String(300), nullable=False)
    template_name: Mapped[str] = mapped_column(String(500), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str] = mapped_column(String(4096), nullable=False)
    matched_at: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, native_enum=False, length=20), nullable=False
    )
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, native_enum=False, length=30), nullable=False
    )
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    raw_artifact_path: Mapped[str] = mapped_column(String(4096), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ExportArtifact(TimestampActorMixin, Base):
    __tablename__ = "export_artifacts"
    __table_args__ = (Index("ix_exports_project_created", "project_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    export_format: Mapped[ExportFormat] = mapped_column(
        Enum(ExportFormat, native_enum=False, length=20), nullable=False
    )
    export_scope: Mapped[ExportScope] = mapped_column(
        Enum(ExportScope, native_enum=False, length=30), nullable=False
    )
    status: Mapped[ExportStatus] = mapped_column(
        Enum(ExportStatus, native_enum=False, length=20), nullable=False
    )
    path: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    media_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row_counts: Mapped[dict[str, int]] = mapped_column(JSONB, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanRun(TimestampActorMixin, Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 100", name="ck_scan_run_progress"),
        CheckConstraint(
            "coverage_score IS NULL OR (coverage_score >= 0 AND coverage_score <= 100)",
            name="ck_scan_run_coverage_score",
        ),
        Index("ix_scan_runs_project_status", "project_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    profile: Mapped[ScanProfile] = mapped_column(
        Enum(ScanProfile, native_enum=False, length=20), nullable=False
    )
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, native_enum=False, length=30),
        default=ScanStatus.PENDING,
        nullable=False,
    )
    progress: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    coverage_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    coverage_level: Mapped[str | None] = mapped_column(String(30), nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class ScanJob(TimestampActorMixin, Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "idempotency_key", name="uq_scan_job_idempotency"),
        UniqueConstraint("scan_run_id", "sequence", name="uq_scan_job_sequence"),
        CheckConstraint("attempt >= 0", name="ck_scan_job_attempt"),
        CheckConstraint("sequence >= 0", name="ck_scan_job_sequence"),
        CheckConstraint("max_attempts > 0", name="ck_scan_job_max_attempts"),
        CheckConstraint("timeout_seconds > 0", name="ck_scan_job_timeout"),
        Index("ix_scan_jobs_run_status", "scan_run_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    job_type: Mapped[str] = mapped_column(String(100), nullable=False)
    adapter_name: Mapped[str] = mapped_column(String(100), nullable=False)
    input_ref: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, native_enum=False, length=30),
        default=ScanStatus.PENDING,
        nullable=False,
    )
    attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stdout_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    stderr_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class FileArtifact(Base):
    __tablename__ = "file_artifacts"
    __table_args__ = (UniqueConstraint("path", name="uq_file_artifact_path"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scan_job_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=True, index=True
    )
    artifact_type: Mapped[str] = mapped_column(String(100), nullable=False)
    path: Mapped[str] = mapped_column(String(4096), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    media_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DNSRecord(Base):
    __tablename__ = "dns_records"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "domain_asset_id",
            "record_type",
            "value",
            name="uq_dns_record_run_value",
        ),
        Index("ix_dns_records_project_type", "project_id", "record_type"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    record_type: Mapped[DNSRecordType] = mapped_column(
        Enum(DNSRecordType, native_enum=False, length=10), nullable=False
    )
    value: Mapped[str] = mapped_column(String(4096), nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolver: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IPDetail(TimestampActorMixin, Base):
    __tablename__ = "ip_details"
    __table_args__ = (
        UniqueConstraint("project_id", "asset_id", name="uq_ip_detail_asset"),
        Index("ix_ip_details_project_classification", "project_id", "classification"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    classification: Mapped[IPClassification] = mapped_column(
        Enum(IPClassification, native_enum=False, length=30),
        default=IPClassification.UNKNOWN,
        nullable=False,
    )
    classification_source: Mapped[str] = mapped_column(String(100), nullable=False)
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    organization: Mapped[str | None] = mapped_column(String(500), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(300), nullable=True)
    reverse_dns: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_cdn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id", "ip_asset_id", "port", "protocol", name="uq_port_run_endpoint"
        ),
        CheckConstraint("port >= 1 AND port <= 65535", name="ck_port_number"),
        Index("ix_ports_project_state", "project_id", "state"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip_asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[TransportProtocol] = mapped_column(
        Enum(TransportProtocol, native_enum=False, length=10), nullable=False
    )
    state: Mapped[PortState] = mapped_column(
        Enum(PortState, native_enum=False, length=20), nullable=False
    )
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("scan_run_id", "port_id", name="uq_service_run_port"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port_id: Mapped[UUID] = mapped_column(
        ForeignKey("ports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    product: Mapped[str | None] = mapped_column(String(500), nullable=True)
    version: Mapped[str | None] = mapped_column(String(300), nullable=True)
    tunnel: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    tls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Website(TimestampActorMixin, Base):
    __tablename__ = "websites"
    __table_args__ = (
        UniqueConstraint("project_id", "asset_id", name="uq_website_url_asset"),
        Index("ix_websites_project_alive", "project_id", "is_alive"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_asset_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ip_asset_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    normalized_url: Mapped[str] = mapped_column(String(4096), nullable=False)
    final_url: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    title: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(300), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ownership_status: Mapped[OwnershipStatus] = mapped_column(
        Enum(OwnershipStatus, native_enum=False, length=30), nullable=False
    )
    icp_status: Mapped[ICPAssociationStatus] = mapped_column(
        Enum(ICPAssociationStatus, native_enum=False, length=40),
        default=ICPAssociationStatus.NOT_FOUND,
        nullable=False,
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class WebSnapshot(Base):
    __tablename__ = "web_snapshots"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "website_id", name="uq_web_snapshot_run_website"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    website_id: Mapped[UUID] = mapped_column(
        ForeignKey("websites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    input_url: Mapped[str] = mapped_column(String(4096), nullable=False)
    final_url: Mapped[str] = mapped_column(String(4096), nullable=False)
    redirect_chain: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    response_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    server_header: Mapped[str | None] = mapped_column(String(500), nullable=True)
    response_headers: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    cdn_waf: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    tls_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    favicon_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    body_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    screenshot_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Certificate(Base):
    __tablename__ = "certificates"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id", "website_id", "fingerprint_sha256", name="uq_certificate_run_fingerprint"
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    website_id: Mapped[UUID] = mapped_column(
        ForeignKey("websites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subject: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    issuer: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(300), nullable=True)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    san: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    validation_errors: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Technology(Base):
    __tablename__ = "technologies"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id", "website_id", "name", "version", name="uq_technology_run_identity"
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    website_id: Mapped[UUID] = mapped_column(
        ForeignKey("websites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    version: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    category: Mapped[str | None] = mapped_column(String(300), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "normalized_url", "method", name="uq_endpoint_run_url"),
        Index("ix_endpoints_project_scope", "project_id", "scope_status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    website_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("websites.id", ondelete="CASCADE"), nullable=True, index=True
    )
    normalized_url: Mapped[str] = mapped_column(String(4096), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    kind: Mapped[EndpointKind] = mapped_column(
        Enum(EndpointKind, native_enum=False, length=30), nullable=False
    )
    scope_status: Mapped[ScopeStatus] = mapped_column(
        Enum(ScopeStatus, native_enum=False, length=30), nullable=False
    )
    actively_visited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ICPRecord(TimestampActorMixin, Base):
    __tablename__ = "icp_records"
    __table_args__ = (
        UniqueConstraint(
            "project_id", "record_kind", "normalized_number", name="uq_icp_record_number"
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    record_kind: Mapped[ICPRecordKind] = mapped_column(
        Enum(ICPRecordKind, native_enum=False, length=30), nullable=False
    )
    normalized_number: Mapped[str] = mapped_column(String(200), nullable=False)
    display_number: Mapped[str] = mapped_column(String(200), nullable=False)
    subject_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    website_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source_url: Mapped[str] = mapped_column(String(4096), nullable=False)
    excerpt: Mapped[str] = mapped_column(String(2000), nullable=False)
    official_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WebsiteICPLink(Base):
    __tablename__ = "website_icp_links"
    __table_args__ = (UniqueConstraint("website_id", "icp_record_id", name="uq_website_icp_link"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    website_id: Mapped[UUID] = mapped_column(
        ForeignKey("websites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    icp_record_id: Mapped[UUID] = mapped_column(
        ForeignKey("icp_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    association_status: Mapped[ICPAssociationStatus] = mapped_column(
        Enum(ICPAssociationStatus, native_enum=False, length=40), nullable=False
    )
    source_url: Mapped[str] = mapped_column(String(4096), nullable=False)
    evidence_excerpt: Mapped[str] = mapped_column(String(2000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    actor: Mapped[str] = mapped_column(String(100), default="local-admin", nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
