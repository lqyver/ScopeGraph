"""Create phase-one project, scope, asset, and evidence core.

Revision ID: 0002_phase_one
Revises: 0001_phase_zero
Create Date: 2026-07-16
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_phase_one"
down_revision: str | None = "0001_phase_zero"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

project_status = sa.Enum("DRAFT", "ACTIVE", "ARCHIVED", name="projectstatus", native_enum=False)
scan_profile = sa.Enum("quick", "standard", "deep", "custom", name="scanprofile", native_enum=False)
scope_rule_type = sa.Enum(
    "DOMAIN", "ROOT_DOMAIN", "IP", "CIDR", "URL", name="scoperuletype", native_enum=False
)
scope_action = sa.Enum("INCLUDE", "EXCLUDE", name="scopeaction", native_enum=False)
scope_source = sa.Enum("USER", "AUTO_CONFIRMED", name="scopesource", native_enum=False)
asset_type = sa.Enum(
    "company",
    "domain",
    "ip",
    "cidr",
    "url",
    "service",
    "certificate",
    "icp_record",
    name="assettype",
    native_enum=False,
)
scope_status = sa.Enum(
    "IN_SCOPE",
    "OUT_OF_SCOPE",
    "EXCLUDED",
    "PENDING_REVIEW",
    "THIRD_PARTY",
    "CDN_SHARED",
    "UNKNOWN",
    name="scopestatus",
    native_enum=False,
)
ownership_status = sa.Enum(
    "CONFIRMED",
    "HIGH_CONFIDENCE",
    "PENDING_REVIEW",
    "WEAK_RELATION",
    "THIRD_PARTY",
    "REJECTED",
    name="ownershipstatus",
    native_enum=False,
)
relation_type = sa.Enum(
    "HAS_SUBDOMAIN",
    "RESOLVES_TO",
    "CNAME_TO",
    "HOSTS_SERVICE",
    "SERVES_WEBSITE",
    "REDIRECTS_TO",
    "PRESENTS_CERTIFICATE",
    "HAS_ICP_RECORD",
    "OFFICIAL_LINK_TO",
    "DISCOVERED_FROM",
    "THIRD_PARTY_HOSTED_BY",
    "CLUSTERED_WITH",
    name="relationtype",
    native_enum=False,
)


def _actor_columns() -> list[sa.Column[object]]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=True),
        sa.Column("updated_by", sa.String(length=100), nullable=True),
    ]


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("company_name", sa.String(length=300), nullable=False),
        sa.Column("company_normalized_name", sa.String(length=300), nullable=False),
        sa.Column("status", project_status, nullable=False),
        sa.Column("default_scan_profile", scan_profile, nullable=False),
        sa.Column("authorization_confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("proxy_config_encrypted", sa.Text(), nullable=True),
        sa.Column(
            "retention_policy",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{\"raw_artifacts\": \"PERMANENT\"}'::jsonb"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        *_actor_columns(),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_projects_company_normalized_name", "projects", ["company_normalized_name"])
    op.create_index("ix_projects_deleted_at", "projects", ["deleted_at"])

    op.create_table(
        "scope_rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("rule_type", scope_rule_type, nullable=False),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("action", scope_action, nullable=False),
        sa.Column("source", scope_source, nullable=False),
        *_actor_columns(),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id", "rule_type", "value", "action", name="uq_scope_rule_identity"
        ),
    )
    op.create_index("ix_scope_rules_project_id", "scope_rules", ["project_id"])
    op.create_index("ix_scope_rules_project_action", "scope_rules", ["project_id", "action"])

    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("asset_type", asset_type, nullable=False),
        sa.Column("normalized_value", sa.String(length=2048), nullable=False),
        sa.Column("display_value", sa.String(length=2048), nullable=False),
        sa.Column("normalized_key", sa.String(length=2100), nullable=False),
        sa.Column("scope_status", scope_status, nullable=False),
        sa.Column("ownership_status", ownership_status, nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        *_actor_columns(),
        sa.CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100", name="ck_asset_score"
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id", "asset_type", "normalized_value", name="uq_asset_normalized"
        ),
    )
    op.create_index("ix_assets_project_id", "assets", ["project_id"])
    op.create_index("ix_assets_project_scope", "assets", ["project_id", "scope_status"])

    op.create_table(
        "observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=True),
        sa.Column("source_tool", sa.String(length=100), nullable=False),
        sa.Column("source_version", sa.String(length=100), nullable=False),
        sa.Column("subject_type", sa.String(length=30), nullable=False),
        sa.Column("subject_value", sa.String(length=2048), nullable=False),
        sa.Column("predicate", sa.String(length=100), nullable=False),
        sa.Column("object_type", sa.String(length=30), nullable=True),
        sa.Column("object_value", sa.String(length=2048), nullable=True),
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("raw_artifact_path", sa.String(length=4096), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "observation_hash", name="uq_observation_hash"),
    )
    op.create_index("ix_observations_project_id", "observations", ["project_id"])
    op.create_index("ix_observations_scan_run_id", "observations", ["scan_run_id"])
    op.create_index(
        "ix_observations_subject",
        "observations",
        ["project_id", "subject_type", "subject_value"],
    )

    op.create_table(
        "asset_relations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("source_asset_id", sa.Uuid(), nullable=False),
        sa.Column("target_asset_id", sa.Uuid(), nullable=False),
        sa.Column("relation_type", relation_type, nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.CheckConstraint("source_asset_id <> target_asset_id", name="ck_relation_not_self"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id",
            "source_asset_id",
            "target_asset_id",
            "relation_type",
            name="uq_asset_relation_identity",
        ),
    )
    op.create_index("ix_asset_relations_project_id", "asset_relations", ["project_id"])
    op.create_index("ix_asset_relations_source_asset_id", "asset_relations", ["source_asset_id"])
    op.create_index("ix_asset_relations_target_asset_id", "asset_relations", ["target_asset_id"])

    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_type", sa.String(length=100), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("score_delta", sa.Float(), nullable=False),
        sa.Column("source_tool", sa.String(length=100), nullable=True),
        sa.Column("source_url", sa.String(length=4096), nullable=True),
        sa.Column("source_observation_id", sa.Uuid(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_manual", sa.Boolean(), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["source_observation_id"], ["observations.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_project_id", "evidence", ["project_id"])
    op.create_index("ix_evidence_asset_id", "evidence", ["asset_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=False),
        sa.Column("resource_id", sa.String(length=100), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_project_id", "audit_logs", ["project_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    op.execute("UPDATE system_metadata SET value = '1' WHERE key = 'schema_phase'")


def downgrade() -> None:
    op.execute("UPDATE system_metadata SET value = '0' WHERE key = 'schema_phase'")
    op.drop_table("audit_logs")
    op.drop_table("evidence")
    op.drop_table("asset_relations")
    op.drop_table("observations")
    op.drop_table("assets")
    op.drop_table("scope_rules")
    op.drop_table("projects")

