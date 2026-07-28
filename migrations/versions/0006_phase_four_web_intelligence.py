"""Add phase-four website, crawl, certificate, technology, and filing inventory.

Revision ID: 0006_phase_four
Revises: 0005_phase_three
Create Date: 2026-07-16
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_phase_four"
down_revision: str | None = "0005_phase_three"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ownership_status = sa.Enum(
    "CONFIRMED", "HIGH_CONFIDENCE", "PENDING_REVIEW", "WEAK_RELATION", "THIRD_PARTY",
    "REJECTED", name="ownershipstatus", native_enum=False,
)
scope_status = sa.Enum(
    "IN_SCOPE", "OUT_OF_SCOPE", "EXCLUDED", "PENDING_REVIEW", "THIRD_PARTY",
    "CDN_SHARED", "UNKNOWN", name="scopestatus", native_enum=False,
)
endpoint_kind = sa.Enum(
    "PAGE", "JAVASCRIPT", "XHR", "WEBSOCKET", "ROBOTS", "SITEMAP", "API",
    "EXTERNAL_LINK", name="endpointkind", native_enum=False,
)
icp_record_kind = sa.Enum(
    "ICP", "PUBLIC_SECURITY", name="icprecordkind", native_enum=False
)
icp_status = sa.Enum(
    "PAGE_DIRECT", "ROOT_DOMAIN_INFERRED", "SUBJECT_MATCH", "RELATED_SUBJECT",
    "SUBJECT_CONFLICT", "NOT_FOUND", "NOT_APPLICABLE", "PENDING_MANUAL_VERIFY",
    "HISTORICAL", name="icpassociationstatus", native_enum=False,
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
        "websites",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("domain_asset_id", sa.Uuid(), nullable=True),
        sa.Column("ip_asset_id", sa.Uuid(), nullable=True),
        sa.Column("normalized_url", sa.String(length=4096), nullable=False),
        sa.Column("final_url", sa.String(length=4096), nullable=True),
        sa.Column("title", sa.String(length=1000), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=300), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("is_alive", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("ownership_status", ownership_status, nullable=False),
        sa.Column("icp_status", icp_status, nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        *_actor_columns(),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["domain_asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["ip_asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "asset_id", name="uq_website_url_asset"),
    )
    for column in ("project_id", "asset_id", "domain_asset_id", "ip_asset_id"):
        op.create_index(f"ix_websites_{column}", "websites", [column])
    op.create_index("ix_websites_project_alive", "websites", ["project_id", "is_alive"])

    op.create_table(
        "web_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("website_id", sa.Uuid(), nullable=False),
        sa.Column("input_url", sa.String(length=4096), nullable=False),
        sa.Column("final_url", sa.String(length=4096), nullable=False),
        sa.Column("redirect_chain", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("response_time_ms", sa.Float(), nullable=True),
        sa.Column("content_length", sa.Integer(), nullable=True),
        sa.Column("server_header", sa.String(length=500), nullable=True),
        sa.Column("response_headers", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("cdn_waf", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("tls_summary", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("favicon_hash", sa.String(length=128), nullable=True),
        sa.Column("body_hash", sa.String(length=128), nullable=True),
        sa.Column("screenshot_path", sa.String(length=4096), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_run_id", "website_id", name="uq_web_snapshot_run_website"),
    )
    for column in ("project_id", "scan_run_id", "website_id"):
        op.create_index(f"ix_web_snapshots_{column}", "web_snapshots", [column])

    op.create_table(
        "certificates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("website_id", sa.Uuid(), nullable=False),
        sa.Column("subject", sa.String(length=2000), nullable=True),
        sa.Column("issuer", sa.String(length=2000), nullable=True),
        sa.Column("serial_number", sa.String(length=300), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("san", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("validation_errors", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_run_id", "website_id", "fingerprint_sha256",
            name="uq_certificate_run_fingerprint",
        ),
    )
    for column in ("project_id", "scan_run_id", "website_id"):
        op.create_index(f"ix_certificates_{column}", "certificates", [column])

    op.create_table(
        "technologies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("website_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("version", sa.String(length=300), server_default="", nullable=False),
        sa.Column("category", sa.String(length=300), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="1", nullable=False),
        sa.Column("source_tool", sa.String(length=100), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_run_id", "website_id", "name", "version", name="uq_technology_run_identity"
        ),
    )
    for column in ("project_id", "scan_run_id", "website_id"):
        op.create_index(f"ix_technologies_{column}", "technologies", [column])

    op.create_table(
        "endpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("website_id", sa.Uuid(), nullable=True),
        sa.Column("normalized_url", sa.String(length=4096), nullable=False),
        sa.Column("method", sa.String(length=10), server_default="GET", nullable=False),
        sa.Column("kind", endpoint_kind, nullable=False),
        sa.Column("scope_status", scope_status, nullable=False),
        sa.Column("actively_visited", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("source_tool", sa.String(length=100), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_run_id", "normalized_url", "method", name="uq_endpoint_run_url"),
    )
    for column in ("project_id", "scan_run_id", "website_id"):
        op.create_index(f"ix_endpoints_{column}", "endpoints", [column])
    op.create_index("ix_endpoints_project_scope", "endpoints", ["project_id", "scope_status"])

    op.create_table(
        "icp_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("record_kind", icp_record_kind, nullable=False),
        sa.Column("normalized_number", sa.String(length=200), nullable=False),
        sa.Column("display_number", sa.String(length=200), nullable=False),
        sa.Column("subject_name", sa.String(length=500), nullable=True),
        sa.Column("website_name", sa.String(length=500), nullable=True),
        sa.Column("source_url", sa.String(length=4096), nullable=False),
        sa.Column("excerpt", sa.String(length=2000), nullable=False),
        sa.Column("official_confirmed", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        *_actor_columns(),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id", "record_kind", "normalized_number", name="uq_icp_record_number"
        ),
    )
    op.create_index("ix_icp_records_project_id", "icp_records", ["project_id"])

    op.create_table(
        "website_icp_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("website_id", sa.Uuid(), nullable=False),
        sa.Column("icp_record_id", sa.Uuid(), nullable=False),
        sa.Column("association_status", icp_status, nullable=False),
        sa.Column("source_url", sa.String(length=4096), nullable=False),
        sa.Column("evidence_excerpt", sa.String(length=2000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["icp_record_id"], ["icp_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("website_id", "icp_record_id", name="uq_website_icp_link"),
    )
    for column in ("project_id", "website_id", "icp_record_id"):
        op.create_index(f"ix_website_icp_links_{column}", "website_icp_links", [column])
    op.execute(sa.text("UPDATE system_metadata SET value = '4' WHERE key = 'schema_phase'"))


def downgrade() -> None:
    op.execute(sa.text("UPDATE system_metadata SET value = '3' WHERE key = 'schema_phase'"))
    op.drop_table("website_icp_links")
    op.drop_table("icp_records")
    op.drop_table("endpoints")
    op.drop_table("technologies")
    op.drop_table("certificates")
    op.drop_table("web_snapshots")
    op.drop_table("websites")
