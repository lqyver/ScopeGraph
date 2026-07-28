"""Add security findings and export artifacts.

Revision ID: 0008_phase_six
Revises: 0007_phase_five
Create Date: 2026-07-16
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_phase_six"
down_revision: str | None = "0007_phase_five"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _actor_columns() -> list[sa.Column[object]]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=True),
        sa.Column("updated_by", sa.String(length=100), nullable=True),
    ]


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("first_scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("last_scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("template_id", sa.String(length=300), nullable=False),
        sa.Column("template_name", sa.String(length=500), nullable=False),
        sa.Column("tool_version", sa.String(length=100), nullable=False),
        sa.Column("target", sa.String(length=4096), nullable=False),
        sa.Column("matched_at", sa.String(length=4096), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("raw_artifact_path", sa.String(length=4096), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        *_actor_columns(),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["first_scan_run_id"], ["scan_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["last_scan_run_id"], ["scan_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "template_id", "target", name="uq_finding_identity"),
    )
    for column in ("project_id", "first_scan_run_id", "last_scan_run_id", "asset_id"):
        op.create_index(f"ix_findings_{column}", "findings", [column])
    op.create_index("ix_findings_project_status", "findings", ["project_id", "status"])

    op.create_table(
        "export_artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("export_format", sa.String(length=20), nullable=False),
        sa.Column("export_scope", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("path", sa.String(length=4096), nullable=True),
        sa.Column("media_type", sa.String(length=200), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("row_counts", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        *_actor_columns(),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_export_artifacts_project_id", "export_artifacts", ["project_id"])
    op.create_index("ix_exports_project_created", "export_artifacts", ["project_id", "created_at"])


def downgrade() -> None:
    op.drop_table("export_artifacts")
    op.drop_table("findings")
