"""Add enterprise discovery, evidence scoring, and review audit tables.

Revision ID: 0007_phase_five
Revises: 0006_phase_four
Create Date: 2026-07-16
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_phase_five"
down_revision: str | None = "0006_phase_four"
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
    op.add_column("evidence", sa.Column("evidence_hash", sa.String(length=64), nullable=True))
    op.execute("UPDATE evidence SET evidence_hash = replace(id::text, '-', '')")
    op.alter_column("evidence", "evidence_hash", nullable=False)
    op.create_unique_constraint("uq_evidence_hash", "evidence", ["project_id", "evidence_hash"])

    op.create_table(
        "enterprise_discovery_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("company_normalized_name", sa.String(length=300), nullable=False),
        sa.Column("aliases", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("search_keywords", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("execution_mode", sa.String(length=20), nullable=False),
        sa.Column("source_results", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("summary", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        *_actor_columns(),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_enterprise_discovery_runs_project_id", "enterprise_discovery_runs", ["project_id"])
    op.create_index("ix_enterprise_discovery_project_status", "enterprise_discovery_runs", ["project_id", "status"])

    op.create_table(
        "candidate_root_domains",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("discovery_run_id", sa.Uuid(), nullable=True),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("root_domain", sa.String(length=253), nullable=False),
        sa.Column("display_domain", sa.String(length=253), nullable=False),
        sa.Column("score", sa.Float(), server_default="0", nullable=False),
        sa.Column("raw_score", sa.Float(), server_default="0", nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("source_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("evidence_summary", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("source_failures", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        *_actor_columns(),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["discovery_run_id"], ["enterprise_discovery_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "root_domain", name="uq_candidate_root_domain"),
    )
    for column in ("project_id", "discovery_run_id", "asset_id"):
        op.create_index(f"ix_candidate_root_domains_{column}", "candidate_root_domains", [column])
    op.create_index("ix_candidate_root_project_status", "candidate_root_domains", ["project_id", "status"])

    op.create_table(
        "review_actions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("resource_type", sa.String(length=40), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("decision", sa.String(length=30), nullable=False),
        sa.Column("previous_status", sa.String(length=50), nullable=False),
        sa.Column("resulting_status", sa.String(length=50), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(length=100), server_default="local-admin", nullable=False),
        sa.Column("details", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_review_actions_project_id", "review_actions", ["project_id"])
    op.create_index("ix_review_actions_created_at", "review_actions", ["created_at"])
    op.create_index("ix_review_actions_resource", "review_actions", ["resource_type", "resource_id"])


def downgrade() -> None:
    op.drop_table("review_actions")
    op.drop_table("candidate_root_domains")
    op.drop_table("enterprise_discovery_runs")
    op.drop_constraint("uq_evidence_hash", "evidence", type_="unique")
    op.drop_column("evidence", "evidence_hash")
