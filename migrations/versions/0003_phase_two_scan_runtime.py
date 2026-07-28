"""Create phase-two scan runtime and artifact tables.

Revision ID: 0003_phase_two
Revises: 0002_phase_one
Create Date: 2026-07-16
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_phase_two"
down_revision: str | None = "0002_phase_one"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

scan_profile = sa.Enum("quick", "standard", "deep", "custom", name="scanprofile", native_enum=False)
scan_status = sa.Enum(
    "PENDING",
    "QUEUED",
    "RUNNING",
    "PAUSED",
    "PARTIAL_SUCCESS",
    "SUCCESS",
    "FAILED",
    "TIMEOUT",
    "CANCELLED",
    "SKIPPED",
    name="scanstatus",
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
        "scan_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("profile", scan_profile, nullable=False),
        sa.Column(
            "config_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("progress", sa.Float(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("coverage_score", sa.Float(), nullable=True),
        sa.Column("coverage_level", sa.String(length=30), nullable=True),
        sa.Column(
            "summary",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("cancellation_requested", sa.Boolean(), server_default=sa.false(), nullable=False),
        *_actor_columns(),
        sa.CheckConstraint("progress >= 0 AND progress <= 100", name="ck_scan_run_progress"),
        sa.CheckConstraint(
            "coverage_score IS NULL OR (coverage_score >= 0 AND coverage_score <= 100)",
            name="ck_scan_run_coverage_score",
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_runs_project_id", "scan_runs", ["project_id"])
    op.create_index("ix_scan_runs_project_status", "scan_runs", ["project_id", "status"])

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("job_type", sa.String(length=100), nullable=False),
        sa.Column("adapter_name", sa.String(length=100), nullable=False),
        sa.Column(
            "input_ref",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("attempt", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default="2", nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stdout_path", sa.String(length=4096), nullable=True),
        sa.Column("stderr_path", sa.String(length=4096), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "result_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        *_actor_columns(),
        sa.CheckConstraint("attempt >= 0", name="ck_scan_job_attempt"),
        sa.CheckConstraint("max_attempts > 0", name="ck_scan_job_max_attempts"),
        sa.CheckConstraint("timeout_seconds > 0", name="ck_scan_job_timeout"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_run_id", "idempotency_key", name="uq_scan_job_idempotency"),
    )
    op.create_index("ix_scan_jobs_scan_run_id", "scan_jobs", ["scan_run_id"])
    op.create_index("ix_scan_jobs_run_status", "scan_jobs", ["scan_run_id", "status"])

    op.create_table(
        "file_artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=True),
        sa.Column("scan_job_id", sa.Uuid(), nullable=True),
        sa.Column("artifact_type", sa.String(length=100), nullable=False),
        sa.Column("path", sa.String(length=4096), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("path", name="uq_file_artifact_path"),
    )
    op.create_index("ix_file_artifacts_project_id", "file_artifacts", ["project_id"])
    op.create_index("ix_file_artifacts_scan_job_id", "file_artifacts", ["scan_job_id"])
    op.create_index("ix_file_artifacts_scan_run_id", "file_artifacts", ["scan_run_id"])

    op.create_foreign_key(
        "fk_observations_scan_run_id",
        "observations",
        "scan_runs",
        ["scan_run_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.execute(
        sa.text(
            "UPDATE system_metadata SET value = '2' WHERE key = 'schema_phase'"
        )
    )


def downgrade() -> None:
    op.drop_constraint("fk_observations_scan_run_id", "observations", type_="foreignkey")
    op.drop_table("file_artifacts")
    op.drop_table("scan_jobs")
    op.drop_table("scan_runs")
    op.execute(
        sa.text(
            "UPDATE system_metadata SET value = '1' WHERE key = 'schema_phase'"
        )
    )
