"""Index scan evidence mode independently from the immutable config snapshot.

Revision ID: 0010_scan_run_execution_mode
Revises: 0009_evidence_mode
Create Date: 2026-08-31
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_scan_run_execution_mode"
down_revision: str | None = "0009_evidence_mode"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("execution_mode", sa.String(length=20), nullable=True))
    op.execute(
        """
        UPDATE scan_runs
        SET execution_mode = COALESCE(config_snapshot ->> 'execution_mode', 'host')
        WHERE execution_mode IS NULL
        """
    )
    op.execute("UPDATE scan_runs SET execution_mode = 'host' WHERE execution_mode IS NULL")
    op.alter_column("scan_runs", "execution_mode", nullable=False)
    op.create_index(
        "ix_scan_runs_project_execution_mode_created_at",
        "scan_runs",
        ["project_id", "execution_mode", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_runs_project_execution_mode_created_at", table_name="scan_runs")
    op.drop_column("scan_runs", "execution_mode")
