"""Separate host and fixture findings and label exports.

Revision ID: 0009_evidence_mode
Revises: 0008_phase_six
Create Date: 2026-08-10
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_evidence_mode"
down_revision: str | None = "0008_phase_six"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("execution_mode", sa.String(length=20), nullable=True))
    op.execute(
        """
        UPDATE findings AS finding
        SET execution_mode = COALESCE(run.config_snapshot ->> 'execution_mode', 'host')
        FROM scan_runs AS run
        WHERE run.id = finding.last_scan_run_id
        """
    )
    op.execute("UPDATE findings SET execution_mode = 'host' WHERE execution_mode IS NULL")
    op.alter_column("findings", "execution_mode", nullable=False)
    op.drop_constraint("uq_finding_identity", "findings", type_="unique")
    op.create_unique_constraint(
        "uq_finding_identity_mode",
        "findings",
        ["project_id", "execution_mode", "template_id", "target"],
    )
    op.create_index(
        "ix_findings_project_execution_mode",
        "findings",
        ["project_id", "execution_mode"],
    )

    op.add_column(
        "export_artifacts",
        sa.Column(
            "execution_mode",
            sa.String(length=20),
            nullable=False,
            server_default="legacy-mixed",
        ),
    )
    op.alter_column("export_artifacts", "execution_mode", server_default=None)


def downgrade() -> None:
    op.drop_column("export_artifacts", "execution_mode")
    op.drop_index("ix_findings_project_execution_mode", table_name="findings")
    op.drop_constraint("uq_finding_identity_mode", "findings", type_="unique")
    op.execute(
        """
        DELETE FROM findings AS duplicate
        USING findings AS retained
        WHERE duplicate.project_id = retained.project_id
          AND duplicate.template_id = retained.template_id
          AND duplicate.target = retained.target
          AND duplicate.id > retained.id
        """
    )
    op.create_unique_constraint(
        "uq_finding_identity", "findings", ["project_id", "template_id", "target"]
    )
    op.drop_column("findings", "execution_mode")
