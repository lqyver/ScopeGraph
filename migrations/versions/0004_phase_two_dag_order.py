"""Add deterministic scan job DAG order.

Revision ID: 0004_phase_two_order
Revises: 0003_phase_two
Create Date: 2026-07-16
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_phase_two_order"
down_revision: str | None = "0003_phase_two"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("sequence", sa.Integer(), nullable=True))
    op.execute(
        sa.text(
            "UPDATE scan_jobs SET sequence = CASE job_type "
            "WHEN 'passive_subdomain' THEN 0 "
            "WHEN 'dns_enrichment' THEN 1 "
            "WHEN 'http_probe' THEN 2 ELSE 100 END"
        )
    )
    op.alter_column("scan_jobs", "sequence", nullable=False)
    op.create_check_constraint("ck_scan_job_sequence", "scan_jobs", "sequence >= 0")
    op.create_unique_constraint("uq_scan_job_sequence", "scan_jobs", ["scan_run_id", "sequence"])


def downgrade() -> None:
    op.drop_constraint("uq_scan_job_sequence", "scan_jobs", type_="unique")
    op.drop_constraint("ck_scan_job_sequence", "scan_jobs", type_="check")
    op.drop_column("scan_jobs", "sequence")
