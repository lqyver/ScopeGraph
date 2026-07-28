"""Create phase-zero system metadata.

Revision ID: 0001_phase_zero
Revises:
Create Date: 2026-07-16
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_phase_zero"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "system_metadata",
        sa.Column("key", sa.String(length=100), primary_key=True),
        sa.Column("value", sa.String(length=500), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.bulk_insert(
        sa.table(
            "system_metadata",
            sa.column("key", sa.String()),
            sa.column("value", sa.String()),
        ),
        [{"key": "schema_phase", "value": "0"}],
    )


def downgrade() -> None:
    op.drop_table("system_metadata")

