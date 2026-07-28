"""Add phase-three DNS, IP, port, and service inventory.

Revision ID: 0005_phase_three
Revises: 0004_phase_two_order
Create Date: 2026-07-16
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_phase_three"
down_revision: str | None = "0004_phase_two_order"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

dns_record_type = sa.Enum(
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR",
    name="dnsrecordtype", native_enum=False,
)
ip_classification = sa.Enum(
    "OWNED", "CLOUD_SERVER", "SHARED_HOSTING", "CDN_WAF", "UNKNOWN",
    "PRIVATE_RESERVED", name="ipclassification", native_enum=False,
)
transport_protocol = sa.Enum("tcp", "udp", name="transportprotocol", native_enum=False)
port_state = sa.Enum(
    "OPEN", "CLOSED", "FILTERED", "UNKNOWN", name="portstate", native_enum=False
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
        "dns_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("domain_asset_id", sa.Uuid(), nullable=False),
        sa.Column("record_type", dns_record_type, nullable=False),
        sa.Column("value", sa.String(length=4096), nullable=False),
        sa.Column("ttl", sa.Integer(), nullable=True),
        sa.Column("resolver", sa.String(length=255), nullable=True),
        sa.Column("source_tool", sa.String(length=100), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["domain_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_run_id", "domain_asset_id", "record_type", "value",
            name="uq_dns_record_run_value",
        ),
    )
    op.create_index("ix_dns_records_project_id", "dns_records", ["project_id"])
    op.create_index("ix_dns_records_scan_run_id", "dns_records", ["scan_run_id"])
    op.create_index("ix_dns_records_domain_asset_id", "dns_records", ["domain_asset_id"])
    op.create_index("ix_dns_records_project_type", "dns_records", ["project_id", "record_type"])

    op.create_table(
        "ip_details",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("classification", ip_classification, nullable=False),
        sa.Column("classification_source", sa.String(length=100), nullable=False),
        sa.Column("asn", sa.Integer(), nullable=True),
        sa.Column("organization", sa.String(length=500), nullable=True),
        sa.Column("provider", sa.String(length=300), nullable=True),
        sa.Column("reverse_dns", sa.String(length=2048), nullable=True),
        sa.Column("is_private", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("is_cdn", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column(
            "metadata", postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"), nullable=False,
        ),
        *_actor_columns(),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "asset_id", name="uq_ip_detail_asset"),
    )
    op.create_index("ix_ip_details_project_id", "ip_details", ["project_id"])
    op.create_index("ix_ip_details_asset_id", "ip_details", ["asset_id"])
    op.create_index(
        "ix_ip_details_project_classification", "ip_details", ["project_id", "classification"]
    )

    op.create_table(
        "ports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("ip_asset_id", sa.Uuid(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", transport_protocol, nullable=False),
        sa.Column("state", port_state, nullable=False),
        sa.Column("source_tool", sa.String(length=100), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("port >= 1 AND port <= 65535", name="ck_port_number"),
        sa.ForeignKeyConstraint(["ip_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_run_id", "ip_asset_id", "port", "protocol", name="uq_port_run_endpoint"
        ),
    )
    op.create_index("ix_ports_project_id", "ports", ["project_id"])
    op.create_index("ix_ports_scan_run_id", "ports", ["scan_run_id"])
    op.create_index("ix_ports_ip_asset_id", "ports", ["ip_asset_id"])
    op.create_index("ix_ports_project_state", "ports", ["project_id", "state"])

    op.create_table(
        "services",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("port_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=True),
        sa.Column("product", sa.String(length=500), nullable=True),
        sa.Column("version", sa.String(length=300), nullable=True),
        sa.Column("tunnel", sa.String(length=50), nullable=True),
        sa.Column("cpe", sa.String(length=1024), nullable=True),
        sa.Column("tls", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("source_tool", sa.String(length=100), nullable=False),
        sa.Column(
            "attributes", postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"), nullable=False,
        ),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["port_id"], ["ports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_run_id", "port_id", name="uq_service_run_port"),
    )
    op.create_index("ix_services_project_id", "services", ["project_id"])
    op.create_index("ix_services_scan_run_id", "services", ["scan_run_id"])
    op.create_index("ix_services_port_id", "services", ["port_id"])
    op.execute(sa.text("UPDATE system_metadata SET value = '3' WHERE key = 'schema_phase'"))


def downgrade() -> None:
    op.execute(sa.text("UPDATE system_metadata SET value = '2' WHERE key = 'schema_phase'"))
    op.drop_table("services")
    op.drop_table("ports")
    op.drop_table("ip_details")
    op.drop_table("dns_records")
