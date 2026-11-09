"""Hardening: external_ref idempotente + audit client_ip.

Revision ID: 0004_hardening
Revises: 0003_job_findings
Create Date: 2026-11-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0004_hardening"
down_revision = "0003_job_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "engagements" in tables:
        columns = {column["name"] for column in inspector.get_columns("engagements")}
        if "external_ref" not in columns:
            with op.batch_alter_table("engagements") as batch:
                batch.add_column(sa.Column("external_ref", sa.String(120), nullable=True))
        indexes = {index["name"] for index in inspector.get_indexes("engagements")}
        if "ix_engagements_external_ref" not in indexes:
            op.create_index(
                "ix_engagements_external_ref",
                "engagements",
                ["external_ref"],
                unique=True,
            )

    if "audit_events" in tables:
        columns = {column["name"] for column in inspector.get_columns("audit_events")}
        if "client_ip" not in columns:
            with op.batch_alter_table("audit_events") as batch:
                batch.add_column(sa.Column("client_ip", sa.String(64), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "audit_events" in tables:
        columns = {column["name"] for column in inspector.get_columns("audit_events")}
        if "client_ip" in columns:
            with op.batch_alter_table("audit_events") as batch:
                batch.drop_column("client_ip")
    if "engagements" in tables:
        indexes = {index["name"] for index in inspector.get_indexes("engagements")}
        if "ix_engagements_external_ref" in indexes:
            op.drop_index("ix_engagements_external_ref", table_name="engagements")
        columns = {column["name"] for column in inspector.get_columns("engagements")}
        if "external_ref" in columns:
            with op.batch_alter_table("engagements") as batch:
                batch.drop_column("external_ref")
