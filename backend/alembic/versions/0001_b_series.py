"""B-series: tool_runs on jobs, mocked on findings.

Revision ID: 0001_b_series
Revises:
Create Date: 2026-09-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_b_series"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "engagements" not in tables:
        op.create_table(
            "engagements",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("scope_targets", sa.JSON(), nullable=False),
            sa.Column("intensity", sa.String(32), nullable=False),
            sa.Column("roe_acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("roe_text", sa.Text(), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if "jobs" not in tables:
        op.create_table(
            "jobs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("engagement_id", sa.Integer(), sa.ForeignKey("engagements.id"), nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("phase", sa.String(50), nullable=False),
            sa.Column("current_tool", sa.String(100), nullable=True),
            sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("report_path", sa.String(500), nullable=True),
            sa.Column("tool_runs", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        )
    else:
        cols = {c["name"] for c in inspector.get_columns("jobs")}
        if "tool_runs" not in cols:
            with op.batch_alter_table("jobs") as batch:
                batch.add_column(sa.Column("tool_runs", sa.JSON(), nullable=True))

    if "findings" not in tables:
        op.create_table(
            "findings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("engagement_id", sa.Integer(), sa.ForeignKey("engagements.id"), nullable=False),
            sa.Column("job_id", sa.Integer(), sa.ForeignKey("jobs.id"), nullable=True),
            sa.Column("title", sa.String(300), nullable=False),
            sa.Column("severity", sa.String(32), nullable=False),
            sa.Column("target", sa.String(500), nullable=False),
            sa.Column("tool", sa.String(100), nullable=False),
            sa.Column("category", sa.String(100), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("evidence", sa.Text(), nullable=True),
            sa.Column("cve", sa.String(64), nullable=True),
            sa.Column("cwe", sa.String(64), nullable=True),
            sa.Column("remediation", sa.Text(), nullable=True),
            sa.Column("fingerprint", sa.String(64), nullable=False),
            sa.Column("mocked", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    else:
        cols = {c["name"] for c in inspector.get_columns("findings")}
        if "mocked" not in cols:
            with op.batch_alter_table("findings") as batch:
                batch.add_column(
                    sa.Column("mocked", sa.Boolean(), nullable=False, server_default=sa.false())
                )

    if "audit_events" not in tables:
        op.create_table(
            "audit_events",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("engagement_id", sa.Integer(), sa.ForeignKey("engagements.id"), nullable=True),
            sa.Column("actor", sa.String(100), nullable=False),
            sa.Column("action", sa.String(100), nullable=False),
            sa.Column("detail", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )


def downgrade() -> None:
    pass
