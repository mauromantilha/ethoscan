"""baseline

Revision ID: 6d8b5e247c83
Revises:
Create Date: 2026-09-30 14:49:59.782838+00:00

Baseline do schema (Sprint 3): cria engagements/jobs/findings/audit_events.

A baseline é reconciliável: se o banco já tiver o schema (criado por
``Base.metadata.create_all`` em versões anteriores), ela não recria nada e apenas
marca a revisão — ``alembic upgrade head`` funciona nos dois casos. Alternativa
manual equivalente: ``alembic stamp head``.

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "6d8b5e247c83"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FINGERPRINT_INDEX = "ix_findings_fingerprint"


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _existing_indexes(table: str) -> set[str]:
    if table not in _existing_tables():
        return set()
    return {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table)}


def _create_engagements() -> None:
    op.create_table(
        "engagements",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("scope_targets", sa.JSON(), nullable=False),
        sa.Column(
            "intensity",
            sa.Enum("safe", "standard", "aggressive", name="intensity", native_enum=False),
            nullable=False,
        ),
        sa.Column("roe_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("roe_text", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_audit_events() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

def _create_jobs() -> None:
    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "running",
                "completed",
                "failed",
                "cancelled",
                name="jobstatus",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column("phase", sa.String(length=50), nullable=False),
        sa.Column("current_tool", sa.String(length=100), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("report_path", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_findings() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "info",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column("tool", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("cve", sa.String(length=64), nullable=True),
        sa.Column("cwe", sa.String(length=64), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

def upgrade() -> None:
    tables = _existing_tables()
    if "engagements" not in tables:
        _create_engagements()
    if "audit_events" not in tables:
        _create_audit_events()
    if "jobs" not in tables:
        _create_jobs()
    if "findings" not in tables:
        _create_findings()
    if FINGERPRINT_INDEX not in _existing_indexes("findings"):
        op.create_index(FINGERPRINT_INDEX, "findings", ["fingerprint"], unique=False)


def downgrade() -> None:
    if FINGERPRINT_INDEX in _existing_indexes("findings"):
        op.drop_index(FINGERPRINT_INDEX, table_name="findings")
    tables = _existing_tables()
    for table in ("findings", "jobs", "audit_events", "engagements"):
        if table in tables:
            op.drop_table(table)
