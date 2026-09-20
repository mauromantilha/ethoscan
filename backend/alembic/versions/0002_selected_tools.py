"""selected_tools + report_pdf_path.

Revision ID: 0002_selected_tools
Revises: 0001_b_series
Create Date: 2026-09-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_selected_tools"
down_revision = "0001_b_series"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "engagements" in tables:
        cols = {c["name"] for c in inspector.get_columns("engagements")}
        if "selected_tools" not in cols:
            with op.batch_alter_table("engagements") as batch:
                batch.add_column(sa.Column("selected_tools", sa.JSON(), nullable=True))

    if "jobs" in tables:
        cols = {c["name"] for c in inspector.get_columns("jobs")}
        with op.batch_alter_table("jobs") as batch:
            if "selected_tools" not in cols:
                batch.add_column(sa.Column("selected_tools", sa.JSON(), nullable=True))
            if "report_pdf_path" not in cols:
                batch.add_column(sa.Column("report_pdf_path", sa.String(500), nullable=True))


def downgrade() -> None:
    pass
