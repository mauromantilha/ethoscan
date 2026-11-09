"""job_findings association + unique fingerprint per engagement.

Revision ID: 0003_job_findings
Revises: 0002_selected_tools
Create Date: 2026-11-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0003_job_findings"
down_revision = "0002_selected_tools"
branch_labels = None
depends_on = None


def _has_unique_fingerprint(inspector: sa.Inspector) -> bool:
    for constraint in inspector.get_unique_constraints("findings"):
        columns = list(constraint.get("column_names") or [])
        if columns == ["engagement_id", "fingerprint"]:
            return True
    return False


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "job_findings" not in tables:
        op.create_table(
            "job_findings",
            sa.Column(
                "job_id",
                sa.Integer(),
                sa.ForeignKey("jobs.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column(
                "finding_id",
                sa.Integer(),
                sa.ForeignKey("findings.id", ondelete="CASCADE"),
                primary_key=True,
            ),
        )
        tables.add("job_findings")

    if "findings" in tables and "job_findings" in tables:
        # Backfill: cada finding pertence ao job original (job_id).
        rows = bind.execute(
            sa.text("SELECT id, job_id FROM findings WHERE job_id IS NOT NULL")
        ).fetchall()
        for finding_id, job_id in rows:
            job_exists = bind.execute(
                sa.text("SELECT 1 FROM jobs WHERE id = :job_id"), {"job_id": job_id}
            ).first()
            if not job_exists:
                continue
            exists = bind.execute(
                sa.text(
                    "SELECT 1 FROM job_findings "
                    "WHERE job_id = :job_id AND finding_id = :finding_id"
                ),
                {"job_id": job_id, "finding_id": finding_id},
            ).first()
            if not exists:
                bind.execute(
                    sa.text(
                        "INSERT INTO job_findings (job_id, finding_id) "
                        "VALUES (:job_id, :finding_id)"
                    ),
                    {"job_id": job_id, "finding_id": finding_id},
                )

        # Deduplicar findings antigos antes de criar a unique constraint.
        duplicate_groups = bind.execute(
            sa.text(
                "SELECT engagement_id, fingerprint FROM findings "
                "GROUP BY engagement_id, fingerprint HAVING COUNT(*) > 1"
            )
        ).fetchall()
        for engagement_id, fingerprint in duplicate_groups:
            ids = [
                row[0]
                for row in bind.execute(
                    sa.text(
                        "SELECT id FROM findings "
                        "WHERE engagement_id = :engagement_id AND fingerprint = :fingerprint "
                        "ORDER BY id"
                    ),
                    {"engagement_id": engagement_id, "fingerprint": fingerprint},
                ).fetchall()
            ]
            keeper, duplicates = ids[0], ids[1:]
            for duplicate_id in duplicates:
                links = bind.execute(
                    sa.text("SELECT job_id FROM job_findings WHERE finding_id = :finding_id"),
                    {"finding_id": duplicate_id},
                ).fetchall()
                for (job_id,) in links:
                    exists = bind.execute(
                        sa.text(
                            "SELECT 1 FROM job_findings "
                            "WHERE job_id = :job_id AND finding_id = :finding_id"
                        ),
                        {"job_id": job_id, "finding_id": keeper},
                    ).first()
                    if not exists:
                        bind.execute(
                            sa.text(
                                "INSERT INTO job_findings (job_id, finding_id) "
                                "VALUES (:job_id, :finding_id)"
                            ),
                            {"job_id": job_id, "finding_id": keeper},
                        )
                bind.execute(
                    sa.text("DELETE FROM job_findings WHERE finding_id = :finding_id"),
                    {"finding_id": duplicate_id},
                )
                bind.execute(
                    sa.text("DELETE FROM findings WHERE id = :finding_id"),
                    {"finding_id": duplicate_id},
                )

    inspector = sa.inspect(bind)
    if "findings" in tables and not _has_unique_fingerprint(inspector):
        with op.batch_alter_table("findings") as batch:
            batch.create_unique_constraint(
                "uq_findings_engagement_fingerprint", ["engagement_id", "fingerprint"]
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "findings" in tables and _has_unique_fingerprint(inspector):
        with op.batch_alter_table("findings") as batch:
            batch.drop_constraint("uq_findings_engagement_fingerprint", type_="unique")
    if "job_findings" in tables:
        op.drop_table("job_findings")
