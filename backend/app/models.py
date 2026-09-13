from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class Intensity(str, enum.Enum):
    safe = "safe"
    standard = "standard"
    aggressive = "aggressive"


class JobStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def _str_enum(enum_cls: type[enum.Enum]) -> Enum:
    return Enum(enum_cls, values_callable=lambda x: [e.value for e in x], native_enum=False)


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    scope_targets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    intensity: Mapped[Intensity] = mapped_column(_str_enum(Intensity), default=Intensity.safe)
    roe_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    roe_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    jobs: Mapped[list[Job]] = relationship(back_populates="engagement", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="engagement", cascade="all, delete-orphan")
    audit_events: Mapped[list[AuditEvent]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    status: Mapped[JobStatus] = mapped_column(_str_enum(JobStatus), default=JobStatus.pending)
    phase: Mapped[str] = mapped_column(String(50), default="F0")
    current_tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped[Engagement] = relationship(back_populates="jobs")
    findings: Mapped[list[Finding]] = relationship(back_populates="job", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[Severity] = mapped_column(_str_enum(Severity), default=Severity.info)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    tool: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(String(100), default="general")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    engagement: Mapped[Engagement] = relationship(back_populates="findings")
    job: Mapped[Job | None] = relationship(back_populates="findings")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagements.id"), nullable=True)
    actor: Mapped[str] = mapped_column(String(100), default="system")
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    engagement: Mapped[Engagement | None] = relationship(back_populates="audit_events")
