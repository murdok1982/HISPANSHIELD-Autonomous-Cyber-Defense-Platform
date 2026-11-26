"""Compliance frameworks, assessments, evidence mapping and reports."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class ComplianceFramework(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "compliance_frameworks"
    __table_args__ = (UniqueConstraint("code", "version", name="uq_framework_code_version"),)

    code: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    jurisdiction: Mapped[str] = mapped_column(String(80), default="EU", nullable=False)
    authority: Mapped[str | None] = mapped_column(String(200), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    effective_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="published", nullable=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ComplianceControl(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "compliance_controls"
    __table_args__ = (UniqueConstraint("framework_id", "control_id", name="uq_control_framework_code"),)

    framework_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(120), default="general", nullable=False)
    evidence_requirements: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    technical_checks: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    references: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    mapping: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class ComplianceAssessment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "compliance_assessments"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    framework_version: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="draft", nullable=False)
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    assessor: Mapped[str | None] = mapped_column(String(200), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    gaps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)


class ComplianceControlStatus(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "compliance_control_status"
    __table_args__ = (UniqueConstraint("assessment_id", "control_id", name="uq_assessment_control"),)

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("compliance_assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(30), default="not_assessed", nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Report(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "reports"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False)  # executive | technical | regulatory
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="generated", nullable=False)
    format: Mapped[str] = mapped_column(String(20), default="html", nullable=False)
    content_md: Mapped[str] = mapped_column(Text, default="", nullable=False)
    content_html: Mapped[str] = mapped_column(Text, default="", nullable=False)
    generated_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)
    framework_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id", ondelete="SET NULL"), nullable=True
    )


class ControlEvidenceLink(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "control_evidence_links"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_status_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("compliance_control_status.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    linked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


__all__ = [
    "ComplianceAssessment",
    "ComplianceControl",
    "ComplianceControlStatus",
    "ComplianceFramework",
    "ControlEvidenceLink",
    "Report",
]
