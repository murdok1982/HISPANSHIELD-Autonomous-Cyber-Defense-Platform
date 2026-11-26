"""Threat intelligence models (STIX 2.1 aligned)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class ThreatActor(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "threat_actors"

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    mitre_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sophistication: Mapped[str] = mapped_column(String(40), default="unknown", nullable=False)
    motivation: Mapped[str] = mapped_column(String(80), default="unknown", nullable=False)
    country: Mapped[str | None] = mapped_column(String(80), nullable=True)
    techniques: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    stix: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class ThreatIndicator(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint("org_id", "indicator_type", "value", name="uq_indicator_org_type_value"),
        Index("ix_indicators_org_value", "org_id", "value"),
        Index("ix_indicators_org_type", "org_id", "indicator_type"),
    )

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    indicator_type: Mapped[str] = mapped_column(String(30), nullable=False)  # ip, domain, url, sha256, email
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    source: Mapped[str] = mapped_column(String(120), default="manual", nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="SET NULL"), nullable=True
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    stix: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class TIFeed(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ti_feeds"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)  # misp | opencti | taxii | csv | stix
    connector_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("connectors.id", ondelete="SET NULL"), nullable=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    schedule_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="idle", nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


__all__ = ["TIFeed", "ThreatActor", "ThreatIndicator"]
