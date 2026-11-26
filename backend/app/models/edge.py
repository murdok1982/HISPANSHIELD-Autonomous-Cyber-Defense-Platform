"""Edge gateway enrollment and telemetry buffering models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class EdgeGateway(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "edge_gateways"
    __table_args__ = (UniqueConstraint("org_id", "fingerprint", name="uq_edge_gateways_org_fingerprint"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    certificate_serial: Mapped[str | None] = mapped_column(String(120), nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    buffer_stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class EdgeIngestEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "edge_ingest_events"

    gateway_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("edge_gateways.id", ondelete="CASCADE"), nullable=False, index=True
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(40), default="telemetry", nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    signature_valid: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    accepted: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    processed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class EdgeSyncCursor(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "edge_sync_cursors"

    gateway_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("edge_gateways.id", ondelete="CASCADE"), nullable=False, index=True
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    last_sequence: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


__all__ = ["EdgeGateway", "EdgeIngestEvent", "EdgeSyncCursor"]
