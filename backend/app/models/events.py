"""Event fabric, detection and alerting models (OCSF-normalized)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class IngestSource(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ingest_sources"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)  # syslog | webhook | api | connector | file
    parser: Mapped[str] = mapped_column(String(40), default="auto", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    hmac_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    connector_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("connectors.id", ondelete="SET NULL"), nullable=True
    )
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class IngestNonce(Base):
    """Single-use HMAC v2 nonces, scoped per ingestion source.

    Rows are pruned in bounded batches once they are older than the replay
    tolerance (a superset of the signature window), so an attacker cannot grow
    the table without bound.
    """

    __tablename__ = "ingest_nonces"
    __table_args__ = (
        UniqueConstraint("source_id", "nonce", name="uq_ingest_nonces_source_nonce"),
        Index("ix_ingest_nonces_received", "received_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ingest_sources.id", ondelete="CASCADE"), nullable=False
    )
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_org_occurred", "org_id", "occurred_at"),
        Index("ix_events_org_severity", "org_id", "severity_id"),
        Index("ix_events_org_src_ip", "org_id", "src_ip"),
        Index("ix_events_org_host", "org_id", "host_name"),
        Index(
            "uq_events_org_dedupe",
            "org_id",
            "dedupe_key",
            unique=True,
            postgresql_where=text("dedupe_key IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    event_uid: Mapped[str] = mapped_column(String(80), nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ingest_sources.id", ondelete="SET NULL"), nullable=True
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    class_uid: Mapped[int] = mapped_column(Integer, default=6003, nullable=False)
    class_name: Mapped[str] = mapped_column(String(80), default="Network Activity", nullable=False)
    category_uid: Mapped[int] = mapped_column(Integer, default=4, nullable=False)
    activity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity_id: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    normalized: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    raw_format: Mapped[str] = mapped_column(String(30), default="json", nullable=False)
    schema_version: Mapped[str] = mapped_column(String(20), default="1.1.0", nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(30), nullable=True)
    user_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    host_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_hash_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ioc_matches: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    dedupe_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_connector: Mapped[str | None] = mapped_column(String(80), nullable=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class DetectionRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "detection_rules"

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="production", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    logsource: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    mitre: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    true_positive_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Alert(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_org_status", "org_id", "status"),
        Index("ix_alerts_org_created", "org_id", "created_at"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="new", nullable=False)
    dedupe_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event_ids: Mapped[list[int]] = mapped_column(JSONB, default=list, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True, index=True)
    mitre: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


__all__ = ["Alert", "DetectionRule", "IngestNonce", "IngestSource", "SecurityEvent"]
