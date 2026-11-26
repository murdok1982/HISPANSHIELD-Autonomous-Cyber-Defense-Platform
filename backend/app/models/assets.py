"""CAASM/EASM asset, vulnerability and industrial inventory models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, Session, mapped_column, with_loader_criteria

from app.core.db import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class Zone(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "zones"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_zone_org_name"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), default="zone", nullable=False)  # zone | conduit
    purdue_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("zones.id", ondelete="SET NULL"), nullable=True
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "asset_key", name="uq_asset_org_key"),
        Index("ix_assets_org_kind", "org_id", "kind"),
        Index("ix_assets_org_criticality", "org_id", "criticality"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_key: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)  # host, network, cloud, iot, ot, identity, service
    subtype: Mapped[str | None] = mapped_column(String(60), nullable=True)
    criticality: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    environment: Mapped[str] = mapped_column(String(30), default="production", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    ip_addresses: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    mac_addresses: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    hostnames: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    os_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(160), nullable=True)
    model: Mapped[str | None] = mapped_column(String(160), nullable=True)
    firmware: Mapped[str | None] = mapped_column(String(120), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(160), nullable=True)
    location: Mapped[str | None] = mapped_column(String(200), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    discovery_source: Mapped[str] = mapped_column(String(80), default="manual", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("zones.id", ondelete="SET NULL"), nullable=True, index=True
    )
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Soft delete preserves findings, evidence and audit references. Active
    # inventory queries hide rows with a timestamp; the restore endpoint is the
    # only supported path back into the inventory.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class AssetIdentity(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "asset_identities"
    __table_args__ = (UniqueConstraint("asset_id", "kind", "value", name="uq_asset_identity"),)

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    value: Mapped[str] = mapped_column(String(400), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AssetRelationship(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (UniqueConstraint("source_asset_id", "target_asset_id", "kind", name="uq_asset_relationship"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(60), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)


class IoTDevice(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "iot_devices"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    protocols: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    connectivity: Mapped[str | None] = mapped_column(String(80), nullable=True)
    edge_gateway_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True, index=True)
    firmware_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_telemetry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    security_posture: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class OTDevice(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "ot_devices"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    protocols: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("zones.id", ondelete="SET NULL"), nullable=True
    )
    safety_critical: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    passive_only: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    controller_model: Mapped[str | None] = mapped_column(String(160), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_telemetry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    baseline: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class CVECatalog(Base):
    __tablename__ = "cve_catalog"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    references: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    cpes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    cwe: Mapped[str | None] = mapped_column(String(80), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Vulnerability(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vuln_org_status", "org_id", "status"),
        Index("ix_vuln_org_priority", "org_id", "priority_score"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    exploitable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exposure: Mapped[str] = mapped_column(String(30), default="internal", nullable=False)
    priority_score: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    priority_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(80), default="manual", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)


class AttackSurfaceFinding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "attack_surface_findings"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    kind: Mapped[str] = mapped_column(String(60), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(80), default="inventory", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)


class DiscoveryAuthorization(UUIDPrimaryKeyMixin, Base):
    """Explicit, dual-control authorization to enumerate a network scope.

    A discovery job may only run while linked to an authorization that is
    approved, unexpired and not revoked. The creator of the authorization can
    never approve it (separation of duties).
    """

    __tablename__ = "discovery_authorizations"
    __table_args__ = (Index("ix_discovery_auth_org_created", "org_id", "created_at"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    cidrs: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    ports: Mapped[list[int]] = mapped_column(JSONB, default=list, nullable=False)
    max_hosts: Mapped[int] = mapped_column(Integer, default=256, nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class DiscoveryJob(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "discovery_jobs"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), default="passive", nullable=False)
    scope_cidrs: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("discovery_authorizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    authorized_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    authorization_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


@event.listens_for(Session, "do_orm_execute")
def _hide_soft_deleted_assets(execute_state: object) -> None:
    """Exclude soft-deleted assets from every ORM read by default.

    Soft-deleted rows keep their vulnerabilities, evidence and relationships
    for forensic and reporting purposes, but they must disappear from the
    inventory, graph, posture and agent tooling. Callers that genuinely need
    deleted rows (the restore endpoint) opt in with
    ``execution_options(include_soft_deleted=True)``.
    """
    state = execute_state
    if not getattr(state, "is_select", False):
        return
    options = getattr(state, "execution_options", {}) or {}
    if options.get("include_soft_deleted"):
        return
    state.statement = state.statement.options(  # type: ignore[attr-defined]
        with_loader_criteria(Asset, Asset.deleted_at.is_(None), include_aliases=True)
    )


__all__ = [
    "AttackSurfaceFinding",
    "Asset",
    "AssetIdentity",
    "AssetRelationship",
    "CVECatalog",
    "DiscoveryAuthorization",
    "DiscoveryJob",
    "IoTDevice",
    "OTDevice",
    "Vulnerability",
    "Zone",
]
