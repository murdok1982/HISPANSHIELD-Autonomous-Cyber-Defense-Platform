"""Pydantic contracts for digital forensics (cases, evidence, timelines)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from app.core.schemas import ORMModel, StrictModel


class CaseOut(StrictModel):
    id: UUID
    ref: str
    title: str
    description: str | None
    severity: str
    status: str
    priority: int
    detected_at: datetime
    contained_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    mitre: list[str]
    evidence_count: int = 0
    alert_count: int = 0


class EvidenceOut(StrictModel):
    id: UUID
    incident_id: UUID | None
    kind: str
    title: str
    description: str | None
    sha256: str
    content_type: str
    size_bytes: int
    collected_by: str | None
    collected_at: datetime
    sealed: bool
    chain_length: int = 0
    has_file: bool = False


class TimelineEntryOut(ORMModel):
    id: UUID
    incident_id: UUID
    at: datetime
    kind: str
    actor: str | None
    summary: str
    detail: dict[str, Any]


class CaseAlertOut(StrictModel):
    id: UUID
    title: str
    severity: str
    status: str
    first_seen: datetime
    last_seen: datetime
    count: int
    mitre: list[str]


class CaseDetailOut(StrictModel):
    case: CaseOut
    timeline: list[TimelineEntryOut]
    evidence: list[EvidenceOut]
    alerts: list[CaseAlertOut]


class HashVerificationOut(StrictModel):
    evidence_id: UUID
    expected_sha256: str
    computed_sha256: str | None
    match: bool
    status: str
    file_size: int | None
    verified_at: datetime
    chain_of_custody: list[dict[str, Any]] = Field(default_factory=list)


class ChainOfCustodyOut(StrictModel):
    evidence_id: UUID
    incident_id: UUID | None
    sha256: str
    sealed: bool
    entries: list[dict[str, Any]]
    last_verified_at: datetime | None


class ExportSummaryOut(StrictModel):
    incident_id: UUID
    filename: str
    size_bytes: int
    sha256: str
    evidence_included: int
    evidence_missing: int
    evidence_errors: int


__all__ = [
    "CaseAlertOut",
    "CaseDetailOut",
    "CaseOut",
    "ChainOfCustodyOut",
    "EvidenceOut",
    "ExportSummaryOut",
    "HashVerificationOut",
    "TimelineEntryOut",
]
