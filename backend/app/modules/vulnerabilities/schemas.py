"""Pydantic contracts for vulnerabilities and intelligence imports."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.schemas import ORMModel, StrictModel
from app.modules.assets.schemas import AssetRef

SEVERITIES = ("critical", "high", "medium", "low", "info")
VULN_STATUSES = ("open", "reopened", "mitigated", "accepted", "false_positive")
EXPOSURES = ("public", "dmz", "internal")

CVE_PATTERN = r"^CVE-\d{4}-\d{4,10}$"


def _clean_metadata(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    if len(value) > 80:
        raise ValueError("metadata supports at most 80 keys")
    return value


class VulnerabilityCreate(StrictModel):
    asset_id: UUID | None = None
    cve_id: str | None = Field(default=None, pattern=CVE_PATTERN)
    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=8000)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None, max_length=200)
    epss_score: float | None = Field(default=None, ge=0, le=1)
    kev: bool = False
    severity: str | None = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    status: str = Field(default="open", pattern="^(open|reopened)$")
    exploitable: bool = False
    exposure: str = Field(default="internal", pattern="^(public|dmz|internal)$")
    source: str = Field(default="manual", min_length=1, max_length=80)
    due_at: datetime | None = None
    remediation: str | None = Field(default=None, max_length=8000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _clean_metadata(value)


class VulnerabilityPatch(StrictModel):
    status: str | None = Field(default=None, pattern="^(open|reopened|mitigated|accepted|false_positive)$")
    severity: str | None = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    exposure: str | None = Field(default=None, pattern="^(public|dmz|internal)$")
    exploitable: bool | None = None
    kev: bool | None = None
    due_at: datetime | None = None
    remediation: str | None = Field(default=None, max_length=8000)
    metadata: dict[str, Any] | None = None

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return None if value is None else _clean_metadata(value)


class VulnerabilityOut(ORMModel):
    id: UUID
    asset_id: UUID | None
    cve_id: str | None
    title: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    kev: bool
    severity: str
    status: str
    exploitable: bool
    exposure: str
    priority_score: float
    priority_reason: str | None
    source: str
    first_seen: datetime
    last_seen: datetime
    due_at: datetime | None
    remediation: str | None
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_json")
    created_at: datetime
    updated_at: datetime


class CVECatalogOut(ORMModel):
    cve_id: str
    description: str
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    kev: bool
    published_at: datetime | None
    modified_at: datetime | None
    references: list[str]
    cpes: list[str]
    cwe: str | None
    updated_at: datetime


class VulnerabilityDetailOut(VulnerabilityOut):
    asset: AssetRef | None
    catalog: CVECatalogOut | None


class CVEImportItem(StrictModel):
    cve_id: str = Field(pattern=CVE_PATTERN)
    description: str = Field(min_length=1, max_length=8000)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None, max_length=200)
    epss_score: float | None = Field(default=None, ge=0, le=1)
    kev: bool = False
    published_at: datetime | None = None
    modified_at: datetime | None = None
    references: list[str] = Field(default_factory=list, max_length=50)
    cpes: list[str] = Field(default_factory=list, max_length=50)
    cwe: str | None = Field(default=None, max_length=80)
    asset_ids: list[UUID] = Field(default_factory=list, max_length=500)


class CVEImportRequest(StrictModel):
    items: list[CVEImportItem] = Field(min_length=1, max_length=500)


class ImportRowError(StrictModel):
    row: int
    identifier: str | None = None
    message: str


class CVEImportResult(StrictModel):
    catalog_created: int
    catalog_updated: int
    vulnerabilities_created: int
    vulnerabilities_updated: int
    errors: list[ImportRowError]


class KEVEntry(BaseModel):
    """CISA KEV subset.

    Vendor feeds add columns over time; unknown keys are ignored (but every
    consumed field is strictly typed) so a feed revision cannot break ingestion.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    cveID: str = Field(pattern=CVE_PATTERN)
    vendorProject: str | None = Field(default=None, max_length=200)
    product: str | None = Field(default=None, max_length=200)
    vulnerabilityName: str | None = Field(default=None, max_length=300)
    dateAdded: str | None = Field(default=None, max_length=40)
    shortDescription: str | None = Field(default=None, max_length=8000)
    requiredAction: str | None = Field(default=None, max_length=2000)
    dueDate: str | None = Field(default=None, max_length=40)
    knownRansomwareCampaignUse: str | None = Field(default=None, max_length=40)
    notes: str | None = Field(default=None, max_length=4000)


class KEVImportRequest(StrictModel):
    vulnerabilities: list[KEVEntry] = Field(default_factory=list, max_length=500)
    cves: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("cves")
    @classmethod
    def _validate_cves(cls, value: list[str]) -> list[str]:
        for cve in value:
            if not re.match(CVE_PATTERN, cve):
                raise ValueError(f"Invalid CVE identifier: {cve}")
        return value

    @model_validator(mode="after")
    def _at_least_one(self) -> KEVImportRequest:
        if not self.vulnerabilities and not self.cves:
            raise ValueError("Provide vulnerabilities or cves")
        return self


class KEVImportResult(StrictModel):
    catalog_created: int
    catalog_marked: int
    vulnerabilities_marked: int
    unknown_cves: list[str]


class EPSSItem(StrictModel):
    cve: str = Field(pattern=CVE_PATTERN)
    epss: float = Field(ge=0, le=1)
    percentile: float | None = Field(default=None, ge=0, le=1)


class EPSSImportRequest(StrictModel):
    items: list[EPSSItem] = Field(default_factory=list, max_length=500)
    csv: str | None = Field(default=None, max_length=200_000)

    @model_validator(mode="after")
    def _at_least_one(self) -> EPSSImportRequest:
        if not self.items and not self.csv:
            raise ValueError("Provide items or csv")
        return self


class EPSSImportResult(StrictModel):
    parsed: int
    catalog_updated: int
    vulnerabilities_updated: int
    errors: list[ImportRowError]


class TopRiskyOut(StrictModel):
    id: UUID
    title: str
    cve_id: str | None
    severity: str
    status: str
    priority_score: float
    asset_id: UUID | None
    asset_name: str | None


class VulnerabilitySummaryOut(StrictModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    kev: int
    exploitable: int
    overdue: int
    mean_priority: float
    top_risky: list[TopRiskyOut]


__all__ = [
    "CVEImportItem",
    "CVEImportRequest",
    "CVEImportResult",
    "CVECatalogOut",
    "EPSSImportRequest",
    "EPSSImportResult",
    "EPSSItem",
    "EXPOSURES",
    "ImportRowError",
    "KEVEntry",
    "KEVImportRequest",
    "KEVImportResult",
    "SEVERITIES",
    "TopRiskyOut",
    "VULN_STATUSES",
    "VulnerabilityCreate",
    "VulnerabilityDetailOut",
    "VulnerabilityOut",
    "VulnerabilityPatch",
    "VulnerabilitySummaryOut",
]
