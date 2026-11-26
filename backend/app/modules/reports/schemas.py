"""Pydantic contracts for generated reports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.schemas import ORMModel, StrictModel

REPORT_KINDS = ("executive", "technical", "regulatory", "incident")
REPORT_FORMATS = ("html", "md")

REPORT_DISCLAIMER = (
    "Compliance and certification disclaimer: this report is a technical self-assessment built "
    "from platform evidence. It is not a certification, accreditation, audit opinion or legal advice, "
    "and it does not replace an accredited assessment by a notified body or supervisory authority."
)


class ReportGenerateRequest(StrictModel):
    kind: Literal["executive", "technical", "regulatory", "incident"]
    period_start: datetime
    period_end: datetime
    framework_id: UUID | None = None

    @field_validator("period_start", "period_end")
    @classmethod
    def _aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _period_order(self) -> ReportGenerateRequest:
        if self.period_end <= self.period_start:
            raise ValueError("period_end must be after period_start")
        if (self.period_end - self.period_start).days > 366:
            raise ValueError("Reporting period cannot exceed 366 days")
        return self


class ReportSummary(ORMModel):
    id: UUID
    kind: str
    title: str
    period_start: datetime | None = None
    period_end: datetime | None = None
    status: str
    format: str
    checksum: str
    generated_by: str | None = None
    generated_at: datetime
    framework_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReportDetail(ReportSummary):
    content_md: str
    content_html: str
    disclaimer: str = REPORT_DISCLAIMER
