"""Framework catalogue loading/import and assessment lifecycle logic."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.crypto import sha256_hex
from app.core.db import utcnow
from app.core.errors import Conflict, NotFound, ValidationFailure
from app.models.compliance import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceControlStatus,
    ComplianceFramework,
)
from app.models.core import Organization
from app.modules.compliance.checks import (
    build_signals,
    control_weight,
    derive_control_status,
    evaluate_check,
    summarise_checks,
)
from app.modules.compliance.schemas import (
    DISCLAIMER,
    AssessmentSummary,
    ControlOut,
    ControlStatusOut,
    FrameworkDocument,
    FrameworkSummary,
)

FRAMEWORKS_DIR = Path(__file__).resolve().parents[2] / "data" / "frameworks"

STATUS_VALUES = {
    "compliant": 1.0,
    "partial": 0.5,
    "non_compliant": 0.0,
    "not_assessed": 0.0,
}

SCORING_FORMULA = (
    "score = Σ(weight × value) / Σ(weight) × 100, where compliant=1.0, partial=0.5, "
    "non_compliant=0.0, not_assessed=0.0 and not_applicable is excluded. "
    "Control weights are 3 for mandatory, 2 for standard and 1 for optional."
)


class SeedResult(dict):
    """Plain dict subclass so callers can inspect the seed summary easily."""


def _validation_error(exc: ValidationError) -> ValidationFailure:
    details = [
        {
            "field": ".".join(str(part) for part in error.get("loc", ())) or "document",
            "message": str(error.get("msg", "invalid value")),
        }
        for error in exc.errors()[:25]
    ]
    return ValidationFailure(details, message="Invalid framework document")


def parse_framework_document(
    content: str, document_format: Literal["auto", "yaml", "json"] = "auto"
) -> tuple[FrameworkDocument, Literal["yaml", "json"]]:
    """Parse and strictly validate a YAML or JSON framework document."""
    stripped = content.lstrip()
    resolved: Literal["yaml", "json"]
    if document_format == "auto":
        resolved = "json" if stripped.startswith("{") else "yaml"
    elif document_format == "json":
        resolved = "json"
    else:
        resolved = "yaml"
    if resolved == "json":
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValidationFailure(
                [{"field": "content", "message": f"Invalid JSON: {exc.msg} at line {exc.lineno}"}]
            ) from exc
    else:
        try:
            payload = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ValidationFailure([{"field": "content", "message": f"Invalid YAML: {exc}"}]) from exc
    if not isinstance(payload, dict):
        raise ValidationFailure([{"field": "content", "message": "Document root must be a mapping"}])
    try:
        document = FrameworkDocument.model_validate(payload)
    except ValidationError as exc:
        raise _validation_error(exc) from exc
    return document, resolved


def framework_checksum(document: FrameworkDocument) -> str:
    canonical = json.dumps(
        document.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256_hex(canonical)


def load_builtin_documents() -> list[FrameworkDocument]:
    """Load every built-in framework YAML from app/data/frameworks."""
    if not FRAMEWORKS_DIR.is_dir():
        raise RuntimeError(f"Built-in framework directory is missing: {FRAMEWORKS_DIR}")
    documents: list[FrameworkDocument] = []
    for path in sorted(FRAMEWORKS_DIR.glob("*.yaml")):
        raw = path.read_text(encoding="utf-8")
        document, _ = parse_framework_document(raw, "yaml")
        documents.append(document)
    if not documents:
        raise RuntimeError("No built-in framework documents found")
    return documents


def persist_framework(
    db: Session,
    document: FrameworkDocument,
    *,
    is_builtin: bool,
) -> ComplianceFramework:
    """Insert a framework version and its controls; caller owns the transaction."""
    framework = ComplianceFramework(
        code=document.code,
        name=document.name,
        version=document.version,
        jurisdiction=document.jurisdiction,
        authority=document.authority,
        description=document.description,
        source_url=document.source_url,
        effective_date=document.effective_date,
        status=document.status,
        is_builtin=is_builtin,
        published_at=utcnow() if document.status == "published" else None,
    )
    db.add(framework)
    db.flush()

    for control in document.controls:
        mapping = dict(control.mapping)
        mapping["weight"] = control.weight
        db.add(
            ComplianceControl(
                framework_id=framework.id,
                control_id=control.control_id,
                title=control.title,
                description=control.description,
                category=control.category,
                evidence_requirements=[item.model_dump(mode="json") for item in control.evidence_requirements],
                technical_checks=[item.model_dump(mode="json") for item in control.technical_checks],
                references=list(control.references),
                mapping=mapping,
            )
        )
    db.flush()
    return framework


def seed_builtin_frameworks(db: Session) -> SeedResult:
    """Idempotently seed the built-in catalogue keyed by (code, version)."""
    documents = load_builtin_documents()
    created = 0
    skipped = 0
    frameworks: list[dict[str, Any]] = []
    for document in documents:
        existing = db.execute(
            select(ComplianceFramework).where(
                ComplianceFramework.code == document.code,
                ComplianceFramework.version == document.version,
            )
        ).scalar_one_or_none()
        if existing is not None:
            skipped += 1
            frameworks.append(
                {
                    "id": str(existing.id),
                    "code": existing.code,
                    "version": existing.version,
                    "status": "existing",
                }
            )
            continue
        framework = persist_framework(db, document, is_builtin=True)
        created += 1
        frameworks.append(
            {
                "id": str(framework.id),
                "code": framework.code,
                "version": framework.version,
                "status": "created",
            }
        )
    db.commit()
    return SeedResult(
        created=created,
        skipped=skipped,
        total=len(documents),
        frameworks=frameworks,
    )


def get_framework(db: Session, identifier: str, version: str | None = None) -> ComplianceFramework:
    """Resolve a framework by UUID or code, optionally pinning a version."""
    try:
        parsed = uuid.UUID(identifier)
    except ValueError:
        parsed = None
    if parsed is not None:
        framework = db.get(ComplianceFramework, parsed)
        if framework is None:
            raise NotFound("Framework")
        return framework

    stmt = select(ComplianceFramework).where(ComplianceFramework.code == identifier)
    if version:
        stmt = stmt.where(ComplianceFramework.version == version)
    stmt = stmt.order_by(
        ComplianceFramework.published_at.desc().nullslast(),
        ComplianceFramework.created_at.desc(),
    ).limit(1)
    framework = db.execute(stmt).scalar_one_or_none()
    if framework is None:
        raise NotFound("Framework")
    return framework


def controls_for_framework(db: Session, framework_id: uuid.UUID) -> list[ComplianceControl]:
    return list(
        db.execute(
            select(ComplianceControl)
            .where(ComplianceControl.framework_id == framework_id)
            .order_by(ComplianceControl.control_id.asc())
        ).scalars()
    )


def controls_by_id(db: Session, framework_id: uuid.UUID) -> dict[uuid.UUID, ComplianceControl]:
    return {control.id: control for control in controls_for_framework(db, framework_id)}


def serialize_framework_summary(
    framework: ComplianceFramework,
    *,
    controls_count: int,
    technical_checks_count: int,
) -> FrameworkSummary:
    return FrameworkSummary(
        id=framework.id,
        code=framework.code,
        name=framework.name,
        version=framework.version,
        jurisdiction=framework.jurisdiction,
        authority=framework.authority,
        effective_date=framework.effective_date,
        source_url=framework.source_url,
        status=framework.status,
        is_builtin=framework.is_builtin,
        published_at=framework.published_at,
        controls_count=controls_count,
        technical_checks_count=technical_checks_count,
    )


def serialize_control(control: ComplianceControl) -> ControlOut:
    return ControlOut(
        id=control.id,
        control_id=control.control_id,
        title=control.title,
        description=control.description,
        category=control.category,
        weight=control_weight(control),
        references=list(control.references or []),
        evidence_requirements=list(control.evidence_requirements or []),
        technical_checks=list(control.technical_checks or []),
        mapping=dict(control.mapping or {}),
    )


def latest_assessments_by_framework(db: Session, org_id: uuid.UUID) -> dict[uuid.UUID, ComplianceAssessment]:
    """Return the most recent assessment per framework for an organization."""
    rows = list(
        db.execute(
            select(ComplianceAssessment)
            .where(ComplianceAssessment.org_id == org_id)
            .order_by(ComplianceAssessment.started_at.desc())
        ).scalars()
    )
    latest: dict[uuid.UUID, ComplianceAssessment] = {}
    for assessment in rows:
        latest.setdefault(assessment.framework_id, assessment)
    return latest


def create_assessment(
    db: Session,
    *,
    org: Organization,
    framework: ComplianceFramework,
    assessor: str | None,
) -> ComplianceAssessment:
    """Create an assessment and derive initial control statuses from live data."""
    if framework.status != "published":
        raise Conflict("Only published framework versions can be assessed")

    assessment = ComplianceAssessment(
        org_id=org.id,
        framework_id=framework.id,
        framework_version=framework.version,
        status="in_progress",
        score=0.0,
        assessor=assessor,
        started_at=utcnow(),
        gaps=[],
    )
    db.add(assessment)
    db.flush()

    signals = build_signals(db, org.id, org.settings)
    for control in controls_for_framework(db, framework.id):
        results = [evaluate_check(check, signals) for check in (control.technical_checks or [])]
        db.add(
            ComplianceControlStatus(
                assessment_id=assessment.id,
                control_id=control.id,
                status=derive_control_status(results),
                evidence_ids=[],
                notes=summarise_checks(results),
            )
        )
    db.flush()
    return assessment


def load_assessment(db: Session, org_id: uuid.UUID, assessment_id: uuid.UUID) -> ComplianceAssessment:
    assessment = db.get(ComplianceAssessment, assessment_id)
    if assessment is None or assessment.org_id != org_id:
        raise NotFound("Assessment")
    return assessment


def assessment_statuses(db: Session, assessment_id: uuid.UUID) -> list[ComplianceControlStatus]:
    return list(
        db.execute(
            select(ComplianceControlStatus)
            .where(ComplianceControlStatus.assessment_id == assessment_id)
            .order_by(ComplianceControlStatus.id.asc())
        ).scalars()
    )


def score_breakdown(
    statuses: list[ComplianceControlStatus],
    controls: dict[uuid.UUID, ComplianceControl],
) -> dict[str, Any]:
    counts = {"compliant": 0, "partial": 0, "non_compliant": 0, "not_applicable": 0, "not_assessed": 0}
    weighted_points = 0.0
    weighted_total = 0.0
    for status in statuses:
        key = status.status if status.status in counts else "not_assessed"
        counts[key] += 1
        if key == "not_applicable":
            continue
        control = controls.get(status.control_id)
        weight = control_weight(control) if control is not None else 2
        weighted_total += weight
        weighted_points += weight * STATUS_VALUES.get(key, 0.0)
    score = round((weighted_points / weighted_total) * 100, 1) if weighted_total else 0.0
    applicable = len(statuses) - counts["not_applicable"]
    return {
        "total_controls": len(statuses),
        "applicable_controls": applicable,
        "compliant": counts["compliant"],
        "partial": counts["partial"],
        "non_compliant": counts["non_compliant"],
        "not_applicable": counts["not_applicable"],
        "not_assessed": counts["not_assessed"],
        "weighted_points": round(weighted_points, 4),
        "weighted_total": round(weighted_total, 4),
        "score": score,
        "formula": SCORING_FORMULA,
    }


def serialize_control_status(
    status: ComplianceControlStatus,
    control: ComplianceControl | None,
) -> ControlStatusOut:
    return ControlStatusOut(
        id=status.id,
        control_id=status.control_id,
        control_code=control.control_id if control else "unknown",
        title=control.title if control else "Unknown control",
        category=control.category if control else "unknown",
        status=status.status,
        weight=control_weight(control) if control else 2,
        notes=status.notes,
        owner=status.owner,
        reviewed_at=status.reviewed_at,
        reviewed_by=status.reviewed_by,
        evidence_ids=list(status.evidence_ids or []),
        technical_checks=list(control.technical_checks or []) if control else [],
    )


def serialize_assessment_summary(
    assessment: ComplianceAssessment,
    framework: ComplianceFramework,
) -> AssessmentSummary:
    return AssessmentSummary(
        id=assessment.id,
        framework_id=assessment.framework_id,
        framework_code=framework.code,
        framework_name=framework.name,
        framework_version=assessment.framework_version,
        status=assessment.status,
        score=assessment.score,
        assessor=assessment.assessor,
        started_at=assessment.started_at,
        completed_at=assessment.completed_at,
        summary=assessment.summary,
        gaps_count=len(assessment.gaps or []),
        created_at=assessment.created_at,
    )


def serialize_assessment_detail(
    db: Session,
    assessment: ComplianceAssessment,
) -> dict[str, Any]:
    framework = db.get(ComplianceFramework, assessment.framework_id)
    if framework is None:
        raise NotFound("Framework")
    statuses = assessment_statuses(db, assessment.id)
    controls = controls_by_id(db, assessment.framework_id)
    ordered_statuses = sorted(
        statuses,
        key=lambda item: controls[item.control_id].control_id if item.control_id in controls else "",
    )
    breakdown = score_breakdown(statuses, controls)
    summary = serialize_assessment_summary(assessment, framework)
    return {
        **summary.model_dump(),
        "controls": [
            serialize_control_status(status, controls.get(status.control_id)).model_dump()
            for status in ordered_statuses
        ],
        "gaps": list(assessment.gaps or []),
        "score_breakdown": breakdown,
        "disclaimer": DISCLAIMER,
    }


def _severity(status: str, weight: int) -> str:
    if status == "non_compliant":
        return "high" if weight >= 3 else "medium"
    if status == "partial":
        return "medium" if weight >= 3 else "low"
    return "medium" if weight >= 3 else "low"


def _recommendation(status: str, missing: list[dict[str, Any]]) -> str:
    if missing:
        names = ", ".join(str(item.get("title") or item.get("key")) for item in missing[:4])
        return f"Remediate failing technical checks and attach supporting evidence: {names}."
    if status == "not_assessed":
        return "Run the assessment again after configuring evidence sources, or record a manual review with evidence."
    return "Attach current evidence and complete the missing technical configuration for this control."


def build_gaps(
    db: Session,
    org: Organization,
    framework: ComplianceFramework,
    statuses: list[ComplianceControlStatus],
    controls: dict[uuid.UUID, ComplianceControl],
) -> list[dict[str, Any]]:
    """Build the gap list from stored statuses plus fresh technical evidence."""
    signals = build_signals(db, org.id, org.settings)
    gaps: list[dict[str, Any]] = []
    for status in statuses:
        if status.status in {"compliant", "not_applicable"}:
            continue
        control = controls.get(status.control_id)
        if control is None:
            continue
        results = [evaluate_check(check, signals) for check in (control.technical_checks or [])]
        missing = [
            {
                "key": result["key"],
                "title": result["title"],
                "type": result["type"],
                "detail": result["detail"],
            }
            for result in results
            if result["applicable"] and not result["passed"]
        ]
        weight = control_weight(control)
        gaps.append(
            {
                "control_status_id": str(status.id),
                "control_id": str(control.id),
                "control_code": control.control_id,
                "title": control.title,
                "category": control.category,
                "status": status.status,
                "severity": _severity(status.status, weight),
                "weight": weight,
                "missing_checks": missing,
                "recommendation": _recommendation(status.status, missing),
            }
        )
    gaps.sort(
        key=lambda item: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[item["severity"]], item["control_code"])
    )
    return gaps


def complete_assessment(
    db: Session,
    *,
    org: Organization,
    assessment: ComplianceAssessment,
) -> dict[str, Any]:
    """Freeze an assessment: compute weighted score, gaps and summary."""
    if assessment.status == "completed":
        raise Conflict("The assessment is already completed")
    statuses = assessment_statuses(db, assessment.id)
    if not statuses:
        raise Conflict("The assessment has no controls to score")
    framework = db.get(ComplianceFramework, assessment.framework_id)
    if framework is None:
        raise NotFound("Framework")
    controls = controls_by_id(db, assessment.framework_id)
    breakdown = score_breakdown(statuses, controls)
    gaps = build_gaps(db, org, framework, statuses, controls)

    assessment.score = breakdown["score"]
    assessment.status = "completed"
    assessment.completed_at = utcnow()
    assessment.gaps = gaps
    assessment.summary = (
        f"Technical self-assessment of {framework.code} {framework.version}: "
        f"{breakdown['score']}% weighted compliance across {breakdown['total_controls']} controls "
        f"({breakdown['compliant']} compliant, {breakdown['partial']} partial, "
        f"{breakdown['non_compliant']} non-compliant, {breakdown['not_applicable']} not applicable, "
        f"{breakdown['not_assessed']} not assessed). {DISCLAIMER}"
    )
    db.flush()
    return breakdown


__all__ = [
    "FRAMEWORKS_DIR",
    "SCORING_FORMULA",
    "assessment_statuses",
    "build_gaps",
    "complete_assessment",
    "controls_by_id",
    "controls_for_framework",
    "create_assessment",
    "framework_checksum",
    "get_framework",
    "latest_assessments_by_framework",
    "load_assessment",
    "load_builtin_documents",
    "parse_framework_document",
    "persist_framework",
    "score_breakdown",
    "seed_builtin_frameworks",
    "serialize_assessment_detail",
    "serialize_assessment_summary",
    "serialize_control",
    "serialize_control_status",
    "serialize_framework_summary",
]


def framework_control_stats(db: Session, framework_ids: list[uuid.UUID]) -> dict[uuid.UUID, tuple[int, int]]:
    """Return {framework_id: (controls_count, technical_checks_count)} for list views."""
    if not framework_ids:
        return {}
    rows = db.execute(
        select(ComplianceControl.framework_id, ComplianceControl.technical_checks).where(
            ComplianceControl.framework_id.in_(framework_ids)
        )
    ).all()
    stats: dict[uuid.UUID, tuple[int, int]] = {}
    for framework_id, checks in rows:
        count, check_count = stats.get(framework_id, (0, 0))
        stats[framework_id] = (count + 1, check_count + len(checks or []))
    return stats


def count_controls(db: Session, framework_id: uuid.UUID) -> tuple[int, int]:
    rows = db.execute(
        select(
            func.count(), func.coalesce(func.sum(func.jsonb_array_length(ComplianceControl.technical_checks)), 0)
        ).where(ComplianceControl.framework_id == framework_id)
    ).one()
    return int(rows[0]), int(rows[1])
