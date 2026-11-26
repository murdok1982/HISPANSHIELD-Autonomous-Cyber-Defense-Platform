"""Compliance framework catalogue, assessments, gaps and posture API."""

from __future__ import annotations

from collections import Counter
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, Forbidden, NotFound
from app.core.schemas import Page, paginate
from app.models.compliance import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceControlStatus,
    ComplianceFramework,
    ControlEvidenceLink,
)
from app.models.incidents import Evidence
from app.modules.compliance import service
from app.modules.compliance.schemas import (
    DISCLAIMER,
    AssessmentCreate,
    AssessmentDetail,
    AssessmentSummary,
    ComplianceSummary,
    ControlOut,
    ControlStatusOut,
    ControlStatusPatch,
    FrameworkDetail,
    FrameworkImportRequest,
    FrameworkImportResult,
    FrameworkPosture,
    FrameworkSummary,
    GapAnalysis,
    GapItem,
)

router = APIRouter(prefix="/compliance", tags=["Compliance"])

_FRAMEWORK_SORTS = {
    "code": ComplianceFramework.code,
    "name": ComplianceFramework.name,
    "version": ComplianceFramework.version,
    "published_at": ComplianceFramework.published_at,
    "created_at": ComplianceFramework.created_at,
}


def _latest_per_code_subquery():
    return (
        select(ComplianceFramework.id)
        .distinct(ComplianceFramework.code)
        .order_by(
            ComplianceFramework.code,
            ComplianceFramework.published_at.desc().nullslast(),
            ComplianceFramework.created_at.desc(),
        )
    )


@router.get("/frameworks", response_model=Page[FrameworkSummary], summary="List catalogue frameworks")
def list_frameworks(
    ctx: RequestContext = Depends(require_permission("compliance:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    q: str | None = Query(default=None, max_length=120),
    code: str | None = Query(default=None, max_length=40),
    jurisdiction: str | None = Query(default=None, max_length=80),
    status: str | None = Query(default=None, pattern="^(published|draft|retired)$"),
    all_versions: bool = Query(default=False),
    sort: str | None = Query(default=None, max_length=40),
    order: str = Query(default="asc", pattern="^(asc|desc)$"),
) -> Page[FrameworkSummary]:
    stmt = select(ComplianceFramework)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(ComplianceFramework.code).like(needle),
                func.lower(ComplianceFramework.name).like(needle),
                func.lower(ComplianceFramework.authority).like(needle),
            )
        )
    if code:
        stmt = stmt.where(ComplianceFramework.code == code)
    if jurisdiction:
        stmt = stmt.where(ComplianceFramework.jurisdiction == jurisdiction)
    if status:
        stmt = stmt.where(ComplianceFramework.status == status)
    if not all_versions:
        stmt = stmt.where(ComplianceFramework.id.in_(_latest_per_code_subquery()))

    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    column = _FRAMEWORK_SORTS.get(sort or "code", ComplianceFramework.code)
    ordering = column.desc() if order == "desc" else column.asc()
    rows = list(
        ctx.db.execute(
            stmt.order_by(ordering, ComplianceFramework.created_at.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).scalars()
    )
    stats = service.framework_control_stats(ctx.db, [row.id for row in rows])
    items = [
        service.serialize_framework_summary(
            row,
            controls_count=stats.get(row.id, (0, 0))[0],
            technical_checks_count=stats.get(row.id, (0, 0))[1],
        )
        for row in rows
    ]
    return Page[FrameworkSummary](**paginate(items, total, page, page_size))


@router.get(
    "/frameworks/{code}/versions",
    response_model=list[FrameworkSummary],
    summary="List every stored version of a framework code",
)
def framework_versions(
    code: str,
    ctx: RequestContext = Depends(require_permission("compliance:read")),
) -> list[FrameworkSummary]:
    rows = list(
        ctx.db.execute(
            select(ComplianceFramework)
            .where(ComplianceFramework.code == code)
            .order_by(ComplianceFramework.published_at.desc().nullslast(), ComplianceFramework.created_at.desc())
        ).scalars()
    )
    if not rows:
        raise NotFound("Framework")
    stats = service.framework_control_stats(ctx.db, [row.id for row in rows])
    return [
        service.serialize_framework_summary(
            row,
            controls_count=stats.get(row.id, (0, 0))[0],
            technical_checks_count=stats.get(row.id, (0, 0))[1],
        )
        for row in rows
    ]


@router.post(
    "/frameworks/import",
    response_model=FrameworkImportResult,
    status_code=201,
    summary="Import a versioned framework (YAML or JSON, platform administrators only)",
)
def import_framework(
    payload: FrameworkImportRequest,
    response: Response,
    ctx: RequestContext = Depends(require_permission("compliance:write")),
) -> FrameworkImportResult:
    if not (ctx.user and ctx.user.is_platform_admin):
        raise Forbidden("Only platform administrators can import framework catalogues")

    document, resolved_format = service.parse_framework_document(payload.content, payload.format)
    checksum = service.framework_checksum(document)
    existing = ctx.db.execute(
        select(ComplianceFramework).where(
            ComplianceFramework.code == document.code,
            ComplianceFramework.version == document.version,
        )
    ).scalar_one_or_none()
    if existing is not None:
        stats = service.count_controls(ctx.db, existing.id)
        ctx.audit(
            action="compliance.framework.import",
            resource_type="compliance_framework",
            resource_id=str(existing.id),
            payload={
                "code": document.code,
                "version": document.version,
                "checksum": checksum,
                "created": False,
                "controls": stats[0],
            },
        )
        ctx.db.commit()
        response.status_code = 200
        return FrameworkImportResult(
            framework=service.serialize_framework_summary(
                existing, controls_count=stats[0], technical_checks_count=stats[1]
            ),
            created=False,
            checksum=checksum,
            format=resolved_format,
            controls_imported=stats[0],
        )

    framework = service.persist_framework(ctx.db, document, is_builtin=False)
    stats = service.count_controls(ctx.db, framework.id)
    ctx.audit(
        action="compliance.framework.import",
        resource_type="compliance_framework",
        resource_id=str(framework.id),
        payload={
            "code": framework.code,
            "version": framework.version,
            "checksum": checksum,
            "created": True,
            "controls": stats[0],
        },
    )
    ctx.db.commit()
    result = FrameworkImportResult(
        framework=service.serialize_framework_summary(
            framework, controls_count=stats[0], technical_checks_count=stats[1]
        ),
        created=True,
        checksum=checksum,
        format=resolved_format,
        controls_imported=stats[0],
    )
    return result


@router.get("/frameworks/{identifier}", response_model=FrameworkDetail, summary="Framework detail with controls")
def framework_detail(
    identifier: str,
    ctx: RequestContext = Depends(require_permission("compliance:read")),
    version: str | None = Query(default=None, max_length=40),
) -> FrameworkDetail:
    framework = service.get_framework(ctx.db, identifier, version)
    controls = service.controls_for_framework(ctx.db, framework.id)
    summary = service.serialize_framework_summary(
        framework,
        controls_count=len(controls),
        technical_checks_count=sum(len(control.technical_checks or []) for control in controls),
    )
    return FrameworkDetail(
        **summary.model_dump(),
        description=framework.description,
        controls=[ControlOut(**service.serialize_control(control).model_dump()) for control in controls],
    )


@router.post(
    "/assessments",
    response_model=AssessmentDetail,
    status_code=201,
    summary="Create an assessment and derive control statuses from live evidence",
)
def create_assessment(
    payload: AssessmentCreate, ctx: RequestContext = Depends(require_permission("compliance:assess"))
) -> dict:
    if payload.framework_id is not None:
        framework = ctx.db.get(ComplianceFramework, payload.framework_id)
        if framework is None:
            raise NotFound("Framework")
    else:
        assert payload.code is not None
        framework = service.get_framework(ctx.db, payload.code, payload.version)
    if payload.version and payload.framework_id is not None and framework.version != payload.version:
        raise NotFound("Framework")

    assessment = service.create_assessment(
        ctx.db,
        org=ctx.org,
        framework=framework,
        assessor=payload.assessor or ctx.actor_email or ctx.actor_id,
    )
    ctx.audit(
        action="compliance.assessment.create",
        resource_type="compliance_assessment",
        resource_id=str(assessment.id),
        payload={
            "framework_code": framework.code,
            "framework_version": framework.version,
        },
    )
    ctx.db.commit()
    return service.serialize_assessment_detail(ctx.db, assessment)


@router.get("/assessments", response_model=Page[AssessmentSummary], summary="List organization assessments")
def list_assessments(
    ctx: RequestContext = Depends(require_permission("compliance:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    status: str | None = Query(default=None, pattern="^(in_progress|completed|archived)$"),
    framework_id: UUID | None = Query(default=None),
    code: str | None = Query(default=None, max_length=40),
    q: str | None = Query(default=None, max_length=120),
) -> Page[AssessmentSummary]:
    stmt = (
        select(ComplianceAssessment, ComplianceFramework)
        .join(ComplianceFramework, ComplianceFramework.id == ComplianceAssessment.framework_id)
        .where(ComplianceAssessment.org_id == ctx.org.id)
    )
    if status:
        stmt = stmt.where(ComplianceAssessment.status == status)
    if framework_id:
        stmt = stmt.where(ComplianceAssessment.framework_id == framework_id)
    if code:
        stmt = stmt.where(ComplianceFramework.code == code)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(ComplianceFramework.code).like(needle),
                func.lower(ComplianceFramework.name).like(needle),
            )
        )
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = ctx.db.execute(
        stmt.order_by(ComplianceAssessment.started_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    items = [service.serialize_assessment_summary(assessment, framework) for assessment, framework in rows]
    return Page[AssessmentSummary](**paginate(items, total, page, page_size))


@router.get("/assessments/{assessment_id}", response_model=AssessmentDetail, summary="Assessment detail")
def assessment_detail(
    assessment_id: UUID,
    ctx: RequestContext = Depends(require_permission("compliance:read")),
) -> dict:
    assessment = service.load_assessment(ctx.db, ctx.org.id, assessment_id)
    return service.serialize_assessment_detail(ctx.db, assessment)


@router.patch(
    "/assessments/{assessment_id}/controls/{control_status_id}",
    response_model=ControlStatusOut,
    summary="Update a control status, notes, owner and linked evidence",
)
def update_control_status(
    assessment_id: UUID,
    control_status_id: UUID,
    payload: ControlStatusPatch,
    ctx: RequestContext = Depends(require_permission("compliance:assess")),
) -> ControlStatusOut:
    assessment = service.load_assessment(ctx.db, ctx.org.id, assessment_id)
    if assessment.status == "completed":
        raise Conflict("Completed assessments are locked; create a new assessment to re-evaluate")

    status_row = ctx.db.get(ComplianceControlStatus, control_status_id)
    if status_row is None or status_row.assessment_id != assessment.id:
        raise NotFound("Control status")
    control = ctx.db.get(ComplianceControl, status_row.control_id)
    if control is None or control.framework_id != assessment.framework_id:
        raise NotFound("Control")

    if payload.evidence_ids is not None:
        requested = list(dict.fromkeys(payload.evidence_ids))
        found = set(
            ctx.db.execute(
                select(Evidence.id).where(Evidence.id.in_(requested), Evidence.org_id == ctx.org.id)
            ).scalars()
        )
        if len(found) != len(requested):
            # Cross-tenant evidence must not be distinguishable from missing evidence.
            raise NotFound("Evidence")
        status_row.evidence_ids = [str(evidence_id) for evidence_id in requested]

        ctx.db.execute(
            ControlEvidenceLink.__table__.delete().where(
                ControlEvidenceLink.control_status_id == status_row.id,
                ControlEvidenceLink.org_id == ctx.org.id,
            )
        )
        for evidence_id in requested:
            ctx.db.add(
                ControlEvidenceLink(
                    org_id=ctx.org.id,
                    control_status_id=status_row.id,
                    evidence_id=evidence_id,
                    linked_by=ctx.actor_id,
                    verified=False,
                )
            )

    if payload.status is not None:
        status_row.status = payload.status
    if payload.notes is not None:
        status_row.notes = payload.notes
    if payload.owner is not None:
        status_row.owner = payload.owner
    status_row.reviewed_at = utcnow()
    status_row.reviewed_by = ctx.actor_id or ctx.actor_email

    ctx.audit(
        action="compliance.control.update",
        resource_type="compliance_control_status",
        resource_id=str(status_row.id),
        payload={
            "assessment_id": str(assessment.id),
            "control_code": control.control_id,
            "status": status_row.status,
            "owner": status_row.owner,
            "evidence_count": len(status_row.evidence_ids or []),
        },
    )
    ctx.db.commit()
    return service.serialize_control_status(status_row, control)


@router.post(
    "/assessments/{assessment_id}/complete",
    response_model=AssessmentDetail,
    summary="Complete an assessment with weighted score and gap snapshot",
)
def complete_assessment(
    assessment_id: UUID,
    ctx: RequestContext = Depends(require_permission("compliance:assess")),
) -> dict:
    assessment = service.load_assessment(ctx.db, ctx.org.id, assessment_id)
    breakdown = service.complete_assessment(ctx.db, org=ctx.org, assessment=assessment)
    ctx.audit(
        action="compliance.assessment.complete",
        resource_type="compliance_assessment",
        resource_id=str(assessment.id),
        payload={
            "score": breakdown["score"],
            "gaps": len(assessment.gaps or []),
            "controls": breakdown["total_controls"],
        },
    )
    ctx.db.commit()
    return service.serialize_assessment_detail(ctx.db, assessment)


@router.get(
    "/assessments/{assessment_id}/gap-analysis",
    response_model=GapAnalysis,
    summary="Gap analysis with current technical evidence",
)
def gap_analysis(
    assessment_id: UUID,
    ctx: RequestContext = Depends(require_permission("compliance:read")),
) -> GapAnalysis:
    assessment = service.load_assessment(ctx.db, ctx.org.id, assessment_id)
    framework = ctx.db.get(ComplianceFramework, assessment.framework_id)
    if framework is None:
        raise NotFound("Framework")
    controls = service.controls_by_id(ctx.db, assessment.framework_id)
    statuses = service.assessment_statuses(ctx.db, assessment.id)
    breakdown = service.score_breakdown(statuses, controls)
    if assessment.status == "completed" and assessment.gaps:
        raw_gaps = assessment.gaps
    else:
        raw_gaps = service.build_gaps(ctx.db, ctx.org, framework, statuses, controls)
    gaps = [GapItem.model_validate(gap) for gap in raw_gaps]
    severity_counter = Counter(gap.severity for gap in gaps)
    return GapAnalysis(
        assessment_id=assessment.id,
        framework_code=framework.code,
        framework_version=assessment.framework_version,
        status=assessment.status,
        score=breakdown["score"],
        gap_count=len(gaps),
        gaps_by_severity=dict(severity_counter),
        gaps=gaps,
        generated_at=utcnow(),
        disclaimer=DISCLAIMER,
    )


@router.get("/summary", response_model=ComplianceSummary, summary="Organization posture per framework")
def compliance_summary(ctx: RequestContext = Depends(require_permission("compliance:read"))) -> ComplianceSummary:
    frameworks = list(
        ctx.db.execute(
            select(ComplianceFramework)
            .where(ComplianceFramework.status == "published", ComplianceFramework.id.in_(_latest_per_code_subquery()))
            .order_by(ComplianceFramework.code.asc())
        ).scalars()
    )
    latest = service.latest_assessments_by_framework(ctx.db, ctx.org.id)
    postures: list[FrameworkPosture] = []
    scores: list[float] = []
    assessed = 0

    for framework in frameworks:
        assessment = latest.get(framework.id)
        posture = FrameworkPosture(
            framework_id=framework.id,
            framework_code=framework.code,
            framework_name=framework.name,
            framework_version=framework.version,
        )
        if assessment is not None:
            assessed += 1
            statuses = service.assessment_statuses(ctx.db, assessment.id)
            counts = Counter(status.status for status in statuses)
            posture = FrameworkPosture(
                framework_id=framework.id,
                framework_code=framework.code,
                framework_name=framework.name,
                framework_version=framework.version,
                assessment_id=assessment.id,
                assessment_status=assessment.status,
                score=assessment.score,
                completed_at=assessment.completed_at,
                controls_total=len(statuses),
                compliant=counts.get("compliant", 0),
                partial=counts.get("partial", 0),
                non_compliant=counts.get("non_compliant", 0),
                not_applicable=counts.get("not_applicable", 0),
                not_assessed=counts.get("not_assessed", 0),
            )
            if assessment.status == "completed":
                scores.append(assessment.score)
        postures.append(posture)

    return ComplianceSummary(
        organization_id=ctx.org.id,
        organization_name=ctx.org.name,
        generated_at=utcnow(),
        frameworks=postures,
        assessed_frameworks=assessed,
        average_score=round(sum(scores) / len(scores), 1) if scores else None,
        disclaimer=DISCLAIMER,
    )
