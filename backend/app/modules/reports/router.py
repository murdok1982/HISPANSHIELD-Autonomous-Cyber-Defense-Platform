"""Report generation, retrieval and signed download API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import NotFound
from app.core.schemas import Page, paginate
from app.models.compliance import ComplianceFramework, Report
from app.modules.reports import service
from app.modules.reports.schemas import ReportDetail, ReportGenerateRequest, ReportSummary

router = APIRouter(prefix="/reports", tags=["Reports"])

_REPORT_SORTS = {
    "generated_at": Report.generated_at,
    "title": Report.title,
    "kind": Report.kind,
    "status": Report.status,
}


def _get_report(ctx: RequestContext, report_id: UUID) -> Report:
    report = ctx.db.get(Report, report_id)
    if report is None or report.org_id != ctx.org.id:
        raise NotFound("Report")
    return report


@router.post(
    "/generate",
    response_model=ReportDetail,
    status_code=201,
    summary="Generate a report from live platform data",
)
def generate_report(
    payload: ReportGenerateRequest,
    ctx: RequestContext = Depends(require_permission("report:generate")),
) -> dict:
    framework: ComplianceFramework | None = None
    if payload.framework_id is not None:
        framework = ctx.db.get(ComplianceFramework, payload.framework_id)
        if framework is None:
            raise NotFound("Framework")

    snapshot = service.collect_snapshot(
        ctx.db,
        ctx.org,
        payload.period_start,
        payload.period_end,
        framework_id=framework.id if framework else None,
    )
    title, content_md, content_html = service.build_content(payload.kind, snapshot)
    checksum = service.report_checksum(content_html, content_md)
    metadata = service.build_metadata(
        snapshot,
        kind=payload.kind,
        framework_code=framework.code if framework else None,
    )
    report = Report(
        org_id=ctx.org.id,
        kind=payload.kind,
        title=title,
        period_start=payload.period_start,
        period_end=payload.period_end,
        status="generated",
        format="html",
        content_md=content_md,
        content_html=content_html,
        generated_by=ctx.actor_email or ctx.actor_id,
        generated_at=utcnow(),
        checksum=checksum,
        metadata_json=metadata,
        framework_id=framework.id if framework else None,
    )
    ctx.db.add(report)
    ctx.db.flush()
    ctx.audit(
        action="report.generate",
        resource_type="report",
        resource_id=str(report.id),
        payload={
            "kind": report.kind,
            "checksum": checksum,
            "period_start": payload.period_start.isoformat(),
            "period_end": payload.period_end.isoformat(),
            "framework_code": framework.code if framework else None,
        },
    )
    ctx.db.commit()
    return service.serialize_report_detail(report)


@router.get("", response_model=Page[ReportSummary], summary="List generated reports")
def list_reports(
    ctx: RequestContext = Depends(require_permission("report:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    kind: str | None = Query(default=None, pattern="^(executive|technical|regulatory|incident)$"),
    status: str | None = Query(default=None, max_length=30),
    framework_id: UUID | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    from_date: datetime | None = Query(default=None),
    to_date: datetime | None = Query(default=None),
    sort: str | None = Query(default=None, max_length=40),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[ReportSummary]:
    stmt = select(Report).where(Report.org_id == ctx.org.id)
    if kind:
        stmt = stmt.where(Report.kind == kind)
    if status:
        stmt = stmt.where(Report.status == status)
    if framework_id:
        stmt = stmt.where(Report.framework_id == framework_id)
    if q:
        stmt = stmt.where(func.lower(Report.title).like(f"%{q.lower()}%"))
    if from_date:
        stmt = stmt.where(Report.generated_at >= from_date)
    if to_date:
        stmt = stmt.where(Report.generated_at <= to_date)

    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    column = _REPORT_SORTS.get(sort or "generated_at", Report.generated_at)
    ordering = column.desc() if order == "desc" else column.asc()
    rows = list(
        ctx.db.execute(
            stmt.order_by(ordering, Report.id.desc()).offset((page - 1) * page_size).limit(page_size)
        ).scalars()
    )
    items = [ReportSummary.model_validate(service.serialize_report_summary(row)) for row in rows]
    return Page[ReportSummary](**paginate(items, total, page, page_size))


@router.get("/{report_id}", response_model=ReportDetail, summary="Report detail with rendered content")
def get_report(
    report_id: UUID,
    ctx: RequestContext = Depends(require_permission("report:read")),
) -> dict:
    report = _get_report(ctx, report_id)
    return service.serialize_report_detail(report)


@router.get("/{report_id}/download", summary="Download a report as HTML or Markdown attachment")
def download_report(
    report_id: UUID,
    ctx: RequestContext = Depends(require_permission("report:read")),
    format: Literal["html", "md"] = Query(default="html"),
) -> Response:
    report = _get_report(ctx, report_id)
    extension = "html" if format == "html" else "md"
    filename = service.safe_filename(report.id, report.kind, report.generated_at, extension)
    if format == "html":
        body = report.content_html
        media_type = "text/html; charset=utf-8"
        security_headers = {
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'"
            ),
        }
    else:
        body = report.content_md
        media_type = "text/markdown; charset=utf-8"
        security_headers = {}
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "X-Report-Checksum": report.checksum,
        **security_headers,
    }
    return Response(content=body, media_type=media_type, headers=headers)


@router.delete(
    "/{report_id}",
    status_code=204,
    response_class=Response,
    summary="Delete a generated report",
)
def delete_report(
    report_id: UUID,
    ctx: RequestContext = Depends(require_permission("report:generate")),
) -> Response:
    report = _get_report(ctx, report_id)
    ctx.audit(
        action="report.delete",
        resource_type="report",
        resource_id=str(report.id),
        payload={"kind": report.kind, "checksum": report.checksum, "title": report.title},
    )
    ctx.db.delete(report)
    ctx.db.commit()
    return Response(status_code=204, headers={"X-Report-Disclaimer": "technical-self-assessment"})


__all__ = ["router"]
