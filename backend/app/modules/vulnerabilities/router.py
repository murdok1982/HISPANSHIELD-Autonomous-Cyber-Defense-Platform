"""Vulnerability management API with deterministic prioritisation."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy import case, func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import PolicyDenied
from app.core.idempotency import execute as execute_idempotent
from app.core.schemas import Page, paginate
from app.models.assets import Vulnerability
from app.modules.vulnerabilities import importers, service
from app.modules.vulnerabilities.schemas import (
    CVEImportRequest,
    CVEImportResult,
    EPSSImportRequest,
    EPSSImportResult,
    KEVImportRequest,
    KEVImportResult,
    ScannerImportRequest,
    ScannerImportResult,
    VulnerabilityCreate,
    VulnerabilityDetailOut,
    VulnerabilityOut,
    VulnerabilityPatch,
    VulnerabilitySummaryOut,
)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

SEVERITY_RANK = case(
    (Vulnerability.severity == "critical", 5),
    (Vulnerability.severity == "high", 4),
    (Vulnerability.severity == "medium", 3),
    (Vulnerability.severity == "low", 2),
    else_=1,
)

VULN_SORTS = {
    "priority_score": Vulnerability.priority_score,
    "cvss_score": Vulnerability.cvss_score,
    "epss_score": Vulnerability.epss_score,
    "severity": SEVERITY_RANK,
    "first_seen": Vulnerability.first_seen,
    "last_seen": Vulnerability.last_seen,
    "due_at": Vulnerability.due_at,
    "status": Vulnerability.status,
}


@router.get("", response_model=Page[VulnerabilityOut], summary="List vulnerabilities ordered by priority")
def list_vulnerabilities(
    ctx: RequestContext = Depends(require_permission("vuln:read")),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    status: str | None = Query(default=None, pattern="^(open|reopened|mitigated|accepted|false_positive)$"),
    kev: bool | None = Query(default=None),
    asset_id: UUID | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="priority_score", pattern="^(" + "|".join(VULN_SORTS) + ")$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[VulnerabilityOut]:
    stmt = select(Vulnerability).where(Vulnerability.org_id == ctx.org.id)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    if status:
        stmt = stmt.where(Vulnerability.status == status)
    if kev is not None:
        stmt = stmt.where(Vulnerability.kev.is_(kev))
    if asset_id:
        stmt = stmt.where(Vulnerability.asset_id == asset_id)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Vulnerability.title).like(needle),
                func.lower(Vulnerability.cve_id).like(needle),
                func.lower(Vulnerability.description).like(needle),
            )
        )
    column = VULN_SORTS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), Vulnerability.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[VulnerabilityOut](
        **paginate([VulnerabilityOut.model_validate(row) for row in rows], int(total), page, page_size)
    )


@router.post(
    "/import",
    response_model=ScannerImportResult,
    summary="Import a Nessus, OpenVAS or Trivy report (idempotent by fingerprint)",
)
def import_scanner_report(
    payload: ScannerImportRequest,
    response: Response,
    ctx: RequestContext = Depends(require_permission("vuln:import")),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> ScannerImportResult:
    def run() -> ScannerImportResult:
        data = importers.import_scanner_report(
            ctx.db,
            ctx.org.id,
            format=payload.format,
            content=payload.content,
            asset_key=payload.asset_key,
        )
        ctx.audit(
            action="vuln.import.scanner",
            resource_type="vulnerability",
            payload={
                "format": data["format"],
                "total": data["total"],
                "created": data["created"],
                "updated": data["updated"],
                "skipped": data["skipped"],
                "errors": len(data["errors"]),
            },
        )
        ctx.db.commit()
        return ScannerImportResult(**data)

    body, replayed = execute_idempotent(
        ctx,
        idempotency_key,
        method="POST",
        path="/api/v1/vulnerabilities/import",
        payload=payload,
        fn=run,
    )
    if replayed:
        response.headers["Idempotent-Replayed"] = "true"
    return body  # type: ignore[return-value]


@router.post("/import/cve", response_model=CVEImportResult, summary="Upsert CVE catalogue and create asset findings")
def import_cve(
    payload: CVEImportRequest,
    response: Response,
    ctx: RequestContext = Depends(require_permission("vuln:import")),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> CVEImportResult:
    def run() -> CVEImportResult:
        result = service.import_cve(ctx.db, ctx.org.id, payload)
        ctx.audit(
            action="vuln.import.cve",
            resource_type="cve_catalog",
            payload={
                "catalog_created": result.catalog_created,
                "catalog_updated": result.catalog_updated,
                "vulnerabilities_created": result.vulnerabilities_created,
                "vulnerabilities_updated": result.vulnerabilities_updated,
                "errors": len(result.errors),
            },
        )
        ctx.db.commit()
        return result

    body, replayed = execute_idempotent(
        ctx,
        idempotency_key,
        method="POST",
        path="/api/v1/vulnerabilities/import/cve",
        payload=payload,
        fn=run,
    )
    if replayed:
        response.headers["Idempotent-Replayed"] = "true"
    return body  # type: ignore[return-value]


@router.post("/import/kev", response_model=KEVImportResult, summary="Apply CISA KEV entries")
def import_kev(
    payload: KEVImportRequest, ctx: RequestContext = Depends(require_permission("vuln:import"))
) -> KEVImportResult:
    result = service.import_kev(ctx.db, ctx.org.id, payload)
    ctx.audit(
        action="vuln.import.kev",
        resource_type="cve_catalog",
        payload={
            "catalog_created": result.catalog_created,
            "catalog_marked": result.catalog_marked,
            "vulnerabilities_marked": result.vulnerabilities_marked,
            "unknown_cves": len(result.unknown_cves),
        },
    )
    ctx.db.commit()
    return result


@router.post("/import/epss", response_model=EPSSImportResult, summary="Apply EPSS scores and recalculate priority")
def import_epss(
    payload: EPSSImportRequest, ctx: RequestContext = Depends(require_permission("vuln:import"))
) -> EPSSImportResult:
    result = service.import_epss(ctx.db, ctx.org.id, payload)
    ctx.audit(
        action="vuln.import.epss",
        resource_type="cve_catalog",
        payload={
            "parsed": result.parsed,
            "catalog_updated": result.catalog_updated,
            "vulnerabilities_updated": result.vulnerabilities_updated,
            "errors": len(result.errors),
        },
    )
    ctx.db.commit()
    return result


@router.get("/summary", response_model=VulnerabilitySummaryOut, summary="Vulnerability posture summary")
def vulnerability_summary(ctx: RequestContext = Depends(require_permission("vuln:read"))) -> VulnerabilitySummaryOut:
    return service.summary(ctx.db, ctx.org.id)


@router.post("", response_model=VulnerabilityOut, status_code=201, summary="Create a vulnerability")
def create_vulnerability(
    payload: VulnerabilityCreate, ctx: RequestContext = Depends(require_permission("vuln:write"))
) -> Vulnerability:
    vulnerability = service.create_vulnerability(ctx.db, ctx.org.id, payload)
    ctx.audit(
        action="vuln.create",
        resource_type="vulnerability",
        resource_id=str(vulnerability.id),
        payload={
            "cve_id": vulnerability.cve_id,
            "asset_id": str(vulnerability.asset_id) if vulnerability.asset_id else None,
            "severity": vulnerability.severity,
            "priority_score": vulnerability.priority_score,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(vulnerability)
    return vulnerability


@router.get("/{vulnerability_id}", response_model=VulnerabilityDetailOut, summary="Read a vulnerability")
def read_vulnerability(
    vulnerability_id: UUID, ctx: RequestContext = Depends(require_permission("vuln:read"))
) -> VulnerabilityDetailOut:
    vulnerability = service.get_vulnerability(ctx.db, ctx.org.id, vulnerability_id)
    return service.detail(ctx.db, vulnerability)


@router.patch(
    "/{vulnerability_id}", response_model=VulnerabilityOut, summary="Update lifecycle or prioritisation inputs"
)
def update_vulnerability(
    vulnerability_id: UUID,
    payload: VulnerabilityPatch,
    ctx: RequestContext = Depends(require_permission("vuln:write")),
) -> Vulnerability:
    vulnerability = service.get_vulnerability(ctx.db, ctx.org.id, vulnerability_id)
    changes = payload.model_dump(exclude_unset=True)
    if "status" in changes and changes["status"] is not None:
        service.validate_transition(vulnerability.status, changes["status"])
        vulnerability.status = changes["status"]
    if "severity" in changes and changes["severity"] is not None:
        vulnerability.severity = changes["severity"]
    if "exposure" in changes and changes["exposure"] is not None:
        vulnerability.exposure = changes["exposure"]
    if "exploitable" in changes and changes["exploitable"] is not None:
        vulnerability.exploitable = changes["exploitable"]
    if "kev" in changes and changes["kev"] is not None:
        vulnerability.kev = changes["kev"]
    if "due_at" in changes:
        vulnerability.due_at = changes["due_at"]
    if "remediation" in changes:
        vulnerability.remediation = changes["remediation"]
    if "metadata" in changes and changes["metadata"] is not None:
        vulnerability.metadata_json = changes["metadata"]
    if {"exposure", "exploitable", "kev"} & set(changes):
        service.recalculate_vulnerability(ctx.db, ctx.org.id, vulnerability)
    vulnerability.last_seen = utcnow()
    ctx.audit(
        action="vuln.update",
        resource_type="vulnerability",
        resource_id=str(vulnerability.id),
        payload={"fields": sorted(changes.keys()), "status": vulnerability.status},
    )
    ctx.db.commit()
    ctx.db.refresh(vulnerability)
    return vulnerability


@router.delete("/{vulnerability_id}", status_code=204, response_class=Response, summary="Delete a vulnerability")
def delete_vulnerability(
    vulnerability_id: UUID, ctx: RequestContext = Depends(require_permission("vuln:write"))
) -> Response:
    vulnerability = service.get_vulnerability(ctx.db, ctx.org.id, vulnerability_id)
    ctx.audit(
        action="vuln.delete",
        resource_type="vulnerability",
        resource_id=str(vulnerability.id),
        payload={"cve_id": vulnerability.cve_id, "severity": vulnerability.severity},
    )
    ctx.db.delete(vulnerability)
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/{vulnerability_id}/recalculate", response_model=VulnerabilityOut, summary="Recompute priority")
def recalculate(
    vulnerability_id: UUID, ctx: RequestContext = Depends(require_permission("vuln:write"))
) -> Vulnerability:
    vulnerability = service.get_vulnerability(ctx.db, ctx.org.id, vulnerability_id)
    if vulnerability.status in {"accepted", "false_positive"}:
        raise PolicyDenied(
            "Accepted and false-positive vulnerabilities are excluded from prioritisation; "
            "reopen the finding before recalculating."
        )
    service.recalculate_vulnerability(ctx.db, ctx.org.id, vulnerability)
    ctx.audit(
        action="vuln.recalculate",
        resource_type="vulnerability",
        resource_id=str(vulnerability.id),
        payload={"priority_score": vulnerability.priority_score},
    )
    ctx.db.commit()
    ctx.db.refresh(vulnerability)
    return vulnerability


__all__ = ["router"]
