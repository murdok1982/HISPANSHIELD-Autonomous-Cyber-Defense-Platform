"""Digital forensics logic: evidence hashing, custody and bounded ZIP export.

Evidence files live outside the web root under ``HS_EVIDENCE_DIR`` (default
``backend/data/evidence``). Every path is resolved and must remain inside that
root; absolute paths supplied in the database are only accepted when they do.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import zipfile
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import redact
from app.core.db import utcnow
from app.core.deps import RequestContext
from app.core.errors import NotFound
from app.models.events import Alert
from app.models.incidents import Evidence, Incident, IncidentTimeline, PlaybookExecution, Remediation

EVIDENCE_ROOT = Path(
    os.environ.get(
        "HS_EVIDENCE_DIR",
        str(Path(__file__).resolve().parents[3] / "data" / "evidence"),
    )
).resolve()

MAX_EXPORT_BYTES = 100 * 1024 * 1024
HASH_CHUNK_SIZE = 1024 * 1024
MAX_EXPORT_TIMELINE = 500
MAX_EXPORT_ALERTS = 200
_UNSAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(value: str | None, fallback: str, max_length: int = 80) -> str:
    """Sanitize any user/database-provided name used inside a ZIP archive."""
    cleaned = _UNSAFE_FILENAME_RE.sub("_", (value or "").strip()).strip("._")
    cleaned = cleaned[:max_length]
    if not cleaned or cleaned in {".", ".."}:
        return fallback
    return cleaned


def resolve_evidence_path(storage_path: str | None) -> Path | None:
    """Resolve a stored path, rejecting traversal outside the evidence root."""
    if not storage_path or "\x00" in storage_path or len(storage_path) > 500:
        return None
    candidate = Path(storage_path)
    if not candidate.is_absolute():
        candidate = EVIDENCE_ROOT / candidate
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    if resolved != EVIDENCE_ROOT and EVIDENCE_ROOT not in resolved.parents:
        return None
    return resolved


def hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def get_incident(db: Session, org_id: UUID, incident_id: UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.org_id != org_id:
        raise NotFound("Case")
    return incident


def get_evidence(db: Session, org_id: UUID, evidence_id: UUID) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.org_id != org_id:
        raise NotFound("Evidence")
    return evidence


def evidence_file_state(evidence: Evidence) -> tuple[Path | None, str | None]:
    """Return ``(path, error)`` without ever exposing the resolved server path."""
    path = resolve_evidence_path(evidence.storage_path)
    if path is None:
        return None, "path_outside_evidence_root"
    if not path.is_file():
        return None, "file_missing"
    return path, None


def evidence_view(evidence: Evidence) -> dict[str, Any]:
    _path, error = evidence_file_state(evidence)
    return {
        "id": evidence.id,
        "incident_id": evidence.incident_id,
        "kind": evidence.kind,
        "title": evidence.title,
        "description": evidence.description,
        "sha256": evidence.sha256,
        "content_type": evidence.content_type,
        "size_bytes": evidence.size_bytes,
        "collected_by": evidence.collected_by,
        "collected_at": evidence.collected_at,
        "sealed": evidence.sealed,
        "chain_length": len(evidence.chain_of_custody or []),
        "has_file": error is None,
    }


def verify_evidence_hash(db: Session, ctx: RequestContext, evidence: Evidence) -> dict[str, Any]:
    path, error = evidence_file_state(evidence)
    verified_at = utcnow()
    if path is None:
        computed = None
        matched = False
        status = error or "file_missing"
        size = None
    else:
        computed, size = hash_file(path)
        matched = computed == evidence.sha256
        status = "match" if matched else "mismatch"

    custody = list(evidence.chain_of_custody or [])
    custody.append(
        {
            "at": verified_at.isoformat(),
            "action": "verify_hash",
            "actor": ctx.actor_email or ctx.actor_id or "system",
            "result": status,
            "expected_sha256": evidence.sha256,
            "computed_sha256": computed,
        }
    )
    evidence.chain_of_custody = custody
    ctx.audit(
        action="forensics.evidence.verify_hash",
        resource_type="evidence",
        resource_id=str(evidence.id),
        payload={
            "incident_id": str(evidence.incident_id) if evidence.incident_id else None,
            "result": status,
            "sha256_match": matched,
        },
    )
    db.commit()
    return {
        "evidence_id": evidence.id,
        "expected_sha256": evidence.sha256,
        "computed_sha256": computed,
        "match": matched,
        "status": status,
        "file_size": size,
        "verified_at": verified_at,
        "chain_of_custody": custody,
    }


def case_counts(db: Session, incident: Incident) -> tuple[int, int]:
    from sqlalchemy import func

    evidence_count = db.execute(
        select(func.count()).select_from(Evidence).where(Evidence.incident_id == incident.id)
    ).scalar_one()
    alert_count = db.execute(
        select(func.count()).select_from(Alert).where(Alert.incident_id == incident.id)
    ).scalar_one()
    return int(evidence_count), int(alert_count)


def case_view(db: Session, incident: Incident) -> dict[str, Any]:
    evidence_count, alert_count = case_counts(db, incident)
    return {
        "id": incident.id,
        "ref": incident.ref,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "priority": incident.priority,
        "detected_at": incident.detected_at,
        "contained_at": incident.contained_at,
        "resolved_at": incident.resolved_at,
        "closed_at": incident.closed_at,
        "mitre": incident.mitre,
        "evidence_count": evidence_count,
        "alert_count": alert_count,
    }


def build_case_manifest(
    db: Session,
    ctx: RequestContext,
    incident: Incident,
    evidence_items: list[Evidence],
) -> tuple[bytes, dict[str, Any]]:
    """Build the ZIP in memory, reporting per-evidence failures without aborting."""
    timeline = list(
        db.execute(
            select(IncidentTimeline)
            .where(IncidentTimeline.incident_id == incident.id)
            .order_by(IncidentTimeline.at.asc())
            .limit(MAX_EXPORT_TIMELINE)
        ).scalars()
    )
    alerts = list(
        db.execute(
            select(Alert)
            .where(Alert.incident_id == incident.id)
            .order_by(Alert.created_at.desc())
            .limit(MAX_EXPORT_ALERTS)
        ).scalars()
    )
    executions = list(
        db.execute(
            select(PlaybookExecution)
            .where(PlaybookExecution.incident_id == incident.id)
            .order_by(PlaybookExecution.started_at.asc())
            .limit(100)
        ).scalars()
    )
    remediations = list(
        db.execute(
            select(Remediation)
            .where(Remediation.incident_id == incident.id)
            .order_by(Remediation.executed_at.asc().nulls_last())
            .limit(200)
        ).scalars()
    )

    generated_at = utcnow()
    manifest_items: list[dict[str, Any]] = []
    files: list[tuple[str, bytes]] = []
    included = 0
    missing = 0
    errors = 0
    total_bytes = 0

    for evidence in evidence_items:
        entry: dict[str, Any] = {
            "id": str(evidence.id),
            "kind": evidence.kind,
            "title": evidence.title,
            "filename": None,
            "sha256": evidence.sha256,
            "content_type": evidence.content_type,
            "size_bytes": evidence.size_bytes,
            "collected_by": evidence.collected_by,
            "collected_at": evidence.collected_at.isoformat(),
            "sealed": evidence.sealed,
            "chain_of_custody": redact(list(evidence.chain_of_custody or [])),
        }
        path, error = evidence_file_state(evidence)
        if path is None:
            entry["status"] = "missing" if error == "file_missing" else "error"
            entry["error"] = error
            if error == "file_missing":
                missing += 1
            else:
                errors += 1
            manifest_items.append(entry)
            continue
        if total_bytes + path.stat().st_size > MAX_EXPORT_BYTES:
            entry["status"] = "error"
            entry["error"] = "export_size_limit_exceeded"
            errors += 1
            manifest_items.append(entry)
            continue
        try:
            payload = path.read_bytes()
        except OSError:
            entry["status"] = "error"
            entry["error"] = "file_unreadable_during_export"
            errors += 1
            manifest_items.append(entry)
            continue

        extension = path.suffix[:12] if path.suffix else ""
        archive_name = f"evidence/{safe_filename(evidence.title, 'evidence', 60)}-{evidence.id}{extension}"
        entry["status"] = "included"
        entry["filename"] = archive_name
        manifest_items.append(entry)
        files.append((archive_name, payload))
        included += 1
        total_bytes += len(payload)

    manifest = {
        "manifest_version": "1.0",
        "generated_at": generated_at.isoformat(),
        "generated_by": ctx.actor_email or ctx.actor_id,
        "organization": {"id": str(ctx.org.id), "name": ctx.org.name, "slug": ctx.org.slug},
        "case": {
            "id": str(incident.id),
            "ref": incident.ref,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "priority": incident.priority,
            "detected_at": incident.detected_at.isoformat(),
            "contained_at": incident.contained_at.isoformat() if incident.contained_at else None,
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
            "mitre": list(incident.mitre or []),
            "affected_asset_ids": list(incident.affected_asset_ids or []),
        },
        "timeline": [
            {
                "at": entry.at.isoformat(),
                "kind": entry.kind,
                "actor": entry.actor,
                "summary": entry.summary,
                "detail": redact(entry.detail or {}),
            }
            for entry in timeline
        ],
        "alerts": [
            {
                "id": str(alert.id),
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
                "count": alert.count,
                "first_seen": alert.first_seen.isoformat(),
                "last_seen": alert.last_seen.isoformat(),
                "mitre": list(alert.mitre or []),
            }
            for alert in alerts
        ],
        "playbook_executions": [
            {
                "id": str(execution.id),
                "playbook_id": str(execution.playbook_id),
                "status": execution.status,
                "started_at": execution.started_at.isoformat(),
                "finished_at": execution.finished_at.isoformat() if execution.finished_at else None,
                "autonomy_level": execution.autonomy_level,
            }
            for execution in executions
        ],
        "remediations": [
            {
                "id": str(item.id),
                "action_type": item.action_type,
                "target_type": item.target_type,
                "status": item.status,
                "risk_level": item.risk_level,
                "executed_at": item.executed_at.isoformat() if item.executed_at else None,
            }
            for item in remediations
        ],
        "evidence": manifest_items,
        "summary": {
            "evidence_total": len(evidence_items),
            "evidence_included": included,
            "evidence_missing": missing,
            "evidence_errors": errors,
            "files_bytes": total_bytes,
        },
        "checksum_algorithm": "SHA-256",
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, default=str, ensure_ascii=False))
        for archive_name, payload in files:
            archive.writestr(archive_name, payload)

    content = buffer.getvalue()
    result = {
        "incident_id": incident.id,
        "filename": f"case-{safe_filename(incident.ref, 'case', 40)}-evidence.zip",
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "evidence_included": manifest["summary"]["evidence_included"],
        "evidence_missing": manifest["summary"]["evidence_missing"],
        "evidence_errors": manifest["summary"]["evidence_errors"],
    }
    return content, result


def timeline_rows(db: Session, incident: Incident) -> list[dict[str, Any]]:
    rows = db.execute(
        select(IncidentTimeline).where(IncidentTimeline.incident_id == incident.id).order_by(IncidentTimeline.at.asc())
    ).scalars()
    return [
        {
            "id": str(entry.id),
            "at": entry.at,
            "kind": entry.kind,
            "actor": entry.actor,
            "summary": entry.summary,
            "detail": entry.detail or {},
        }
        for entry in rows
    ]


__all__ = [
    "EVIDENCE_ROOT",
    "MAX_EXPORT_BYTES",
    "build_case_manifest",
    "case_counts",
    "case_view",
    "evidence_file_state",
    "evidence_view",
    "get_evidence",
    "get_incident",
    "hash_file",
    "resolve_evidence_path",
    "safe_filename",
    "timeline_rows",
    "verify_evidence_hash",
]
