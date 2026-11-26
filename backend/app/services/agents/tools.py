"""Read-only internal tools available to defensive agents.

Every query is scoped to the caller's organization. These tools cannot mutate
state, call connectors or expand permissions; tool arguments are bounded and
unsupported fields are ignored.
"""

from __future__ import annotations

from datetime import UTC
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.assets import Asset, AssetRelationship, Vulnerability
from app.models.events import Alert, SecurityEvent
from app.models.incidents import Incident, IncidentTimeline
from app.models.ti import ThreatIndicator
from app.services.rag.retrieval import search_knowledge

MAX_EVENTS = 50
MAX_ASSETS = 50
MAX_INDICATORS = 50
MAX_KNOWLEDGE = 5


def _strings(value: Any, limit: int = 10, max_length: int = 300) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            cleaned = item.strip()[:max_length]
            if cleaned not in result:
                result.append(cleaned)
        if len(result) >= limit:
            break
    return result


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "astimezone"):
        return value.astimezone(UTC).isoformat()
    return str(value)


def _event_view(event: SecurityEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "event_uid": event.event_uid,
        "occurred_at": _iso(event.occurred_at),
        "severity_id": event.severity_id,
        "class_name": event.class_name,
        "message": (event.message or "")[:500],
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "user_name": event.user_name,
        "host_name": event.host_name,
        "domain": event.domain,
        "file_hash_sha256": event.file_hash_sha256,
        "ioc_matches": event.ioc_matches or [],
        "mitre_techniques": event.mitre_techniques or [],
    }


def _asset_view(asset: Asset) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "asset_key": asset.asset_key,
        "name": asset.name,
        "kind": asset.kind,
        "criticality": asset.criticality,
        "environment": asset.environment,
        "status": asset.status,
        "ip_addresses": list(asset.ip_addresses or []),
        "hostnames": list(asset.hostnames or []),
        "os_name": asset.os_name,
        "vendor": asset.vendor,
    }


def _indicator_view(indicator: ThreatIndicator) -> dict[str, Any]:
    return {
        "id": str(indicator.id),
        "indicator_type": indicator.indicator_type,
        "value": indicator.value,
        "confidence": indicator.confidence,
        "severity": indicator.severity,
        "source": indicator.source,
        "description": (indicator.description or "")[:300],
        "active": indicator.active,
    }


def _incident_view(incident: Incident, timeline: list[IncidentTimeline], alerts: list[Alert]) -> dict[str, Any]:
    return {
        "id": str(incident.id),
        "ref": incident.ref,
        "title": incident.title,
        "description": (incident.description or "")[:1000],
        "severity": incident.severity,
        "status": incident.status,
        "priority": incident.priority,
        "detected_at": _iso(incident.detected_at),
        "mitre": incident.mitre or [],
        "affected_asset_ids": list(incident.affected_asset_ids or []),
        "timeline": [
            {"at": _iso(item.at), "kind": item.kind, "actor": item.actor, "summary": item.summary[:300]}
            for item in timeline[:100]
        ],
        "alerts": [
            {
                "id": str(alert.id),
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
                "count": alert.count,
                "risk_score": alert.risk_score,
                "event_ids": list(alert.event_ids or [])[:100],
            }
            for alert in alerts[:50]
        ],
    }


def tool_outcome(name: str, data: dict[str, Any], *, count: int, citations: list[dict[str, Any]] | None = None) -> dict:
    return {
        "name": name,
        "ok": True,
        "data": data,
        "count": count,
        "citations": citations or [],
        "error": None,
    }


def tool_failure(name: str, error: str) -> dict:
    return {"name": name, "ok": False, "data": {}, "count": 0, "citations": [], "error": error[:500]}


def search_events_tool(db: Session, org_id: UUID, arguments: dict[str, Any]) -> dict:
    limit = arguments.get("limit", 20)
    limit = max(1, min(int(limit) if isinstance(limit, int) else 20, MAX_EVENTS))
    src_ips = _strings(arguments.get("src_ips"))
    host_names = _strings(arguments.get("host_names"))
    user_names = _strings(arguments.get("user_names"))
    q = arguments.get("q")
    conditions = []
    conditions.extend(SecurityEvent.src_ip == value for value in src_ips)
    conditions.extend(SecurityEvent.host_name == value for value in host_names)
    conditions.extend(SecurityEvent.user_name == value for value in user_names)
    stmt = select(SecurityEvent).where(SecurityEvent.org_id == org_id)
    if conditions:
        stmt = stmt.where(or_(*conditions))
    if isinstance(q, str) and q.strip():
        stmt = stmt.where(func.lower(SecurityEvent.message).like(f"%{q.strip().lower()[:200]}%"))
    rows = list(db.execute(stmt.order_by(SecurityEvent.occurred_at.desc()).limit(limit)).scalars())
    return tool_outcome("search_events", {"events": [_event_view(row) for row in rows]}, count=len(rows))


def get_incident_tool(db: Session, org_id: UUID, incident_id: UUID | None) -> dict:
    if incident_id is None:
        return tool_failure("get_incident", "No incident identifier supplied")
    incident = db.get(Incident, incident_id)
    if incident is None or incident.org_id != org_id:
        return tool_failure("get_incident", "Incident not found in this organization")
    timeline = list(
        db.execute(
            select(IncidentTimeline)
            .where(IncidentTimeline.incident_id == incident.id, IncidentTimeline.org_id == org_id)
            .order_by(IncidentTimeline.at.asc())
            .limit(100)
        ).scalars()
    )
    alerts = list(
        db.execute(
            select(Alert)
            .where(Alert.org_id == org_id, Alert.incident_id == incident.id)
            .order_by(Alert.created_at.desc())
            .limit(50)
        ).scalars()
    )
    return tool_outcome(
        "get_incident", {"incident": _incident_view(incident, timeline, alerts)}, count=1 + len(timeline) + len(alerts)
    )


def list_assets_tool(db: Session, org_id: UUID, arguments: dict[str, Any]) -> dict:
    limit = arguments.get("limit", 20)
    limit = max(1, min(int(limit) if isinstance(limit, int) else 20, MAX_ASSETS))
    asset_ids: list[UUID] = []
    for raw in _strings(arguments.get("asset_ids"), limit=MAX_ASSETS, max_length=64):
        try:
            asset_ids.append(UUID(raw))
        except ValueError:
            continue
    q = arguments.get("q")
    stmt = select(Asset).where(Asset.org_id == org_id)
    if asset_ids:
        stmt = stmt.where(Asset.id.in_(asset_ids))
    if isinstance(q, str) and q.strip():
        needle = f"%{q.strip().lower()[:100]}%"
        stmt = stmt.where(or_(func.lower(Asset.name).like(needle), func.lower(Asset.asset_key).like(needle)))
    assets = list(db.execute(stmt.order_by(Asset.criticality.desc(), Asset.name).limit(limit)).scalars())
    ids = [asset.id for asset in assets]
    relationships: list[AssetRelationship] = []
    vulnerabilities: list[Vulnerability] = []
    if ids:
        relationships = list(
            db.execute(
                select(AssetRelationship)
                .where(
                    AssetRelationship.org_id == org_id,
                    or_(AssetRelationship.source_asset_id.in_(ids), AssetRelationship.target_asset_id.in_(ids)),
                )
                .limit(100)
            ).scalars()
        )
        vulnerabilities = list(
            db.execute(
                select(Vulnerability)
                .where(Vulnerability.org_id == org_id, Vulnerability.asset_id.in_(ids))
                .order_by(Vulnerability.priority_score.desc())
                .limit(100)
            ).scalars()
        )
    return tool_outcome(
        "list_assets",
        {
            "assets": [_asset_view(asset) for asset in assets],
            "relationships": [
                {
                    "id": str(row.id),
                    "source_asset_id": str(row.source_asset_id),
                    "target_asset_id": str(row.target_asset_id),
                    "kind": row.kind,
                    "confidence": row.confidence,
                }
                for row in relationships
            ],
            "vulnerabilities": [
                {
                    "id": str(row.id),
                    "asset_id": str(row.asset_id) if row.asset_id else None,
                    "cve_id": row.cve_id,
                    "title": row.title,
                    "severity": row.severity,
                    "status": row.status,
                    "kev": row.kev,
                    "cvss_score": row.cvss_score,
                    "epss_score": row.epss_score,
                    "priority_score": row.priority_score,
                }
                for row in vulnerabilities
            ],
        },
        count=len(assets) + len(relationships) + len(vulnerabilities),
    )


def lookup_indicator_tool(db: Session, org_id: UUID, arguments: dict[str, Any]) -> dict:
    value = arguments.get("value")
    if not isinstance(value, str) or not value.strip():
        return tool_failure("lookup_indicator", "No indicator value supplied")
    needle = value.strip()[:500]
    stmt = select(ThreatIndicator).where(
        or_(ThreatIndicator.org_id == org_id, ThreatIndicator.org_id.is_(None)),
        func.lower(ThreatIndicator.value) == needle.lower(),
        ThreatIndicator.active.is_(True),
    )
    rows = list(db.execute(stmt.order_by(ThreatIndicator.confidence.desc()).limit(MAX_INDICATORS)).scalars())
    return tool_outcome(
        "lookup_indicator",
        {"value": needle, "indicators": [_indicator_view(row) for row in rows]},
        count=len(rows),
    )


def search_knowledge_tool(db: Session, org_id: UUID, arguments: dict[str, Any]) -> dict:
    query = arguments.get("query")
    if not isinstance(query, str) or not query.strip():
        return tool_failure("search_knowledge", "No knowledge query supplied")
    result = search_knowledge(db, org_id, query.strip()[:1000], top_k=MAX_KNOWLEDGE)
    return tool_outcome(
        "search_knowledge",
        {"results": result["results"]},
        count=result["count"],
        citations=result["citations"],
    )


TOOLS = {
    "search_events": search_events_tool,
    "get_incident": get_incident_tool,
    "list_assets": list_assets_tool,
    "lookup_indicator": lookup_indicator_tool,
    "search_knowledge": search_knowledge_tool,
}


def execute_tool(
    db: Session,
    org_id: UUID,
    name: str,
    arguments: dict[str, Any],
    *,
    incident_id: UUID | None = None,
) -> dict:
    if name not in TOOLS:
        return tool_failure(name, "Unknown or disallowed tool")
    if not isinstance(arguments, dict):
        return tool_failure(name, "Tool arguments must be an object")
    if name == "get_incident":
        return get_incident_tool(db, org_id, incident_id)
    return TOOLS[name](db, org_id, arguments)


__all__ = ["TOOLS", "execute_tool", "tool_failure", "tool_outcome"]
