"""SIEM API integration: rules, Sigma, rule testing, alerts, promotion, MITRE."""

from __future__ import annotations

import re
import uuid

from sqlalchemy import select

from app.core.db import utcnow
from app.models.core import AuditRecord
from app.models.events import Alert, DetectionRule, IngestSource, SecurityEvent
from app.models.incidents import Incident, IncidentTimeline
from scripts.seed_siem import seed_builtin_rules, seed_siem


def _definition(**overrides):
    definition = {"selection": {"message": {"contains": "suspicious login"}}, "condition": "and"}
    definition.update(overrides)
    return definition


def _create_rule(client, **overrides):
    payload = {
        "name": "Suspicious login rule",
        "description": "test rule",
        "severity": "high",
        "definition": _definition(),
        "mitre": ["T1078"],
        "tags": ["test"],
    }
    payload.update(overrides)
    response = client.post("/api/v1/siem/rules", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _add_member(client, *, email: str, role: str, password: str):
    response = client.post(
        "/api/v1/organizations/current/members",
        json={"email": email, "full_name": "SIEM User", "role": role, "password": password},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _login_as(client, email: str, password: str):
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    client.headers.update({"X-CSRF-Token": client.cookies.get("hs_csrf")})
    return client


def _alert(org_id, **overrides):
    values = {
        "org_id": org_id,
        "title": "Alert for tests",
        "description": "test alert",
        "severity": "high",
        "status": "new",
        "event_ids": [],
        "first_seen": utcnow(),
        "last_seen": utcnow(),
        "count": 1,
        "mitre": [],
        "evidence": {},
        "risk_score": 60.0,
        "is_demo": False,
    }
    values.update(overrides)
    return Alert(**values)


def _event(org_id, **overrides):
    values = {
        "org_id": org_id,
        "event_uid": str(uuid.uuid4()),
        "occurred_at": utcnow(),
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "severity_id": 3,
        "message": "event for mitre coverage",
        "raw": {},
        "normalized": {},
        "raw_format": "json",
        "schema_version": "1.1.0",
        "ioc_matches": [],
        "mitre_techniques": [],
        "is_demo": False,
    }
    values.update(overrides)
    return SecurityEvent(**values)


def test_rule_crud_and_versioning(auth_client, db):
    rule = _create_rule(auth_client)
    assert rule["version"] == 1
    assert rule["scope"] == "organization"
    assert rule["enabled"] is True

    fetched = auth_client.get(f"/api/v1/siem/rules/{rule['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["definition"]["selection"]["message"]["contains"] == "suspicious login"

    updated = auth_client.patch(
        f"/api/v1/siem/rules/{rule['id']}",
        json={
            "definition": _definition(selection={"message": {"contains": "privilege escalation"}}),
            "severity": "critical",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["version"] == 2
    assert updated.json()["severity"] == "critical"

    listing = auth_client.get("/api/v1/siem/rules")
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 1

    assert auth_client.delete(f"/api/v1/siem/rules/{rule['id']}").status_code == 204
    assert auth_client.get(f"/api/v1/siem/rules/{rule['id']}").status_code == 404

    db.expire_all()
    audit_actions = {
        record.action
        for record in db.execute(select(AuditRecord).where(AuditRecord.resource_id == rule["id"])).scalars()
    }
    assert {"detection_rule.create", "detection_rule.update", "detection_rule.delete"} <= audit_actions


def test_rule_validation_rejects_bad_definitions(auth_client):
    bad_key = auth_client.post(
        "/api/v1/siem/rules",
        json={"name": "Bad key", "definition": {"selection": {"message": "x"}, "aggregation": "count"}},
    )
    assert bad_key.status_code == 422
    assert any("Unknown keys" in item["message"] for item in bad_key.json()["error"]["details"])

    bad_regex = auth_client.post(
        "/api/v1/siem/rules",
        json={"name": "Bad regex", "definition": {"selection": {"message": {"regex": "(a+)+$"}}}},
    )
    assert bad_regex.status_code == 422
    assert any("nested quantifier" in item["message"] for item in bad_regex.json()["error"]["details"])

    unknown_field = auth_client.post(
        "/api/v1/siem/rules",
        json={"name": "Unknown field", "definition": {"selection": {"not_a_real_field": "x"}}},
    )
    assert unknown_field.status_code == 422
    assert any("Unknown field" in item["message"] for item in unknown_field.json()["error"]["details"])

    assert auth_client.get("/api/v1/siem/rules").json()["meta"]["total"] == 0


def test_global_rules_require_platform_admin(auth_client):
    global_rule = _create_rule(auth_client, name="Global private rule", is_global=True)
    assert global_rule["scope"] == "global"
    assert global_rule["org_id"] is None

    _add_member(
        auth_client,
        email="analystuser@example.eu",
        role="soc_analyst",
        password="Str0ng-Test-Passw0rd!2026",
    )
    _login_as(auth_client, "analystuser@example.eu", "Str0ng-Test-Passw0rd!2026")

    denied = auth_client.post(
        "/api/v1/siem/rules",
        json={"name": "Escalated global", "definition": _definition(), "is_global": True},
    )
    assert denied.status_code == 403

    org_rule = _create_rule(auth_client, name="Analyst organization rule")
    assert org_rule["scope"] == "organization"

    assert auth_client.patch(f"/api/v1/siem/rules/{global_rule['id']}", json={"name": "Hijacked"}).status_code == 403
    assert auth_client.get(f"/api/v1/siem/rules/{global_rule['id']}").status_code == 200


def test_rule_test_endpoint_matches_and_explains_threshold(auth_client):
    rule = _create_rule(
        auth_client,
        name="Threshold test rule",
        definition={
            "selection": {"message": {"contains": "failed login"}},
            "condition": "and",
            "threshold": {"count": 3, "group_by": ["src_ip"], "window_seconds": 300},
        },
    )
    samples = [
        {"message": "failed login for bob", "src_ip": "5.5.5.5"},
        {"message": "failed login for alice", "src_ip": "5.5.5.5"},
        {"message": "failed login for eve", "src_ip": "5.5.5.5"},
    ]
    response = auth_client.post(f"/api/v1/siem/rules/{rule['id']}/test", json={"events": samples})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["matched_count"] == 3
    assert payload["threshold"]["required"] == 3
    assert payload["threshold"]["would_trigger"] is True
    assert payload["would_alert"] is True
    assert payload["matches"][0]["checks"][0]["field"] == "message"

    below = auth_client.post(f"/api/v1/siem/rules/{rule['id']}/test", json={"events": samples[:2]}).json()
    assert below["threshold"]["would_trigger"] is False
    assert below["would_alert"] is False

    assert (
        auth_client.post(
            f"/api/v1/siem/rules/{rule['id']}/test", json={"events": samples, "event_ids": [1]}
        ).status_code
        == 422
    )
    assert auth_client.post(f"/api/v1/siem/rules/{rule['id']}/test", json={}).status_code == 422


def test_sigma_import_conversion_duplicate_and_unsupported(auth_client):
    payload = {
        "rules": [
            {
                "title": "PowerShell execution",
                "description": "Imported from Sigma",
                "logsource": {"product": "windows", "service": "sysmon"},
                "detection": {
                    "selection": {"CommandLine": "*powershell*", "User": "root"},
                    "condition": "selection",
                },
                "tags": ["attack.t1059", "execution"],
                "level": "high",
            },
            {
                "title": "Unsupported condition",
                "logsource": {"product": "windows"},
                "detection": {
                    "selection": {"EventID": 4688},
                    "condition": "selection and not filter",
                },
            },
        ]
    }
    response = auth_client.post("/api/v1/siem/rules/import", json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["imported"]) == 1
    assert len(body["skipped"]) == 1
    imported = body["imported"][0]
    assert imported["severity"] == "high"
    assert imported["definition"]["selection"]["message"]["regex"] == "^.*powershell.*$"
    assert imported["definition"]["selection"]["user_name"] == "root"
    assert imported["mitre"] == ["T1059"]
    assert imported["tags"] == ["execution"]

    duplicate = auth_client.post("/api/v1/siem/rules/import", json={"rules": [payload["rules"][0]]})
    assert duplicate.status_code == 200
    assert duplicate.json()["imported"] == []
    assert duplicate.json()["skipped"][0]["reason"] == "duplicate rule name"


def test_alert_triage_stats_filters_and_bulk(auth_client, seeded, db):
    seed_builtin_rules(db)
    db.commit()

    events = [
        {"message": f"failed login attempt {index}", "src_ip": "8.8.8.8", "severity": "medium"} for index in range(5)
    ]
    ingest = auth_client.post("/api/v1/events/ingest", json={"events": events})
    assert ingest.status_code == 200, ingest.text
    assert ingest.json()["alerts_created"] >= 1

    alerts = auth_client.get("/api/v1/siem/alerts")
    assert alerts.status_code == 200
    assert alerts.json()["meta"]["total"] == 1
    alert = alerts.json()["items"][0]
    assert alert["severity"] == "high"
    assert alert["status"] == "new"
    assert alert["rule_name"].startswith("Builtin: Brute force")

    filtered = auth_client.get("/api/v1/siem/alerts?severity=high&status=new&q=Brute")
    assert filtered.json()["meta"]["total"] == 1

    triaged = auth_client.patch(
        f"/api/v1/siem/alerts/{alert['id']}",
        json={"status": "triaged", "note": "Confirmed with the user"},
    )
    assert triaged.status_code == 200, triaged.text
    body = triaged.json()
    assert body["status"] == "triaged"
    assert body["evidence"]["notes"][0]["note"] == "Confirmed with the user"

    assert auth_client.patch(f"/api/v1/siem/alerts/{alert['id']}", json={"status": "unknown"}).status_code == 422
    assert (
        auth_client.patch(f"/api/v1/siem/alerts/{alert['id']}", json={"assignee_id": str(uuid.uuid4())}).status_code
        == 422
    )

    stats = auth_client.get("/api/v1/siem/alerts/stats")
    assert stats.status_code == 200
    stats_body = stats.json()
    assert stats_body["total"] == 1
    assert stats_body["open"] == 1
    assert stats_body["by_status"]["triaged"] == 1
    assert stats_body["by_severity"]["high"] == 1
    assert len(stats_body["timeline"]) == 24

    random_id = uuid.uuid4()
    bulk = auth_client.post(
        "/api/v1/siem/alerts/bulk",
        json={"ids": [alert["id"], str(random_id)], "status": "closed", "note": "Bulk close"},
    )
    assert bulk.status_code == 200, bulk.text
    assert bulk.json()["updated"] == 1
    assert bulk.json()["skipped"] == 1

    stats_after = auth_client.get("/api/v1/siem/alerts/stats").json()
    assert stats_after["open"] == 0
    assert stats_after["by_status"]["closed"] == 1


def test_alert_cross_tenant_isolation(auth_client):
    other_org_response = auth_client.post(
        "/api/v1/organizations", json={"name": "Other SIEM org", "slug": "siem-other"}
    )
    assert other_org_response.status_code == 201
    other_org_id = other_org_response.json()["id"]

    # Presence in another tenant must be indistinguishable from absence.
    from app.core.db import SessionLocal

    with SessionLocal() as db:
        foreign = _alert(uuid.UUID(other_org_id), title="Foreign alert")
        db.add(foreign)
        db.commit()
        foreign_id = foreign.id

    assert auth_client.get(f"/api/v1/siem/alerts/{foreign_id}").status_code == 404
    assert auth_client.patch(f"/api/v1/siem/alerts/{foreign_id}", json={"status": "closed"}).status_code == 404
    assert auth_client.post(f"/api/v1/siem/alerts/{foreign_id}/promote", json={}).status_code == 404


def test_promote_alert_creates_incident_timeline_and_audit(auth_client, seeded, db):
    alert = _alert(seeded["org"].id, title="Ransomware on critical asset", severity="critical")
    db.add(alert)
    db.commit()
    alert_id = alert.id

    response = auth_client.post(
        f"/api/v1/siem/alerts/{alert_id}/promote",
        json={"title": "Ransomware incident", "description": "Promoted by integration test"},
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    assert re.fullmatch(r"HS-\d{4}-\d{4}", payload["incident"]["ref"])
    assert payload["incident"]["priority"] == 1
    assert payload["incident"]["severity"] == "critical"
    assert payload["alert_id"] == str(alert_id)

    db.expire_all()
    incident = db.get(Incident, payload["incident"]["id"])
    assert incident is not None
    assert incident.ref == payload["incident"]["ref"]
    timeline = db.execute(select(IncidentTimeline).where(IncidentTimeline.incident_id == incident.id)).scalar_one()
    assert timeline.kind == "created_from_alert"
    assert timeline.detail["alert_id"] == str(alert_id)

    refreshed_alert = db.get(Alert, alert_id)
    assert refreshed_alert is not None
    assert refreshed_alert.incident_id == incident.id
    assert refreshed_alert.status == "investigating"

    audit = db.execute(
        select(AuditRecord).where(AuditRecord.action == "alert.promote", AuditRecord.resource_id == str(alert_id))
    ).scalar_one_or_none()
    assert audit is not None
    assert audit.payload["incident_ref"] == incident.ref

    again = auth_client.post(f"/api/v1/siem/alerts/{alert_id}/promote", json={})
    assert again.status_code == 409


def test_promote_requires_incident_write(auth_client, seeded, db):
    alert = _alert(seeded["org"].id)
    db.add(alert)
    db.commit()
    alert_id = alert.id

    _add_member(
        auth_client,
        email="vieweruser@example.eu",
        role="viewer",
        password="Str0ng-Test-Passw0rd!2026",
    )
    _login_as(auth_client, "vieweruser@example.eu", "Str0ng-Test-Passw0rd!2026")

    assert auth_client.post(f"/api/v1/siem/alerts/{alert_id}/promote", json={}).status_code == 403


def test_mitre_coverage_counts_events_and_alerts(auth_client, seeded, db):
    org = seeded["org"]
    db.add(_event(org.id, mitre_techniques=["T1110", "T1046"]))
    db.add(_alert(org.id, mitre=["T1110"]))
    db.commit()

    response = auth_client.get("/api/v1/siem/mitre/coverage")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_techniques"] == 2
    by_technique = {item["technique"]: item for item in payload["techniques"]}
    assert by_technique["T1110"]["events"] == 1
    assert by_technique["T1110"]["alerts"] == 1
    assert by_technique["T1110"]["total"] == 2
    assert by_technique["T1046"]["events"] == 1
    assert by_technique["T1110"]["name"] == "Brute Force"


def test_rule_templates_catalog(auth_client):
    response = auth_client.get("/api/v1/siem/rules/templates")
    assert response.status_code == 200
    templates = response.json()
    assert len(templates) == 6
    keys = {item["key"] for item in templates}
    assert {"brute-force-auth", "port-scan", "threat-intel-match", "privilege-escalation"} <= keys
    for template in templates:
        assert template["definition"]["selection"]
        assert template["severity"] in {"informational", "low", "medium", "high", "critical"}


def test_seed_siem_is_idempotent(db, seeded):
    org = seeded["org"]
    first = seed_siem(db, org=org, with_source=True, commit=False)
    second = seed_siem(db, org=org, with_source=True, commit=False)
    db.commit()

    assert first["rules_created"] == 6
    assert second["rules_created"] == 0
    assert first["source_token"].startswith("hs_ing_")
    assert second["source_token"] is None
    assert second["source_created"] is False
    global_rules = list(db.execute(select(DetectionRule).where(DetectionRule.org_id.is_(None))).scalars())
    assert len(global_rules) == 6
    sources = list(db.execute(select(IngestSource).where(IngestSource.org_id == org.id)).scalars())
    assert len(sources) == 1


def test_alert_detail_exposes_evidence_and_rule_name(auth_client, seeded, db):
    rule = DetectionRule(
        org_id=seeded["org"].id,
        name="Evidence rule",
        severity="medium",
        status="production",
        enabled=True,
        version=1,
        logsource={},
        definition={"selection": {"message": "x"}},
        mitre=[],
        tags=[],
    )
    db.add(rule)
    db.flush()
    alert = _alert(seeded["org"].id, rule_id=rule.id, evidence={"observed": 3, "group": {"src_ip": "1.2.3.4"}})
    db.add(alert)
    db.commit()

    detail = auth_client.get(f"/api/v1/siem/alerts/{alert.id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["rule_name"] == "Evidence rule"
    assert body["evidence"]["observed"] == 3
