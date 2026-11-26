"""Report generation, escaping, checksum and download integration tests."""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.crypto import hash_password
from app.core.db import utcnow
from app.models.assets import Asset, Vulnerability
from app.models.compliance import ComplianceFramework, Report
from app.models.connectors import Connector
from app.models.core import Membership, Organization, Policy, User
from app.models.events import IngestSource
from app.models.incidents import Evidence, Incident, IncidentTimeline
from app.modules.compliance.service import seed_builtin_frameworks
from tests.conftest import login

MEMBER_PASSWORD = "S3cure-Pass!2026x"
MALICIOUS_NAME = "<script>alert(1)</script> asset"


def _period() -> tuple[str, str]:
    end = utcnow()
    start = end - timedelta(days=30)
    return start.isoformat(), end.isoformat()


def _seed_report_data(db, seeded) -> dict:
    org = seeded["org"]
    now = utcnow()
    host = Asset(
        org_id=org.id,
        asset_key=f"host-{uuid.uuid4().hex[:8]}",
        name=MALICIOUS_NAME,
        kind="host",
        criticality=4,
        owner="Infrastructure",
    )
    ot = Asset(
        org_id=org.id,
        asset_key=f"ot-{uuid.uuid4().hex[:8]}",
        name="PLC line 1",
        kind="ot",
        criticality=5,
    )
    db.add_all([host, ot])
    db.flush()

    db.add(
        Vulnerability(
            org_id=org.id,
            asset_id=host.id,
            cve_id="CVE-2026-0001",
            title="Remote code execution in edge agent",
            severity="critical",
            status="open",
            kev=True,
            cvss_score=9.8,
            priority_score=97.5,
            due_at=now - timedelta(days=3),
        )
    )
    db.add(
        Connector(
            org_id=org.id,
            name="EDR collector",
            connector_type="edr",
            status="degraded",
            enabled=True,
            verify_tls=False,
        )
    )
    db.add(IngestSource(org_id=org.id, name="Firewall syslog", kind="syslog", parser="syslog", enabled=True))
    db.add(
        Policy(
            org_id=org.id,
            name="retention-365",
            kind="retention",
            version=1,
            enabled=True,
            definition={"days": 365},
        )
    )
    resolved = Incident(
        org_id=org.id,
        ref=f"INC-{uuid.uuid4().hex[:6]}",
        title="Ransomware attempt on file server",
        severity="high",
        status="resolved",
        detected_at=now - timedelta(days=2),
        resolved_at=now - timedelta(days=1, hours=6),
        affected_asset_ids=[str(host.id)],
    )
    open_incident = Incident(
        org_id=org.id,
        ref=f"INC-{uuid.uuid4().hex[:6]}",
        title="Suspicious OT beacon",
        severity="critical",
        status="investigating",
        detected_at=now - timedelta(hours=4),
        affected_asset_ids=[str(ot.id)],
    )
    db.add_all([resolved, open_incident])
    db.flush()
    db.add(
        IncidentTimeline(
            org_id=org.id,
            incident_id=resolved.id,
            at=now - timedelta(days=2),
            kind="detection",
            summary="EDR raised a ransomware behaviour alert",
        )
    )
    db.add(
        Evidence(
            org_id=org.id,
            incident_id=resolved.id,
            kind="log",
            title="EDR export",
            sha256="d" * 64,
            storage_path="evidence/edr-export.json",
            content_type="application/json",
            size_bytes=2048,
        )
    )
    db.commit()
    return {"resolved_ref": resolved.ref, "open_ref": open_incident.ref, "asset_name": host.name}


def _generate(client: TestClient, kind: str = "executive", framework_id: str | None = None) -> dict:
    start, end = _period()
    body: dict = {"kind": kind, "period_start": start, "period_end": end}
    if framework_id:
        body["framework_id"] = framework_id
    response = client.post("/api/v1/reports/generate", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _add_member(db, org: Organization, email: str, role: str) -> User:
    user = User(
        email=email,
        full_name=email.split("@")[0].title(),
        password_hash=hash_password(MEMBER_PASSWORD),
        status="active",
    )
    db.add(user)
    db.flush()
    db.add(Membership(org_id=org.id, user_id=user.id, role=role, status="active"))
    db.commit()
    return user


def test_generate_executive_report_with_real_data(seeded, auth_client: TestClient, db) -> None:
    refs = _seed_report_data(db, seeded)
    report = _generate(auth_client, "executive")

    assert report["kind"] == "executive"
    assert seeded["org"].name in report["title"]
    assert report["status"] == "generated"
    assert len(report["checksum"]) == 64
    assert report["metadata"]["counts"]["assets"] == 2
    assert report["metadata"]["counts"]["incidents"] == 2
    assert report["metadata"]["counts"]["open_vulnerabilities"] == 1
    assert report["metadata"]["provenance"]["synthetic_values"] is False
    assert refs["resolved_ref"] in report["content_md"]
    assert "not a certification" in report["content_html"]
    assert "Data provenance" in report["content_md"]


def test_checksum_equals_sha256_of_stored_content(seeded, auth_client: TestClient, db) -> None:
    _seed_report_data(db, seeded)
    report = _generate(auth_client, "technical")
    expected = hashlib.sha256((report["content_html"] + report["content_md"]).encode()).hexdigest()
    assert report["checksum"] == expected

    stored = auth_client.get(f"/api/v1/reports/{report['id']}")
    assert stored.status_code == 200
    payload = stored.json()
    assert payload["checksum"] == hashlib.sha256((payload["content_html"] + payload["content_md"]).encode()).hexdigest()


def test_html_escapes_malicious_asset_names(seeded, auth_client: TestClient, db) -> None:
    _seed_report_data(db, seeded)
    report = _generate(auth_client, "technical")
    html = report["content_html"]
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # The Markdown variant keeps the plain text so readers know the real asset name.
    assert MALICIOUS_NAME in report["content_md"]


def test_html_has_no_external_assets_or_scripts(seeded, auth_client: TestClient, db) -> None:
    _seed_report_data(db, seeded)
    html = _generate(auth_client, "regulatory")["content_html"]
    assert "<script" not in html.lower()
    assert "<link" not in html.lower()
    assert "@import" not in html
    assert "url(" not in html
    assert "<!doctype html>" in html


def test_download_html_returns_safe_attachment(seeded, auth_client: TestClient, db) -> None:
    _seed_report_data(db, seeded)
    report = _generate(auth_client, "executive")
    response = auth_client.get(f"/api/v1/reports/{report['id']}/download", params={"format": "html"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert disposition.endswith('.html"')
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-report-checksum"] == report["checksum"]
    assert response.text == report["content_html"]


def test_download_markdown_returns_attachment(seeded, auth_client: TestClient, db) -> None:
    _seed_report_data(db, seeded)
    report = _generate(auth_client, "executive")
    response = auth_client.get(f"/api/v1/reports/{report['id']}/download", params={"format": "md"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.headers["content-disposition"].endswith('.md"')
    assert response.text.startswith("# ")


def test_list_reports_filters_by_kind(seeded, auth_client: TestClient, db) -> None:
    _seed_report_data(db, seeded)
    _generate(auth_client, "executive")
    _generate(auth_client, "incident")

    all_reports = auth_client.get("/api/v1/reports")
    assert all_reports.status_code == 200
    assert all_reports.json()["meta"]["total"] == 2

    filtered = auth_client.get("/api/v1/reports", params={"kind": "executive"})
    assert filtered.status_code == 200
    payload = filtered.json()
    assert payload["meta"]["total"] == 1
    assert payload["items"][0]["kind"] == "executive"


def test_report_detail_includes_content_and_metadata(seeded, auth_client: TestClient, db) -> None:
    _seed_report_data(db, seeded)
    report = _generate(auth_client, "technical")
    response = auth_client.get(f"/api/v1/reports/{report['id']}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["content_md"].startswith("# ")
    assert payload["content_html"].startswith("<!doctype html>")
    assert payload["metadata"]["provenance"]["source"] == "HISPANSHIELD PostgreSQL operational data"
    assert "not a certification" in payload["disclaimer"]


def test_delete_report_requires_generate_permission(seeded, auth_client: TestClient, db) -> None:
    _seed_report_data(db, seeded)
    report = _generate(auth_client, "executive")
    deleted = auth_client.delete(f"/api/v1/reports/{report['id']}")
    assert deleted.status_code == 204
    assert auth_client.get(f"/api/v1/reports/{report['id']}").status_code == 404

    second = _generate(auth_client, "technical")
    _add_member(db, seeded["org"], "viewer.reports@example.eu", "viewer")
    auth_client.cookies.clear()
    login(auth_client, email="viewer.reports@example.eu", password=MEMBER_PASSWORD)
    assert auth_client.get(f"/api/v1/reports/{second['id']}").status_code == 200
    assert auth_client.delete(f"/api/v1/reports/{second['id']}").status_code == 403


def test_regulatory_report_embeds_compliance_assessment(seeded, auth_client: TestClient, db) -> None:
    seed_builtin_frameworks(db)
    framework = db.execute(select(ComplianceFramework).where(ComplianceFramework.code == "NIS2")).scalar_one()
    created = auth_client.post("/api/v1/compliance/assessments", json={"code": "NIS2"})
    assert created.status_code == 201, created.text
    assessment_id = created.json()["id"]
    completed = auth_client.post(f"/api/v1/compliance/assessments/{assessment_id}/complete")
    assert completed.status_code == 200, completed.text

    _seed_report_data(db, seeded)
    report = _generate(auth_client, "regulatory", framework_id=str(framework.id))
    assert "Compliance self-assessment posture" in report["content_md"]
    assert "NIS2" in report["content_md"]
    assert "not a certification" in report["content_md"]
    assert report["framework_id"] == str(framework.id)


def test_incident_report_contains_register_timeline_and_mttr(seeded, auth_client: TestClient, db) -> None:
    refs = _seed_report_data(db, seeded)
    report = _generate(auth_client, "incident")
    markdown = report["content_md"]
    assert refs["resolved_ref"] in markdown
    assert refs["open_ref"] in markdown
    assert "Ransomware attempt on file server" in markdown
    assert "Mean time to resolve" in markdown
    assert "Timeline events" in markdown
    assert "EDR raised a ransomware behaviour alert" in report["content_html"]


def test_invalid_report_requests_are_rejected(seeded, auth_client: TestClient, db) -> None:
    start, end = _period()
    bad_kind = auth_client.post(
        "/api/v1/reports/generate",
        json={"kind": "unknown", "period_start": start, "period_end": end},
    )
    assert bad_kind.status_code == 422

    inverted = auth_client.post(
        "/api/v1/reports/generate",
        json={"kind": "executive", "period_start": end, "period_end": start},
    )
    assert inverted.status_code == 422

    missing_framework = auth_client.post(
        "/api/v1/reports/generate",
        json={
            "kind": "regulatory",
            "period_start": start,
            "period_end": end,
            "framework_id": str(uuid.uuid4()),
        },
    )
    assert missing_framework.status_code == 404


def test_cross_tenant_report_is_hidden(seeded, auth_client: TestClient, db) -> None:
    other = Organization(slug="report-foreign-org", name="Report Foreign Org")
    db.add(other)
    db.flush()
    report = Report(
        org_id=other.id,
        kind="executive",
        title="Foreign executive report",
        status="generated",
        format="html",
        content_md="# Foreign\n",
        content_html="<html>foreign</html>",
        checksum="e" * 64,
    )
    db.add(report)
    db.commit()

    assert auth_client.get(f"/api/v1/reports/{report.id}").status_code == 404
    assert auth_client.get(f"/api/v1/reports/{report.id}/download").status_code == 404
    assert auth_client.delete(f"/api/v1/reports/{report.id}").status_code == 404


def test_zero_data_report_states_zero_without_inventing(seeded, auth_client: TestClient) -> None:
    report = _generate(auth_client, "executive")
    assert report["metadata"]["counts"]["assets"] == 0
    assert report["metadata"]["counts"]["incidents"] == 0
    assert report["metadata"]["counts"]["open_vulnerabilities"] == 0
    assert "No incidents were recorded in the selected reporting period." in report["content_md"]
    assert "No compliance assessment has been created" in report["content_md"]
    assert "| none recorded | 0 |" in report["content_md"]


def test_report_generation_is_audited(seeded, auth_client: TestClient, db) -> None:
    _seed_report_data(db, seeded)
    report = _generate(auth_client, "technical")
    from app.models.core import AuditRecord

    audit = db.execute(
        select(AuditRecord).where(
            AuditRecord.org_id == seeded["org"].id,
            AuditRecord.action == "report.generate",
            AuditRecord.resource_id == report["id"],
        )
    ).scalar_one_or_none()
    assert audit is not None
    assert audit.payload["checksum"] == report["checksum"]
