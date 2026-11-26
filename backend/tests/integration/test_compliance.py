"""Compliance framework, assessment, evidence and RBAC integration tests."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app.core.crypto import hash_password
from app.models.compliance import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceControlStatus,
    ComplianceFramework,
    ControlEvidenceLink,
)
from app.models.core import AuditRecord, Membership, Organization, Policy, User
from app.models.incidents import Evidence
from app.modules.compliance.service import seed_builtin_frameworks
from tests.conftest import login

MEMBER_PASSWORD = "S3cure-Pass!2026x"
CUSTOM_FRAMEWORK = """
code: CUSTOM-1
name: Custom internal framework
version: "1.0"
jurisdiction: EU
authority: Internal security office
effective_date: 2026-01-01
source_url: https://example.eu/custom
status: published
description: Internal control set used for import tests.
controls:
  - control_id: C-1
    title: Strong authentication
    description: All users authenticate with a second factor.
    category: access_control
    weight: 3
    references:
      - "Internal policy 1"
    evidence_requirements:
      - key: policy
        title: Authentication policy
        description: Approved policy document.
    technical_checks:
      - key: mfa
        title: MFA coverage
        type: mfa_enforced
        params:
          min_ratio: 1.0
        description: Every active member uses MFA.
"""


def _seed(db) -> None:
    seed_builtin_frameworks(db)


def _framework_row(client: TestClient, code: str = "NIS2") -> dict:
    response = client.get("/api/v1/compliance/frameworks", params={"code": code})
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert items, f"framework {code} not seeded"
    return items[0]


def _create_assessment(client: TestClient, code: str = "NIS2") -> dict:
    response = client.post("/api/v1/compliance/assessments", json={"code": code})
    assert response.status_code == 201, response.text
    return response.json()


def _control(detail: dict, control_code: str) -> dict:
    for control in detail["controls"]:
        if control["control_code"] == control_code:
            return control
    raise AssertionError(f"control {control_code} not found in assessment")


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


def test_framework_catalogue_lists_counts_and_status(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    response = auth_client.get("/api/v1/compliance/frameworks", params={"page_size": 50})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["meta"]["total"] == 10
    codes = {item["code"] for item in payload["items"]}
    assert {
        "NIS2",
        "CRA",
        "GDPR",
        "ENS",
        "ISO27001:2022",
        "ISO27002:2022",
        "IEC62443-3-3",
        "ETSI EN 303 645",
    }.issubset(codes)
    for item in payload["items"]:
        assert item["status"] == "published"
        assert item["controls_count"] > 0
        assert item["technical_checks_count"] > 0
        assert item["is_builtin"] is True


def test_framework_detail_and_versions(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    nis2 = _framework_row(auth_client, "NIS2")
    by_id = auth_client.get(f"/api/v1/compliance/frameworks/{nis2['id']}")
    assert by_id.status_code == 200, by_id.text
    detail = by_id.json()
    assert len(detail["controls"]) == nis2["controls_count"]
    assert detail["description"]
    control = detail["controls"][0]
    assert control["evidence_requirements"]
    assert control["technical_checks"]
    assert control["weight"] >= 1

    by_code = auth_client.get("/api/v1/compliance/frameworks/NIS2", params={"version": nis2["version"]})
    assert by_code.status_code == 200
    assert by_code.json()["id"] == nis2["id"]

    versions = auth_client.get("/api/v1/compliance/frameworks/NIS2/versions")
    assert versions.status_code == 200
    assert len(versions.json()) == 1
    assert versions.json()[0]["version"] == nis2["version"]


def test_assessment_derives_control_statuses_from_evidence(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    detail = _create_assessment(auth_client)
    assert detail["framework_code"] == "NIS2"
    assert detail["status"] == "in_progress"
    assert len(detail["controls"]) == 12
    assert detail["score_breakdown"]["total_controls"] == 12
    allowed = {"compliant", "partial", "non_compliant", "not_applicable"}
    for control in detail["controls"]:
        assert control["status"] in allowed
        assert control["notes"]
        assert control["evidence_ids"] == []
    assert "not a certification" in detail["disclaimer"]


def test_assessment_score_changes_when_mfa_adoption_changes(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    db.execute(update(User).values(mfa_enabled=True))
    db.commit()

    first = _create_assessment(auth_client)
    assert _control(first, "NIS2-08")["status"] == "compliant"

    _add_member(db, seeded["org"], "new.analyst@example.eu", "soc_analyst")
    second = _create_assessment(auth_client)
    mfa_control = _control(second, "NIS2-08")
    assert mfa_control["status"] in {"partial", "non_compliant"}
    assert second["score_breakdown"]["score"] < first["score_breakdown"]["score"]


def test_assessment_status_changes_when_continuity_policy_is_added(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    first = _create_assessment(auth_client)
    assert _control(first, "NIS2-04")["status"] == "non_compliant"

    db.add(
        Policy(
            org_id=seeded["org"].id,
            name="continuity-plan",
            kind="continuity",
            version=1,
            enabled=True,
            definition={"configured": True},
        )
    )
    db.commit()

    second = _create_assessment(auth_client)
    assert _control(second, "NIS2-04")["status"] == "compliant"


def test_control_patch_updates_fields_and_audits(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    detail = _create_assessment(auth_client)
    control = _control(detail, "NIS2-01")
    response = auth_client.patch(
        f"/api/v1/compliance/assessments/{detail['id']}/controls/{control['id']}",
        json={"status": "compliant", "notes": "Board approved policy", "owner": "CISO"},
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["status"] == "compliant"
    assert updated["notes"] == "Board approved policy"
    assert updated["owner"] == "CISO"
    assert updated["reviewed_at"]

    audit = db.execute(
        select(AuditRecord).where(
            AuditRecord.org_id == seeded["org"].id, AuditRecord.action == "compliance.control.update"
        )
    ).scalar_one_or_none()
    assert audit is not None
    invalid = auth_client.patch(
        f"/api/v1/compliance/assessments/{detail['id']}/controls/{control['id']}",
        json={"status": "certified"},
    )
    assert invalid.status_code == 422


def test_evidence_links_are_tenant_scoped(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    detail = _create_assessment(auth_client)
    control = _control(detail, "NIS2-03")

    evidence = Evidence(
        org_id=seeded["org"].id,
        kind="document",
        title="Incident response policy",
        sha256="a" * 64,
        storage_path="evidence/ir-policy.pdf",
        content_type="application/pdf",
        size_bytes=1024,
    )
    db.add(evidence)
    db.flush()
    foreign_org = Organization(slug="foreign-evidence-org", name="Foreign Evidence Org")
    db.add(foreign_org)
    db.flush()
    foreign_evidence = Evidence(
        org_id=foreign_org.id,
        kind="document",
        title="Foreign policy",
        sha256="b" * 64,
        storage_path="evidence/foreign.pdf",
        content_type="application/pdf",
        size_bytes=512,
    )
    db.add(foreign_evidence)
    db.commit()

    linked = auth_client.patch(
        f"/api/v1/compliance/assessments/{detail['id']}/controls/{control['id']}",
        json={"status": "compliant", "evidence_ids": [str(evidence.id)]},
    )
    assert linked.status_code == 200, linked.text
    assert linked.json()["evidence_ids"] == [str(evidence.id)]
    links = db.execute(
        select(func.count())
        .select_from(ControlEvidenceLink)
        .where(ControlEvidenceLink.control_status_id == uuid.UUID(control["id"]))
    ).scalar_one()
    assert links == 1

    denied = auth_client.patch(
        f"/api/v1/compliance/assessments/{detail['id']}/controls/{control['id']}",
        json={"status": "compliant", "evidence_ids": [str(foreign_evidence.id)]},
    )
    assert denied.status_code == 404


def test_completed_assessment_is_locked_and_scored(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    detail = _create_assessment(auth_client)
    control = _control(detail, "NIS2-06")
    auth_client.patch(
        f"/api/v1/compliance/assessments/{detail['id']}/controls/{control['id']}",
        json={"status": "non_compliant", "notes": "Patch evidence missing"},
    )

    completed = auth_client.post(f"/api/v1/compliance/assessments/{detail['id']}/complete")
    assert completed.status_code == 200, completed.text
    payload = completed.json()
    assert payload["status"] == "completed"
    assert payload["completed_at"]
    assert isinstance(payload["score"], float)
    assert payload["gaps_count"] >= 1
    assert len(payload["gaps"]) == payload["gaps_count"]
    assert payload["gaps"][0]["recommendation"]
    assert "weighted" in payload["summary"]
    assert "not a certification" in payload["summary"]

    again = auth_client.post(f"/api/v1/compliance/assessments/{detail['id']}/complete")
    assert again.status_code == 409
    locked = auth_client.patch(
        f"/api/v1/compliance/assessments/{detail['id']}/controls/{control['id']}",
        json={"status": "compliant"},
    )
    assert locked.status_code == 409


def test_gap_analysis_reports_current_gaps(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    detail = _create_assessment(auth_client)
    control = _control(detail, "NIS2-04")
    auth_client.patch(
        f"/api/v1/compliance/assessments/{detail['id']}/controls/{control['id']}",
        json={"status": "non_compliant"},
    )
    auth_client.post(f"/api/v1/compliance/assessments/{detail['id']}/complete")

    response = auth_client.get(f"/api/v1/compliance/assessments/{detail['id']}/gap-analysis")
    assert response.status_code == 200, response.text
    analysis = response.json()
    assert analysis["framework_code"] == "NIS2"
    assert analysis["gap_count"] == len(analysis["gaps"])
    assert analysis["gap_count"] >= 1
    assert analysis["gaps_by_severity"]
    for gap in analysis["gaps"]:
        assert gap["severity"] in {"critical", "high", "medium", "low"}
        assert gap["recommendation"]
        assert gap["status"] in {"partial", "non_compliant", "not_assessed"}


def test_compliance_summary_exposes_posture_and_disclaimer(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    detail = _create_assessment(auth_client)
    auth_client.post(f"/api/v1/compliance/assessments/{detail['id']}/complete")

    response = auth_client.get("/api/v1/compliance/summary")
    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["organization_name"] == "HISPANSHIELD Test Organisation"
    assert summary["assessed_frameworks"] == 1
    assert summary["average_score"] is not None
    assert "not a certification" in summary["disclaimer"]
    nis2 = next(item for item in summary["frameworks"] if item["framework_code"] == "NIS2")
    assert nis2["assessment_id"] == detail["id"]
    assert nis2["controls_total"] == 12
    assert (
        nis2["compliant"] + nis2["partial"] + nis2["non_compliant"] + nis2["not_applicable"] + nis2["not_assessed"]
        == 12
    )


def test_cross_tenant_assessment_is_not_visible(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    framework = db.execute(select(ComplianceFramework).where(ComplianceFramework.code == "NIS2")).scalar_one()
    foreign_org = Organization(slug="other-assessment-org", name="Other Assessment Org")
    db.add(foreign_org)
    db.flush()
    foreign = ComplianceAssessment(
        org_id=foreign_org.id,
        framework_id=framework.id,
        framework_version=framework.version,
        status="in_progress",
        score=0.0,
    )
    db.add(foreign)
    db.flush()
    db.add(
        ComplianceControlStatus(
            assessment_id=foreign.id,
            control_id=db.execute(select(ComplianceControl.id).where(ComplianceControl.framework_id == framework.id))
            .scalars()
            .first(),
            status="compliant",
        )
    )
    db.commit()

    assert auth_client.get(f"/api/v1/compliance/assessments/{foreign.id}").status_code == 404
    assert auth_client.get(f"/api/v1/compliance/assessments/{foreign.id}/gap-analysis").status_code == 404
    assert auth_client.post(f"/api/v1/compliance/assessments/{foreign.id}/complete").status_code == 404
    assert (
        auth_client.patch(
            f"/api/v1/compliance/assessments/{foreign.id}/controls/{uuid.uuid4()}",
            json={"status": "compliant"},
        ).status_code
        == 404
    )


def test_invalid_import_returns_422(seeded, auth_client: TestClient) -> None:
    response = auth_client.post(
        "/api/v1/compliance/frameworks/import",
        json={"content": '{"code": "BROKEN"}', "format": "json"},
    )
    assert response.status_code == 422


def test_framework_import_is_versioned_and_idempotent(seeded, auth_client: TestClient, db) -> None:
    first = auth_client.post(
        "/api/v1/compliance/frameworks/import",
        json={"content": CUSTOM_FRAMEWORK, "format": "yaml"},
    )
    assert first.status_code == 201, first.text
    payload = first.json()
    assert payload["created"] is True
    assert payload["controls_imported"] == 1
    assert len(payload["checksum"]) == 64
    assert payload["framework"]["code"] == "CUSTOM-1"
    assert payload["framework"]["is_builtin"] is False

    second = auth_client.post(
        "/api/v1/compliance/frameworks/import",
        json={"content": CUSTOM_FRAMEWORK, "format": "yaml"},
    )
    assert second.status_code == 200, second.text
    assert second.json()["created"] is False
    assert second.json()["checksum"] == payload["checksum"]

    listed = auth_client.get("/api/v1/compliance/frameworks", params={"code": "CUSTOM-1"})
    assert listed.status_code == 200
    assert listed.json()["items"][0]["controls_count"] == 1
    audits = db.execute(
        select(func.count()).select_from(AuditRecord).where(AuditRecord.action == "compliance.framework.import")
    ).scalar_one()
    assert audits == 2


def test_viewer_can_read_but_not_assess(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    detail = _create_assessment(auth_client)
    control = _control(detail, "NIS2-01")
    _add_member(db, seeded["org"], "viewer@example.eu", "viewer")

    auth_client.cookies.clear()
    login(auth_client, email="viewer@example.eu", password=MEMBER_PASSWORD)

    assert auth_client.get("/api/v1/compliance/frameworks").status_code == 200
    assert auth_client.get("/api/v1/compliance/assessments").status_code == 200
    assert auth_client.post("/api/v1/compliance/assessments", json={"code": "NIS2"}).status_code == 403
    assert (
        auth_client.patch(
            f"/api/v1/compliance/assessments/{detail['id']}/controls/{control['id']}",
            json={"status": "compliant"},
        ).status_code
        == 403
    )
    assert auth_client.post(f"/api/v1/compliance/assessments/{detail['id']}/complete").status_code == 403
    assert (
        auth_client.post(
            "/api/v1/compliance/frameworks/import",
            json={"content": CUSTOM_FRAMEWORK, "format": "yaml"},
        ).status_code
        == 403
    )


def test_non_platform_admin_cannot_import(seeded, auth_client: TestClient, db) -> None:
    _add_member(db, seeded["org"], "admin2@example.eu", "org_admin")
    auth_client.cookies.clear()
    login(auth_client, email="admin2@example.eu", password=MEMBER_PASSWORD)
    response = auth_client.post(
        "/api/v1/compliance/frameworks/import",
        json={"content": CUSTOM_FRAMEWORK, "format": "yaml"},
    )
    assert response.status_code == 403


def test_unknown_framework_and_assessment_return_404(seeded, auth_client: TestClient, db) -> None:
    _seed(db)
    assert auth_client.get("/api/v1/compliance/frameworks/NOT-A-FRAMEWORK").status_code == 404
    assert auth_client.post("/api/v1/compliance/assessments", json={"code": "NOT-A-FRAMEWORK"}).status_code == 404
    assert auth_client.get(f"/api/v1/compliance/assessments/{uuid.uuid4()}").status_code == 404
