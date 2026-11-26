"""Incident lifecycle, timeline, evidence and metrics integration tests."""

from __future__ import annotations

import hashlib
import re
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.assets import Asset
from app.models.core import AuditRecord
from app.models.incidents import Evidence, Incident, IncidentTimeline
from tests.conftest import ADMIN_EMAIL, login

API = "/api/v1/incidents"


def _create(client: TestClient, **overrides) -> dict:
    payload = {"title": "Suspicious activity detected", "severity": "high", **overrides}
    response = client.post(API, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _walk_to_recovered(client: TestClient, incident_id: str) -> None:
    for status in ("triage", "investigating", "contained", "eradicated", "recovered"):
        response = client.post(f"{API}/{incident_id}/status", json={"status": status})
        assert response.status_code == 200, response.text


def _add_member(client: TestClient, email: str, password: str, role: str) -> None:
    response = client.post(
        "/api/v1/organizations/current/members",
        json={"email": email, "full_name": "Test Member", "role": role, "password": password},
    )
    assert response.status_code == 201, response.text


def test_create_incident_and_reference_sequence(auth_client: TestClient) -> None:
    first = _create(auth_client)
    second = _create(auth_client, title="Second incident", severity="low")
    assert re.fullmatch(r"HS-\d{4}-\d{4}", first["ref"])
    assert re.fullmatch(r"HS-\d{4}-\d{4}", second["ref"])
    first_number = int(first["ref"].rsplit("-", 1)[-1])
    second_number = int(second["ref"].rsplit("-", 1)[-1])
    assert second_number == first_number + 1
    assert first["status"] == "new"
    assert first["priority"] == 2
    assert first["sla_due_at"] is not None
    assert [entry["kind"] for entry in first["timeline"]] == ["created"]


def test_list_filters_sorting_and_pagination(auth_client: TestClient) -> None:
    high = _create(auth_client, title="Ransomware beacon", severity="critical")
    _create(auth_client, title="Phishing mail", severity="low")
    _create(auth_client, title="Ransomware staging", severity="critical")

    filtered = auth_client.get(API, params={"severity": "critical", "q": "ransomware"})
    assert filtered.status_code == 200
    body = filtered.json()
    assert body["meta"]["total"] == 2
    assert all("ransomware" in item["title"].lower() for item in body["items"])

    sorted_response = auth_client.get(API, params={"sort": "ref", "order": "asc", "page_size": 2})
    assert sorted_response.status_code == 200
    assert len(sorted_response.json()["items"]) == 2
    assert sorted_response.json()["meta"]["has_next"] is True

    invalid = auth_client.get(API, params={"sort": "drop table"})
    assert invalid.status_code == 422
    assert auth_client.get(API, params={"date_from": "2026-01-01T00:00:00Z"}).status_code == 200
    assert auth_client.get(API, params={"assignee": str(high["assignee_id"] or uuid4())}).status_code == 200


def test_lifecycle_transitions_and_invalid_transition(auth_client: TestClient) -> None:
    incident = _create(auth_client)
    incident_id = incident["id"]

    invalid_jump = auth_client.post(f"{API}/{incident_id}/status", json={"status": "closed"})
    assert invalid_jump.status_code == 409

    triaged = auth_client.post(f"{API}/{incident_id}/status", json={"status": "triage"})
    assert triaged.status_code == 200
    assert triaged.json()["status"] == "triage"

    backwards = auth_client.post(f"{API}/{incident_id}/status", json={"status": "new"})
    assert backwards.status_code == 409

    for status in ("investigating", "contained"):
        assert auth_client.post(f"{API}/{incident_id}/status", json={"status": status}).status_code == 200
    contained = auth_client.get(f"{API}/{incident_id}").json()
    assert contained["contained_at"] is not None

    for status in ("eradicated", "recovered"):
        assert auth_client.post(f"{API}/{incident_id}/status", json={"status": status}).status_code == 200
    recovered = auth_client.get(f"{API}/{incident_id}").json()
    assert recovered["resolved_at"] is not None

    missing = auth_client.post(f"{API}/{incident_id}/status", json={"status": "closed"})
    assert missing.status_code == 422

    closed = auth_client.post(
        f"{API}/{incident_id}/status",
        json={
            "status": "closed",
            "root_cause": "Credential reuse enabled access to the VPN gateway",
            "lessons_learned": "Enforce phishing-resistant MFA for all remote access",
        },
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "closed"
    assert closed.json()["closed_at"] is not None
    statuses = [entry["kind"] for entry in closed.json()["timeline"]]
    assert statuses.count("status_change") == 6


def test_close_requires_incident_close_permission(auth_client: TestClient, db) -> None:
    _add_member(auth_client, "analyst@hispanshield.eu", "Guardian-Str0ng-Pass!9", "soc_analyst")
    incident = _create(auth_client)
    _walk_to_recovered(auth_client, incident["id"])

    auth_client.cookies.clear()
    login(auth_client, email="analyst@hispanshield.eu", password="Guardian-Str0ng-Pass!9")
    still_open = auth_client.post(f"{API}/{incident['id']}/status", json={"status": "triage"})
    assert still_open.status_code == 409

    denied = auth_client.post(
        f"{API}/{incident['id']}/status",
        json={
            "status": "closed",
            "root_cause": "The analyst lacks the closing permission for this action",
            "lessons_learned": "Only incident commanders close major incidents",
        },
    )
    assert denied.status_code == 403
    assert db.get(Incident, UUID(incident["id"])).status == "recovered"


def test_cross_tenant_incident_is_404(seeded, auth_client: TestClient, db) -> None:
    from app.models.core import Organization

    other = Organization(slug="foreign-incidents", name="Foreign Incidents")
    db.add(other)
    db.commit()
    foreign = Incident(
        org_id=other.id,
        ref="HS-2026-9001",
        title="Foreign incident",
        severity="critical",
        status="new",
        priority=1,
        mitre=[],
        affected_asset_ids=[],
    )
    db.add(foreign)
    db.commit()

    assert auth_client.get(f"{API}/{foreign.id}").status_code == 404
    assert auth_client.patch(f"{API}/{foreign.id}", json={"title": "hijack"}).status_code == 404
    assert auth_client.post(f"{API}/{foreign.id}/timeline", json={"summary": "hijack"}).status_code == 404
    assert auth_client.post(f"{API}/{foreign.id}/status", json={"status": "triage"}).status_code == 404


def test_timeline_notes_and_pagination(auth_client: TestClient) -> None:
    incident = _create(auth_client)
    for index in range(3):
        response = auth_client.post(
            f"{API}/{incident['id']}/timeline",
            json={"kind": "note", "summary": f"Analyst note {index}", "detail": {"index": index}},
        )
        assert response.status_code == 201, response.text

    timeline = auth_client.get(f"{API}/{incident['id']}/timeline")
    assert timeline.status_code == 200
    assert timeline.json()["meta"]["total"] == 4
    notes = auth_client.get(f"{API}/{incident['id']}/timeline", params={"kind": "note"})
    assert notes.json()["meta"]["total"] == 3
    assert notes.json()["items"][0]["actor"] == ADMIN_EMAIL

    invalid = auth_client.post(f"{API}/{incident['id']}/timeline", json={"kind": "note", "summary": "x"})
    assert invalid.status_code == 422


def test_evidence_upload_hash_download_and_seal(auth_client: TestClient, db, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    incident = _create(auth_client)
    content = b"2026-11-26T10:00:00Z ssh login failure src=203.0.113.9\n"
    response = auth_client.post(
        f"{API}/{incident['id']}/evidence",
        files={"file": ("auth.log", content, "text/plain")},
        data={"title": "SSH authentication log", "kind": "log"},
    )
    assert response.status_code == 201, response.text
    evidence = response.json()
    assert evidence["sha256"] == hashlib.sha256(content).hexdigest()
    assert evidence["size_bytes"] == len(content)
    assert evidence["sealed"] is False
    assert evidence["content_type"] == "text/plain"
    assert evidence["chain_of_custody"][0]["action"] == "collected"

    stored = db.execute(select(Evidence).where(Evidence.id == UUID(evidence["id"]))).scalar_one()
    assert stored.storage_path.startswith(str(stored.org_id))
    assert ".." not in stored.storage_path
    assert (tmp_path / "evidence" / stored.storage_path).is_file()

    download = auth_client.get(f"{API}/evidence/{evidence['id']}/download")
    assert download.status_code == 200
    assert download.content == content
    assert "attachment" in download.headers["content-disposition"]
    assert download.headers["x-content-sha256"] == evidence["sha256"]

    sealed = auth_client.post(f"{API}/evidence/{evidence['id']}/seal")
    assert sealed.status_code == 200, sealed.text
    assert sealed.json()["sealed"] is True
    assert len(sealed.json()["chain_of_custody"]) == 2
    assert auth_client.post(f"{API}/evidence/{evidence['id']}/seal").status_code == 409


def test_evidence_rejects_spoofed_magic_and_unsupported(auth_client: TestClient, db, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    incident = _create(auth_client)

    spoofed = auth_client.post(
        f"{API}/{incident['id']}/evidence",
        files={"file": ("screenshot.png", b"this is definitely not a png", "image/png")},
    )
    assert spoofed.status_code == 422

    unsupported = auth_client.post(
        f"{API}/{incident['id']}/evidence",
        files={"file": ("payload.exe", b"MZ\x90\x00", "application/octet-stream")},
    )
    assert unsupported.status_code == 422

    empty = auth_client.post(
        f"{API}/{incident['id']}/evidence",
        files={"file": ("empty.txt", b"", "text/plain")},
    )
    assert empty.status_code == 422

    traversal = auth_client.post(
        f"{API}/{incident['id']}/evidence",
        files={"file": ("../../etc/passwd.txt", b"root:x:0:0\n", "text/plain")},
        data={"title": "Traversal attempt"},
    )
    assert traversal.status_code == 201
    stored = db.execute(select(Evidence).where(Evidence.id == UUID(traversal.json()["id"]))).scalar_one()
    assert ".." not in stored.storage_path
    assert (tmp_path / "evidence" / stored.storage_path).is_file()


def test_evidence_size_limit(auth_client: TestClient, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    from app.services import forensic_evidence

    monkeypatch.setattr(forensic_evidence, "MAX_EVIDENCE_BYTES", 1024)
    incident = _create(auth_client)
    response = auth_client.post(
        f"{API}/{incident['id']}/evidence",
        files={"file": ("large.log", b"x" * 4096, "text/plain")},
    )
    assert response.status_code == 413


def test_evidence_download_requires_write_role(auth_client: TestClient, monkeypatch, tmp_path, db) -> None:
    monkeypatch.setenv("HS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    incident = _create(auth_client)
    upload = auth_client.post(
        f"{API}/{incident['id']}/evidence",
        files={"file": ("notes.txt", b"sensitive evidence", "text/plain")},
        data={"title": "Sensitive notes"},
    )
    assert upload.status_code == 201
    evidence_id = upload.json()["id"]

    _add_member(auth_client, "viewer@hispanshield.eu", "Guardian-Str0ng-Pass!9", "viewer")
    auth_client.cookies.clear()
    login(auth_client, email="viewer@hispanshield.eu", password="Guardian-Str0ng-Pass!9")
    denied = auth_client.get(f"{API}/evidence/{evidence_id}/download")
    assert denied.status_code == 403

    denial = db.execute(
        select(AuditRecord).where(AuditRecord.action == "incident.evidence.download", AuditRecord.outcome == "failure")
    ).scalars()
    assert list(denial)


def test_evidence_cross_tenant_download_is_404(seeded, auth_client: TestClient, db, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    from app.models.core import Organization

    other = Organization(slug="foreign-evidence", name="Foreign Evidence")
    db.add(other)
    db.commit()
    evidence = Evidence(
        org_id=other.id,
        incident_id=None,
        kind="log",
        title="Foreign evidence",
        sha256="0" * 64,
        storage_path="missing/file.txt",
        content_type="text/plain",
        size_bytes=1,
        chain_of_custody=[],
    )
    db.add(evidence)
    db.commit()
    assert auth_client.get(f"{API}/evidence/{evidence.id}/download").status_code == 404
    assert auth_client.post(f"{API}/evidence/{evidence.id}/seal").status_code == 404


def test_metrics_open_by_severity_and_mttr(auth_client: TestClient) -> None:
    critical = _create(auth_client, severity="critical")
    _create(auth_client, severity="low")
    closed = _create(auth_client, severity="medium")
    _walk_to_recovered(auth_client, closed["id"])
    closed_response = auth_client.post(
        f"{API}/{closed['id']}/status",
        json={
            "status": "closed",
            "root_cause": "Misconfigured service account exposed an internal endpoint",
            "lessons_learned": "Rotate service credentials and alert on unexpected grants",
        },
    )
    assert closed_response.status_code == 200

    metrics = auth_client.get(f"{API}/metrics")
    assert metrics.status_code == 200
    body = metrics.json()
    assert body["total"] == 3
    assert body["closed_total"] == 1
    assert body["open_total"] == 2
    assert body["open_by_severity"]["critical"] == 1
    assert body["open_by_severity"]["low"] == 1
    assert body["mttr_seconds"] is not None
    assert critical["status"] == "new"


def test_patch_assignment_severity_and_validation(auth_client: TestClient, seeded, db) -> None:
    incident = _create(auth_client)
    updated = auth_client.patch(
        f"{API}/{incident['id']}",
        json={
            "severity": "critical",
            "assignee_id": str(seeded["user"].id),
            "commander_id": str(seeded["user"].id),
            "mitre": ["T1566", "T1078"],
        },
    )
    assert updated.status_code == 200, updated.text
    body = updated.json()
    assert body["severity"] == "critical"
    assert body["priority"] == 1
    assert body["assignee_id"] == str(seeded["user"].id)
    kinds = [entry["kind"] for entry in body["timeline"]]
    assert "severity_change" in kinds and "assignment" in kinds and "commander" in kinds

    invalid_assignee = auth_client.patch(f"{API}/{incident['id']}", json={"assignee_id": str(uuid4())})
    assert invalid_assignee.status_code == 422

    asset = Asset(
        org_id=seeded["org"].id,
        asset_key="srv-1",
        name="Server 1",
        kind="host",
        ip_addresses=["10.0.0.5"],
    )
    db.add(asset)
    db.commit()
    with_asset = auth_client.patch(f"{API}/{incident['id']}", json={"affected_asset_ids": [str(asset.id)]})
    assert with_asset.status_code == 200, with_asset.text
    assert with_asset.json()["affected_asset_ids"] == [str(asset.id)]
    assert with_asset.json()["assets"][0]["name"] == "Server 1"

    unknown_asset = auth_client.patch(f"{API}/{incident['id']}", json={"affected_asset_ids": [str(uuid4())]})
    assert unknown_asset.status_code == 422


def test_closed_incident_cannot_be_patched(auth_client: TestClient) -> None:
    incident = _create(auth_client)
    _walk_to_recovered(auth_client, incident["id"])
    closed = auth_client.post(
        f"{API}/{incident['id']}/status",
        json={
            "status": "closed",
            "root_cause": "Exposed debug endpoint allowed unauthenticated access",
            "lessons_learned": "Disable debug surfaces before production deployment",
        },
    )
    assert closed.status_code == 200
    patched = auth_client.patch(f"{API}/{incident['id']}", json={"title": "Reopen attempt"})
    assert patched.status_code == 409


def test_incident_detail_links_alerts_and_assets(auth_client: TestClient, seeded, db) -> None:
    asset = Asset(
        org_id=seeded["org"].id,
        asset_key="endpoint-42",
        name="Endpoint 42",
        kind="host",
        criticality=5,
        ip_addresses=["203.0.113.42"],
    )
    db.add(asset)
    db.commit()
    incident = _create(auth_client, affected_asset_ids=[str(asset.id)])
    detail = auth_client.get(f"{API}/{incident['id']}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["assets"][0]["id"] == str(asset.id)
    assert body["assets"][0]["criticality"] == 5
    assert body["alerts"] == []
    assert body["remediations"] == []
    assert len(body["timeline"]) == 1
    assert isinstance(body["evidence"], list)

    from app.models.events import Alert

    alert = Alert(
        org_id=seeded["org"].id,
        title="Credential stuffing",
        severity="high",
        status="triaged",
        incident_id=incident["id"],
        event_ids=[1, 2],
        mitre=["T1110"],
        evidence={},
    )
    db.add(alert)
    db.commit()
    refreshed = auth_client.get(f"{API}/{incident['id']}").json()
    assert refreshed["alerts"][0]["title"] == "Credential stuffing"


def test_incident_requires_authentication(client: TestClient) -> None:
    assert client.get(API).status_code == 401


def test_incident_not_found(auth_client: TestClient) -> None:
    assert auth_client.get(f"{API}/{uuid4()}").status_code == 404
    assert auth_client.get(f"{API}/evidence/{uuid4()}/download").status_code == 404
    assert auth_client.post(f"{API}/evidence/{uuid4()}/seal").status_code == 404


def test_incident_timeline_counts_status_changes(auth_client: TestClient, db) -> None:
    incident = _create(auth_client)
    _walk_to_recovered(auth_client, incident["id"])
    rows = list(
        db.execute(select(IncidentTimeline).where(IncidentTimeline.incident_id == UUID(incident["id"]))).scalars()
    )
    status_changes = [row for row in rows if row.kind == "status_change"]
    assert len(status_changes) == 5
    assert all(row.actor for row in status_changes)
    assert all(row.detail.get("to") for row in status_changes)
