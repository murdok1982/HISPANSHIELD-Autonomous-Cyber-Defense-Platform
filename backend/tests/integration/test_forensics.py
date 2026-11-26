"""Integration tests: forensic cases, evidence integrity, custody and exports."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile

from fastapi.testclient import TestClient

from app.core.db import utcnow
from app.models.core import Organization
from app.models.events import Alert
from app.models.incidents import Evidence, Incident, IncidentTimeline
from app.modules.forensics import service
from tests.conftest import login

BASE = "/api/v1/forensics"


def _case(db, org_id, *, ref: str = "CASE-0001", status: str = "investigating") -> Incident:
    incident = Incident(
        org_id=org_id,
        ref=ref,
        title=f"Investigation {ref}",
        description="Suspected ransomware staging",
        severity="high",
        status=status,
        priority=2,
        detected_at=utcnow(),
        mitre=["T1486"],
    )
    db.add(incident)
    db.flush()
    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            org_id=org_id,
            at=utcnow(),
            kind="created",
            actor="analyst@example.eu",
            summary="Case opened from alert",
            detail={"alert": "A-1"},
        )
    )
    db.commit()
    return incident


def _evidence(
    db,
    org_id,
    incident: Incident,
    tmp_path,
    *,
    storage_path: str,
    content: bytes = b"forensic log contents",
    title: str = "Firewall log",
    kind: str = "log",
) -> Evidence:
    if storage_path and not storage_path.startswith(".."):
        target = tmp_path / storage_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    evidence = Evidence(
        org_id=org_id,
        incident_id=incident.id,
        kind=kind,
        title=title,
        sha256=digest,
        storage_path=storage_path,
        content_type="text/plain",
        size_bytes=len(content),
        collected_by="responder@example.eu",
        chain_of_custody=[{"at": utcnow().isoformat(), "action": "collected", "actor": "responder@example.eu"}],
    )
    db.add(evidence)
    db.commit()
    return evidence


def test_empty_case_list(seeded, auth_client: TestClient) -> None:
    response = auth_client.get(f"{BASE}/cases")
    assert response.status_code == 200
    assert response.json() == {
        "items": [],
        "meta": {"total": 0, "page": 1, "page_size": 25, "pages": 0, "has_next": False},
    }


def test_case_list_and_detail_with_counts(seeded, auth_client: TestClient, db, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "EVIDENCE_ROOT", tmp_path.resolve())
    incident = _case(db, seeded["org"].id)
    _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="a.log", title="Evidence A")
    _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="b.log", title="Evidence B", kind="memory")
    db.add(
        Alert(
            org_id=seeded["org"].id,
            title="Ransomware staging detected",
            severity="critical",
            status="new",
            incident_id=incident.id,
            event_ids=[],
            mitre=["T1486"],
        )
    )
    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            org_id=seeded["org"].id,
            at=utcnow(),
            kind="note",
            actor="analyst@example.eu",
            summary="Evidence acquired",
            detail={},
        )
    )
    db.commit()

    listed = auth_client.get(f"{BASE}/cases", params={"severity": "high", "q": "ransomware"})
    assert listed.status_code == 200, listed.text
    item = listed.json()["items"][0]
    assert item["ref"] == "CASE-0001"
    assert item["evidence_count"] == 2
    assert item["alert_count"] == 1

    detail = auth_client.get(f"{BASE}/cases/{incident.id}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert len(body["timeline"]) == 2
    assert len(body["evidence"]) == 2
    assert body["alerts"][0]["title"] == "Ransomware staging detected"
    assert body["case"]["mitre"] == ["T1486"]


def test_evidence_filters(seeded, auth_client: TestClient, db, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "EVIDENCE_ROOT", tmp_path.resolve())
    incident = _case(db, seeded["org"].id)
    _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="one.log", title="Auth log", kind="log")
    memory = _evidence(
        db, seeded["org"].id, incident, tmp_path, storage_path="mem.raw", title="Memory dump", kind="memory"
    )
    memory.sealed = True
    db.commit()

    by_kind = auth_client.get(f"{BASE}/evidence", params={"kind": "memory"})
    assert by_kind.status_code == 200
    assert by_kind.json()["meta"]["total"] == 1
    assert by_kind.json()["items"][0]["title"] == "Memory dump"
    assert by_kind.json()["items"][0]["chain_length"] == 1

    sealed = auth_client.get(f"{BASE}/evidence", params={"sealed": True})
    assert sealed.json()["meta"]["total"] == 1

    by_case = auth_client.get(f"{BASE}/evidence", params={"incident_id": str(incident.id)})
    assert by_case.json()["meta"]["total"] == 2

    by_query = auth_client.get(f"{BASE}/evidence", params={"q": "auth"})
    assert by_query.json()["meta"]["total"] == 1


def test_verify_hash_match_appends_custody(seeded, auth_client: TestClient, db, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "EVIDENCE_ROOT", tmp_path.resolve())
    incident = _case(db, seeded["org"].id)
    content = b"immutable log line\n"
    evidence = _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="verify.log", content=content)

    verified = auth_client.post(f"{BASE}/evidence/{evidence.id}/verify-hash")
    assert verified.status_code == 200, verified.text
    body = verified.json()
    assert body["match"] is True
    assert body["status"] == "match"
    assert body["computed_sha256"] == hashlib.sha256(content).hexdigest()
    assert body["file_size"] == len(content)
    assert len(body["chain_of_custody"]) == 2

    custody = auth_client.get(f"{BASE}/evidence/{evidence.id}/chain-of-custody")
    assert custody.status_code == 200
    chain = custody.json()
    assert chain["entries"][-1]["result"] == "match"
    assert chain["entries"][-1]["action"] == "verify_hash"
    assert chain["last_verified_at"] is not None


def test_verify_hash_detects_tampering(seeded, auth_client: TestClient, db, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "EVIDENCE_ROOT", tmp_path.resolve())
    incident = _case(db, seeded["org"].id)
    evidence = _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="tamper.log")
    (tmp_path / "tamper.log").write_bytes(b"modified after collection")

    verified = auth_client.post(f"{BASE}/evidence/{evidence.id}/verify-hash")
    assert verified.status_code == 200
    assert verified.json()["match"] is False
    assert verified.json()["status"] == "mismatch"

    custody = auth_client.get(f"{BASE}/evidence/{evidence.id}/chain-of-custody").json()
    assert custody["entries"][-1]["result"] == "mismatch"


def test_verify_hash_missing_file(seeded, auth_client: TestClient, db, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "EVIDENCE_ROOT", tmp_path.resolve())
    incident = _case(db, seeded["org"].id)
    evidence = _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="")
    (tmp_path / "deleted.log").unlink(missing_ok=True)
    evidence.storage_path = "deleted.log"
    db.commit()

    verified = auth_client.post(f"{BASE}/evidence/{evidence.id}/verify-hash")
    assert verified.status_code == 200
    assert verified.json()["status"] == "file_missing"
    assert verified.json()["match"] is False
    assert verified.json()["computed_sha256"] is None


def test_case_export_contains_manifest_and_reports_missing_items(
    seeded, auth_client: TestClient, db, tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(service, "EVIDENCE_ROOT", tmp_path.resolve())
    incident = _case(db, seeded["org"].id, ref="CASE-EXPORT-1")
    payload = b"PCAP-ish bytes for export"
    _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="present.log", content=payload, title="Present")
    _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="", title="Missing").storage_path = "gone.log"
    db.commit()

    export = auth_client.post(f"{BASE}/cases/{incident.id}/export")
    assert export.status_code == 200, export.text
    content = export.content
    assert export.headers["content-type"] == "application/zip"
    assert export.headers["x-content-sha256"] == hashlib.sha256(content).hexdigest()
    assert "CASE-EXPORT-1" in export.headers["content-disposition"]
    assert export.headers["x-evidence-missing"] == "1"

    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        names = archive.namelist()
        assert "manifest.json" in names
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["case"]["ref"] == "CASE-EXPORT-1"
        assert manifest["summary"]["evidence_included"] == 1
        assert manifest["summary"]["evidence_missing"] == 1
        statuses = {item["title"]: item["status"] for item in manifest["evidence"]}
        assert statuses["Present"] == "included"
        assert statuses["Missing"] == "missing"
        included_name = next(name for name in names if name != "manifest.json")
        assert archive.read(included_name) == payload


def test_export_never_follows_path_traversal(seeded, auth_client: TestClient, db, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "EVIDENCE_ROOT", tmp_path.resolve())
    incident = _case(db, seeded["org"].id, ref="CASE-TRAVERSAL")
    evidence = _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="")
    evidence.storage_path = "../../../../etc/passwd"
    db.commit()

    listed = auth_client.get(f"{BASE}/evidence", params={"incident_id": str(incident.id)})
    assert listed.status_code == 200
    assert listed.json()["items"][0]["has_file"] is False

    verified = auth_client.post(f"{BASE}/evidence/{evidence.id}/verify-hash")
    assert verified.status_code == 200
    assert verified.json()["status"] == "path_outside_evidence_root"

    export = auth_client.post(f"{BASE}/cases/{incident.id}/export")
    assert export.status_code == 200
    with zipfile.ZipFile(io.BytesIO(export.content)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["evidence"][0]["status"] == "error"
        assert manifest["evidence"][0]["error"] == "path_outside_evidence_root"


def test_timeline_export_csv_and_json(seeded, auth_client: TestClient, db) -> None:
    incident = _case(db, seeded["org"].id, ref="CASE-TIMELINE")
    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            org_id=seeded["org"].id,
            at=utcnow(),
            kind="containment",
            actor="responder@example.eu",
            summary="Host isolated",
            detail={"host": "srv-01"},
        )
    )
    db.commit()

    csv_export = auth_client.get(f"{BASE}/timeline/export", params={"incident_id": str(incident.id), "format": "csv"})
    assert csv_export.status_code == 200
    assert csv_export.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(csv_export.text)))
    assert rows[0] == ["at", "kind", "actor", "summary", "detail"]
    assert rows[1][1] == "created"
    assert rows[2][3] == "Host isolated"

    json_export = auth_client.get(f"{BASE}/timeline/export", params={"incident_id": str(incident.id), "format": "json"})
    assert json_export.status_code == 200
    body = json_export.json()
    assert body["ref"] == "CASE-TIMELINE"
    assert body["entry_count"] == 2
    assert body["entries"][1]["detail"]["host"] == "srv-01"

    invalid = auth_client.get(f"{BASE}/timeline/export", params={"incident_id": str(incident.id), "format": "pdf"})
    assert invalid.status_code == 422


def test_timeline_export_neutralises_spreadsheet_formulas(seeded, auth_client: TestClient, db) -> None:
    incident = _case(db, seeded["org"].id, ref="CASE-CSV-INJECTION")
    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            org_id=seeded["org"].id,
            at=utcnow(),
            kind="note",
            actor='=HYPERLINK("http://evil.example","click")',
            summary="=cmd|' /C calc'!A0",
            detail={"payload": "@SUM(1+1)"},
        )
    )
    db.commit()

    export = auth_client.get(f"{BASE}/timeline/export", params={"incident_id": str(incident.id), "format": "csv"})
    assert export.status_code == 200
    rows = list(csv.reader(io.StringIO(export.text)))
    # Every attacker-controlled cell that begins with a formula trigger must
    # start with a literal apostrophe so Excel/LibreOffice treat it as text.
    assert len(rows) == 3, rows
    assert rows[2][2].startswith("'="), rows
    assert rows[2][3].startswith("'="), rows
    assert rows[2][4] == '{"payload": "@SUM(1+1)"}', rows


def test_case_tenant_isolation_returns_404(seeded, auth_client: TestClient, db) -> None:
    foreign_org = Organization(slug="forensic-foreign", name="Foreign Forensics", country="ES", sector="energy")
    db.add(foreign_org)
    db.flush()
    foreign_case = Incident(
        org_id=foreign_org.id,
        ref="CASE-FOREIGN",
        title="Foreign case",
        severity="high",
        status="open",
        detected_at=utcnow(),
    )
    db.add(foreign_case)
    db.commit()

    assert auth_client.get(f"{BASE}/cases/{foreign_case.id}").status_code == 404
    assert auth_client.post(f"{BASE}/cases/{foreign_case.id}/export").status_code == 404


def test_rbac_viewer_cannot_verify_hashes(seeded, auth_client: TestClient, db, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "EVIDENCE_ROOT", tmp_path.resolve())
    incident = _case(db, seeded["org"].id)
    evidence = _evidence(db, seeded["org"].id, incident, tmp_path, storage_path="rbac.log")

    member = auth_client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": "viewer.forensics@hispanshield.eu",
            "full_name": "Viewer Forensics",
            "role": "viewer",
            "password": "Viewer-Forensic-Pass!9",
        },
    )
    assert member.status_code == 201, member.text
    login(auth_client, email="viewer.forensics@hispanshield.eu", password="Viewer-Forensic-Pass!9")

    assert auth_client.get(f"{BASE}/cases").status_code == 200
    denied = auth_client.post(f"{BASE}/evidence/{evidence.id}/verify-hash")
    assert denied.status_code == 403
