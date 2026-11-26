"""AC-84: IEC 62443 conduits require required_sl and compensating controls at SL>=3."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.modules.compliance.service import seed_builtin_frameworks


def _control(detail: dict, control_code: str) -> dict:
    for control in detail["controls"]:
        if control["control_code"] == control_code:
            return control
    raise AssertionError(f"control {control_code} not found")


def _assessment_control(auth_client: TestClient, control_code: str) -> dict:
    assessment = auth_client.post("/api/v1/compliance/assessments", json={"code": "IEC62443-3-3"})
    assert assessment.status_code == 201, assessment.text
    detail = auth_client.get(f"/api/v1/compliance/assessments/{assessment.json()['id']}").json()
    return _control(detail, control_code)


def test_conduit_requires_required_sl(auth_client: TestClient) -> None:
    missing = auth_client.post(
        "/api/v1/zones",
        json={"name": "PLANT-to-DMZ", "kind": "conduit", "metadata": {}},
    )
    assert missing.status_code == 422
    assert missing.json()["error"]["details"][0]["field"] == "metadata.required_sl"

    valid = auth_client.post(
        "/api/v1/zones",
        json={"name": "PLANT-to-DMZ", "kind": "conduit", "metadata": {"required_sl": 3}},
    )
    assert valid.status_code == 201, valid.text

    conduit_id = valid.json()["id"]
    broken = auth_client.patch(
        f"/api/v1/zones/{conduit_id}",
        json={"metadata": {"note": "no sl anymore"}},
    )
    assert broken.status_code == 422


def test_assessment_marks_gap_for_uncompensated_sl3_conduit(auth_client: TestClient, seeded, db) -> None:
    seed_builtin_frameworks(db)
    auth_client.post("/api/v1/zones", json={"name": "PLANT", "kind": "zone"})
    conduit = auth_client.post(
        "/api/v1/zones",
        json={"name": "PLANT-to-DMZ", "kind": "conduit", "metadata": {"required_sl": 3}},
    )
    assert conduit.status_code == 201, conduit.text
    conduit_id = conduit.json()["id"]

    control = _assessment_control(auth_client, "IEC-5")
    assert control["status"] == "non_compliant"
    assert "FAIL segmentation" in (control["notes"] or "")
    assert "compensating control" in (control["notes"] or "")

    # Documenting a compensating control clears the specific gap.
    patched = auth_client.patch(
        f"/api/v1/zones/{conduit_id}",
        json={
            "metadata": {
                "required_sl": 3,
                "compensating_controls": "Unidirectional gateway with protocol break and IDS monitoring",
            }
        },
    )
    assert patched.status_code == 200, patched.text
    cleared = _assessment_control(auth_client, "IEC-5")
    assert cleared["status"] == "compliant"
    assert "FAIL segmentation" not in (cleared["notes"] or "")
