"""IoT/OT inventory, passive telemetry, baseline anomalies and IEC 62443 posture."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.models.events import Alert
from tests.conftest import break_glass, login

TELEMETRY_TIME = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)


def _iot_payload(key: str, **overrides) -> dict:
    payload = {
        "asset_key": key,
        "name": f"IoT {key}",
        "kind": "iot",
        "criticality": 2,
        "protocols": ["MQTT"],
        "connectivity": "wifi",
    }
    payload.update(overrides)
    return payload


def _ot_payload(key: str, **overrides) -> dict:
    payload = {
        "asset_key": key,
        "name": f"OT {key}",
        "kind": "ot",
        "criticality": 4,
        "protocols": ["Modbus TCP"],
    }
    payload.update(overrides)
    return payload


def _make_foreign_tenant(admin: TestClient, slug: str, email: str) -> None:
    org = admin.post("/api/v1/organizations", json={"name": f"Org {slug}", "slug": slug})
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]
    with break_glass(admin, org_id):
        member = admin.post(
            "/api/v1/organizations/current/members",
            json={
                "email": email,
                "full_name": "Foreign",
                "role": "vulnerability_manager",
                "password": "Str0ng-Viewer-Pass!2026",
            },
        )
        assert member.status_code == 201, member.text


def _login(email: str) -> TestClient:
    other = TestClient(app)
    login(other, email=email, password="Str0ng-Viewer-Pass!2026")
    return other


def test_iot_protocol_registry_and_device_crud(auth_client: TestClient) -> None:
    protocols = auth_client.get("/api/v1/iot/protocols")
    assert protocols.status_code == 200
    registry = protocols.json()
    assert len(registry) == 14
    names = {entry["name"] for entry in registry}
    assert {"MQTT", "MQTT/TLS", "CoAP", "OPC UA", "LoRaWAN", "Matter", "LTE-M"} <= names
    assert all(entry["read_only_default"] is True for entry in registry)
    mqtt_tls = next(entry for entry in registry if entry["name"] == "MQTT/TLS")
    assert mqtt_tls["default_ports"] == [8883]
    assert mqtt_tls["support_level"] == "full"

    created = auth_client.post(
        "/api/v1/iot/devices",
        json=_iot_payload("cam-01", protocols=["mqtt", "coap"], security_posture={"tls": False}),
    )
    assert created.status_code == 201, created.text
    device = created.json()
    assert device["protocols"] == ["MQTT", "CoAP"]
    assert "tls_disabled" in device["risk_flags"]
    asset_id = device["asset_id"]

    listing = auth_client.get("/api/v1/iot/devices", params={"protocol": "mqtt"})
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 1

    patched = auth_client.patch(
        f"/api/v1/iot/devices/{asset_id}", json={"connectivity": "ethernet", "security_posture": {"tls": True}}
    )
    assert patched.status_code == 200
    assert patched.json()["connectivity"] == "ethernet"
    assert "tls_disabled" not in patched.json()["risk_flags"]

    summary = auth_client.get("/api/v1/iot/summary")
    assert summary.status_code == 200
    assert summary.json()["total_devices"] == 1
    assert summary.json()["by_protocol"]["MQTT"] == 1

    assert auth_client.delete(f"/api/v1/iot/devices/{asset_id}").status_code == 204
    assert auth_client.get("/api/v1/iot/devices?q=cam-01").json()["meta"]["total"] == 0


def test_iot_device_validation(auth_client: TestClient) -> None:
    wrong_kind = auth_client.post("/api/v1/iot/devices", json=_iot_payload("bad-kind", kind="ot"))
    assert wrong_kind.status_code == 422

    unknown_protocol = auth_client.post("/api/v1/iot/devices", json=_iot_payload("bad-proto", protocols=["smoke"]))
    assert unknown_protocol.status_code == 422

    missing_zone = auth_client.post(
        "/api/v1/iot/devices",
        json=_iot_payload("bad-zone", zone_id="00000000-0000-0000-0000-000000000002"),
    )
    assert missing_zone.status_code == 404

    first = auth_client.post("/api/v1/iot/devices", json=_iot_payload("dup-iot"))
    assert first.status_code == 201
    duplicate = auth_client.post("/api/v1/iot/devices", json=_iot_payload("dup-iot"))
    assert duplicate.status_code == 409


def test_iot_telemetry_updates_last_seen_and_identities(auth_client: TestClient) -> None:
    device = auth_client.post("/api/v1/iot/devices", json=_iot_payload("sensor-01")).json()

    response = auth_client.post(
        "/api/v1/iot/telemetry",
        json={
            "items": [
                {
                    "asset_key": "sensor-01",
                    "protocol": "mqtt",
                    "observed_at": TELEMETRY_TIME.isoformat(),
                    "metrics": {"temperature": 21.5, "ip": "10.42.0.9", "mac": "aa:bb:cc:dd:ee:01"},
                }
            ]
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] == 1
    assert body["devices_updated"] == 1
    assert body["protocols"] == ["MQTT"]
    assert body["identities_upserted"] >= 3

    listed = auth_client.get("/api/v1/iot/devices", params={"q": "sensor-01"}).json()["items"][0]
    assert listed["last_telemetry_at"] is not None

    identities = auth_client.get(f"/api/v1/assets/{device['asset_id']}/identities").json()
    kinds = {identity["kind"] for identity in identities}
    assert {"telemetry_protocol", "ip", "mac"} <= kinds


def test_iot_telemetry_rejects_active_commands(auth_client: TestClient) -> None:
    auth_client.post("/api/v1/iot/devices", json=_iot_payload("actuator-01"))

    command = auth_client.post(
        "/api/v1/iot/telemetry",
        json={"items": [{"asset_key": "actuator-01", "protocol": "MQTT", "metrics": {"command": "unlock"}}]},
    )
    assert command.status_code == 403
    assert command.json()["error"]["code"] == "policy_denied"

    write = auth_client.post(
        "/api/v1/iot/telemetry",
        json={"items": [{"asset_key": "actuator-01", "protocol": "MQTT", "metrics": {"write_register": 1}}]},
    )
    assert write.status_code == 403

    operation = auth_client.post(
        "/api/v1/iot/telemetry",
        json={"items": [{"asset_key": "actuator-01", "protocol": "MQTT", "metrics": {"operation": "write"}}]},
    )
    assert operation.status_code == 403

    unknown = auth_client.post(
        "/api/v1/iot/telemetry",
        json={"items": [{"asset_key": "actuator-01", "protocol": "carrier-pigeon", "metrics": {"value": 1}}]},
    )
    assert unknown.status_code == 422


def test_ot_device_defaults_zone_and_passive_denial(auth_client: TestClient) -> None:
    zone = auth_client.post("/api/v1/zones", json={"name": "Purdue L1", "purdue_level": 1}).json()

    created = auth_client.post("/api/v1/ot/devices", json=_ot_payload("plc-01", zone_id=zone["id"]))
    assert created.status_code == 201, created.text
    device = created.json()
    assert device["passive_only"] is True
    assert device["safety_critical"] is True
    assert device["zone_name"] == "Purdue L1"

    denied = auth_client.post("/api/v1/ot/devices", json=_ot_payload("plc-active", passive_only=False))
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "policy_denied"

    patch_denied = auth_client.patch(f"/api/v1/ot/devices/{device['asset_id']}", json={"passive_only": False})
    assert patch_denied.status_code == 403

    listing = auth_client.get("/api/v1/ot/devices", params={"zone_id": zone["id"]})
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 1
    assert listing.json()["items"][0]["safety_critical"] is True

    protocols = auth_client.get("/api/v1/ot/protocols").json()
    assert len(protocols) >= 12
    modbus = next(entry for entry in protocols if entry["name"] == "Modbus TCP")
    assert modbus["safety_class"] == "process_critical"
    assert "write_register" in modbus["active_operations_denied"]
    assert all(entry["passive_only_default"] is True for entry in protocols)

    for suffix in ("scan", "reboot", "write"):
        active = auth_client.post(f"/api/v1/ot/devices/{device['asset_id']}/{suffix}")
        assert active.status_code in {404, 405}, suffix


def test_ot_telemetry_baseline_anomaly_and_dedupe(seeded, auth_client: TestClient, db) -> None:
    device = auth_client.post("/api/v1/ot/devices", json=_ot_payload("plc-baseline")).json()

    for index, value in enumerate([20.0, 20.2, 20.1, 20.3, 20.2, 20.1]):
        response = auth_client.post(
            "/api/v1/ot/telemetry",
            json={
                "items": [
                    {
                        "asset_id": device["asset_id"],
                        "protocol": "Modbus TCP",
                        "metric": "temperature",
                        "value": value,
                        "observed_at": (TELEMETRY_TIME + timedelta(minutes=index)).isoformat(),
                    }
                ]
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["anomalies"] == 0

    anomalous = auth_client.post(
        "/api/v1/ot/telemetry",
        json={
            "items": [
                {
                    "asset_id": device["asset_id"],
                    "protocol": "Modbus TCP",
                    "metric": "temperature",
                    "value": 95.0,
                    "observed_at": (TELEMETRY_TIME + timedelta(minutes=10)).isoformat(),
                }
            ]
        },
    )
    assert anomalous.status_code == 200, anomalous.text
    assert anomalous.json()["anomalies"] == 1
    assert anomalous.json()["alerts_created"] == 1

    duplicate = auth_client.post(
        "/api/v1/ot/telemetry",
        json={
            "items": [
                {
                    "asset_id": device["asset_id"],
                    "protocol": "Modbus TCP",
                    "metric": "temperature",
                    "value": 96.0,
                    "observed_at": (TELEMETRY_TIME + timedelta(minutes=20)).isoformat(),
                }
            ]
        },
    )
    assert duplicate.json()["alerts_deduplicated"] == 1

    unauthorized = auth_client.post(
        "/api/v1/ot/telemetry",
        json={
            "items": [
                {
                    "asset_id": device["asset_id"],
                    "protocol": "DNP3",
                    "metric": "voltage",
                    "value": 230.0,
                    "observed_at": (TELEMETRY_TIME + timedelta(minutes=30)).isoformat(),
                }
            ]
        },
    )
    assert unauthorized.status_code == 200, unauthorized.text
    assert unauthorized.json()["unauthorized_protocols"] == ["DNP3"]
    assert unauthorized.json()["alerts_created"] == 1

    db.expire_all()
    alerts = list(
        db.execute(select(Alert).where(Alert.org_id == seeded["org"].id).order_by(Alert.first_seen.asc())).scalars()
    )
    assert len(alerts) == 2
    assert alerts[0].count == 2
    assert alerts[0].severity == "high"
    assert alerts[1].dedupe_key != alerts[0].dedupe_key

    refreshed = auth_client.get("/api/v1/ot/devices", params={"q": "plc-baseline"}).json()["items"][0]
    metric_stats = refreshed["baseline"]["metrics"]["temperature"]
    assert metric_stats["samples"] == 6
    assert 20.0 <= metric_stats["mean"] <= 20.4


def test_ot_posture_iec62443(auth_client: TestClient) -> None:
    zone = auth_client.post("/api/v1/zones", json={"name": "Cell A", "purdue_level": 2}).json()
    auth_client.post("/api/v1/zones", json={"name": "Conduit A", "kind": "conduit", "purdue_level": 3})

    zoned = auth_client.post("/api/v1/ot/devices", json=_ot_payload("posture-zoned", zone_id=zone["id"])).json()
    auth_client.post("/api/v1/ot/devices", json=_ot_payload("posture-unzoned", safety_critical=False))

    auth_client.post(
        "/api/v1/ot/telemetry",
        json={
            "items": [
                {
                    "asset_id": zoned["asset_id"],
                    "protocol": "Modbus TCP",
                    "metric": "pressure",
                    "value": 1.5,
                    "observed_at": datetime.now(UTC).isoformat(),
                }
            ]
        },
    )

    posture = auth_client.get("/api/v1/ot/posture")
    assert posture.status_code == 200, posture.text
    body = posture.json()
    assert body["ot_devices_total"] == 2
    assert body["ot_devices_zoned"] == 1
    assert body["unzoned_devices"] == 1
    assert body["safety_critical_devices"] == 1
    assert body["zones_total"] == 2
    assert body["conduits_total"] == 1
    assert body["purdue_documented_zones"] == 2
    assert body["zone_coverage_pct"] == 50.0
    assert body["monitored_devices"] == 1
    assert body["unmonitored_devices"] == 1
    assert body["posture_level"] == "partial"
    assert body["iec62443"]["sr_3_1_communication_control"] is True
    assert len(body["zone_breakdown"]) == 2


def test_iot_ot_cross_tenant_and_rbac(auth_client: TestClient) -> None:
    iot = auth_client.post("/api/v1/iot/devices", json=_iot_payload("tenant-iot")).json()
    ot = auth_client.post("/api/v1/ot/devices", json=_ot_payload("tenant-ot")).json()

    _make_foreign_tenant(auth_client, "foreign-iot", "foreign.iot@example.eu")
    other = _login("foreign.iot@example.eu")
    try:
        assert other.get("/api/v1/iot/devices?q=tenant-iot").json()["meta"]["total"] == 0
        assert other.get(f"/api/v1/assets/{iot['asset_id']}").status_code == 404
        assert other.patch(f"/api/v1/ot/devices/{ot['asset_id']}", json={"criticality": 1}).status_code in {
            404,
            422,
        }
        assert other.get("/api/v1/ot/posture").json()["ot_devices_total"] == 0
    finally:
        other.close()

    membership = auth_client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": "viewer.iot@example.eu",
            "full_name": "Viewer IoT",
            "role": "viewer",
            "password": "Str0ng-Viewer-Pass!2026",
        },
    )
    assert membership.status_code == 201
    viewer = _login("viewer.iot@example.eu")
    try:
        assert viewer.get("/api/v1/iot/devices").status_code == 200
        assert viewer.get("/api/v1/ot/posture").status_code == 200
        assert viewer.post("/api/v1/iot/devices", json=_iot_payload("viewer-iot")).status_code == 403
        assert (
            viewer.post(
                "/api/v1/ot/telemetry",
                json={
                    "items": [
                        {
                            "asset_id": ot["asset_id"],
                            "protocol": "Modbus TCP",
                            "metric": "temperature",
                            "value": 20.0,
                        }
                    ]
                },
            ).status_code
            == 403
        )
    finally:
        viewer.close()
