"""Demo dataset for HISPANSHIELD.

This dataset is fictional, consistently marked `is_demo=true`, and can only be
loaded with `HS_SEED_DEMO=true` outside production. It exercises the real schema
and the real APIs; it is never mixed silently with operational telemetry.
"""

from __future__ import annotations

import hashlib
import os
import random
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crypto import hash_password
from app.core.db import SessionLocal, utcnow
from app.models.ai import AIModel, AIProvider, KnowledgeChunk, KnowledgeDocument
from app.models.assets import (
    Asset,
    AssetRelationship,
    AttackSurfaceFinding,
    CVECatalog,
    IoTDevice,
    OTDevice,
    Vulnerability,
    Zone,
)
from app.models.compliance import ComplianceAssessment, ComplianceControl, ComplianceControlStatus, ComplianceFramework
from app.models.connectors import Connector
from app.models.core import Membership, Notification, Organization, Policy, User
from app.models.events import Alert, IngestSource, SecurityEvent
from app.models.incidents import Evidence, Incident, IncidentTimeline, Playbook
from app.models.ti import ThreatActor, ThreatIndicator

DEMO_SLUG = "demo-nova-iberia"
DEMO_PASSWORD = os.environ.get("HS_DEMO_PASSWORD", "Demo-Str0ng-Pass!2026")
EVIDENCE_ROOT = Path(os.environ.get("HS_EVIDENCE_DIR", "data/evidence"))


def _risk(cvss: float, epss: float, kev: bool, criticality: int, exposure: str) -> tuple[float, str]:
    base = cvss * 6.0
    exploit = epss * 25.0
    kev_bonus = 14.0 if kev else 0.0
    asset_bonus = (criticality - 1) * 4.0
    exposure_bonus = 8.0 if exposure == "internet" else 0.0
    score = min(100.0, round(base + exploit + kev_bonus + asset_bonus + exposure_bonus, 1))
    reason = (
        f"CVSS {cvss} · EPSS {round(epss * 100, 1)}% · KEV={'yes' if kev else 'no'} · "
        f"criticidad {criticality}/5 · exposición {exposure}"
    )
    return score, reason


def _asset(
    org_id,
    key: str,
    name: str,
    kind: str,
    *,
    criticality: int = 3,
    environment: str = "production",
    ips: list[str] | None = None,
    hostnames: list[str] | None = None,
    os_name: str | None = None,
    vendor: str | None = None,
    model: str | None = None,
    firmware: str | None = None,
    zone_id=None,
    source: str = "demo-seed",
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Asset:
    return Asset(
        org_id=org_id,
        asset_key=key,
        name=name,
        kind=kind,
        criticality=criticality,
        environment=environment,
        ip_addresses=ips or [],
        hostnames=hostnames or [],
        os_name=os_name,
        vendor=vendor,
        model=model,
        firmware=firmware,
        zone_id=zone_id,
        discovery_source=source,
        confidence=92,
        tags=tags or [],
        metadata_json=metadata or {},
        is_demo=True,
        last_seen=utcnow(),
    )


def _event(
    org_id,
    source_id,
    *,
    offset_minutes: int,
    message: str,
    severity: int,
    class_uid: int,
    class_name: str,
    host: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    user: str | None = None,
    mitre: list[str] | None = None,
    iocs: list[dict[str, Any]] | None = None,
    raw: dict[str, Any] | None = None,
) -> SecurityEvent:
    occurred = utcnow() - timedelta(minutes=offset_minutes)
    return SecurityEvent(
        org_id=org_id,
        event_uid=f"demo-{occurred.timestamp():.0f}-{random.randint(1000, 9999)}",
        source_id=source_id,
        occurred_at=occurred,
        received_at=occurred,
        class_uid=class_uid,
        class_name=class_name,
        category_uid=4 if class_uid >= 4000 else 1,
        severity_id=severity,
        message=message,
        raw=raw or {"demo": True, "message": message, "host": host},
        normalized={"demo": True, "host": host, "message": message, "severity_id": severity},
        raw_format="json",
        src_ip=src_ip,
        dst_ip=dst_ip,
        user_name=user,
        host_name=host,
        mitre_techniques=mitre or [],
        ioc_matches=iocs or [],
        dedupe_key=hashlib.sha256(f"{message}{host}{user}{src_ip}".encode()).hexdigest(),
        source_connector="demo",
        is_demo=True,
    )


def seed_demo(db: Session) -> tuple[Organization, bool]:
    if settings.is_production:
        raise RuntimeError("Demo seeding is forbidden in production")
    if not settings.seed_demo:
        raise RuntimeError("Set HS_SEED_DEMO=true to load demo data")

    existing = db.execute(select(Organization).where(Organization.slug == DEMO_SLUG)).scalar_one_or_none()
    if existing is not None:
        # Re-running the demo seed must attach admins created after the first
        # run (normal order is bootstrap_admin -> seed_demo).
        for admin in db.execute(select(User).where(User.is_platform_admin.is_(True))).scalars():
            if not db.execute(
                select(Membership).where(Membership.org_id == existing.id, Membership.user_id == admin.id)
            ).scalar_one_or_none():
                db.add(Membership(org_id=existing.id, user_id=admin.id, role="org_admin", status="active"))
        db.commit()
        return existing, False

    random.seed(20261126)
    now = utcnow()
    org = Organization(
        slug=DEMO_SLUG,
        name="Ayuntamiento de Nova Iberia (demo)",
        kind="public",
        country="ES",
        sector="smart-city",
        tier="high",
        autonomy_level="A2",
        status="active",
        is_demo=True,
        settings={
            "reporting_timezone": "Europe/Madrid",
            "backup_configured": True,
            "retention_days": 365,
            "data_protection_contact": "dpo@nova-iberia.example",
        },
    )
    db.add(org)
    db.flush()
    org_id = org.id

    # ---------------------------------------------------------------- people
    analyst = User(
        email="analista.demo@nova-iberia.example",
        full_name="Elena Navarro",
        password_hash=hash_password(DEMO_PASSWORD),
        status="active",
        locale="es",
        mfa_enabled=False,
    )
    db.add(analyst)
    db.flush()
    db.add(Membership(org_id=org_id, user_id=analyst.id, role="soc_manager", status="active"))
    platform_admins = list(db.execute(select(User).where(User.is_platform_admin.is_(True))).scalars())
    for admin in platform_admins:
        if not db.execute(
            select(Membership).where(Membership.org_id == org_id, Membership.user_id == admin.id)
        ).scalar_one_or_none():
            db.add(Membership(org_id=org_id, user_id=admin.id, role="org_admin", status="active"))

    db.add(
        Policy(
            org_id=org_id,
            name="demo-autonomy",
            kind="autonomy",
            version=1,
            enabled=True,
            description="A2 por defecto; bloqueo de IP y aislamiento requieren A3 + aprobación",
            definition={
                "default_level": "A2",
                "max_level": "A2",
                "require_approval_from": "A3",
                "action_levels": {"ip.block": "A3", "endpoint.isolate": "A3", "identity.disable": "A3"},
                "denied_actions": ["patch.apply"],
                "allow_ot_automation": False,
            },
            created_by=str(analyst.id),
        )
    )

    # ----------------------------------------------------------------- zones
    zone_it = Zone(
        org_id=org_id, name="Corporativo IT", kind="zone", purdue_level=4, description="Usuarios y servidores internos"
    )
    zone_dmz = Zone(org_id=org_id, name="DMZ", kind="zone", purdue_level=3, description="Servicios expuestos")
    zone_ot = Zone(
        org_id=org_id,
        name="Planta OT",
        kind="zone",
        purdue_level=1,
        description="Control industrial del ciclo del agua",
    )
    zone_iot = Zone(
        org_id=org_id, name="IoT urbano", kind="zone", purdue_level=4, description="Sensores y cámaras municipales"
    )
    db.add_all([zone_it, zone_dmz, zone_ot, zone_iot])
    db.flush()
    conduit = Zone(
        org_id=org_id,
        name="Conduit DMZ → OT",
        kind="conduit",
        purdue_level=2,
        description="Única ruta autorizada, inspeccionada por el firewall industrial",
    )
    db.add(conduit)
    db.flush()

    # ---------------------------------------------------------------- assets
    assets = [
        _asset(
            org_id,
            "srv-dc-01",
            "DC-01 (Domain Controller)",
            "host",
            criticality=5,
            ips=["10.10.1.10"],
            hostnames=["dc01.nova-iberia.local"],
            os_name="Windows Server 2022",
            zone_id=zone_it.id,
        ),
        _asset(
            org_id,
            "srv-erp-01",
            "ERP Municipal",
            "host",
            criticality=5,
            ips=["10.10.1.20"],
            hostnames=["erp.nova-iberia.local"],
            os_name="Ubuntu 22.04",
            zone_id=zone_it.id,
            tags=["critical"],
        ),
        _asset(
            org_id,
            "srv-backup-01",
            "Servidor de copias",
            "host",
            criticality=5,
            ips=["10.10.1.30"],
            os_name="Debian 12",
            zone_id=zone_it.id,
        ),
        _asset(
            org_id,
            "srv-print-01",
            "Servidor de impresión",
            "host",
            criticality=2,
            ips=["10.10.1.40"],
            os_name="Windows Server 2019",
            zone_id=zone_it.id,
        ),
        _asset(
            org_id,
            "ws-fin-07",
            "Workstation Finanzas 07",
            "host",
            criticality=3,
            ips=["10.10.20.57"],
            hostnames=["ws-fin-07"],
            os_name="Windows 11",
            zone_id=zone_it.id,
        ),
        _asset(
            org_id,
            "ws-rrhh-12",
            "Workstation RRHH 12",
            "host",
            criticality=3,
            ips=["10.10.20.62"],
            os_name="Windows 11",
            zone_id=zone_it.id,
        ),
        _asset(
            org_id,
            "web-cms-01",
            "Portal municipal (CMS)",
            "service",
            criticality=4,
            ips=["203.0.113.40"],
            hostnames=["www.nova-iberia.example"],
            os_name="Ubuntu 24.04",
            zone_id=zone_dmz.id,
            metadata={"exposed_ports": [443, 80], "tls": "TLS1.2"},
        ),
        _asset(
            org_id,
            "vpn-gw",
            "VPN perimetral",
            "network",
            criticality=5,
            ips=["203.0.113.41"],
            vendor="Fortinet",
            model="FortiGate 100F",
            firmware="7.2.8",
            zone_id=zone_dmz.id,
            metadata={"exposed_ports": [443]},
        ),
        _asset(
            org_id,
            "fw-ot-01",
            "Firewall industrial",
            "network",
            criticality=5,
            ips=["10.20.0.1"],
            vendor="Moxa",
            model="EDR-G903",
            firmware="3.12",
            zone_id=zone_ot.id,
            metadata={"exposed_ports": []},
        ),
        _asset(
            org_id,
            "net-sw-core",
            "Switch core",
            "network",
            criticality=4,
            ips=["10.10.0.2"],
            vendor="Cisco",
            model="Catalyst 9300",
            firmware="17.9.4",
            zone_id=zone_it.id,
        ),
        _asset(
            org_id,
            "cloud-backup",
            "Bucket de copias cloud",
            "cloud",
            criticality=4,
            ips=[],
            zone_id=None,
            metadata={
                "provider": "aws",
                "service": "s3",
                "region": "eu-south-2",
                "public": False,
                "encryption": "SSE-KMS",
            },
        ),
        _asset(
            org_id,
            "cloud-analytics",
            "Cluster analítica cloud",
            "cloud",
            criticality=3,
            metadata={"provider": "azure", "service": "aks", "region": "spaincentral", "public": False},
        ),
        _asset(
            org_id,
            "id-service-01",
            "Cuenta de servicio backup",
            "identity",
            criticality=4,
            hostnames=["svc-backup"],
            metadata={"privileged": True, "mfa": False, "last_review": "2026-01-12"},
        ),
        _asset(
            org_id,
            "id-admin-01",
            "Administrador de dominio",
            "identity",
            criticality=5,
            hostnames=["adm-domain"],
            metadata={"privileged": True, "mfa": True},
        ),
        _asset(
            org_id,
            "cam-014",
            "Cámara tráfico 014",
            "iot",
            criticality=2,
            ips=["10.30.5.14"],
            vendor="Hikvision",
            model="DS-2CD2T47",
            firmware="5.7.3",
            zone_id=zone_iot.id,
        ),
        _asset(
            org_id,
            "cam-021",
            "Cámara tráfico 021",
            "iot",
            criticality=2,
            ips=["10.30.5.21"],
            vendor="Hikvision",
            model="DS-2CD2T47",
            firmware="5.6.1",
            zone_id=zone_iot.id,
        ),
        _asset(
            org_id,
            "iot-air-03",
            "Sensor calidad del aire 03",
            "iot",
            criticality=2,
            ips=["10.30.6.3"],
            vendor="Libelium",
            model="Waspmote",
            firmware="1.4.2",
            zone_id=zone_iot.id,
        ),
        _asset(
            org_id,
            "iot-park-11",
            "Sensor aparcamiento 11",
            "iot",
            criticality=1,
            ips=["10.30.6.11"],
            vendor="Bosch",
            model="TSS",
            firmware="2.1.0",
            zone_id=zone_iot.id,
        ),
        _asset(
            org_id,
            "ot-plc-pump-01",
            "PLC bomba principal",
            "ot",
            criticality=5,
            ips=["10.20.1.11"],
            vendor="Siemens",
            model="S7-1200",
            firmware="4.5.1",
            zone_id=zone_ot.id,
        ),
        _asset(
            org_id,
            "ot-hmi-01",
            "HMI sala de control",
            "ot",
            criticality=5,
            ips=["10.20.1.20"],
            os_name="Windows 10 LTSC",
            zone_id=zone_ot.id,
        ),
        _asset(
            org_id,
            "ot-rtu-02",
            "RTU estación de bombeo",
            "ot",
            criticality=5,
            ips=["10.20.1.32"],
            vendor="Schneider",
            model="SCADAPack 474",
            firmware="2.8",
            zone_id=zone_ot.id,
        ),
        _asset(
            org_id,
            "ot-plc-valve-03",
            "PLC válvulas",
            "ot",
            criticality=4,
            ips=["10.20.1.15"],
            vendor="Allen-Bradley",
            model="CompactLogix 5380",
            zone_id=zone_ot.id,
        ),
        _asset(
            org_id,
            "unknown-10-30-6-77",
            "Activo desconocido 10.30.6.77",
            "host",
            criticality=2,
            ips=["10.30.6.77"],
            source="passive-flow",
            zone_id=zone_iot.id,
            metadata={"unknown_asset": True},
        ),
        _asset(
            org_id,
            "unknown-10-10-1-99",
            "Activo desconocido 10.10.1.99",
            "host",
            criticality=3,
            ips=["10.10.1.99"],
            source="passive-flow",
            zone_id=zone_it.id,
            metadata={"unknown_asset": True},
        ),
    ]
    db.add_all(assets)
    db.flush()
    by_key = {asset.asset_key: asset for asset in assets}

    relationships = [
        ("srv-erp-01", "srv-dc-01", "authenticates_against"),
        ("ws-fin-07", "srv-dc-01", "authenticates_against"),
        ("ws-rrhh-12", "srv-dc-01", "authenticates_against"),
        ("web-cms-01", "srv-erp-01", "calls_api"),
        ("vpn-gw", "fw-ot-01", "routes_to"),
        ("fw-ot-01", "ot-plc-pump-01", "controls"),
        ("ot-hmi-01", "ot-plc-pump-01", "monitors"),
        ("ot-rtu-02", "ot-plc-pump-01", "reports_to"),
        ("cam-014", "net-sw-core", "connects_to"),
        ("cam-021", "net-sw-core", "connects_to"),
        ("iot-park-11", "net-sw-core", "connects_to"),
    ]
    for source_key, target_key, kind in relationships:
        db.add(
            AssetRelationship(
                org_id=org_id,
                source_asset_id=by_key[source_key].id,
                target_asset_id=by_key[target_key].id,
                kind=kind,
                confidence=90,
            )
        )

    db.add_all(
        [
            IoTDevice(
                asset_id=by_key["cam-014"].id,
                org_id=org_id,
                protocols=["ONVIF", "HTTP/HTTPS"],
                connectivity="ethernet",
                firmware_version="5.7.3",
                last_telemetry_at=now - timedelta(minutes=4),
                security_posture={"default_credentials": False, "signed_firmware": False, "ethernet": True},
            ),
            IoTDevice(
                asset_id=by_key["cam-021"].id,
                org_id=org_id,
                protocols=["ONVIF", "HTTP/HTTPS"],
                connectivity="ethernet",
                firmware_version="5.6.1",
                last_telemetry_at=now - timedelta(minutes=9),
                security_posture={"default_credentials": True, "signed_firmware": False, "ethernet": True},
            ),
            IoTDevice(
                asset_id=by_key["iot-air-03"].id,
                org_id=org_id,
                protocols=["MQTT/TLS", "LoRaWAN"],
                connectivity="lora",
                firmware_version="1.4.2",
                last_telemetry_at=now - timedelta(minutes=2),
                security_posture={"default_credentials": False, "signed_firmware": True},
            ),
            IoTDevice(
                asset_id=by_key["iot-park-11"].id,
                org_id=org_id,
                protocols=["NB-IoT", "MQTT"],
                connectivity="cellular",
                firmware_version="2.1.0",
                last_telemetry_at=now - timedelta(hours=2),
                security_posture={"default_credentials": False, "signed_firmware": False},
            ),
            OTDevice(
                asset_id=by_key["ot-plc-pump-01"].id,
                org_id=org_id,
                protocols=["S7", "PROFINET"],
                zone_id=zone_ot.id,
                safety_critical=True,
                passive_only=True,
                controller_model="S7-1200",
                firmware_version="4.5.1",
                last_telemetry_at=now - timedelta(minutes=1),
                baseline={"cpu_load": {"mean": 31.2, "std": 4.1}, "allowed_protocols": ["S7", "PROFINET"]},
            ),
            OTDevice(
                asset_id=by_key["ot-hmi-01"].id,
                org_id=org_id,
                protocols=["OPC UA", "S7"],
                zone_id=zone_ot.id,
                safety_critical=True,
                passive_only=True,
                firmware_version="LTSC 2021",
                last_telemetry_at=now - timedelta(minutes=1),
                baseline={"allowed_protocols": ["OPC UA", "S7"]},
            ),
            OTDevice(
                asset_id=by_key["ot-rtu-02"].id,
                org_id=org_id,
                protocols=["DNP3"],
                zone_id=zone_ot.id,
                safety_critical=True,
                passive_only=True,
                controller_model="SCADAPack 474",
                firmware_version="2.8",
                last_telemetry_at=now - timedelta(minutes=3),
                baseline={"allowed_protocols": ["DNP3"]},
            ),
            OTDevice(
                asset_id=by_key["ot-plc-valve-03"].id,
                org_id=org_id,
                protocols=["EtherNet/IP"],
                zone_id=zone_ot.id,
                safety_critical=True,
                passive_only=True,
                controller_model="CompactLogix 5380",
                last_telemetry_at=now - timedelta(minutes=2),
                baseline={"allowed_protocols": ["EtherNet/IP"]},
            ),
        ]
    )

    # ------------------------------------------------------------------ CVEs
    cves = [
        ("CVE-2021-44228", "Apache Log4j2 JNDI remote code execution (Log4Shell)", 10.0, 0.97, True, "CWE-502"),
        ("CVE-2023-4966", "Citrix NetScaler session token disclosure (CitrixBleed)", 9.4, 0.94, True, "CWE-125"),
        ("CVE-2024-3400", "Palo Alto PAN-OS unauthenticated command injection", 10.0, 0.93, True, "CWE-77"),
        ("CVE-2021-34473", "Microsoft Exchange ProxyShell remote code execution", 9.8, 0.94, True, "CWE-918"),
        ("CVE-2022-22965", "Spring Framework data binding RCE (Spring4Shell)", 9.8, 0.90, True, "CWE-94"),
        ("CVE-2024-21762", "Fortinet FortiOS out-of-bounds write", 9.6, 0.88, True, "CWE-787"),
        ("CVE-2023-34362", "MOVEit Transfer SQL injection", 9.8, 0.93, True, "CWE-89"),
        ("CVE-2022-0185", "Linux kernel filesystem context heap overflow", 8.4, 0.55, False, "CWE-190"),
        ("CVE-2024-6387", "OpenSSH signal handler race condition (regreSSHion)", 8.1, 0.62, False, "CWE-364"),
        ("CVE-2023-38408", "OpenSSH PKCS#11 remote code execution", 9.8, 0.48, False, "CWE-670"),
        ("CVE-2022-26134", "Atlassian Confluence OGNL injection", 9.8, 0.95, True, "CWE-917"),
        ("CVE-2023-36884", "Microsoft Office/Windows Search RCE", 8.3, 0.72, True, "CWE-20"),
    ]
    for cve_id, description, cvss, epss, kev, cwe in cves:
        db.add(
            CVECatalog(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                epss_score=epss,
                kev=kev,
                published_at=now - timedelta(days=random.randint(60, 900)),
                modified_at=now - timedelta(days=random.randint(1, 30)),
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                cpes=[],
                cwe=cwe,
            )
        )

    vuln_specs = [
        (
            "srv-erp-01",
            "CVE-2021-44228",
            "Log4j2 vulnerable library",
            10.0,
            0.97,
            True,
            "critical",
            "internet",
            "Actualizar Log4j a 2.17.1 y rotar credenciales",
        ),
        (
            "vpn-gw",
            "CVE-2024-21762",
            "FortiOS out-of-bounds write",
            9.6,
            0.88,
            True,
            "critical",
            "internet",
            "Aplicar parche FortiOS 7.2.9",
        ),
        (
            "web-cms-01",
            "CVE-2023-4966",
            "NetScaler ADC token leak",
            9.4,
            0.94,
            True,
            "critical",
            "internet",
            "Actualizar firmware y revocar sesiones",
        ),
        (
            "srv-dc-01",
            "CVE-2021-34473",
            "Exchange ProxyShell (servicio colateral)",
            9.8,
            0.94,
            True,
            "high",
            "internal",
            "Parche acumulativo de Exchange",
        ),
        (
            "srv-print-01",
            "CVE-2022-0185",
            "Kernel vulnerable en servidor de impresión",
            8.4,
            0.55,
            False,
            "high",
            "internal",
            "Actualizar kernel y reiniciar en ventana",
        ),
        (
            "cam-021",
            "CVE-2023-38408",
            "Firmware de cámara con OpenSSH vulnerable",
            9.8,
            0.48,
            False,
            "medium",
            "internal",
            "Actualizar firmware del fabricante",
        ),
        (
            "ot-hmi-01",
            "CVE-2023-36884",
            "HMI con componente Office vulnerable",
            8.3,
            0.72,
            True,
            "high",
            "internal",
            "Mitigar por segmentación; validar en laboratorio",
        ),
        (
            "cloud-backup",
            "CVE-2022-22965",
            "Dependencia Spring vulnerable en herramienta de backup",
            9.8,
            0.90,
            True,
            "high",
            "internal",
            "Actualizar herramienta de copia",
        ),
        (
            "ws-fin-07",
            "CVE-2024-6387",
            "OpenSSH regreSSHion en endpoint",
            8.1,
            0.62,
            False,
            "medium",
            "internal",
            "Actualizar OpenSSH",
        ),
        (
            "net-sw-core",
            "CVE-2023-34362",
            "Componente de gestión con SQLi",
            9.8,
            0.93,
            True,
            "high",
            "internal",
            "Parche de gestión fuera de banda",
        ),
        (
            "srv-backup-01",
            "CVE-2022-26134",
            "Confluence local en servidor de copias",
            9.8,
            0.95,
            True,
            "critical",
            "internal",
            "Aislar servicio y parchear",
        ),
        (
            "ws-rrhh-12",
            "CVE-2023-36884",
            "Office vulnerable",
            8.3,
            0.72,
            True,
            "medium",
            "internal",
            "Actualizar Office",
        ),
        (
            "ot-rtu-02",
            "CVE-2021-44228",
            "Servicio de diagnóstico con Log4j",
            10.0,
            0.97,
            True,
            "high",
            "internal",
            "Coordinar con fabricante; monitorización pasiva",
        ),
        (
            "iot-air-03",
            "CVE-2024-6387",
            "Stack SSH del gateway IoT",
            8.1,
            0.62,
            False,
            "low",
            "internal",
            "Actualizar firmware",
        ),
        (
            "unknown-10-10-1-99",
            "CVE-2022-0185",
            "Activo desconocido con kernel vulnerable",
            8.4,
            0.55,
            False,
            "medium",
            "internal",
            "Identificar propietario antes de remediar",
        ),
    ]
    for asset_key, cve_id, title, cvss, epss, kev, severity, exposure, remediation in vuln_specs:
        asset = by_key[asset_key]
        score, reason = _risk(cvss, epss, kev, asset.criticality, exposure)
        db.add(
            Vulnerability(
                org_id=org_id,
                asset_id=asset.id,
                cve_id=cve_id,
                title=title,
                description=f"{title}. Datos de demostración vinculados a {cve_id}.",
                cvss_score=cvss,
                epss_score=epss,
                kev=kev,
                severity=severity,
                status="open",
                exploitable=kev or epss > 0.7,
                exposure=exposure,
                priority_score=score,
                priority_reason=reason,
                source="demo-nvd",
                due_at=now + timedelta(days=7 if severity == "critical" else 21 if severity == "high" else 45),
                remediation=remediation,
                metadata_json={"demo": True},
            )
        )

    findings = [
        (
            "vpn-gw",
            "exposed_service",
            "Consola de administración VPN expuesta a Internet",
            "critical",
            "Puerto 443 con interfaz de gestión accesible desde 0.0.0.0/0",
        ),
        (
            "web-cms-01",
            "tls_weak",
            "TLS 1.0/1.1 habilitado en el portal",
            "medium",
            "El endpoint acepta protocolos obsoletos",
        ),
        (
            "unknown-10-30-6-77",
            "unknown_asset",
            "Activo no inventariado en VLAN IoT",
            "high",
            "Tráfico observado sin propietario ni agente",
        ),
        (
            "unknown-10-10-1-99",
            "unknown_asset",
            "Activo no inventariado en red corporativa",
            "high",
            "ARP y DNS observados; sin registro en CMDB",
        ),
        (
            "cloud-backup",
            "public_storage",
            "Bucket de copias con política pública (corregido)",
            "critical",
            "Block Public Access deshabilitado en la política",
        ),
        (
            "cam-021",
            "default_credentials",
            "Credenciales por defecto en cámara IoT",
            "high",
            "El firmware conserva el usuario de fábrica",
        ),
        (
            "srv-print-01",
            "eol_os",
            "Sistema operativo al final de soporte",
            "medium",
            "Windows Server 2019 fuera de soporte extendido",
        ),
        (
            "ot-hmi-01",
            "flat_network",
            "Ruta directa HMI → Internet detectada",
            "critical",
            "Flujo 10.20.1.20 → 203.0.113.40:443 no autorizado",
        ),
    ]
    for asset_key, kind, title, severity, evidence in findings:
        db.add(
            AttackSurfaceFinding(
                org_id=org_id,
                asset_id=by_key[asset_key].id,
                kind=kind,
                title=title,
                severity=severity,
                status="open",
                evidence=evidence,
                source="demo-analysis",
                metadata_json={"demo": True},
            )
        )

    # -------------------------------------------------------------- ingestion
    source = IngestSource(
        org_id=org_id,
        name="Wazuh demo (reenvío syslog)",
        kind="syslog",
        parser="auto",
        enabled=True,
        config={"demo": True, "port": 1514},
        event_count=0,
        last_event_at=now,
        created_by=str(analyst.id),
    )
    db.add(source)
    db.flush()

    event_specs = [
        (
            "Failed password for invalid user admin from 203.0.113.77",
            3,
            3002,
            "Authentication",
            "dc01",
            "203.0.113.77",
            "10.10.1.10",
            "admin",
            ["T1110"],
        ),
        (
            "Failed password for user j.perez from 203.0.113.77",
            3,
            3002,
            "Authentication",
            "dc01",
            "203.0.113.77",
            "10.10.1.10",
            "j.perez",
            ["T1110"],
        ),
        (
            "Accepted password for j.perez from 10.10.20.57",
            1,
            3002,
            "Authentication",
            "dc01",
            "10.10.20.57",
            "10.10.1.10",
            "j.perez",
            [],
        ),
        (
            "Sudo command executed: /usr/bin/nmap -sS 10.20.0.0/24",
            4,
            1007,
            "Process Activity",
            "srv-erp-01",
            "10.10.1.20",
            None,
            "svc-backup",
            ["T1046", "T1548"],
        ),
        (
            "Outbound connection to known C2 domain update-check.example",
            4,
            4001,
            "Network Activity",
            "ws-fin-07",
            "10.10.20.57",
            "198.51.100.23",
            "a.martin",
            ["T1071"],
        ),
        (
            "Large outbound transfer 1.8 GB to 198.51.100.55",
            3,
            4001,
            "Network Activity",
            "srv-backup-01",
            "10.10.1.30",
            "198.51.100.55",
            None,
            ["T1041"],
        ),
        (
            "Unauthorized Modbus write request to PLC 10.20.1.11",
            5,
            5001,
            "Industrial Activity",
            "ot-plc-pump-01",
            "10.20.1.20",
            "10.20.1.11",
            None,
            ["T0836"],
        ),
        (
            "New service created: WinUpdateSvc on ws-rrhh-12",
            4,
            1004,
            "System Activity",
            "ws-rrhh-12",
            "10.10.20.62",
            None,
            "SYSTEM",
            ["T1543"],
        ),
        (
            "DNS query to dga-c2.example from IoT VLAN",
            3,
            4003,
            "DNS Activity",
            "iot-park-11",
            "10.30.6.11",
            "10.30.0.1",
            None,
            ["T1568"],
        ),
        (
            "Camera 021 attempted SSH login with default credentials",
            4,
            3002,
            "Authentication",
            "cam-021",
            "10.30.5.21",
            "10.30.6.77",
            "admin",
            ["T1078"],
        ),
        (
            "USB mass storage device mounted on HMI",
            3,
            1001,
            "Device Activity",
            "ot-hmi-01",
            None,
            None,
            "operator",
            ["T1052"],
        ),
        (
            "Impossible logon location for a.navarro (Madrid → Singapore in 4 min)",
            4,
            3002,
            "Authentication",
            "dc01",
            "203.0.113.90",
            "10.10.1.10",
            "a.navarro",
            ["T1078"],
        ),
        (
            "PowerShell encoded command executed",
            4,
            1007,
            "Process Activity",
            "ws-fin-07",
            None,
            None,
            "a.martin",
            ["T1059"],
        ),
        (
            "Firewall denied inbound connection from 198.51.100.77:445",
            2,
            4001,
            "Network Activity",
            "vpn-gw",
            "198.51.100.77",
            "203.0.113.41",
            None,
            ["T1021"],
        ),
        ("Certificate expired for erp.nova-iberia.local", 2, 1000, "Configuration", "srv-erp-01", None, None, None, []),
        ("Backup job completed successfully", 1, 1000, "Configuration", "srv-backup-01", None, None, None, []),
        (
            "EDR detected Mimikatz-like credential dumping",
            5,
            1007,
            "Process Activity",
            "ws-rrhh-12",
            None,
            None,
            "j.perez",
            ["T1003"],
        ),
        (
            "Port scan detected from 203.0.113.77 against DMZ",
            3,
            4001,
            "Network Activity",
            "vpn-gw",
            "203.0.113.77",
            "203.0.113.41",
            None,
            ["T1046"],
        ),
        (
            "Suspicious OPC UA browse request from engineering laptop",
            3,
            5001,
            "Industrial Activity",
            "ot-hmi-01",
            "10.20.1.50",
            "10.20.1.20",
            None,
            ["T0846"],
        ),
        (
            "MFA disabled for privileged account svc-backup",
            4,
            3003,
            "Authentication",
            "id-service-01",
            None,
            None,
            "svc-backup",
            ["T1556"],
        ),
    ]
    events: list[SecurityEvent] = []
    for index, (message, severity_id, class_uid, class_name, host, src, dst, user, mitre) in enumerate(event_specs):
        for repeat in range(3 if "Failed password" in message else 1):
            event = _event(
                org_id,
                source.id,
                offset_minutes=180 - index * 6 + repeat,
                message=message,
                severity=severity_id,
                class_uid=class_uid,
                class_name=class_name,
                host=host,
                src_ip=src,
                dst_ip=dst,
                user=user,
                mitre=mitre,
                iocs=[{"value": "update-check.example", "type": "domain", "confidence": 88}] if "C2" in message else [],
            )
            db.add(event)
            events.append(event)
    db.flush()
    source.event_count = len(events)

    # ------------------------------------------------------------------- TI
    actors = [
        ThreatActor(
            org_id=None,
            name="APT29 (Cozy Bear)",
            aliases=["Cozy Bear", "NOBELIUM"],
            mitre_id="G0016",
            description="Grupo de espionaje vinculado al SVR ruso; campañas de spear-phishing y abuso de identidad.",
            sophistication="strategic",
            motivation="espionage",
            country="RU",
            techniques=["T1566", "T1078", "T1059", "T1556"],
        ),
        ThreatActor(
            org_id=None,
            name="Lazarus Group",
            aliases=["Hidden Cobra"],
            mitre_id="G0032",
            description="Grupo de amenaza persistente con motivación financiera y sabotaje.",
            sophistication="advanced",
            motivation="financial",
            country="KP",
            techniques=["T1566", "T1486", "T1055"],
        ),
        ThreatActor(
            org_id=org_id,
            name="Operador local simulado (demo)",
            aliases=["NovaPhantom"],
            mitre_id=None,
            description="Actor ficticio usado exclusivamente en datos de demostración.",
            sophistication="intermediate",
            motivation="hacktivism",
            country=None,
            techniques=["T1190", "T1046"],
        ),
    ]
    db.add_all(actors)
    db.flush()
    indicators = [
        ("domain", "update-check.example", 88, "high", "demo-osint", ["c2", "demo"], actors[0]),
        ("ip", "203.0.113.77", 95, "critical", "demo-osint", ["bruteforce", "demo"], actors[2]),
        ("ip", "198.51.100.23", 82, "high", "demo-misp", ["c2", "demo"], actors[0]),
        (
            "sha256",
            hashlib.sha256(b"demo-mimikatz").hexdigest(),
            91,
            "critical",
            "demo-misp",
            ["credential-dumping", "demo"],
            actors[1],
        ),
        ("domain", "dga-c2.example", 77, "medium", "demo-osint", ["dga", "demo"], actors[2]),
        ("url", "https://update-check.example/payload.bin", 85, "high", "demo-opencti", ["malware", "demo"], actors[0]),
        ("ip", "198.51.100.55", 70, "medium", "demo-misp", ["exfil", "demo"], actors[0]),
        ("email", "facturas@nova-iberia-payments.example", 66, "medium", "demo-osint", ["phishing", "demo"], actors[2]),
    ]
    for indicator_type, value, confidence, severity, source_name, tags, actor in indicators:
        db.add(
            ThreatIndicator(
                org_id=org_id,
                indicator_type=indicator_type,
                value=value,
                confidence=confidence,
                severity=severity,
                source=source_name,
                description=f"Indicador sintético de demostración ({source_name}).",
                tags=tags,
                actor_id=actor.id if actor in actors[1:] else None,
                first_seen=now - timedelta(days=4),
                last_seen=now - timedelta(hours=2),
            )
        )

    # --------------------------------------------------------------- alerts
    alert_specs = [
        ("Credential dumping detectado en WS-RRHH-12", "critical", "investigating", 96.0, ["T1003"], [events[-6].id]),
        ("Posible exfiltración desde servidor de copias", "high", "triaged", 84.0, ["T1041"], [events[5].id]),
        (
            "Fuerza bruta contra DC-01 desde 203.0.113.77",
            "high",
            "investigating",
            78.0,
            ["T1110"],
            [events[0].id, events[1].id],
        ),
        ("Escritura Modbus no autorizada en PLC de bombeo", "critical", "new", 93.0, ["T0836"], [events[6].id]),
        ("Conexión a dominio C2 conocido", "high", "new", 81.0, ["T1071"], [events[4].id]),
        ("Movimiento lateral potencial: sudo nmap desde ERP", "medium", "new", 64.0, ["T1046"], [events[3].id]),
        ("Activo no inventariado con credenciales por defecto", "medium", "triaged", 58.0, ["T1078"], [events[9].id]),
        ("Dispositivo USB montado en HMI crítica", "high", "new", 72.0, ["T1052"], [events[10].id]),
    ]
    alerts: list[Alert] = []
    for title, severity, status, risk, mitre, event_ids in alert_specs:
        alert = Alert(
            org_id=org_id,
            rule_id=None,
            title=title,
            description=title,
            severity=severity,
            status=status,
            dedupe_key=hashlib.sha256(title.encode()).hexdigest(),
            event_ids=event_ids,
            first_seen=now - timedelta(hours=3),
            last_seen=now - timedelta(minutes=random.randint(5, 80)),
            count=random.randint(1, 6),
            mitre=mitre,
            risk_score=risk,
            evidence={"demo": True, "events": event_ids},
            is_demo=True,
        )
        db.add(alert)
        alerts.append(alert)
    db.flush()

    # ------------------------------------------------------------ incidents
    incident_specs = [
        (
            "HS-2026-1042",
            "Compromiso de endpoint con robo de credenciales",
            "critical",
            "investigating",
            1,
            ["T1003", "T1078"],
            ["ws-rrhh-12", "srv-dc-01"],
            "Credenciales de j.perez expuestas; endpoint aislado en laboratorio.",
        ),
        (
            "HS-2026-1041",
            "Actividad C2 desde Workstation de Finanzas",
            "high",
            "contained",
            2,
            ["T1071"],
            ["ws-fin-07"],
            "Conexión periódica a update-check.example. Bloqueo DNS aplicado.",
        ),
        (
            "HS-2026-1040",
            "Intento de acceso no autorizado a VPN perimetral",
            "high",
            "triaged",
            3,
            ["T1110"],
            ["vpn-gw"],
            "Fuerza bruta desde 203.0.113.77; cuenta bloqueada.",
        ),
        (
            "HS-2026-1039",
            "Anomalía de comunicación en red OT",
            "critical",
            "investigating",
            1,
            ["T0836"],
            ["ot-plc-pump-01"],
            "Solicitud Modbus de escritura fuera de ventana de mantenimiento.",
        ),
        (
            "HS-2026-1038",
            "Bucket cloud con política pública",
            "high",
            "recovered",
            3,
            ["T1530"],
            ["cloud-backup"],
            "Política corregida; acceso auditado sin indicios de exfiltración.",
        ),
        (
            "HS-2026-1037",
            "Phishing dirigido a RRHH",
            "medium",
            "closed",
            4,
            ["T1566"],
            ["ws-rrhh-12"],
            "Correo bloqueado; usuario formado.",
        ),
    ]
    for ref, title, severity, status, priority, mitre, asset_keys, summary in incident_specs:
        detected = now - timedelta(hours=random.randint(6, 70))
        incident = Incident(
            org_id=org_id,
            ref=ref,
            title=title,
            description=summary,
            severity=severity,
            status=status,
            priority=priority,
            detected_at=detected,
            contained_at=detected + timedelta(hours=2) if status in {"contained", "recovered", "closed"} else None,
            resolved_at=detected + timedelta(hours=5) if status == "recovered" else None,
            closed_at=detected + timedelta(hours=7) if status == "closed" else None,
            sla_due_at=detected + timedelta(hours=4 if severity == "critical" else 12),
            mitre=mitre,
            affected_asset_ids=[str(by_key[key].id) for key in asset_keys],
            root_cause="Credenciales comprometidas por phishing" if status == "closed" else None,
            lessons_learned="Reforzar MFA y formación" if status == "closed" else None,
            is_demo=True,
            created_by=str(analyst.id),
        )
        db.add(incident)
        db.flush()
        db.add_all(
            [
                IncidentTimeline(
                    incident_id=incident.id,
                    org_id=org_id,
                    at=detected,
                    kind="detection",
                    actor="SIEM",
                    summary="Detección automática por regla de correlación",
                    detail={"mitre": mitre},
                ),
                IncidentTimeline(
                    incident_id=incident.id,
                    org_id=org_id,
                    at=detected + timedelta(minutes=18),
                    kind="triage",
                    actor="Elena Navarro",
                    summary="Incidente validado; severidad confirmada",
                ),
                IncidentTimeline(
                    incident_id=incident.id,
                    org_id=org_id,
                    at=detected + timedelta(minutes=35),
                    kind="action",
                    actor="HISPANSHIELD",
                    summary="Propuesta de contención generada; pendiente de aprobación",
                    detail={"autonomy": "A2", "action": "endpoint.isolate"},
                ),
            ]
        )
        if len(incident_specs) and incident.ref == "HS-2026-1042":
            directory = EVIDENCE_ROOT / DEMO_SLUG / str(incident.id)
            directory.mkdir(parents=True, exist_ok=True)
            content = (
                "HISPANSHIELD DEMO EVIDENCE\n"
                f"incident={incident.ref}\nhost=ws-rrhh-12\n"
                "process=lsass.dmp\nsha256=simulated\n"
            ).encode()
            path = directory / "process-tree.txt"
            path.write_bytes(content)
            db.add(
                Evidence(
                    org_id=org_id,
                    incident_id=incident.id,
                    kind="process_tree",
                    title="Árbol de procesos del endpoint",
                    description="Evidencia sintética de demostración",
                    sha256=hashlib.sha256(content).hexdigest(),
                    storage_path=str(path),
                    content_type="text/plain",
                    size_bytes=len(content),
                    collected_by="EDR demo",
                    collected_at=detected + timedelta(minutes=40),
                    chain_of_custody=[{"actor": "EDR demo", "action": "collected", "at": detected.isoformat()}],
                    sealed=True,
                )
            )

    # -------------------------------------------------------------- playbooks
    db.add_all(
        [
            Playbook(
                org_id=org_id,
                name="Contención de endpoint comprometido",
                description="Investiga, solicita aprobación y aísla un endpoint con verificación posterior.",
                version=1,
                status="published",
                trigger={"alert_severity": ["critical", "high"], "rules": []},
                definition={
                    "steps": [
                        {
                            "key": "collect",
                            "name": "Recopilar contexto del incidente",
                            "action": "internal.investigate",
                            "params": {},
                            "retries": 0,
                        },
                        {
                            "key": "isolate",
                            "name": "Aislar endpoint",
                            "action": "defence.execute",
                            "params": {"action_type": "endpoint.isolate"},
                            "requires_approval": True,
                            "retries": 0,
                        },
                        {
                            "key": "notify",
                            "name": "Notificar al SOC",
                            "action": "internal.notify",
                            "params": {"title": "Endpoint aislado"},
                            "retries": 1,
                        },
                    ]
                },
                min_autonomy_level="A3",
                created_by=str(analyst.id),
                published_at=now - timedelta(days=3),
            ),
            Playbook(
                org_id=org_id,
                name="Enriquecimiento de IOC",
                description="Cruza un indicador con eventos, activos e inteligencia y registra evidencia.",
                version=1,
                status="published",
                trigger={"alert_severity": ["high", "critical"], "rules": []},
                definition={
                    "steps": [
                        {
                            "key": "enrich",
                            "name": "Enriquecer indicador",
                            "action": "internal.investigate",
                            "params": {},
                            "retries": 0,
                        },
                        {
                            "key": "timeline",
                            "name": "Registrar en el incidente",
                            "action": "internal.add_timeline",
                            "params": {"summary": "IOC enriquecido automáticamente"},
                            "retries": 0,
                        },
                    ]
                },
                min_autonomy_level="A1",
                created_by=str(analyst.id),
                published_at=now - timedelta(days=8),
            ),
        ]
    )

    # -------------------------------------------------------------- connectors
    connector_specs = [
        ("Wazuh (demo)", "wazuh", "https://wazuh.demo.internal:55000", "read_alerts", "unhealthy"),
        (
            "Elastic Security (demo)",
            "elastic_security",
            "https://elastic.demo.internal:9200",
            "read_alerts",
            "unconfigured",
        ),
        ("MISP (demo)", "misp", "https://misp.demo.internal", "read_indicators", "degraded"),
        ("OpenCTI (demo)", "opencti", "https://opencti.demo.internal", "read_indicators", "unconfigured"),
        ("Keycloak (demo)", "keycloak", "https://idp.demo.internal", "revoke_sessions", "healthy"),
        ("pfSense (demo)", "pfsense", "https://fw.demo.internal", "block_ip", "unconfigured"),
        (
            "Microsoft Sentinel (demo)",
            "microsoft_sentinel",
            "https://api.loganalytics.io",
            "read_alerts",
            "unconfigured",
        ),
    ]
    for name, connector_type, url, capability, status in connector_specs:
        db.add(
            Connector(
                org_id=org_id,
                name=name,
                connector_type=connector_type,
                base_url=url,
                auth_type="api_key",
                capabilities={"declared": [capability], "write_enabled": capability in {"block_ip", "revoke_sessions"}},
                status=status,
                enabled=status in {"healthy", "degraded"},
                verify_tls=True,
                created_by=str(analyst.id),
            )
        )

    # ------------------------------------------------------------------- AI
    provider = AIProvider(
        org_id=org_id,
        name="Ollama local (demo)",
        kind="ollama",
        base_url=settings.default_ollama_url,
        default_model="qwen2.5:7b-instruct",
        enabled=True,
        is_local=True,
        health_status="unknown",
        config={"demo": True, "note": "Registrar un modelo disponible en el runtime local"},
    )
    db.add(provider)
    db.flush()
    db.add(
        AIModel(
            provider_id=provider.id,
            name="qwen2.5:7b-instruct",
            display_name="Qwen 2.5 7B Instruct (local)",
            task_tags=["triage", "analysis", "report"],
            context_window=32768,
            max_output_tokens=2048,
            status="available",
            evaluation={},
        )
    )
    doc = KnowledgeDocument(
        org_id=org_id,
        title="Runbook: contención de endpoint comprometido",
        source="internal://runbooks/endpoint-containment",
        kind="runbook",
        version="1.0",
        checksum=hashlib.sha256(b"runbook-demo").hexdigest(),
        text=(
            "Ante un endpoint comprometido: 1) validar la alerta y el activo; 2) preservar evidencia volátil; "
            "3) solicitar aprobación para aislamiento si el activo es crítico; 4) aislar preservando gestión; "
            "5) verificar conectividad de gestión; 6) rotar credenciales; 7) documentar en el timeline."
        ),
        metadata_json={"demo": True},
        created_by=str(analyst.id),
    )
    db.add(doc)
    db.flush()
    chunk_text = doc.text
    vector = [0.0] * 64
    for token in chunk_text.lower().split():
        vector[hash(token) % 64] += 1.0
    norm = sum(value * value for value in vector) ** 0.5 or 1.0
    db.add(
        KnowledgeChunk(
            document_id=doc.id,
            org_id=org_id,
            ordinal=0,
            text=chunk_text,
            embedding=[round(value / norm, 6) for value in vector],
            embedding_model="local-hash-v1",
            tokens=len(chunk_text.split()),
        )
    )

    # ------------------------------------------------------------ compliance
    framework = db.execute(select(ComplianceFramework).where(ComplianceFramework.code == "NIS2")).scalars().first()
    if framework is not None:
        controls = list(
            db.execute(
                select(ComplianceControl).where(ComplianceControl.framework_id == framework.id).limit(12)
            ).scalars()
        )
        assessment = ComplianceAssessment(
            org_id=org_id,
            framework_id=framework.id,
            framework_version=framework.version,
            status="in_progress",
            assessor="Equipo de cumplimiento (demo)",
            summary="Autoevaluación técnica de demostración; no constituye certificación.",
        )
        db.add(assessment)
        db.flush()
        for index, control in enumerate(controls):
            db.add(
                ComplianceControlStatus(
                    assessment_id=assessment.id,
                    control_id=control.id,
                    status=["compliant", "partial", "non_compliant", "compliant"][index % 4],
                    notes="Evaluación de demostración",
                    owner="Equipo de cumplimiento",
                )
            )

    db.add_all(
        [
            Notification(
                org_id=org_id,
                kind="incident",
                title="Incidente crítico HS-2026-1042 asignado",
                body="Requiere triaje humano en menos de 30 minutos.",
                created_at=now - timedelta(minutes=12),
            ),
            Notification(
                org_id=org_id,
                kind="integration",
                title="Conector Wazuh degradado",
                body="El health check ha fallado 3 veces consecutivas.",
                created_at=now - timedelta(hours=1),
            ),
            Notification(
                org_id=org_id,
                kind="compliance",
                title="Evaluación NIS2 iniciada",
                body="Se ha creado una autoevaluación técnica de demostración.",
                created_at=now - timedelta(hours=5),
            ),
        ]
    )

    db.commit()
    return org, True


def main() -> None:
    if settings.is_production:
        raise SystemExit("Refusing to seed demo data in production")
    if not settings.seed_demo:
        raise SystemExit("Set HS_SEED_DEMO=true to acknowledge demo seeding")
    with SessionLocal() as db:
        org, created = seed_demo(db)
    state = "created" if created else "already present"
    print(f"Demo organization {org.slug} {state} (id={org.id})")
    print(f"Demo analyst: analista.demo@nova-iberia.example / {DEMO_PASSWORD}")
    print("All demo records are marked is_demo=true.")


if __name__ == "__main__":
    main()
