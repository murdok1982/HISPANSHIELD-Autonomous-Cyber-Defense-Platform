"""Read-only API smoke test against a running HISPANSHIELD instance.

Usage:
  HS_SMOKE_EMAIL=... HS_SMOKE_PASSWORD=... HS_SMOKE_URL=http://127.0.0.1:8080 \
    python scripts/smoke_api.py

It logs in, scopes to the demo organization when available, exercises the main
read endpoints and fails on any 5xx. It is intentionally read-only: no mutation,
no privilege escalation and no external network calls.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import httpx

BASE = os.environ.get("HS_SMOKE_URL", "http://127.0.0.1:8080")
EMAIL = os.environ.get("HS_SMOKE_EMAIL", "admin@nova-iberia.example")
PASSWORD = os.environ.get("HS_SMOKE_PASSWORD", "Dev-Str0ng-Pass!2026")
ORG_NAME = os.environ.get("HS_SMOKE_ORG", "Ayuntamiento de Nova Iberia (demo)")

FAILURES: list[str] = []
CHECKED = 0


def check(client: httpx.Client, path: str, *, allow: tuple[int, ...] = (200,)) -> dict[str, Any] | list[Any] | None:
    global CHECKED
    CHECKED += 1
    try:
        response = client.get(f"/api/v1{path}")
    except httpx.HTTPError as exc:
        FAILURES.append(f"{path}: transport error {exc}")
        return None
    if response.status_code not in allow:
        FAILURES.append(f"{path}: HTTP {response.status_code} {response.text[:200]}")
        return None
    try:
        return response.json()
    except ValueError:
        return None


def ids(payload: Any) -> list[str]:
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return [str(item["id"]) for item in items if isinstance(item, dict) and "id" in item]
    if isinstance(payload, list):
        return [str(item["id"]) for item in payload if isinstance(item, dict) and "id" in item]
    return []


def main() -> int:
    with httpx.Client(base_url=BASE, timeout=30, follow_redirects=False) as client:
        login = client.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
        if login.status_code != 200 or "mfa_required" in login.text:
            print(f"login failed: HTTP {login.status_code} {login.text[:300]}", file=sys.stderr)
            return 2
        session = login.json()
        csrf = session.get("csrf_token")
        headers = {"X-CSRF-Token": csrf} if csrf else {}
        demo = next((org for org in session["organizations"] if org["name"] == ORG_NAME), None)
        if demo:
            client.post("/api/v1/auth/switch-org", json={"org_id": demo["id"]}, headers=headers)
            headers["X-Organization-Id"] = demo["id"]
        client.headers.update(headers)

        overview = check(client, "/overview/executive")
        check(client, "/overview/soc")
        check(client, "/overview/notifications")
        check(client, "/overview/search?q=demo", allow=(200, 422))
        check(client, "/organizations/current")
        check(client, "/organizations/current/members")
        check(client, "/organizations/current/policies")
        check(client, "/organizations/current/kill-switches")
        check(client, "/organizations/current/approvals")
        check(client, "/organizations/current/audit")
        check(client, "/organizations/current/audit/verify")

        assets = check(client, "/assets?page_size=5")
        check(client, "/zones")
        asset_ids = ids(assets)
        if asset_ids:
            check(client, f"/assets/{asset_ids[0]}")
            check(client, f"/assets/{asset_ids[0]}/graph")
            check(client, f"/assets/{asset_ids[0]}/vulnerabilities")
            check(client, f"/assets/{asset_ids[0]}/relationships")
            check(client, f"/assets/{asset_ids[0]}/identities")
        vulns = check(client, "/vulnerabilities?page_size=5")
        check(client, "/vulnerabilities/summary")
        vuln_ids = ids(vulns)
        if vuln_ids:
            check(client, f"/vulnerabilities/{vuln_ids[0]}")
        check(client, "/attack-surface/findings?page_size=5")
        check(client, "/attack-surface/summary")
        check(client, "/attack-surface/discovery-jobs")
        check(client, "/iot/devices?page_size=5")
        check(client, "/iot/protocols")
        check(client, "/iot/summary")
        check(client, "/ot/devices?page_size=5")
        check(client, "/ot/protocols")
        check(client, "/ot/posture")

        check(client, "/events?page_size=5")
        check(client, "/events/stats")
        check(client, "/events/retention")
        check(client, "/ingest-sources")
        check(client, "/siem/rules")
        check(client, "/siem/rules/templates")
        check(client, "/siem/alerts?page_size=5")
        check(client, "/siem/alerts/stats")
        check(client, "/siem/mitre/coverage")

        incidents = check(client, "/incidents?page_size=5")
        check(client, "/incidents/metrics")
        incident_ids = ids(incidents)
        if incident_ids:
            check(client, f"/incidents/{incident_ids[0]}")
            check(client, f"/incidents/{incident_ids[0]}/timeline")
        check(client, "/soar/playbooks?page_size=5")
        check(client, "/soar/executions?page_size=5")
        check(client, "/defence/actions")
        check(client, "/defence/policy/snapshot")
        check(client, "/defence/kill-switches/effective")
        check(client, "/defence/remediations?page_size=5")

        check(client, "/threat-intel/indicators?page_size=5")
        check(client, "/threat-intel/actors?page_size=5")
        check(client, "/threat-intel/feeds?page_size=5")
        check(client, "/threat-intel/summary")
        check(client, "/threat-intel/mitre/techniques")
        check(client, "/threat-intel/mitre/coverage")
        check(client, "/threat-intel/enrich?value=203.0.113.77&type=ip")

        check(client, "/connectors?page_size=5")
        check(client, "/connectors/catalog")
        check(client, "/connectors/health/summary")
        check(client, "/edge/gateways?page_size=5")
        check(client, "/mcp/servers?page_size=5")
        check(client, "/mcp/tools?page_size=5")

        check(client, "/ai/providers")
        check(client, "/ai/models")
        check(client, "/ai/health")
        check(client, "/ai/usage")
        check(client, "/ai/knowledge")
        check(client, "/agents")
        check(client, "/agents/runs?page_size=5")

        check(client, "/compliance/frameworks")
        check(client, "/compliance/summary")
        check(client, "/compliance/assessments?page_size=5")
        check(client, "/reports?page_size=5")
        check(client, "/forensics/cases")
        check(client, "/forensics/evidence")
        check(client, "/posture/network")
        check(client, "/posture/cloud")
        check(client, "/posture/identity")
        check(client, "/posture/summary")

        print(f"Smoke checks: {CHECKED}, failures: {len(FAILURES)}")
        for failure in FAILURES:
            print(f"  FAIL {failure}")
        return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
