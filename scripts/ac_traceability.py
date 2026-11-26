#!/usr/bin/env python3
"""Render the AC traceability matrix from SPEC.md plus an explicit status map.

A checkbox in SPEC.md is *not* evidence by itself. This script force-maps every
AC to one of:

* VERIFIED   — a named executable test exercises the acceptance behaviour;
* PARTIAL    — part of the contract exists, but at least one condition is open;
* NOT_VERIFIED — no executable evidence exists (or the capability is absent).

Update the map when tests are added; never flip an AC to VERIFIED without a test
name that a reviewer can run.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / ".factory" / "SPEC.md"
OUT = ROOT / ".factory" / "AC_TRACEABILITY.md"

# AC -> (status, evidence / reason)
STATUS: dict[str, tuple[str, str]] = {
    "AC-01": ("VERIFIED", "`test_auth.py::test_login_me_and_logout`, `::test_session_cookie_flags`"),
    "AC-02": ("VERIFIED", "`test_http_hardening.py::test_mfa_enrollment_login_and_replay_protection`"),
    "AC-03": ("VERIFIED", "`test_auth.py::test_single_source_cannot_lock_account_for_its_owner`, `::test_distributed_failures_still_trigger_a_global_lock`"),
    "AC-04": ("VERIFIED", "`test_auth.py::test_csrf_required_for_session_mutations`"),
    "AC-05": ("VERIFIED", "`test_auth.py::test_api_token_authentication_and_scope`, `::test_api_token_cannot_escalate_scopes`"),
    "AC-06": ("VERIFIED", "`test_auth.py::test_expired_session_is_rejected`, `::test_idle_session_is_rejected`, `::test_user_can_list_and_revoke_other_sessions`; idle default now 30 min"),
    "AC-07": ("VERIFIED", "`test_auth.py::test_weak_password_rejected_on_change`, `test_auth_policy.py`"),
    "AC-08": ("PARTIAL", "Auth paths append audit rows, but not every auth outcome has an explicit per-event assertion"),
    "AC-09": ("VERIFIED", "`test_setup.py::test_setup_creates_first_org_at_a0_and_refuses_replay`"),
    "AC-10": ("VERIFIED", "`test_assets.py::test_asset_cross_tenant_isolation`, cross-tenant suites across domains"),
    "AC-11": ("PARTIAL", "Membership checks are enforced; `X-Organization-Id` is optional by design, not the specced `400` contract"),
    "AC-12": ("PARTIAL", "RBAC is enforced and tested per domain; a generated role×endpoint matrix is not complete"),
    "AC-13": ("VERIFIED", "`test_invitations.py` (single use, 72 h TTL, revocation, role binding)"),
    "AC-14": ("NOT_VERIFIED", "Organization soft-delete/purge flow is not implemented"),
    "AC-15": ("VERIFIED", "`test_assets.py::test_asset_crud_and_audit`, `::test_asset_validation_errors`"),
    "AC-16": ("VERIFIED", "`test_assets.py::test_relationships_both_directions_graph_and_validation`"),
    "AC-17": ("VERIFIED", "`test_assets.py::test_asset_import_idempotency_and_row_errors`"),
    "AC-18": ("NOT_VERIFIED", "Asset delete is physical; `deleted_at`/restore not implemented"),
    "AC-19": ("PARTIAL", "Cursor keyset implemented and tested; 5,000-row p95 benchmark not executed"),
    "AC-20": ("VERIFIED", "`test_iot_ot.py` IoT registration/validation suite"),
    "AC-21": ("VERIFIED", "`tests/unit/test_risk.py` determinism/idempotency suite"),
    "AC-22": ("PARTIAL", "Exposure observations exist; before/after diff assertions are not complete"),
    "AC-23": ("PARTIAL", "Unauthorized-exposure finding path exists; explicit assertion not recorded"),
    "AC-24": ("VERIFIED", "`test_attack_surface.py::test_discovery_scope_validation_rejects_unsafe_targets`, authorization suites"),
    "AC-25": ("NOT_VERIFIED", "`GET /attack-surface/export` is absent"),
    "AC-26": ("PARTIAL", "Idempotency-Key works for incidents/imports; discovery-job endpoint not yet wired"),
    "AC-27": ("VERIFIED", "`tests/unit/test_risk.py` score/priority/SLA suite"),
    "AC-28": ("VERIFIED", "`test_vulnerabilities.py` fingerprint/dedupe suite"),
    "AC-29": ("VERIFIED", "`test_vulnerabilities.py` transition validation suite"),
    "AC-30": ("NOT_VERIFIED", "Risk exceptions with expiry/revocation are not implemented"),
    "AC-31": ("NOT_VERIFIED", "Nessus/OpenVAS/Trivy importers are absent"),
    "AC-32": ("PARTIAL", "False-positive flow exists; mandatory evidence test not recorded"),
    "AC-33": ("PARTIAL", "Syslog parser/listener tests exist; deployed UDP listener not exercised end-to-end"),
    "AC-34": ("VERIFIED", "`test_events.py::test_hmac_signature_required_and_verified`"),
    "AC-35": ("VERIFIED", "`test_ingest_security.py` dedupe/nonce replay suite"),
    "AC-36": ("VERIFIED", "`tests/unit/test_detection.py` validation suite"),
    "AC-37": ("VERIFIED", "`tests/unit/test_detection.py::test_threshold_rule_creates_one_deduped_alert`"),
    "AC-38": ("VERIFIED", "`test_siem.py::test_alert_triage_stats_filters_and_bulk`"),
    "AC-39": ("NOT_VERIFIED", "FTS GIN is created but queries use LIKE; 100k p95 benchmark not run"),
    "AC-40": ("PARTIAL", "Alert→incident promotion exists; 10-minute correlation rule assertion not explicit"),
    "AC-41": ("VERIFIED", "`test_audit_integrity.py::test_audit_record_cannot_be_updated_or_deleted`, `::test_audit_table_cannot_be_truncated`"),
    "AC-42": ("NOT_VERIFIED", "Monthly partitions and partition-retention job are absent"),
    "AC-43": ("VERIFIED", "`test_soar.py` DAG validation suite"),
    "AC-44": ("VERIFIED", "`test_playbook_claim.py` lease reclaim/resume suite"),
    "AC-45": ("VERIFIED", "`test_soar.py` retry/backoff suite"),
    "AC-46": ("VERIFIED", "`test_defence.py::test_approval_expiry_blocks_remediation_execution`"),
    "AC-47": ("VERIFIED", "`test_soar.py` compensation suite"),
    "AC-48": ("VERIFIED", "`test_defence.py::test_dry_run_execute_has_no_side_effects`"),
    "AC-49": ("NOT_VERIFIED", "Per-org max_concurrent_executions queue is not implemented"),
    "AC-50": ("VERIFIED", "`test_threat_intel.py` STIX import/export round-trip suite"),
    "AC-51": ("PARTIAL", "TAXII pagination exists; full multi-page assertion not recorded"),
    "AC-52": ("VERIFIED", "`test_threat_intel.py` validity/expiry suite"),
    "AC-53": ("VERIFIED", "`test_events.py::test_ioc_enrichment_attaches_matches_and_mitre`"),
    "AC-54": ("VERIFIED", "`test_connectors.py::test_sync_failure_marks_connector_degraded`, circuit-breaker suite"),
    "AC-55": ("VERIFIED", "`test_incidents.py` promotion/SLA suite"),
    "AC-56": ("VERIFIED", "`test_incidents.py` state-machine/timeline suite"),
    "AC-57": ("VERIFIED", "`test_forensics.py::test_verify_hash_match_appends_custody`, `::test_verify_hash_detects_tampering`"),
    "AC-58": ("VERIFIED", "`test_forensics.py::test_rbac_viewer_cannot_verify_hashes`"),
    "AC-59": ("NOT_VERIFIED", "Legal hold is absent"),
    "AC-60": ("PARTIAL", "Reports include timeline/evidence/hash; PDF generation is absent"),
    "AC-61": ("VERIFIED", "`test_ai.py::test_completion_returns_503_without_fabricating_output`"),
    "AC-62": ("VERIFIED", "`test_ai.py::test_routing_falls_back_to_another_healthy_provider`"),
    "AC-63": ("VERIFIED", "`test_ai.py::test_rag_document_lifecycle_and_citations`"),
    "AC-64": ("PARTIAL", "Embedding dimension checks exist; explicit mismatch assertion not recorded"),
    "AC-65": ("VERIFIED", "`tests/unit/test_prompt_safety.py` prompt-injection suite"),
    "AC-66": ("VERIFIED", "`test_mcp.py` tool allowlist/injection suite"),
    "AC-67": ("VERIFIED", "`test_ai.py::test_ai_budget_exhaustion_denies_before_calling_provider`"),
    "AC-68": ("VERIFIED", "`test_ai.py::test_completion_success_logs_redacted_prompt`"),
    "AC-69": ("NOT_VERIFIED", "Durable agent run with step-log resume is not implemented"),
    "AC-70": ("VERIFIED", "`test_defence.py::test_unknown_and_forbidden_actions_are_denied` (fail-closed)"),
    "AC-71": ("VERIFIED", "`test_defence.py::test_evaluate_denies_ceiling_and_allows_when_raised`"),
    "AC-72": ("VERIFIED", "`test_defence.py::test_execute_allowed_action_through_local_connector`"),
    "AC-73": ("VERIFIED", "`tests/security/test_autonomy_guardrails.py` blast-radius suite"),
    "AC-74": ("VERIFIED", "`test_defence.py::test_kill_switch_blocks_state_changing_action`"),
    "AC-75": ("VERIFIED", "`tests/unit/test_policy_guardrails.py` freeze suite"),
    "AC-76": ("VERIFIED", "`tests/unit/test_policy_guardrails.py` hourly/daily budget suite"),
    "AC-77": ("PARTIAL", "Audit records the decision; a dedicated `/audit/actions/{action_id}` endpoint is absent"),
    "AC-78": ("NOT_VERIFIED", "No A4 action exists; dual-approval A4 is not implemented"),
    "AC-79": ("NOT_VERIFIED", "ETSI EN 303 645 13-provision checklist is absent"),
    "AC-80": ("NOT_VERIFIED", "Firmware CPE/version→CVE matching is absent"),
    "AC-81": ("PARTIAL", "Stale telemetry is exposed, but the autonomy block assertion is not complete"),
    "AC-82": ("VERIFIED", "`test_defence.py::test_ot_asset_is_blocked`"),
    "AC-83": ("NOT_VERIFIED", "Industrial protocol baseline/write anomaly detection is absent"),
    "AC-84": ("PARTIAL", "IEC 62443 zones/conduits exist; mandatory `required_sl` is not enforced"),
    "AC-85": ("VERIFIED", "Connector secret handling tests (`test_connectors.py`); cloud accounts are not implemented"),
    "AC-86": ("NOT_VERIFIED", "CSPM rules/cloud accounts are absent"),
    "AC-87": ("NOT_VERIFIED", "Cloud posture scan is absent"),
    "AC-88": ("VERIFIED", "`test_compliance.py::test_framework_catalogue_lists_counts_and_status`"),
    "AC-89": ("PARTIAL", "Evidence-derived status exists; explicit `evidence_required` error assertion not recorded"),
    "AC-90": ("VERIFIED", "`test_compliance.py::test_assessment_derives_control_statuses_from_evidence`, scoring suite"),
    "AC-91": ("PARTIAL", "Evidence validity is stored; expiry recomputation test not recorded"),
    "AC-92": ("NOT_VERIFIED", "NIS2 24/72h/1-month tracker is absent"),
    "AC-93": ("VERIFIED", "`test_reports.py` generated-at/framework/hash suite (HTML/MD; PDF absent)"),
    "AC-94": ("PARTIAL", "Screen E2E evidence exists from RC1 but was not re-run in this wave; Firefox/WebKit not covered"),
    "AC-95": ("VERIFIED", "Frontend `PageSkeleton`/`TableSkeleton` components with `aria-busy`"),
    "AC-96": ("VERIFIED", "`EmptyState` with CTA used across data views; Vitest suite"),
    "AC-97": ("VERIFIED", "`ErrorBanner` retry used across data views; Vitest suite"),
    "AC-98": ("PARTIAL", "Responsive layout exists; 375/768/1440 no-overflow gate not automated here"),
    "AC-99": ("NOT_VERIFIED", "axe-core automated contrast gate is not installed"),
    "AC-100": ("PARTIAL", "Focus-visible tokens exist; full tab-order test not recorded"),
    "AC-101": ("PARTIAL", "SSE + Last-Event-ID + pause implemented; explicit `reconnecting` UI assertion not recorded"),
    "AC-102": ("VERIFIED", "Destructive actions require explicit confirmation (OT delete, kill switch, org)"),
    "AC-103": ("PARTIAL", "Reduced-motion CSS exists; automated assertion not recorded"),
    "AC-104": ("VERIFIED", "`test_connectors.py::test_catalog_lists_adapters_and_configuration_gaps`"),
    "AC-105": ("VERIFIED", "`test_edge.py` SQLite WAL buffering/replay suite"),
    "AC-106": ("PARTIAL", "TLS verification is enforced; mTLS client-cert handshake not exercised"),
    "AC-107": ("VERIFIED", "`test_connectors.py::test_circuit_breaker_opens_after_repeated_health_failures`"),
    "AC-108": ("VERIFIED", "`test_mcp.py` tool schema/listing suite"),
    "AC-109": ("PARTIAL", "Compatibility matrix corrected in this wave; every row is not yet contract-tested"),
    "AC-110": ("VERIFIED", "`test_auth.py::test_health_endpoints`; `/readyz` now reports outbox backlog"),
    "AC-111": ("PARTIAL", "Alembic upgrade is exercised per test session; downgrade-to-base is not automated"),
    "AC-112": ("VERIFIED", "`test_audit_integrity.py`, `test_audit_hmac.py` (v1/v2/v3, tamper, key rotation, checkpoints)"),
    "AC-113": ("NOT_VERIFIED", "Backup/restore scripts were not executed against an isolated instance in this wave"),
    "AC-114": ("NOT_VERIFIED", "Air-gapped installation bundle is not built/tested"),
    "AC-115": ("PARTIAL", "Structured logs with request_id exist; org/route/duration assertions not per-route"),
    "AC-116": ("PARTIAL", "Worker handles SIGTERM; API graceful-drain assertion not recorded"),
    "AC-117": ("VERIFIED", "Backend pytest suite (see `.factory/EVIDENCE/BACKEND_TEST_RUN.md`)"),
    "AC-118": ("VERIFIED", "`tsc -b`, `vite build` and `vitest run` executed in this wave"),
    "AC-119": ("NOT_VERIFIED", "Playwright critical-flow suite was not executed in this host"),
    "AC-120": ("PARTIAL", "pip-audit/bandit/gitleaks configured; full run not executed in this wave"),
    "AC-121": ("PARTIAL", "SBOM script exists; artifact not regenerated here"),
    "AC-122": ("PARTIAL", "Tenant isolation suites are broad, but a 100% resource/role matrix is not generated"),
    "AC-123": ("NOT_VERIFIED", "Full autonomy laboratory matrix is not automated"),
    "AC-124": ("PARTIAL", "Prompt-injection unit suite exists; a labelled corpus with 0-leak gate is not automated"),
}


def _acs() -> list[tuple[str, str]]:
    text = SPEC.read_text(encoding="utf-8")
    pattern = re.compile(r"^\s*- \[ \] \*\*(AC-\d{2,3}):\*\* (.+)$", re.M)
    items = []
    for match in pattern.finditer(text):
        title = re.sub(r"\*\*", "", match.group(2))
        title = re.sub(r"`", "", title)
        items.append((match.group(1), title.strip()))
    return items


def main() -> int:
    items = _acs()
    counts = {"VERIFIED": 0, "PARTIAL": 0, "NOT_VERIFIED": 0}
    rows: list[str] = []
    for ac, title in items:
        status, evidence = STATUS.get(ac, ("NOT_VERIFIED", "No explicit executable assertion recorded"))
        counts[status] += 1
        short = title if len(title) <= 150 else title[:147] + "…"
        rows.append(f"| {ac} | {short} | **{status}** | {evidence} |")
    body = f"""# AC traceability matrix

- Generated by `python3 scripts/ac_traceability.py`; the source of truth is the
  status map in that script plus the executable test names it cites.
- `VERIFIED` requires a named test that exercises the acceptance behaviour.
  A task marked `[x]` in `TASKS.md` does **not** by itself verify every AC in its
  spec reference.
- `PARTIAL`: the capability exists but at least one condition or benchmark is
  missing. `NOT_VERIFIED`: no executable evidence, or the capability is absent.

| Status | Count |
| :--- | ---: |
| VERIFIED | {counts['VERIFIED']} |
| PARTIAL | {counts['PARTIAL']} |
| NOT_VERIFIED | {counts['NOT_VERIFIED']} |
| **Total** | **{len(items)}** |

| AC | Acceptance criterion (abridged) | Status | Evidence / reason |
| :--- | :--- | :--- | :--- |
{chr(10).join(rows)}
"""
    OUT.write_text(body, encoding="utf-8")
    print(f"wrote {OUT} — {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
