# MATRIZ DE TRAZABILIDAD AC → TEST

- **Documento:** `specs/testing/matrix.md`
- **Estado:** `APPROVED` v1.0
- **Regla:** toda fila debe tener un test existente y ejecutable. Una fila sin test bloquea el Exit Gate.
- **Estado inicial:** `SPECIFIED` (los tests se crean en las tareas indicadas).

---

## 1. IDENTIDAD Y ACCESO (`AC-01..AC-08`)

| AC | Test | Tarea | Estado |
| :--- | :--- | :--- | :--- |
| `AC-01` | `backend/tests/integration/test_auth_login.py::test_login_sets_rotated_session_cookie` | 014 | `SPECIFIED` |
| `AC-02` | `backend/tests/integration/test_auth_mfa.py::test_totp_challenge_required_and_verified` | 015 | `SPECIFIED` |
| `AC-03` | `backend/tests/security/test_auth_rate_limit.py::test_lockout_and_no_user_enumeration` | 016 | `SPECIFIED` |
| `AC-04` | `backend/tests/security/test_csrf.py::test_double_submit_enforced` | 017 | `SPECIFIED` |
| `AC-05` | `backend/tests/integration/test_api_tokens.py::test_scoped_bearer_token` | 018 | `SPECIFIED` |
| `AC-06` | `backend/tests/integration/test_session_lifecycle.py::test_revocation_and_idle_expiry` | 014 | `SPECIFIED` |
| `AC-07` | `backend/tests/unit/test_password_policy.py` | 016 | `SPECIFIED` |
| `AC-08` | `backend/tests/integration/test_audit_chain.py::test_auth_events_chained` | 007 | `SPECIFIED` |

## 2. ORGANIZACIONES (`AC-09..AC-14`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-09` | `backend/tests/integration/test_setup.py::test_first_run_bootstrap_idempotent` | 019 |
| `AC-10` | `backend/tests/security/test_tenant_isolation.py::test_cross_org_read_returns_404` | 028 |
| `AC-11` | `backend/tests/security/test_tenant_isolation.py::test_header_required_and_membership_enforced` | 028 |
| `AC-12` | `backend/tests/security/test_rbac_matrix.py` | 028 |
| `AC-13` | `backend/tests/integration/test_invitations.py` | 020 |
| `AC-14` | `backend/tests/integration/test_org_lifecycle.py::test_soft_delete_requires_confirmation` | 019 |

## 3. ACTIVOS, ASM Y VULNERABILIDADES (`AC-15..AC-32`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-15` | `backend/tests/integration/test_assets_crud.py::test_create_and_validate` | 030 |
| `AC-16` | `backend/tests/unit/test_asset_graph.py::test_cycle_rejected` | 031 |
| `AC-17` | `backend/tests/integration/test_asset_import.py::test_partial_import_report` | 032 |
| `AC-18` | `backend/tests/integration/test_assets_crud.py::test_soft_delete_restore` | 030 |
| `AC-19` | `backend/tests/performance/test_assets_search.py` | 033 |
| `AC-20` | `backend/tests/integration/test_assets_iot_validation.py` | 034 |
| `AC-21` | `backend/tests/integration/test_risk_recompute.py::test_idempotent_recompute` | 033 |
| `AC-22` | `backend/tests/integration/test_asm_diff.py::test_banner_change_diff` | 035 |
| `AC-23` | `backend/tests/integration/test_asm_authorization.py` | 036 |
| `AC-24` | `backend/tests/security/test_asm_scope_guard.py` | 036 |
| `AC-25` | `backend/tests/integration/test_asm_export.py::test_stix_roundtrip` | 037 |
| `AC-26` | `backend/tests/integration/test_jobs_idempotency.py` | 036 |
| `AC-27` | `backend/tests/unit/test_risk_scoring.py::test_known_exploited_internet_facing` | 038 |
| `AC-28` | `backend/tests/integration/test_vuln_dedupe.py` | 039 |
| `AC-29` | `backend/tests/unit/test_vuln_state_machine.py` | 039 |
| `AC-30` | `backend/tests/integration/test_risk_acceptance.py` | 041 |
| `AC-31` | `backend/tests/integration/test_vuln_importers.py` | 040 |
| `AC-32` | `backend/tests/integration/test_vuln_false_positive.py` | 039 |

## 4. SIEM (`AC-33..AC-42`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-33` | `backend/tests/integration/test_syslog_ingest.py::test_rfc5424_udp_normalized` | 044 |
| `AC-34` | `backend/tests/security/test_webhook_hmac.py` | 045 |
| `AC-35` | `backend/tests/integration/test_event_idempotency.py` | 045 |
| `AC-36` | `backend/tests/unit/test_rule_dsl.py::test_invalid_rule_rejected` | 048 |
| `AC-37` | `backend/tests/integration/test_detection_engine.py::test_threshold_and_dedupe` | 049 |
| `AC-38` | `backend/tests/integration/test_alert_lifecycle.py` | 051 |
| `AC-39` | `backend/tests/performance/test_event_search.py` | 047 |
| `AC-40` | `backend/tests/integration/test_correlation_to_incident.py` | 051 |
| `AC-41` | `backend/tests/security/test_event_immutability.py` | 046 |
| `AC-42` | `backend/tests/integration/test_retention_job.py` | 052 |

## 5. SOAR (`AC-43..AC-49`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-43` | `backend/tests/unit/test_playbook_dag.py` | 068 |
| `AC-44` | `backend/tests/integration/test_workflow_resume.py::test_kill_worker_and_resume` | 069 |
| `AC-45` | `backend/tests/unit/test_retry_policy.py` | 070 |
| `AC-46` | `backend/tests/integration/test_approvals.py::test_timeout_denies` | 071 |
| `AC-47` | `backend/tests/integration/test_compensation.py` | 072 |
| `AC-48` | `backend/tests/integration/test_dry_run.py` | 073 |
| `AC-49` | `backend/tests/integration/test_concurrency_limits.py` | 073 |

## 6. THREAT INTELLIGENCE (`AC-50..AC-54`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-50` | `backend/tests/integration/test_stix_roundtrip.py` | 060 |
| `AC-51` | `backend/tests/integration/test_taxii_client.py` | 061 |
| `AC-52` | `backend/tests/unit/test_indicator_ttl.py` | 059 |
| `AC-53` | `backend/tests/integration/test_ioc_matching.py` | 062 |
| `AC-54` | `backend/tests/integration/test_feed_health.py` | 061 |

## 7. INCIDENTES Y FORENSE (`AC-55..AC-60`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-55` | `backend/tests/unit/test_incident_severity.py` | 055 |
| `AC-56` | `backend/tests/integration/test_incident_state_machine.py` | 055 |
| `AC-57` | `backend/tests/security/test_evidence_integrity.py` | 057 |
| `AC-58` | `backend/tests/security/test_evidence_access.py` | 057 |
| `AC-59` | `backend/tests/integration/test_legal_hold.py` | 063 |
| `AC-60` | `backend/tests/integration/test_incident_report.py` | 058 |

## 8. IA (`AC-61..AC-69`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-61` | `backend/tests/integration/test_ai_unavailable.py` | 088 |
| `AC-62` | `backend/tests/integration/test_ai_routing.py` | 089 |
| `AC-63` | `backend/tests/integration/test_rag_citations.py` | 092 |
| `AC-64` | `backend/tests/unit/test_vector_store.py` | 091 |
| `AC-65` | `backend/tests/security/test_prompt_injection.py` | 095 |
| `AC-66` | `backend/tests/security/test_mcp_allowlist.py` | 094 |
| `AC-67` | `backend/tests/integration/test_ai_budget.py` | 089 |
| `AC-68` | `backend/tests/security/test_ai_log_redaction.py` | 090 |
| `AC-69` | `backend/tests/integration/test_agent_durability.py` | 093 |

## 9. AUTONOMÍA (`AC-70..AC-78`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-70` | `backend/tests/autonomy/test_policy_default_deny.py` | 078 |
| `AC-71` | `backend/tests/autonomy/test_level_gating.py` | 079 |
| `AC-72` | `backend/tests/autonomy/test_execute_verify_rollback.py` | 081 |
| `AC-73` | `backend/tests/autonomy/test_blast_radius.py` | 079 |
| `AC-74` | `backend/tests/autonomy/test_kill_switch.py::test_global_halt_latency` | 082 |
| `AC-75` | `backend/tests/autonomy/test_change_freeze.py` | 083 |
| `AC-76` | `backend/tests/autonomy/test_action_budget.py` | 083 |
| `AC-77` | `backend/tests/autonomy/test_action_audit.py` | 085 |
| `AC-78` | `backend/tests/autonomy/test_a4_dual_approval.py` | 084 |

## 10. IOT, OT, CLOUD (`AC-79..AC-87`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-79` | `backend/tests/integration/test_iot_registration.py` | 099 |
| `AC-80` | `backend/tests/integration/test_firmware_cve.py` | 100 |
| `AC-81` | `backend/tests/autonomy/test_stale_sensor.py` | 100 |
| `AC-82` | `backend/tests/autonomy/test_ot_safety_interlock.py` | 084 |
| `AC-83` | `backend/tests/integration/test_ot_anomaly.py` | 102 |
| `AC-84` | `backend/tests/integration/test_iec62443_zones.py` | 101 |
| `AC-85` | `backend/tests/security/test_connector_secret_storage.py` | 108 |
| `AC-86` | `backend/tests/integration/test_cspm_rules.py` | 105 |
| `AC-87` | `backend/tests/integration/test_cloud_degraded_state.py` | 105 |

## 11. CUMPLIMIENTO (`AC-88..AC-93`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-88` | `backend/tests/integration/test_framework_seed.py` | 113 |
| `AC-89` | `backend/tests/integration/test_control_status_derivation.py` | 114 |
| `AC-90` | `backend/tests/unit/test_assessment_scoring.py` | 115 |
| `AC-91` | `backend/tests/integration/test_evidence_expiry.py` | 114 |
| `AC-92` | `backend/tests/integration/test_nis2_timeline.py` | 116 |
| `AC-93` | `backend/tests/integration/test_report_integrity.py` | 117 |

## 12. FRONTEND (`AC-94..AC-103`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-94` | `frontend/e2e/screens.spec.ts` | 132 |
| `AC-95` | `frontend/e2e/states.spec.ts::test_loading_skeleton` | 123 |
| `AC-96` | `frontend/e2e/states.spec.ts::test_empty_state_cta` | 123 |
| `AC-97` | `frontend/e2e/states.spec.ts::test_error_retry` | 123 |
| `AC-98` | `frontend/e2e/responsive.spec.ts` | 124 |
| `AC-99` | `frontend/e2e/a11y.spec.ts` | 125 |
| `AC-100` | `frontend/e2e/keyboard.spec.ts` | 125 |
| `AC-101` | `frontend/e2e/live-stream.spec.ts` | 126 |
| `AC-102` | `frontend/e2e/destructive-confirm.spec.ts` | 087 |
| `AC-103` | `frontend/e2e/reduced-motion.spec.ts` | 125 |

## 13. INTEGRACIONES (`AC-104..AC-109`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-104` | `backend/tests/integration/test_connector_registry.py` | 107 |
| `AC-105` | `edge/tests/test_store_and_forward.py` | 110 |
| `AC-106` | `edge/tests/test_mtls.py` | 111 |
| `AC-107` | `backend/tests/integration/test_circuit_breaker.py` | 108 |
| `AC-108` | `backend/tests/integration/test_mcp_registry.py` | 094 |
| `AC-109` | `backend/tests/unit/test_protocol_registry.py` | 109 |

## 14. PLATAFORMA (`AC-110..AC-116`)

| AC | Test | Tarea |
| :--- | :--- | :--- |
| `AC-110` | `backend/tests/integration/test_health.py` | 138 |
| `AC-111` | `backend/tests/integration/test_migrations.py` | 009 |
| `AC-112` | `backend/tests/security/test_audit_chain_tamper.py` | 007 |
| `AC-113` | `scripts/backup_restore_drill.sh` | 136 |
| `AC-114` | `scripts/verify_airgap.sh` | 137 |
| `AC-115` | `backend/tests/security/test_log_hygiene.py` | 138 |
| `AC-116` | `backend/tests/integration/test_graceful_shutdown.py` | 139 |

## 15. GATES (`AC-117..AC-124`)

| AC | Comando | Tarea |
| :--- | :--- | :--- |
| `AC-117` | `scripts/verify_all.sh::backend` | 142 |
| `AC-118` | `scripts/verify_all.sh::frontend` | 143 |
| `AC-119` | `scripts/verify_all.sh::e2e` | 144 |
| `AC-120` | `scripts/verify_all.sh::security` | 145 |
| `AC-121` | `scripts/verify_all.sh::sbom` | 141 |
| `AC-122` | `pytest -q tests/security/test_tenant_isolation.py` | 146 |
| `AC-123` | `pytest -q tests/autonomy/` | 147 |
| `AC-124` | `pytest -q tests/security/test_prompt_injection.py` | 148 |

## 16. ACs DE DOMINIO (no globales)

| AC | Documento | Test |
| :--- | :--- | :--- |
| `AC-ORG-07` | organizations.md | `test_org_members.py::test_last_owner_guard` |
| `AC-AST-08` | assets.md | `test_asset_dedupe.py` |
| `AC-ASM-06` | attack-surface.md | `test_asm_grace_window.py` |
| `AC-VUL-07` | vulnerabilities.md | `test_risk_acceptance.py::test_expiry_reopens` |
| `AC-INC-05/06` | incidents.md | `test_incident_merge.py`, `test_incident_sla.py` |
| `AC-CTI-08` | threat-intelligence.md | `test_indicator_dedupe.py` |
| `AC-IOT-04/08` | iot.md | `test_zone_isolation.py`, `test_etsi_evidence.py` |
| `AC-OTC-05/08` | ot.md | `test_ot_baseline_learning.py`, `test_ot_action_catalog.py` |
| `AC-CLD-04` | cloud.md | `test_cloud_readonly.py` |
| `AC-FOR-02/03` | forensics.md | `test_forensic_export.py`, `test_forensic_timeline.py` |
| `AC-CMP-06` | compliance.md | `test_gdpr_registry.py` |
| `AC-AIG-10` | ai-agents.md | `test_model_eval_gate.py` |
| `AC-MCP-03/04/05` | mcp-contract.md | `test_mcp_registry.py`, `test_mcp_allowlist.py` |
| `AC-AUTH-06/07` | authorization-model.md | `test_break_glass.py`, `test_token_scopes.py` |
| `AC-DP-01..06` | data-protection.md | `test_gdpr_*.py`, `test_ai_region_block.py` |
| `AC-SAF-02..16` | safety-requirements.md | `tests/autonomy/test_lying_adapter.py`, etc. |

---

## 17. RESUMEN DE COBERTURA

| Bloque | ACs | Con test definido |
| :--- | :--- | :--- |
| Identidad | 8 | 8 |
| Organizaciones | 6 | 6 |
| Activos/ASM/Vulns | 18 | 18 |
| SIEM | 10 | 10 |
| SOAR | 7 | 7 |
| CTI | 5 | 5 |
| Incidentes/Forense | 6 | 6 |
| IA | 9 | 9 |
| Autonomía | 9 | 9 |
| IoT/OT/Cloud | 9 | 9 |
| Cumplimiento | 6 | 6 |
| Frontend | 10 | 10 |
| Integraciones | 6 | 6 |
| Plataforma | 7 | 7 |
| Gates | 8 | 8 |
| **Total global** | **124** | **124** |

Los ACs de dominio se añaden a medida que se implementan; su ausencia no bloquea, su presencia sin test sí.

---

## 18. MANTENIMIENTO

1. Al añadir un AC: fila aquí + test + tarea.
2. Al cambiar un test: actualizar la ruta en esta tabla en el mismo commit.
3. El gate `scripts/verify_all.sh` valida que cada ruta de esta matriz existe (script `verify_matrix.py`).
4. Una fila sin test o con test inexistente falla el gate de documentación.
