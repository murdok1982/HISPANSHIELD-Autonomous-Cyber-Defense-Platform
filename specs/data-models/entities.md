# MODELO DE DATOS — ENTIDADES Y RELACIONES

- **Documento:** `specs/data-models/entities.md`
- **Estado:** `LOCKED` v1.0
- **Convenciones:** `specs/architecture/data-architecture.md §3`
- **Regla:** este documento define columnas obligatorias; los detalles de índice y partición están en `data-architecture.md`.

---

## 1. CONVENCIONES COMUNES

Toda tabla de dominio incluye:

| Columna | Tipo | Regla |
| :--- | :--- | :--- |
| `id` | `UUID` | PK, UUIDv7 |
| `organization_id` | `UUID` | FK → `organizations(id)`, NOT NULL, indexado |
| `created_at` | `TIMESTAMPTZ` | NOT NULL DEFAULT now() |
| `updated_at` | `TIMESTAMPTZ` | NOT NULL DEFAULT now() |
| `created_by` / `updated_by` | `UUID` | NULL = sistema/autónomo |
| `row_version` | `INTEGER` | NOT NULL DEFAULT 1 (agregados editables) |
| `deleted_at` | `TIMESTAMPTZ` | NULL (soft delete donde aplique) |

---

## 2. IDENTIDAD Y TENANCY

### `organizations`
`id`, `slug CITEXT UNIQUE`, `name VARCHAR(160)`, `sector VARCHAR(48)`, `nis2_entity_type VARCHAR(16)`, `data_region VARCHAR(16) DEFAULT 'eu'`, `settings JSONB`, `status VARCHAR(16)`, `deleted_at`.
Índices: `uq_org_slug`, `ix_org_status`.

### `users`
`id`, `email CITEXT UNIQUE`, `password_hash TEXT NULL`, `display_name VARCHAR(120)`, `mfa_secret_enc TEXT NULL`, `mfa_enabled BOOL`, `status VARCHAR(16)`, `last_login_at`, `failed_login_count INT`, `locked_until`.
Sin `organization_id` (global); la pertenencia va en `memberships`.

### `memberships`
`id`, `organization_id`, `user_id`, `role VARCHAR(16)`, `status VARCHAR(16)`, `invited_by`, `joined_at`.
`UNIQUE(user_id, organization_id, role)`; `ix_membership_org_user`.

### `sessions`
`id`, `user_id`, `token_hash CHAR(64) UNIQUE`, `ip INET`, `user_agent TEXT`, `created_at`, `last_used_at`, `expires_at`, `revoked_at`, `csrf_hash CHAR(64)`.

### `api_tokens`
`id`, `organization_id`, `user_id`, `name VARCHAR(80)`, `prefix VARCHAR(16) UNIQUE`, `secret_hash CHAR(64)`, `scopes TEXT[]`, `expires_at`, `last_used_at`, `revoked_at`.

### `invitations`
`id`, `organization_id`, `email CITEXT`, `roles TEXT[]`, `token_hash CHAR(64)`, `expires_at`, `consumed_at`, `invited_by`.

---

## 3. ACTIVOS Y EXPOSICIÓN

### `asset_zones`
`id`, `organization_id`, `name VARCHAR(80)`, `kind VARCHAR(16)` (`it|dmz|iot|ot|cloud`), `purdue_level SMALLINT NULL`, `sl_target SMALLINT NULL`, `description TEXT`, `isolation_level VARCHAR(16)`.

### `assets`
`id`, `organization_id`, `name VARCHAR(200)`, `kind VARCHAR(24)`, `criticality SMALLINT`, `owner_email CITEXT`, `owner_user_id UUID NULL`, `zone_id UUID NULL`, `tags TEXT[]`, `attributes JSONB`, `risk_score NUMERIC(5,2)`, `source VARCHAR(32)`, `first_seen`, `last_seen`, `deleted_at`.
Índices: `ix_assets_org_kind_crit`, `ix_assets_org_risk`, GIN `attributes`, GIN `search_tsv`.

### `asset_relationships`
`id`, `organization_id`, `source_id`, `target_id`, `type VARCHAR(24)`, `created_by`.
`UNIQUE(source_id, target_id, type)`; `CHECK(source_id <> target_id)`.

### `iot_profiles`
`id`, `organization_id`, `asset_id UNIQUE`, `protocol VARCHAR(24)`, `vendor`, `model`, `firmware_version`, `mac MACADDR NULL`, `eol_status VARCHAR(16)`, `eol_date DATE NULL`, `default_credentials_suspected BOOL`, `etsi_score NUMERIC(5,2)`.

### `ot_profiles`
`id`, `organization_id`, `asset_id UNIQUE`, `purdue_level SMALLINT`, `safety_function BOOL`, `protocols TEXT[]`, `vendor`, `model`, `firmware_version`, `last_baseline_at`.

### `ot_conduits`
`id`, `organization_id`, `from_zone_id`, `to_zone_id`, `required_sl SMALLINT`, `protocols TEXT[]`, `direction VARCHAR(16)`, `justification TEXT`.

### `attack_surface_ranges`
`id`, `organization_id`, `cidr CIDR`, `label`, `authorized_from DATE`, `authorized_until DATE NULL`, `evidence_ref`, `authorized_by`.

### `attack_surface_observations`
`id`, `organization_id`, `host VARCHAR(255)`, `ip INET`, `port INT`, `protocol VARCHAR(8)`, `service VARCHAR(120)`, `banner_hash CHAR(64)`, `tls JSONB`, `status VARCHAR(16)`, `authorized BOOL`, `asset_id UUID NULL`, `first_seen`, `last_seen`.
`UNIQUE(organization_id, ip, port, protocol)`.

### `exposure_diffs`
`id`, `organization_id`, `observation_id`, `change_type VARCHAR(16)`, `before JSONB`, `after JSONB`, `detected_at`.

---

## 4. VULNERABILIDADES

### `vulnerabilities`
`id`, `organization_id` (NULL para catálogo global), `cve_id VARCHAR(20) NULL`, `cwe_ids TEXT[]`, `title`, `description`, `cvss_base NUMERIC(3,1)`, `cvss_vector`, `kev BOOL`, `epss NUMERIC(5,4)`, `severity VARCHAR(16)`, `published_at`, `references JSONB`.

### `vulnerability_instances`
`id`, `organization_id`, `vulnerability_id`, `asset_id`, `port INT NULL`, `protocol VARCHAR(8) NULL`, `fingerprint CHAR(64)`, `status VARCHAR(20)`, `priority VARCHAR(4)`, `risk_score NUMERIC(5,2)`, `score_breakdown JSONB`, `sources TEXT[]`, `sla_due_at`, `detected_at`, `resolved_at`, `assignee`, `evidence JSONB`.
`UNIQUE(organization_id, fingerprint)`; `ix_vuln_org_status_risk`.

### `risk_exceptions`
`id`, `organization_id`, `vulnerability_instance_id`, `justification TEXT`, `compensating_controls TEXT[]`, `requested_by`, `approved_by`, `expires_at`, `revoked_at`.

---

## 5. SIEM

### `events` (particionada)
`id`, `organization_id`, `event_uid VARCHAR(128)`, `class_uid INT`, `activity_id INT`, `severity_id SMALLINT`, `occurred_at TIMESTAMPTZ`, `src_ip INET NULL`, `dst_ip INET NULL`, `actor JSONB`, `device JSONB`, `observables JSONB`, `status VARCHAR(32)`, `raw TEXT`, `raw_hash CHAR(64)`, `search_tsv TSVECTOR`, `ingested_at`.
PK `(id, occurred_at)`; `UNIQUE(organization_id, event_uid, occurred_at)`.

### `detection_rules`
`id`, `organization_id`, `name`, `description`, `status VARCHAR(16)`, `current_version INT`, `severity VARCHAR(16)`, `tags TEXT[]`, `created_by`.

### `detection_rule_versions`
`id`, `organization_id`, `rule_id`, `version INT`, `dsl TEXT`, `ast JSONB`, `window_seconds INT`, `group_by TEXT[]`, `threshold INT NULL`, `dedupe_window_seconds INT`, `published_at`, `published_by`.
`UNIQUE(rule_id, version)`.

### `alerts`
`id`, `organization_id`, `rule_version_id`, `dedupe_key CHAR(64)`, `severity VARCHAR(16)`, `priority_score NUMERIC(5,2)`, `status VARCHAR(16)`, `title`, `asset_id`, `event_ids UUID[]`, `count INT`, `first_seen`, `last_seen`, `assignee`, `suppressed_until`, `suppress_reason`.
`UNIQUE(organization_id, dedupe_key, window_bucket)`.

### `alert_events`
`id`, `organization_id`, `alert_id`, `event_id`, `added_at`.

---

## 6. INCIDENTES Y FORENSE

### `incidents`
`id`, `organization_id`, `ref VARCHAR(32)`, `title`, `summary`, `severity VARCHAR(4)`, `state VARCHAR(16)`, `category VARCHAR(48)`, `assignee`, `watchers TEXT[]`, `asset_ids UUID[]`, `alert_ids UUID[]`, `nis2_notifiable BOOL`, `gdpr_personal_data BOOL`, `sla_response_at`, `sla_resolve_at`, `sla_breached BOOL`, `closed_at`, `root_cause TEXT`.

### `incident_timeline`
`id`, `organization_id`, `incident_id`, `type VARCHAR(24)`, `actor_type VARCHAR(16)`, `actor_id`, `detail JSONB`, `at TIMESTAMPTZ`.
Append-only.

### `evidence`
`id`, `organization_id`, `incident_id NULL`, `case_id NULL`, `filename`, `mime`, `size BIGINT`, `sha256 CHAR(64)`, `storage_path`, `description`, `collected_at`, `uploaded_by`, `quarantined BOOL`.

### `custody_entries`
`id`, `organization_id`, `evidence_id`, `action VARCHAR(16)`, `actor_id`, `ip INET`, `request_id`, `hash_at_action CHAR(64)`, `at`.

### `forensic_cases`
`id`, `organization_id`, `ref VARCHAR(32)`, `title`, `incident_id NULL`, `state VARCHAR(16)`, `legal_hold BOOL`, `opened_by`, `opened_at`, `closed_at`.

---

## 7. THREAT INTELLIGENCE

### `indicators`
`id`, `organization_id`, `type VARCHAR(24)`, `value_normalized VARCHAR(512)`, `pattern TEXT`, `confidence SMALLINT`, `tlp VARCHAR(8)`, `valid_from`, `valid_until`, `labels TEXT[]`, `source_feed`, `stix_id`, `expired BOOL`.
`UNIQUE(organization_id, type, value_normalized)`.

### `threat_actors` / `campaigns` / `malware`
`id`, `organization_id`, `stix_id`, `name`, `aliases TEXT[]`, `description`, `first_seen`, `last_seen`, `metadata JSONB`.

### `indicator_relations`
`id`, `organization_id`, `source_indicator_id`, `target_type VARCHAR(24)`, `target_id UUID`, `relationship VARCHAR(24)`.

### `indicator_matches`
`id`, `organization_id`, `indicator_id`, `event_id NULL`, `asset_id NULL`, `confidence_effective NUMERIC(5,2)`, `matched_at`, `suppressed_whitelist BOOL`.

### `feeds`
`id`, `organization_id`, `kind VARCHAR(16)` (`taxii|misp|stix_url`), `url`, `collection_id`, `secret_ref`, `enabled`, `state VARCHAR(16)`, `last_success_at`, `last_error`, `cursor`.

### `ioc_whitelist`
`id`, `organization_id`, `value_normalized`, `reason`, `expires_at`.

---

## 8. SOAR Y AUTONOMÍA

### `playbooks`
`id`, `organization_id`, `name`, `description`, `status VARCHAR(16)`, `current_version INT`.

### `playbook_versions`
`id`, `organization_id`, `playbook_id`, `version INT`, `dag JSONB`, `changelog`, `published_at`, `published_by`.

### `executions`
`id`, `organization_id`, `playbook_version_id`, `state VARCHAR(24)`, `dry_run BOOL`, `incident_id NULL`, `requested_by`, `started_at`, `finished_at`, `input JSONB`, `error JSONB`.

### `execution_steps`
`id`, `organization_id`, `execution_id`, `step_key VARCHAR(64)`, `node_id`, `state VARCHAR(16)`, `attempt INT`, `input_hash`, `output JSONB`, `error JSONB`, `started_at`, `finished_at`.
`UNIQUE(execution_id, step_key)`.

### `approvals`
`id`, `organization_id`, `execution_id NULL`, `action_id NULL`, `approvers TEXT[]`, `required_count INT`, `decisions JSONB`, `state VARCHAR(16)`, `expires_at`, `created_at`.

### `autonomy_policies`
`id`, `organization_id`, `name`, `enabled BOOL`, `priority INT`, `current_version INT`.

### `policy_versions`
`id`, `organization_id`, `policy_id`, `version INT`, `definition JSONB`, `published_at`, `published_by`.

### `policy_decisions`
`id`, `organization_id`, `policy_version_id NULL`, `action_type`, `targets UUID[]`, `decision VARCHAR(20)`, `reason VARCHAR(64)`, `matched_rules JSONB`, `inputs_digest CHAR(71)`, `evaluated_at`, `requested_by`, `approval_id NULL`.

### `actions`
`id`, `organization_id`, `decision_id`, `action_type`, `targets UUID[]`, `parameters JSONB`, `state VARCHAR(24)`, `dry_run BOOL`, `scheduled_at`, `started_at`, `finished_at`.

### `action_results`
`id`, `organization_id`, `action_id`, `target_id`, `attempt INT`, `before_state JSONB`, `response_hash`, `verified BOOL`, `verification_detail JSONB`, `duration_ms`, `error JSONB`.

### `kill_switches`
`id`, `organization_id NULL`, `scope VARCHAR(16)`, `target_id NULL`, `active BOOL`, `reason`, `activated_by`, `activated_at`, `deactivated_at`.

---

## 9. IA Y MCP

### `ai_providers`
`id`, `organization_id NULL`, `key VARCHAR(48)`, `kind VARCHAR(24)`, `base_url`, `api_key_enc NULL`, `enabled`, `data_region`, `health_state`, `last_checked_at`.

### `ai_models`
`id`, `organization_id NULL`, `provider_id`, `name`, `profile VARCHAR(16)`, `context_window INT`, `embedding_dimension INT NULL`, `input_cost NUMERIC(10,6)`, `output_cost NUMERIC(10,6)`, `enabled`.

### `ai_runs`
`id`, `organization_id`, `agent_id NULL`, `kind VARCHAR(16)` (`chat|rag|agent|embed`), `state`, `provider`, `model`, `prompt_tokens`, `completion_tokens`, `cost_usd`, `fallback_used`, `started_at`, `finished_at`, `error`.

### `ai_messages`
`id`, `organization_id`, `run_id`, `role`, `content_redacted`, `created_at`.
Retención 30 d.

### `documents`
`id`, `organization_id`, `filename`, `mime`, `size`, `sha256`, `storage_path`, `uploaded_by`, `indexed_at`, `chunk_count`.

### `document_chunks`
`id`, `organization_id`, `document_id`, `seq`, `content`, `embedding float4[]`, `dimension INT`, `token_count INT`, `metadata JSONB`.

### `mcp_servers`
`id`, `organization_id`, `name`, `transport`, `endpoint`, `auth_secret_ref`, `enabled`, `trust_level`, `health_state`.

### `mcp_tools`
`id`, `organization_id`, `server_id`, `name`, `description`, `input_schema JSONB`, `output_schema JSONB`, `risk_level`, `side_effects BOOL`, `idempotent BOOL`.

### `tool_invocations`
`id`, `organization_id`, `run_id`, `tool_name`, `input_hash`, `decision_id NULL`, `state`, `duration_ms`, `result_status`, `error`.

---

## 10. CUMPLIMIENTO Y PLATAFORMA

### `frameworks`
`id`, `key VARCHAR(32)`, `name`, `version VARCHAR(16)`, `source_reference`, `status VARCHAR(16)`, `published_at`.
`UNIQUE(key, version)`.

### `controls`
`id`, `framework_id`, `code VARCHAR(32)`, `title`, `description`, `category`, `version INT`.
`UNIQUE(framework_id, code, version)`.

### `control_mappings`
`id`, `organization_id NULL`, `from_control_id`, `to_control_id`, `relationship VARCHAR(16)`, `justification`.

### `evidence_items`
`id`, `organization_id`, `control_id`, `type VARCHAR(24)`, `file_ref`, `sha256`, `valid_from`, `valid_until`, `submitted_by`, `reviewed_by`, `status VARCHAR(16)`, `comment`.

### `assessments`
`id`, `organization_id`, `framework_version_id`, `scope_type`, `scope_id NULL`, `state`, `score NUMERIC(5,2)`, `methodology_version`, `locked_at`, `created_by`.

### `assessment_results`
`id`, `organization_id`, `assessment_id`, `control_id`, `status VARCHAR(16)`, `evidence_item_id NULL`, `gap_severity`, `remediation`, `due_at`.

### `ropa_entries` / `dpia_assessments`
`id`, `organization_id`, `activity`, `purpose`, `legal_basis`, `data_categories TEXT[]`, `recipients`, `retention`, `transfers`, `state`, `review_due_at`, `risks JSONB`, `measures JSONB`.

### `nis2_incidents`
`id`, `organization_id`, `incident_id`, `early_warning_due`, `notification_due`, `final_report_due`, `milestones JSONB`, `state`.

### `reports`
`id`, `organization_id`, `type`, `format`, `parameters JSONB`, `storage_path`, `content_hash CHAR(64)`, `generated_at`, `generated_by`, `state`.

### `audit_log` (particionada)
`seq BIGSERIAL`, `organization_id NULL`, `actor_type`, `actor_id`, `action VARCHAR(96)`, `resource_type`, `resource_id`, `payload JSONB`, `prev_hash CHAR(64)`, `entry_hash CHAR(64)`, `request_id`, `created_at`.

### `outbox_events`
`id`, `organization_id NULL`, `event_type`, `payload JSONB`, `status VARCHAR(16)`, `attempts INT`, `available_at`, `created_at`, `processed_at`.

### `jobs`
`id`, `organization_id NULL`, `queue VARCHAR(32)`, `kind`, `payload JSONB`, `state`, `priority INT`, `attempts`, `max_attempts`, `lease_owner`, `lease_expires_at`, `available_at`, `last_error`, `idempotency_key`.
`UNIQUE(queue, idempotency_key)` parcial.

### `settings`
`id`, `organization_id NULL`, `key VARCHAR(64)`, `value JSONB`, `updated_by`, `updated_at`.
`UNIQUE(organization_id, key)`.

---

## 11. RELACIONES CRÍTICAS Y CARDINALIDAD

| Relación | Cardinalidad | Regla |
| :--- | :--- | :--- |
| org → memberships | 1:N | Un usuario puede estar en varias orgs |
| org → assets | 1:N | Soft delete |
| asset → vulnerability_instances | 1:N | Fingerprint único por org |
| asset → iot_profiles/ot_profiles | 1:0..1 | Según `kind` |
| rule → rule_versions | 1:N | Versión publicada inmutable |
| rule_version → alerts | 1:N | Dedupe por ventana |
| alert → incident | N:1 | Promoción |
| incident → timeline/evidence | 1:N | Append-only / hash |
| playbook → versions | 1:N | Publicada inmutable |
| version → executions | 1:N | Durable |
| policy → versions → decisions | 1:N:1..N | Decisión reproducible |
| decision → action | 1:0..1 | Solo si `allow` |
| action → results | 1:N | Por target/intento |
| framework → controls | 1:N | Versionado |
| control → evidence_items | 1:M | M:N vía evidence |
| assessment → results | 1:N | Bloqueada al completar |

---

## 12. VALIDACIONES DE INTEGRIDAD

| Regla | Implementación |
| :--- | :--- |
| `assets.zone_id` obligatorio para `iot`/`ot` | `CHECK` + trigger |
| `iot_profiles.protocol` en catálogo | `CHECK` + validación app |
| `vulnerability_instances.status` en enum | `CHECK` |
| `alerts.dedupe_key` único por ventana | Índice único |
| `execution_steps` único por `step_key` | Índice único |
| `policy_decisions.inputs_digest` no nulo | `NOT NULL` |
| `evidence.sha256` formato 64 hex | `CHECK` |
| `audit_log` inmutable | Trigger |
| `events` inmutable | Trigger |
| `kill_switches` scope válido | `CHECK` |

---

## 13. EVIDENCIA

1. Migraciones que crean todas las tablas (`alembic upgrade head`).
2. Test de constraints (violaciones esperadas).
3. Diagrama ER actualizado.
4. Conteo de tablas/índices por migración.
