# Changelog

All notable changes to HISPANSHIELD are documented here. The format follows
Keep a Changelog and the project uses Semantic Versioning once a stable API is
declared.

## [0.1.3] — 2026-11-26 — Remediation wave: CI recovery, fresh install and closed gaps

### Fixed

- **CI/CD P0:** the `container` job had `needs: [backend, frontend]    steps:`
  fused into one line. Fixed, added least-privilege permissions, timeouts,
  image `load: true` for Trivy and a fail-closed `quality-gate` job.
- **Fresh demo seed** aborted with `uq_events_org_dedupe`; dedupe keys now
  include the unique event uid (`test_seed_demo.py`).
- **Fresh `/setup`** left the compliance catalogue empty; setup, demo seed and
  `scripts/seed_frameworks.py` now load the 10 built-in frameworks.
- **Backup/restore** passed a SQLAlchemy DSN to `pg_dump`/`pg_restore`; the
  driver suffix is stripped before calling libpq.

### Added

- Outbox **`LISTEN/NOTIFY`** trigger + listener thread; polling/leases remain
  the correctness fallback. No generic `jobs` table (ADR-013).
- **Asset soft delete/restore** (`deleted_at`, global ORM read filter,
  `POST /assets/{id}/restore`, `409 asset_key_in_trash`).
- **Attack-surface STIX 2.1 / CSV export** with lossless asset/ip/port
  round-trip and formula-safe CSV.
- **Nessus / OpenVAS / Trivy importers** (`POST /vulnerabilities/import`) with
  tenant-scoped host resolution, cross-scanner dedupe, idempotency and
  `defusedxml` hardening (ADR-014).
- IEC 62443 conduits now require `metadata.required_sl`; SL>=3 without a
  compensating control produces a compliance gap.
- Playwright **responsive** (24×3 viewports) and **axe-core** gates; axe-core
  4.10.2 vendored test-only for offline runs.
- Baseline, CI/CD and backup/restore reports; CycloneDX SBOMs.

### Changed

- Backend suite 650 → 669 tests; migrations 14 → 16.
- README/status/AC matrix reconciled with executed evidence; E2E contradiction
  removed.

### Known limitations

- Cloud/CSPM, legal hold, partitions/retention, A4, durable agent runs, NIS2
  tracker, ETSI/CPE, Firefox/WebKit, Docker/K8s runtime, performance benchmarks
  and external independent review remain open.

## [0.1.2] — 2026-11-26 — Evolution wave 1: evidence, durability and contract

### Added

- **Transactional outbox** (`outbox_events`) with atomic enqueue, `SKIP LOCKED`
  leases, exponential backoff, dead-letter state and a tenant-scoped
  notification consumer; wired to alert creation, incident creation and SOAR
  terminal states. Worker role `outbox` included in `--role all`.
- **SSE** `GET /api/v1/events/stream` with `Last-Event-ID`, heartbeat, bounded
  batches and tenant filtering; frontend `useEventStream` hook with polling
  fallback and a "N new events" refresh affordance.
- **Audit integrity v3**: HMAC-SHA256 with key id and rotation, signed
  checkpoints, verification of v1/v2/v3 chains. Production now requires
  `HS_AUDIT_REQUIRE_HMAC=true` and a key held outside PostgreSQL.
- **Idempotency-Key** ledger (tenant+actor scoped, payload/path binding,
  replay, stale takeover, 24 h TTL) on incident creation, asset import and CVE
  import.
- **Cursor pagination** (`meta.next_cursor`, additive to offset) for assets and
  events.
- **Setup and invitations**: public first-run `POST /setup` (A0 by default,
  race-free, 409 after first org) and single-use 72 h invitations with role
  binding, revocation and password proof for existing accounts.
- **Password policy endpoint** `GET /auth/password-policy`; idle session
  default aligned to 30 min.
- **Active sessions UI** with per-session revocation.
- **Kubernetes render/validate gate**: template, required values, CI job and
  `scripts/validate_deploy.py` that rejects placeholders, `:latest`, missing
  security contexts and unrendered variables.
- Recomputable metrics and AC traceability (`scripts/factory_metrics.py`,
  `scripts/ac_traceability.py`).

### Changed

- `PageMeta` adds `next_cursor` and `total_estimate`; existing offset clients
  keep working.
- `/readyz` reports outbox pending/dead-letter counters.
- README/compatibility matrix no longer advertise unimplemented adapters,
  cloud CSPM, Nessus/OpenVAS/Trivy importers, OIDC/SAML or A4 actions.

### Known limitations

- Outbox `LISTEN/NOTIFY` and a separate `jobs` table remain open (`TASK-008`).
- Cloud/CSPM, Nessus/OpenVAS/Trivy importers, legal hold, event partitions, A4
  actions and durable agent runtime are not implemented.
- Playwright E2E, pip-audit/bandit/gitleaks, Docker/K8s runtime and backup
  restore were **not executed in this environment**; see
  `docs/implementation-status.md`.
- FTS GIN is not used by search queries; cursor p95 benchmarks are not run.

## [0.1.1] — 2026-11-26 — Security remediation wave 2

### Security

- Ingest: HMAC v2 over timestamp + nonce + body, one-time nonce table and
  persistent `(org_id, dedupe_key)` uniqueness; legacy body-only HMAC requires
  an explicit source flag. Tokens can be sent in `Authorization`; the legacy
  path is deprecated and redacted from logs.
- SSRF: connection-time DNS pinning (`httpcore` network backend) for connectors,
  MCP and AI; no redirects; cloud metadata always blocked. Local AI providers
  are restricted to `HS_AI_PRIVATE_ALLOWED_CIDRS`.
- Identity: per-source login-failure attribution (no single-IP account
  lockout), password step-up for MFA enrollment/activation, per-challenge MFA
  rate limiting, one-time recovery codes (Argon2id) and session listing/
  revocation.
- Break-glass: dual control when a second platform admin exists, explicit
  approval endpoint, no implicit grant via `switch-org`.
- Autonomy: deterministic budgets, cooldowns, freeze windows, blast-radius and
  target-kind guardrails; fail-closed on malformed policy or DB errors; playbook
  compensation steps now require the same RBAC as direct steps.
- Audit: versioned hash covers request id, IP, user agent and actor email while
  legacy chains remain verifiable.
- Files/backups: CSV export formula neutralisation; backup directories 0700,
  artefacts 0600, encryption mandatory in production.
- AI: per-organization token/request budgets and concurrency isolation; external
  providers require platform + tenant opt-in, HTTPS and an EU data region.
- Edge: gateway fingerprints unique per organization.
- Body limits now apply to chunked/streaming requests.

### Added

- Durable worker runtime (`app.workers.runtime`) for playbooks and connector
  sync, deployed in Compose and Kubernetes with its own NetworkPolicy.
- Readiness now reports database, migration head/current and queue depth.
- Discovery authorizations (approved, time-boxed, scope-bound) required before
  any active probe.
- One-time MFA recovery-code generation UI and active-session management.
- `.factory/REPO_INVENTORY.md`, `REALITY_CHECK.md`, `SECURITY_FINDINGS.md`,
  `ARCHITECTURE_GAP_ANALYSIS.md`, `BASELINE_TEST_RESULTS.md`.

### Fixed

- Fresh clones now include `backend/app/data/**` reference frameworks (the root
  `data/` ignore rule was too broad).
- Trusted proxy headers default to loopback instead of `*`.

## [0.1.0] — 2026-11-26 — Release candidate 1

### Added

- Clean-room platform foundation: FastAPI modular monolith, PostgreSQL 18,
  Alembic migrations, React 19 + TypeScript + Vite SOC command center.
- Multi-tenant identity: organizations, memberships, RBAC (10 roles), ABAC-ready
  policy engine, Argon2id, TOTP MFA, session cookies + CSRF, API tokens.
- Append-only audit chain per organization with verification endpoint and a
  PostgreSQL trigger that blocks updates/deletes.
- CAASM/EASM inventory: assets, identities, relationships, zones/conduits,
  graphs, authorized passive discovery and bounded reachability probes.
- Vulnerability management with CVE/KEV/EPSS imports and contextual priority
  scoring (CVSS + EPSS + KEV + asset criticality + exposure + TI).
- OCSF-oriented event ingestion, parsers (JSON/CEF/LEEF/syslog), IOC enrichment,
  detection rule DSL, builtin detections, alerts and incident promotion.
- Integration Hub with capability-declared connectors (Wazuh, Elastic,
  Sentinel, MISP, OpenCTI, Suricata/Zeek file sources, Keycloak, pfSense,
  OPNsense, Defender, generic webhook), health, retries, circuit breaker,
  SSRF protection and connector audit.
- Incident response lifecycle, timeline, evidence upload with SHA-256 and chain
  of custody, MTTR/MTTD metrics.
- Durable SOAR playbooks on PostgreSQL: conditions, retries, approval pauses,
  compensation, simulation and execution history.
- Autonomous defence: action catalogue, autonomy levels A0–A4, policy engine,
  authorization, execution broker, approvals with separation of duties,
  kill switches, verification and rollback.
- Local-first AI gateway (Ollama, vLLM, llama.cpp, OpenAI-compatible), model
  registry, routing, usage and evaluation, RAG with deterministic local
  embeddings and citations, 16 specialized agents, MCP discovery/approval/tool
  broker with injection defences.
- Threat intelligence (STIX 2.1, TAXII/MISP/OpenCTI feeds, ATT&CK catalogue,
  enrichment), IoT/OT passive inventory, IEC 62443 zones, edge gateways with
  signed store-and-forward telemetry.
- European compliance engine (NIS2, CRA, GDPR, ENS, ISO/IEC 27001/27002,
  IEC 62443, ETSI EN 303 645, NIST CSF 2.0, EUCC), technical self-assessments,
  evidence linking and HTML/Markdown reports.
- 23-screen SOC Command Center with ES/EN, dark/light theme, command palette,
  responsive layouts, skeleton/empty/error states and accessible interactions.
- Operations: structured logs, Prometheus metrics, health/readiness, backup and
  restore scripts, SBOM, CI, Docker/Kubernetes manifests, air-gapped deployment
  notes.
- Documentation: constitution, product/architecture/domain specs, 10+ ADRs,
  threat model, autonomy policy, C4 diagrams, SOC/IR/IoT/OT/recovery/audit
  manuals, compatibility matrix and implementation status.

### Security

- CSP, HSTS (production), frame denial, nosniff, referrer/permissions policies,
  explicit CORS, request IDs, body limits, rate limiting, lockout.
- SSRF validation for connectors and AI providers (cloud metadata always
  blocked), encrypted secrets at rest, redacted audit payloads.
- Fail-closed policy engine, global/org/connector kill switches, forbidden
  operation classes for OT and offensive actions.

### Known limitations

- Docker/Kubernetes manifests are not runtime-validated in the build
  environment (no Docker daemon available); validate in your platform.
- External IdP SSO federation is not enabled by default; local authentication is
  implemented and the Keycloak connector covers administrative actions.
- Local AI requires an operator-provided runtime/model; without one, AI
  endpoints return an explicit unavailability error.
- MVP uses PostgreSQL for search, queues, workflows and vectors instead of
  OpenSearch/Kafka/Temporal/Qdrant; extension points and ADRs are documented.
- Compliance outputs are technical self-assessments, not certifications.
