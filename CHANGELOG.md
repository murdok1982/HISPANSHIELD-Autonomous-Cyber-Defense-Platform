# Changelog

All notable changes to HISPANSHIELD are documented here. The format follows
Keep a Changelog and the project uses Semantic Versioning once a stable API is
declared.

## [Unreleased] — 2026-11-26 — Security remediation wave 2

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
