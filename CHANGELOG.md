# Changelog

All notable changes to HISPANSHIELD are documented here. The format follows
Keep a Changelog and the project uses Semantic Versioning once a stable API is
declared.

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
