# Security policy

## Supported versions

Only the latest release candidate receives security fixes during evaluation.

## Reporting a vulnerability

Do **not** open a public issue. Send a report to the security contact configured
by your deployment (`HS_SUPPORT_EMAIL`) or `security@hispanshield.eu` once the
corporate mailbox is established.

Include: affected version/commit, component, reproduction steps, impact,
proof-of-concept (non-destructive), and whether the issue affects tenant
isolation, authentication, the autonomy guardrails or audit integrity.

We aim to acknowledge within 3 business days and to provide a remediation plan
within 10 business days for critical/high findings.

## Scope and safe harbour

Testing is authorized only against your own deployment with written approval.
Do not test third-party systems, do not run destructive OT/IoT operations, and
do not exfiltrate real personal data. Use the demo organization and synthetic
data for research.

## Security architecture summary

- Zero Trust between browser, API, workers and connectors.
- Session cookies: HttpOnly, Secure (production), SameSite=Strict, 60-minute idle timeout;
  CSRF double submit; TOTP MFA with single-use recovery codes (Argon2id-hashed,
  shown once); active-session listing and revocation; Argon2id password hashing;
  login throttling and distributed-only account lockout.
- RBAC with 10 roles; tenant scoping on every tenant-owned query; cross-tenant
  access returns 404. Platform administrators need a justified, ticketed,
  time-boxed break-glass grant to access another organization. When a second
  platform administrator exists, the grant must be approved by that different
  administrator (dual control); `switch-org` never creates grants implicitly.
- Secrets encrypted at rest (Fernet) and never returned by the API. Ingestion
  tokens are accepted in the `Authorization` header by default; the legacy URL
  path is deprecated and redacted from application logs.
- SSRF protection resolves and validates the destination at connection time
  (pinned DNS, no redirects); cloud metadata is always blocked. Local AI
  providers are limited to the operator's `HS_AI_PRIVATE_ALLOWED_CIDRS`
  allow-list; external providers require HTTPS, an EU `data_region` and explicit
  platform + tenant opt-in.
- Append-only audit chain (per organization) whose hash covers request id, IP,
  user agent and actor email for new records, with backward-compatible
  verification of older chains.
- Defensive actions: catalogue + policy engine + approval + execution broker +
  verification + rollback + kill switches, with deterministic budgets, cooldowns,
  freeze windows and blast-radius limits. The LLM never holds execution
  authority. Playbook compensation steps require the same permissions as direct
  steps.
- OT/IoT passive by default; dangerous action classes are hard-forbidden.
- Durable worker process (playbooks + connector sync) deployed in Compose/K8s;
  readiness verifies database, migrations and queue depth.
- Supply chain: pinned dependencies, `pip-audit`, `bandit`, secret scanning,
  SBOM generation and container image scanning guidance in CI.

## Known limitations of this evaluation build

- Docker and Kubernetes manifests are provided but were not runtime-executed in
  the build environment (no Docker daemon). Validate them in your platform.
- The audit chain is hash-chained but **not keyed with an external HSM key**; a
  database owner could recompute a forged chain. Ship the audit stream to an
  append-only external sink for high-assurance deployments.
- Break-glass uses dual control whenever a second platform administrator exists.
  A single-administrator deployment self-approves the grant (justification,
  ticket, TTL and audit still apply); provision at least two administrators.
- `allow_legacy_hmac=true` on an ingest source re-enables body-only HMAC and
  weakens replay protection. It is disabled by default.
- The legacy `/api/v1/ingest/{token}` path remains for compatibility; the token
  is redacted from application logs but reverse proxies may still record URLs.
  Use `POST /api/v1/ingest` with `Authorization: Bearer`.
- No external IdP (Keycloak/OIDC federation) is wired by default; local
  authentication is implemented. Keycloak connector covers administrative
  actions, not SSO login.
- The MVP uses PostgreSQL for search, queues and vectors instead of
  OpenSearch/Kafka/Qdrant/Temporal. This reduces operational surface; scale-out
  requires the extension points documented in the ADRs.
- Local AI requires an operator-provided model runtime. Without one, AI
  endpoints return an explicit unavailability error.
