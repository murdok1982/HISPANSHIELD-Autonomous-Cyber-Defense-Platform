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
- Session cookies: HttpOnly, Secure (production), SameSite=Lax; CSRF double
  submit; TOTP MFA; Argon2id password hashing; login throttling and lockout.
- RBAC with 10 roles; tenant scoping on every tenant-owned query; cross-tenant
  access returns 404.
- Secrets encrypted at rest (Fernet) and never returned by the API.
- SSRF allow-list/deny-list with DNS resolution; cloud metadata always blocked.
- Append-only audit chain (per organization) with verification endpoint.
- Defensive actions: catalogue + policy engine + approval + execution broker +
  verification + rollback + kill switches. The LLM never holds execution
  authority.
- OT/IoT passive by default; dangerous action classes are hard-forbidden.
- Supply chain: pinned dependencies, `pip-audit`, `bandit`, secret scanning,
  SBOM generation and container image scanning guidance in CI.

## Known limitations of this evaluation build

- Docker and Kubernetes manifests are provided but were not runtime-executed in
  the build environment (no Docker daemon). Validate them in your platform.
- No external IdP (Keycloak/OIDC federation) is wired by default; local
  authentication is implemented. Keycloak connector covers administrative
  actions, not SSO login.
- The MVP uses PostgreSQL for search, queues and vectors instead of
  OpenSearch/Kafka/Qdrant/Temporal. This reduces operational surface; scale-out
  requires the extension points documented in the ADRs.
- Local AI requires an operator-provided model runtime. Without one, AI
  endpoints return an explicit unavailability error.
