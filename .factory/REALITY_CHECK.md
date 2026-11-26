# REALITY CHECK — HISPANSHIELD RC1 vs. what is documented

- **Date:** 2026-11-26
- **Baseline:** commit `696655b` + working tree
- **Method:** direct code inspection (`backend/`, `frontend/`, `edge/`, `deploy/`), executable baseline (`BASELINE_TEST_RESULTS.md`), independent inventory (`REPO_INVENTORY.md`) and gap analysis (`ARCHITECTURE_GAP_ANALYSIS.md`).
- **Rule:** a capability is only "present" when it has an implementation wired to the real flow plus an executable test. Documentation, classes and UI screens alone do not count.

## 1. Verdict

RC1 is a **real, runnable platform** (FastAPI + PostgreSQL + React SPA + edge agent, 519 backend tests, 92 edge tests, 36 frontend tests), not a mock. However, several statements in the README/specs were **ahead of the code**, and the security audit mixed *verified* fixes with *open* items. This document freezes the delta that matters.

## 2. Confirmed gaps (with evidence)

| # | Claim | Reality at baseline | Evidence | Status in this wave |
| --- | --- | --- | --- | --- |
| R-01 | Transactional outbox + `jobs` + `LISTEN/NOTIFY` | Does not exist; synchronous processing + durable rows | `grep -ri outbox backend/app` = 0; `ARCHITECTURE.md:362-381` | **OPEN** (documented as roadmap, not claimed in README anymore) |
| R-02 | Workers deployed (`hispanshield-worker-*`) | Compose/k8s only started the API; SOAR/sync/syslog were manual scripts | `deploy/compose/docker-compose.yml`, `deploy/k8s/manifests.yaml` | **FIXED** — `app/workers/runtime.py`, compose `worker`, k8s `hispanshield-worker` + NetworkPolicy + test |
| R-03 | SSE `/events/stream` | No SSE endpoint/client; polling only | `grep EventSource frontend/src` = 0 | **OPEN** (P2; see `ARCHITECTURE_GAP_ANALYSIS.md`) |
| R-04 | Recovery codes MFA | Not implemented despite `SPEC.md` and compatibility matrix | `grep recovery_code backend/app` = 0 | **OPEN** (planned SEC-FIX) |
| R-05 | Fresh clone can seed compliance | `backend/app/data/**` ignored by `.gitignore` rule `data/`; clean worktree raises "Built-in framework directory is missing" | `git check-ignore -v backend/app/data/frameworks/nis2.yaml`; reproduced in `/tmp/opencode/hs-baseline` | **FIXED** — ignore rules narrowed, reference data tracked |
| R-06 | Cursor pagination / `Idempotency-Key` / API error shape as specced | Offset pagination, no idempotency key, `details` vs `fields` | `core/schemas.py`, `main.py:80-90` | **OPEN** (contract decision required; not silently renamed) |
| R-07 | Cloud/CSPM module | No `/cloud/*` module; only derived posture | `modules/posture/router.py` | **OPEN** (P2, stated as not implemented) |
| R-08 | Nessus/OpenVAS/Trivy importers | Only JSON CVE/KEV/EPSS import | `modules/vulnerabilities/router.py` | **OPEN** (P2) |
| R-09 | Asset soft delete + restore | Physical delete, no `deleted_at` | `modules/assets/router.py` | **OPEN** (P2) |
| R-10 | `patch.apply` / `configuration.restore` actions | Catalogue entries without adapter | `services/actions.py` + adapters | **OPEN** (actions now fail closed; no fake execution) |
| R-11 | OpenAPI snapshot 283 ops | 284 ops / 215 paths | `docs/openapi.json` vs AST | **DOC FIX PENDING** |
| R-12 | 515 tests / 109 tasks | 519 tests; 106 `[x]` + 44 `[!]` | `implementation-status.md` vs `TASKS.md` | **DOC FIX PENDING** (this wave re-measures) |

## 3. Security claims that were not true at baseline

The previous `SECURITY_AUDIT.md` had **`VERIFIED` rows whose detailed sections still said `OPEN`** and a few claims that the code did not support:

| Finding | Baseline claim | Reality checked | Status after remediation |
| --- | --- | --- | --- |
| VULN-005 approval replay | `VERIFIED` | `broker._validate_approval` consumes the approval under `FOR UPDATE` | confirmed, regression test exists |
| VULN-015 sessions | `VERIFIED` | same-site Strict, idle timeout, MFA revocation present | confirmed |
| VULN-016 fail-open config | `VERIFIED` | `HS_SECRET_KEY` mandatory | confirmed |
| VULN-019 npm audit | `VERIFIED` | Vitest upgraded; `npm audit --audit-level=high` clean | re-run in release gate |
| VULN-008 AI cleartext | `OPEN` | AI providers accepted `http://` and private ranges | **FIXED** — external requires HTTPS + EU region + opt-in; local remains private-capable |
| VULN-009 DNS rebinding | `OPEN` | pre-check then httpx re-resolved | **FIXED** — pinned-DNS `httpcore` backend validates at connect; connectors/MCP/AI use it |
| VULN-010 ingest replay | `OPEN` | no timestamp/nonce and no DB uniqueness | **FIXED** — HMAC v2 + nonce table + unique dedupe (SEC-FIX task) |
| VULN-011 discovery scope | `OPEN` | caller-supplied CIDRs were the only authorization | **FIXED** — approved, time-boxed `DiscoveryAuthorization` |
| VULN-012 double execution | `OPEN` | claim window not proven atomic | **FIXED** — SKIP LOCKED claim + concurrent-worker test |
| VULN-013 autonomy guardrails | `OPEN` | no budgets/cooldown/freeze/blast radius | **FIXED** — deterministic policy guardrails + tests |
| VULN-014 audit integrity | `OPEN` | request metadata outside the hash | **FIXED** — versioned hash covering IP/UA/request id |
| VULN-017 lockout DoS | `OPEN` | one source could lock any account | **FIXED** — per-source attribution; global lock only on distributed attack |
| VULN-018 body limits | `OPEN` | chunked bypass | **FIXED** — pure ASGI limit with streaming guard + test |
| VULN-020 backup exposure | `OPEN` | 0755 dirs, plaintext dump by default | **FIXED** — 0700/0600, encryption mandatory in production |
| VULN-021 AI privacy | `OPEN` | no `data_region`/opt-in enforcement | **FIXED** — platform + tenant opt-in, EU region required |
| VULN-022 CSV injection | `OPEN` | raw cells exported | **FIXED** — `csv_safe` + test |
| VULN-024 MCP drift | `OPEN` | approval not bound to schema | **FIXED** — schema hash binding + test |
| VULN-025 bootstrap escalation | `OPEN` | existing e-mail promoted silently | **FIXED** — explicit `--promote-existing` + test |
| VULN-026 trusted proxy | `OPEN` | `--forwarded-allow-ips='*'` | **FIXED** — loopback default, configurable |
| VULN-027 policy fail-open | `OPEN` | policy errors not proven deny | **FIXED** — fail-closed + audit |
| VULN-028 edge fingerprint | `OPEN` | global unique fingerprint | **FIXED** — unique per organization + migration |

> `VULN-001..007`, `015`, `016`, `023` are re-verified independently in
> `.factory/SECURITY_FINDINGS.md`. Any item not reproduced there must be treated
> as open regardless of what the old audit says.

## 4. What is genuinely strong (keep it)

- Tenant-scoped queries with 404 on cross-organization access, plus `test_tenant_isolation.py`.
- Append-only audit chain with triggers and an integrity endpoint.
- Approval single-use + policy decision id in execution records.
- Real connector adapters with bounded responses, HMAC, no redirects.
- Real AI routing that returns 503 instead of fabricating completions; prompts redacted in the ledger.
- Frontend has no `dangerouslySetInnerHTML`; CSP and CSRF double-submit verified.
- Edge agent has real SQLite WAL buffering, replay protection and signed batches.

## 5. Non-negotiable follow-ups

1. Recovery codes and active-session management (identity spec).
2. Outbox/jobs (or explicitly remove the claim from architecture docs).
3. Cursor/idempotency contract alignment (or update specs).
4. Cloud/CSPM and vulnerability importers must be marked "not implemented" until real.
5. Documentation must stop advertising A4 or connectors that have no adapter.
