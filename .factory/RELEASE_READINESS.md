# RELEASE READINESS — HISPANSHIELD 0.1.2 (evolution wave 1)

- **Date:** 2026-11-26
- **Scope:** Wave 0 reconciliation + Wave 1 security/durability/contract on top
  of 0.1.1 (`ade3431`).
- **Rule:** a gate is `PASS` only with an executable command and an output
  excerpt in `.factory/EVIDENCE/`. Unavailable tooling is `NOT RUN`, never
  simulated.

## 1. Gate summary

| Gate | Status | Evidence |
| :--- | :--- | :--- |
| A — Security (0 CRITICAL / 0 HIGH open) | **PASS (with residuals)** | HMAC v3 + checkpoints, SSRF pinning, replay/nonce, tenant isolation suites; residual risks §4 |
| B — Functional (backend + edge + frontend) | **PASS** | backend 650 passed; edge 92 passed; frontend 36 passed |
| C — Quality (ruff, format, mypy, tsc, build, audits) | **PASS** | `.factory/EVIDENCE/BACKEND_TEST_RUN.md`, `FRONTEND_TEST_RUN.md`; pip-audit clean, bandit 0 MEDIUM/HIGH, npm audit 0 |
| D — Deployment manifests | **PARTIAL** | K8s template render+validate PASS; Docker/K8s runtime **NOT RUN** |
| E — Independent review | **PASS (same auditor, re-verification)** | `.factory/SECURITY_FINDINGS.md`; absence of a truly independent reviewer is stated |
| F — E2E / performance | **NOT RUN** | Playwright browsers not installed; no 5k/100k benchmarks |

## 2. Commands executed

```bash
# Metrics
python3 scripts/factory_metrics.py
python3 scripts/ac_traceability.py

# Backend
cd backend
python -m pytest -o addopts="" -q          # 650 passed
uvx ruff@0.11.10 check app tests           # All checks passed
uvx ruff@0.11.10 format --check app tests  # 238 files formatted
uvx --with types-PyYAML mypy@1.15.0 app    # Success: 188 files
uvx bandit@1.8.3 -q -ll -r app -x tests    # exit 0
uvx pip-audit@2.9.0 --skip-editable        # No known vulnerabilities

# Edge
cd edge && python -m pytest -q -o addopts=""   # 92 passed

# Frontend (Node 22.14)
cd frontend
node node_modules/typescript/bin/tsc -b --force   # exit 0
node node_modules/vite/bin/vite.js build          # built in 4.52s
node node_modules/vitest/vitest.mjs run           # 36 passed
npm audit --audit-level=high                      # 0 vulnerabilities

# Deployment template
./deploy/k8s/render.sh /tmp/values.env > /tmp/rendered.yaml
python3 scripts/validate_deploy.py /tmp/rendered.yaml   # PASS
python3 scripts/validate_deploy.py deploy/k8s/manifests.yaml  # FAIL (expected)
```

## 3. Backlog / AC state

| Metric | 0.1.1 | 0.1.2 |
| :--- | ---: | ---: |
| Tasks verified | 128 / 172 | **138 / 176** |
| Deferred/blocked | 44 | **37** |
| In progress | 0 | **1** (`TASK-008`: outbox without LISTEN/NOTIFY/jobs) |
| AC VERIFIED | 0 checked (not audited) | **70 / 124** |
| AC PARTIAL | — | **32** |
| AC NOT_VERIFIED | — | **22** |
| Backend tests executed | 609 | **650** |
| Edge tests | 92 | **92** |
| Frontend unit | 36 | **36** |
| OpenAPI operations/paths | 284 / 215 | **305 / 233** |
| Navigation / content screens | 23 / 26 | **23 / 26** |

AC evidence is in `.factory/AC_TRACEABILITY.md`. A checked task does not imply
every AC in its spec reference is verified.

## 4. Residual risk (honest)

1. **Outbox without `LISTEN/NOTIFY`/`jobs`:** dispatcher polls every second and
   uses `SKIP LOCKED` + leases; this is correct but not the final low-latency
   design (`TASK-008` remains in progress).
2. **At-least-once consumers:** the notification consumer is idempotent via
   `notifications.source_event_id`. Future handlers with external side effects
   must supply their own idempotency; the outbox cannot provide exactly-once
   HTTP.
3. **Audit HMAC key custody:** production now refuses to start without
   `HS_AUDIT_REQUIRE_HMAC=true` and a key; however, an attacker with both the
   key and PostgreSQL can still forge. Checkpoints help only if exported to
   external/WORM storage, which is operational and not automated.
4. **`allow_legacy_hmac`** on an ingest source re-enables body-only signatures
   (replay protection weakened). Disabled by default and audited.
5. **Legacy `/ingest/{token}`** still exposes the token to reverse-proxy logs;
   the app redacts it and the route is deprecated.
6. **No cloud CSPM, Nessus/OpenVAS/Trivy importers, legal hold, partitions,
   A4 actions or durable agent runtime.** Documented as deferred, not claimed.
7. **Playwright, Docker/K8s runtime, backup restore and the performance
   benchmarks were not executed here.** Manifests and tests exist but are not
   claimed as executed.
8. **Single-admin break-glass** remains self-approved by design when no second
   platform administrator exists; compensating controls are justification,
   ticket, TTL and audit.

## 5. Release recommendation

- **Security gate:** PASS with the residuals above.
- **Functional/quality gates:** PASS.
- **Deployment gate:** PARTIAL (render/validate only).
- **Recommendation:** publish as **0.1.2 release candidate** for lab/pilot
  evaluation. Do not label GA, certified or “production ready”. Before a pilot:
  run Playwright, Docker/K8s rollout, backup restore and a truly independent
  security review.
