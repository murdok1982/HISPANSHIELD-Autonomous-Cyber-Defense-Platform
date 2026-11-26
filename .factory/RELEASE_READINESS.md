# RELEASE READINESS — HISPANSHIELD 0.1.1 (post-RC1 security wave)

- **Date:** 2026-11-26
- **Scope:** security remediation wave 2 + operational hardening, on top of RC1 (`696655b`)
- **Rule:** this document reports commands actually executed in this environment. A gate is `PASS` only with an exit code and an output excerpt. Where a tool is unavailable (Docker, Kubernetes, Playwright browser), the gate is marked `NOT RUN` — never simulated.

## 1. Gate summary

| Gate | Status | Evidence |
| --- | --- | --- |
| A — Security (0 CRITICAL / 0 HIGH open) | **PASS** | `.factory/SECURITY_AUDIT.md`: `APPROVED (RC1)`, 0 CRITICAL / 0 HIGH; VULN-006/003/004/008 resolved after third independent pass; 6 MEDIUM + 3 LOW accepted and documented |
| B — Functional (backend + edge + frontend) | **PASS** | backend suite, edge 92, frontend 36 |
| C — Quality (ruff, format, mypy, tsc, dependency audit) | **PASS** | commands in §2 |
| D — Deployment manifests | **PARTIAL** | Compose/K8s updated and statically reviewed; Docker daemon/`kubectl` unavailable in this host |
| E — Independent review | **PASS** | `.factory/SECURITY_FINDINGS.md` (same auditor, re-verification addendum) |

## 2. Commands executed

```bash
# Backend
cd backend
export HS_DATABASE_URL="postgresql+psycopg://hispanshield:test@127.0.0.1:55432/hispanshield_test_main"
python -m pytest -o addopts="--strict-markers"      # result in §3
ruff check app tests                                # All checks passed
ruff format --check app tests                       # all files formatted
mypy app                                            # Success: no issues found (181 files)
python -m bandit -q -ll -r app -x tests             # exit 0, no MEDIUM/HIGH
python -m pip_audit --skip-editable                 # No known vulnerabilities found

# Edge
cd edge && python -m pytest -q -o addopts=""        # 92 passed

# Frontend
cd frontend
node node_modules/typescript/bin/tsc -b --force     # exit 0
node node_modules/vite/bin/vite.js build            # built successfully
node node_modules/vitest/vitest.mjs run             # 36 passed
npm audit --audit-level=high                        # found 0 vulnerabilities
```

## 3. Backend suite

See `.factory/BASELINE_TEST_RESULTS.md` for the frozen baseline and the row below
for the post-remediation result (recorded after the final run in this wave).

| Metric | Baseline (`696655b`) | Post-remediation |
| --- | --- | --- |
| Tests collected | 519 | **609** |
| Failures / errors | 0 | **0** — `609 passed, 1 warning in 224.21s (0:03:44)` |
| New regression tests | — | replay, nonce, discovery authz, claim concurrency, audit v2, guardrails, SSRF pinning, AI budgets, recovery codes, break-glass dual control, worker runtime |

## 4. Residual risk (honest)

1. **Single-admin break-glass** remains self-approved by design when no second
   platform administrator exists. Compensating controls: justification length,
   mandatory ticket, TTL, full audit, explicit approval endpoint. Documented as
   an operational constraint; organisations must provision at least two
   platform administrators for dual control.
2. **Audit chain is unkeyed SHA-256.** A database owner can recompute a
   forged chain; the trigger/storage separation and external log shipping are
   the compensating controls. HMAC signing needs external key custody and is a
   roadmap item.
3. **`allow_legacy_hmac`** on an ingest source re-enables body-only signatures
   (replay protection weakened). Disabled by default and audited.
4. **Legacy ingest path** `/ingest/{token}` still exposes the token to reverse
   proxy logs; the application redacts it and the deprecated route is documented.
   Use `POST /ingest` with `Authorization: Bearer`.
5. **PostgreSQL test harness** on tmpfs leaked inodes under parallel agents;
   CI uses a normal filesystem. Not an application defect, but a reminder to
   run one suite per database.
6. **Docker/Kubernetes build and Playwright E2E** were not executed in this
   host (no daemon/browser). Manifests and E2E tests are updated but not claimed
   as executed here.
7. **Outbox/jobs** remain unimplemented; documented in `ARCHITECTURE_GAP_ANALYSIS.md`
   and removed from release claims where applicable.

The auditor's accepted residuals (`VULN-014/015/017/018/019/021/023/026/027`)
are listed with rationale in `.factory/SECURITY_AUDIT.md` §7.

## 5. Release recommendation

- **Security gate:** PASS (0 CRITICAL / 0 HIGH open after re-verification).
- **Functional/quality gates:** PASS.
- **Deployment gate:** PARTIAL (static only in this host).
- **Recommendation:** publish as **0.1.1 security-hardening release candidate**
  after CI executes the container build and the E2E suite in GitHub Actions.
  Do not label it GA or certified.
