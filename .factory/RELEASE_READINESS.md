# RELEASE READINESS — HISPANSHIELD 0.1.3 (remediation wave)

- **Date:** 2026-11-26
- **Scope:** 0.1.2 RC (`251846c`) + CI recovery, fresh-install fixes, outbox
  signaling, asset soft delete, STIX export, scanner importers, IEC 62443
  validation, E2E/a11y/responsive gates, migration cycle and backup/restore.
- **Rule:** a gate is `PASS` only with an executable command and an output
  artefact in `.factory/EVIDENCE/`. Unavailable tooling is `NOT RUN`, never
  simulated.

## 1. Gate summary

| Gate | Status | Evidence |
| :--- | :--- | :--- |
| A — Security (0 CRITICAL / 0 HIGH open) | **PASS (with residuals)** | pip-audit, bandit 0 MEDIUM/HIGH, gitleaks 0, npm audit 0; HMAC v3, SSRF pinning, replay/nonce, tenant isolation suites |
| B — Functional (backend + edge + frontend) | **PASS** | backend suite (see `tests/backend-full.log`), edge 92, frontend 36 |
| C — Quality (ruff, format, mypy, tsc, build, audits) | **PASS** | `tests/backend-full.log`, `security/`, frontend build |
| D — Deployment manifests | **PARTIAL** | K8s render+validate PASS; Docker/K8s runtime **NOT RUN** |
| E — Independent review | **PARTIAL** | internal adversarial review + this evidence pack; external reviewer absent |
| F — E2E / accessibility / responsive | **PASS (Chromium only)** | Playwright 10/10, `responsive.spec.ts`, `a11y.spec.ts` (axe 0/0) |
| G — Backup / restore | **PASS** | `EVIDENCE/backup-restore/REPORT.md` |
| H — Migrations | **PASS** | upgrade → downgrade base → upgrade, head `0016` |
| I — Performance (5k/100k) | **NOT RUN** | no benchmark executed in this wave |
| J — CI/CD | **PASS (local + remote)** | `.factory/EVIDENCE/ci/github-actions.md`; all jobs success on commit `8780113` |

## 2. Backlog / AC state

| Metric | 0.1.2 | 0.1.3 |
| :--- | ---: | ---: |
| Tasks verified | 138 / 176 | **143 / 176** |
| Deferred/blocked | 37 | **33** |
| In progress | 1 | **0** |
| AC VERIFIED | 70 / 124 | **81 / 124** |
| AC PARTIAL | 32 | **27** |
| AC NOT_VERIFIED | 22 | **16** |
| Backend tests | 650 | **669** |
| Edge tests | 92 | 92 |
| Frontend unit | 36 | 36 |
| E2E (Chromium) | not run in wave | **12** (10 core + responsive + axe) |
| Migrations | 14 | **16** |

## 3. Residual risk (honest)

1. **External independence:** the security review is still internal. A pilot
   must add an external reviewer with access to code, infrastructure and logs.
2. **Deployment runtime:** Docker/Kubernetes manifests validate, but no real
   rollout, restart, upgrade or rollback was executed here.
3. **Scale:** no 5k/100k benchmark; FTS is not used by every search path and
   event partitioning/retention remains absent.
4. **Cloud/CSPM, legal hold, A4, durable agent runs, NIS2 tracker, ETSI
   checklist, CPE→CVE** remain unimplemented and are explicitly blocked.
5. **Audit key custody:** production refuses to start without
   `HS_AUDIT_REQUIRE_HMAC=true` and a key, but an attacker with key + DB can
   still forge. Checkpoints help only when exported to external/WORM storage.
6. **At-least-once consumers:** outbox handlers must be idempotent; the built-in
   notification consumer is. Exactly-once HTTP is not claimed.
7. **Browser coverage:** Playwright Chromium only; Firefox/WebKit not installed.
8. **Rate limiting vs E2E:** E2E disables the limiter because the suites reload
   the SPA dozens of times. Production keeps it enabled and tested separately.

## 4. Release recommendation

- **Security gate:** PASS with the residuals above.
- **Functional/quality/E2E/backup gates:** PASS.
- **Deployment/performance:** PARTIAL / NOT RUN.
- **Verdict: PILOT READY.** Suitable for a controlled pilot with a seeded,
  isolated environment, documented residual risks and an external security
  review before any production decision. **Not** PRODUCTION READY.
