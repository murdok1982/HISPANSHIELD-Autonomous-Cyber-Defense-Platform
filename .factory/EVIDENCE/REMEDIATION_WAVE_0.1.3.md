# Remediation wave 0.1.3 — engineering evidence

- **Date:** 2026-11-26
- **Baseline:** `main@251846c` (0.1.2 RC)
- **Branch:** `fix/0.1.3-remediation`
- **Method:** SDD loop (spec → task → implementation → executable verification →
  evidence). A defect is only listed as fixed when a test or command proves it.

## 1. Blocking CI defect (P0)

`ci.yml` had `needs: [backend, frontend]    steps:` fused into one line, so the
container job had no valid steps. Fixed, plus least-privilege permissions,
timeouts, `load: true` for the Trivy scan and a fail-closed `quality-gate` job.
YAML parses and the job graph is correct. See
`.factory/reports/CI_CD_REPORT.md`.

## 2. Real defects found in a fresh install (and fixed)

| # | Symptom | Root cause | Fix | Test |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `seed_demo` aborts on a clean DB with `uq_events_org_dedupe` | demo events reused message/host/user, producing identical dedupe keys | include the unique event uid in the demo dedupe key | `test_seed_demo.py::test_demo_seed_is_fresh_install_safe_and_idempotent` |
| 2 | Fresh `/setup` leaves the compliance catalogue empty | frameworks were only seeded by tests/manual scripts | `/setup` now seeds the built-in catalogue; added `scripts/seed_frameworks.py`; demo seed does the same | `test_setup.py::test_setup_creates_first_org_at_a0_and_refuses_replay` |
| 3 | `backup.sh` / `restore.sh` fail with the app DSN | `pg_dump`/`pg_restore` do not accept `postgresql+psycopg://` | strip the SQLAlchemy driver suffix before calling libpq | backup/restore executed end-to-end (see below) |

## 3. Capabilities completed

| Task | Capability | Evidence |
| :--- | :--- | :--- |
| TASK-008 | Outbox `LISTEN/NOTIFY` with polling fallback; no generic `jobs` table (ADR-013) | `test_outbox_notify.py` (2), `test_outbox.py` (9) |
| TASK-030 | Asset soft delete + restore, global ORM read filter, trash-key conflict | `test_asset_soft_delete.py` (2), `test_assets.py` (13) |
| TASK-037 | Attack-surface STIX 2.1 + CSV export with lossless ip/port round-trip | `test_asm_export.py` (3) |
| TASK-040 | Nessus/OpenVAS/Trivy importers, cross-scanner dedupe, DTD/entity rejection, idempotency | `test_scanner_importers.py` (5), `test_vuln_importers.py` (4) |
| TASK-101 | IEC 62443 `required_sl` enforcement and SL3 compensating-control gap | `test_iec62443_zones.py` (2) |
| AC-111 | Migration cycle: upgrade → downgrade base → upgrade | `.factory/EVIDENCE/backup-restore/migration-cycle.log` |

## 4. Security evidence

- `pip-audit --skip-editable`: **no known vulnerabilities**.
- `bandit -ll -r app -x tests`: **0 MEDIUM/HIGH** (XML parser switched to
  `defusedxml`, ADR-014).
- `gitleaks detect` over all 7 commits: **0 leaks** (CI/test placeholders
  allowlisted with specific patterns, none of them real credentials).
- `npm audit --audit-level=high`: **0 vulnerabilities**.
- New importers reject DTD/entity XML with 422 and cap input at 20 MB; hosts
  are resolved only inside the caller's tenant.

## 5. E2E and UX gates

- Fresh demo DB + real API + production bundle, Playwright Chromium 1255:
  - core suite `10 passed` (24 routes, critical flows, screenshots);
  - `responsive.spec.ts` (375/768/1440 × 24 routes, no horizontal overflow,
    navigation present): see `.factory/EVIDENCE/e2e/a11y-responsive.log`;
  - `a11y.spec.ts` (axe-core 4.10.2, color-contrast + critical): see same log.
- Rate limiting must be disabled for the E2E server (`HS_RATE_LIMIT_ENABLED=false`);
  the suites reload the SPA dozens of times and would otherwise trip the
  product's own limiter, which is correct production behaviour.

## 6. Backup / restore

Full logical backup, SHA-256 manifest verification, restore into an isolated
database, row-count equality, audit-chain verification and API smoke test:
see `.factory/EVIDENCE/backup-restore/REPORT.md`.

## 7. SBOM

- Python: CycloneDX 1.6, 84 components.
- Node: CycloneDX 1.7, 154 components.
- Files: `.factory/EVIDENCE/sbom/{python,node}.json`.

## 8. Gaps that remain open (not claimed as fixed)

Cloud CSPM, legal hold, monthly partitions/retention job, A4 actions, durable
agent-run resume, NIS2 24/72 h tracker, Firefox/WebKit E2E, Docker/Kubernetes
runtime, performance benchmarks at 5k/100k, air-gapped bundle and a truly
independent external review. These stay `[!]` in `.factory/TASKS.md` and
`NOT_VERIFIED`/`PARTIAL` in the AC matrix.
