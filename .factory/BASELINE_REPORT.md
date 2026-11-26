# BASELINE REPORT — 2026-11-26

## 1. Repository protection

| Item | Value |
| :--- | :--- |
| Repository | `murdok1982/HISPANSHIELD-Autonomous-Cyber-Defense-Platform` |
| Baseline branch | `main` |
| Baseline commit | `251846c` — `chore(release): align 0.1.2 versions…` |
| Working tree before changes | clean (no local modifications) |
| Work branch | `fix/0.1.3-remediation` |
| Destructive operations | none (no push/merge/release before explicit authorization) |

## 2. Toolchain observed

| Component | Version / location |
| :--- | :--- |
| OS | Linux, 8 vCPU, 15 GB RAM |
| Python | 3.12.16 in `/tmp/opencode/hs-venv` |
| PostgreSQL | 18.6, local cluster `127.0.0.1:55432` |
| Node.js | v22.14.0 (`/tmp/opencode/node-v22.14.0-linux-x64`) |
| Docker | **not installed** (BLOCKED for runtime validation) |
| Playwright | Chromium 1255 in `~/.cache/ms-playwright` |

## 3. Baseline execution (before remediation)

| Gate | Result |
| :--- | :--- |
| Backend `pytest` | **650 passed** (272 s) |
| Edge `pytest` | **92 passed** |
| Frontend `tsc -b --force` | exit 0 |
| Frontend `vitest run` | **36 passed** |
| Frontend `vite build` | PASS |
| `ruff check` / `format --check` | PASS |
| `mypy app` | PASS (188 files) |
| `bandit -ll` | PASS (0 MEDIUM/HIGH) |
| `pip-audit` | PASS (no known vulnerabilities) |
| `npm audit --audit-level=high` | PASS (0) |
| CI workflow | **BROKEN** — `needs: [...]    steps:` fused |
| E2E in 0.1.2 evidence | contradictory (`10/10` vs `NOT RUN`) |

## 4. Defects confirmed by execution (not by reading docs)

1. CI `container` job had no valid `steps` list (P0).
2. A fresh demo seed aborted on `uq_events_org_dedupe`.
3. A fresh `/setup` left the compliance catalogue empty.
4. `backup.sh` / `restore.sh` passed a SQLAlchemy DSN to `pg_dump`/`pg_restore`.
5. The logged E2E claim could not be trusted until re-executed; re-execution
   passed 10/10 on a fresh database, and two new gates (responsive + axe) were
   added and passed.

## 5. Current measurement (post-remediation)

| Gate | Result | Evidence |
| :--- | :--- | :--- |
| Backend suite | 669 tests (see log) | `.factory/EVIDENCE/tests/backend-full.log` |
| Edge | 92 passed | command output |
| Frontend unit | 36 passed | command output |
| E2E core | 10 passed | `.factory/EVIDENCE/e2e/playwright-desktop-8081.log` |
| E2E responsive | PASS (24×3) | `.factory/EVIDENCE/e2e/a11y-responsive.log` |
| axe-core | PASS (0 contrast/critical) | same log |
| Migrations | upgrade→base→upgrade exit 0 | `.factory/EVIDENCE/backup-restore/migration-cycle.log` |
| Backup/restore | PASS | `.factory/EVIDENCE/backup-restore/REPORT.md` |
| Security scans | clean | `.factory/EVIDENCE/security/` |
| SBOM | 84 + 154 components | `.factory/EVIDENCE/sbom/` |

## 6. Module inventory (high level)

- `backend/app/modules/`: identity, organizations, assets, attack_surface,
  vulnerabilities, events, siem, incidents, threat_intel, forensics, soar,
  defence, ai, agents, mcp, connectors, edge, iot, ot, compliance, reports,
  posture, overview, setup, audit.
- `backend/app/core/`: config, db, audit, crypto, ssrf/outbound pinning,
  rate limit, idempotency, RBAC, errors, logging.
- `backend/app/workers/`: durable runtime + outbox listener + syslog receiver.
- `frontend/src/pages/`: 24 authenticated screens (23 nav + profile).
- `edge/`: SQLite WAL gateway, HMAC/replay, sync tests.
- `deploy/`: Dockerfile, Compose, K8s template + render/validate script.

## 7. Blockers carried forward

Docker/K8s runtime, performance benchmarks (5k/100k), Firefox/WebKit, external
independent review, cloud/CSPM, legal hold, partitions/retention, A4, durable
agent runs, NIS2 tracker and air-gapped installation remain blocked or
deferred with explicit IDs in `.factory/TASKS.md`.
