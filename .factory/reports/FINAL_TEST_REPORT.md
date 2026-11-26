# FINAL TEST REPORT — 0.1.3

| Suite | Comando | Resultado | Evidencia |
| :--- | :--- | :--- | :--- |
| Backend | `pytest -o addopts="" -q` (PostgreSQL 18) | **669 passed** (see log) | `EVIDENCE/tests/backend-full.log` |
| Edge | `cd edge && pytest -q -o addopts=""` | **92 passed** | command output |
| Frontend unit | `vitest run` | **36 passed** | `EVIDENCE/FRONTEND_TEST_RUN.md` |
| Frontend types | `tsc -b --force` | exit 0 | idem |
| Frontend build | `vite build` | PASS, route-split chunks | idem |
| E2E core | Playwright Chromium 1255 | **10 passed** (24 rutas) | `EVIDENCE/e2e/playwright-desktop-8081.log` |
| E2E responsive | `responsive.spec.ts` | **PASS** (24×375/768/1440) | `EVIDENCE/e2e/a11y-responsive.log` |
| E2E a11y | `a11y.spec.ts` axe-core 4.10.2 | **PASS** (0 contrast / 0 critical) | idem |
| Migraciones | upgrade → downgrade base → upgrade | **PASS** (head 0016) | `EVIDENCE/backup-restore/migration-cycle.log` |
| Backup/restore | scripts + BD aislada | **PASS** | `EVIDENCE/backup-restore/REPORT.md` |
| Deploy gate | render + `validate_deploy.py` | PASS; template FAIL esperado | `EVIDENCE/infrastructure/` |
| pip-audit | `pip_audit --skip-editable` | No known vulnerabilities | `EVIDENCE/security/pip-audit.txt` |
| bandit | `bandit -ll` | 0 MEDIUM/HIGH | `EVIDENCE/security/bandit.json` |
| gitleaks | 8.30.1 | **0 leaks** (7 commits) | `EVIDENCE/security/gitleaks.json` |
| npm audit | `npm audit --audit-level=high` | 0 vulnerabilities | `EVIDENCE/security/npm-audit.txt` |
| SBOM | CycloneDX Python/Node | 84 / 154 components | `EVIDENCE/sbom/` |
| Load/perf | — | **NOT RUN** | no benchmark executed |
| Docker/K8s runtime | — | **NOT RUN** | Docker not installed |
| Firefox/WebKit E2E | — | **NOT RUN** | browsers not installed |

Nuevas suites 0.1.3: seed demo (1), outbox notify (2), asset soft delete (2),
STIX export (3), scanner parsers (5), scanner import (4), IEC 62443 zones (2).
El total backend pasa de 650 a 669.
