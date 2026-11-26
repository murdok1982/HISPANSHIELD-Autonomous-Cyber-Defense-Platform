# FINAL TEST REPORT — 0.1.2

| Suite | Comando | Resultado | Evidencia |
| :--- | :--- | :--- | :--- |
| Backend | `python -m pytest -o addopts="" -q` | **650 passed** (241.85 s) | `EVIDENCE/BACKEND_TEST_RUN.md` |
| Edge | `cd edge && pytest -q -o addopts=""` | **92 passed** | `EVIDENCE/BACKEND_TEST_RUN.md` |
| Frontend unit | `vitest run` | **36 passed** | `EVIDENCE/FRONTEND_TEST_RUN.md` |
| Frontend types | `tsc -b --force` | exit 0 | idem |
| Frontend build | `vite build` | built in 4.52 s | idem |
| Deploy gate | render + `validate_deploy.py` | PASS; template FAIL esperado | `EVIDENCE/DEPLOY_VALIDATION.md` |
| E2E Playwright | — | **NOT RUN** | sin navegadores |
| pip-audit | `uvx pip-audit` | No known vulnerabilities | `EVIDENCE/BACKEND_TEST_RUN.md` |
| bandit | `uvx bandit -ll` | 0 MEDIUM/HIGH | idem |
| npm audit | `npm audit --audit-level=high` | 0 vulnerabilities | `EVIDENCE/FRONTEND_TEST_RUN.md` |
| gitleaks | — | **NOT RUN** | binario no instalado |
| Load/perf | — | **NOT RUN** | ver informe de rendimiento |

Nuevos suites de la ola: audit HMAC (6), outbox (10), SSE (5), cursor (5),
idempotencia (7), setup (2), invitaciones (4), política de auth (2).
