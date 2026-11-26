# Estado de implementación — HISPANSHIELD 0.1.3

- **Fecha:** 2026-11-26
- **Estado de release:** `RELEASE CANDIDATE 0.1.3`, no GA. Veredicto de
  aseguramiento: **PILOT READY** (piloto controlado, con las limitaciones de la
  sección 4).
- **Regla de honestidad:** `VERIFIED` exige comando ejecutado con éxito en este
  entorno. `DEFERRED` significa ausente o parcial y está enlazado en
  `.factory/TASKS.md`. `IMPLEMENTED` no se presenta como `VERIFIED`.
- **Backlog:** `143 / 176` tareas verificadas; `33` aplazadas/bloqueadas; `0` en
  progreso.
- **Criterios de aceptación:** `81` verificados, `27` parciales, `16` no
  verificados. Matriz reproducible en `.factory/AC_TRACEABILITY.md`.
- **Fuente de métricas:** `python3 scripts/factory_metrics.py` →
  `.factory/EVIDENCE/METRICS.json`.

> Esta entrega evoluciona 0.1.2 sin reescribirla: corrige el pipeline CI,
> completa outbox `LISTEN/NOTIFY`, soft delete/restore de activos, export
> STIX 2.1, importadores Nessus/OpenVAS/Trivy y `required_sl` IEC 62443. Además
> repara dos defectos de instalación limpia (seed demo y catálogo de
> cumplimiento) y el DSN de backup/restore.

---

## 1. Evidencia ejecutada en esta ola

| Gate | Comando | Resultado |
| :--- | :--- | :--- |
| CI YAML | `actionlint 1.7.12` + YAML parse | **PASS** (7 jobs; 0 findings) |
| CI remoto | GitHub Actions runs `45881513134` / `45881504398` | **PASS** (todos los jobs, incluido container/Trivy) |
| Backend lint | `ruff check app tests` | **PASS** — All checks passed |
| Backend format | `ruff format --check app tests` | **PASS** — 248 files formatted |
| Backend types | `mypy app` | **PASS** — 191 source files |
| Backend tests | `pytest -o addopts="" -q` (PostgreSQL 18) | ver `.factory/EVIDENCE/tests/backend-full.log` |
| Edge tests | `cd edge && pytest -q -o addopts=""` | **92 passed** |
| Frontend types | `tsc -b --force` | exit 0 |
| Frontend build | `vite build` | PASS, route-split chunks |
| Frontend unit | `vitest run` | **36 passed** |
| E2E núcleo | Playwright Chromium 1255, BD demo limpia | **10 passed** (24 rutas, flujos, capturas) |
| E2E responsive | `responsive.spec.ts` 24 rutas × 375/768/1440 | **PASS** (0 overflow, navegación presente) |
| E2E accesibilidad | `a11y.spec.ts` axe-core 4.10.2 | **PASS** (0 color-contrast, 0 critical) |
| Migraciones | `alembic upgrade head → downgrade base → upgrade head` | **PASS** (exit 0, head 0016) |
| Backup/restore | `backup.sh` + `restore.sh` en BD aislada | **PASS** (conteos, manifiesto, cadena de auditoría, `/readyz`, login) |
| K8s render+validate | `render.sh values.ci.env \| validate_deploy.py` | **PASS** (plantilla sin renderizar: FAIL esperado) |
| SBOM | CycloneDX Python + Node | **PASS** (84 y 154 componentes) |
| pip-audit / bandit / gitleaks / npm audit | ver `.factory/EVIDENCE/security/` | **PASS**: 0 vulnerabilidades, 0 MEDIUM/HIGH, 0 secretos, 0 npm |
| Docker/Kubernetes runtime | — | **NOT RUN**; solo validación estática/render |

---

## 2. Capacidades verificadas (delta 0.1.3)

| Área | Entregado | Evidencia |
| :--- | :--- | :--- |
| CI/CD | Fix P0 del YAML, permisos mínimos, timeouts, `quality-gate` fail-closed | `.factory/reports/CI_CD_REPORT.md` |
| Instalación limpia | `/setup` siembra 10 marcos; seed demo único; script `seed_frameworks.py` | `test_setup.py`, `test_seed_demo.py` |
| Outbox | `LISTEN/NOTIFY` con polling/leases como red de seguridad | `test_outbox_notify.py`, `test_outbox.py` |
| Activos | Soft delete + restore con relaciones y filtro ORM global | `test_asset_soft_delete.py` |
| Vulnerabilidades | Importadores Nessus/OpenVAS/Trivy, dedupe cross-scanner, XML endurecido | `test_scanner_importers.py`, `test_vuln_importers.py` |
| Superficie de ataque | Export STIX 2.1/CSV con round-trip ip/puerto | `test_asm_export.py` |
| OT/IEC 62443 | `required_sl` obligatorio y gap por falta de control compensatorio | `test_iec62443_zones.py` |
| Operación | Backup/restore verificado y migraciones reversibles | `.factory/EVIDENCE/backup-restore/` |
| Accesibilidad/responsive | axe-core y 3 viewports sobre 24 rutas | `.factory/EVIDENCE/e2e/a11y-responsive.log` |

Las capacidades de 0.1.2 (auth/MFA, RBAC, auditoría HMAC, SIEM, SOAR, IA,
MCP, edge, cumplimiento) siguen cubiertas por la suite; no se han eliminado
controles ni tests.

---

## 3. Aplazado / parcial (33 tareas `[!]`)

No se presenta como implementado:

- **Cloud/CSPM:** cuentas cloud, credenciales y reglas CSPM reales.
- **SIEM a escala:** particiones mensuales, job de retención, benchmark 100k y
  FTS real en todas las búsquedas.
- **Autonomía:** A4 con doble aprobación, cola de concurrencia por organización y
  matriz completa del laboratorio.
- **IA/agentes:** runtime durable con reanudación por step log.
- **Cumplimiento:** legal hold forense, tracker NIS2 24/72 h/1 mes, RoPA/DPIA,
  generación PDF.
- **IoT:** checklist ETSI EN 303 645 y matching CPE/firmware→CVE.
- **Frontend:** teclado/focus trap/reduced-motion automatizados, SSE
  `reconnecting` explícito y Firefox/WebKit.
- **Operación:** Docker/Kubernetes runtime, air-gap real, rendimiento 5k/100k y
  revisión externa independiente.

Ver `.factory/TASKS.md` para IDs, motivos y comandos de verificación.

---

## 4. Limitaciones del entorno de entrega

- **Docker/Kubernetes:** no hay Docker en este host; el manifiesto se renderiza
  y valida, pero no se ejecutó un clúster real.
- **Playwright:** ejecutado en Chromium 1255. Firefox/WebKit no están instalados.
- **Accesibilidad:** gate axe-core sobre Chromium; no sustituye una auditoría
  manual WCAG 2.2 completa.
- **Backup/restore:** dump lógico verificado; no se probó PITR/WAL archiving ni
  cifrado GPG real (solo el camino obligatorio en producción está implementado).
- **Base de datos:** PostgreSQL 18 local en `127.0.0.1:55432`; las pruebas usan
  esa instancia, no un servicio gestionado.
- **CI remoto:** el workflow se validó y todos sus comandos se ejecutaron
  localmente; la primera ejecución en GitHub Actions debe comprobarse tras el
  push.
