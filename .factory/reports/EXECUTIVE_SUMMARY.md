# EXECUTIVE SUMMARY — HISPANSHIELD 0.1.3

## Qué cambia respecto a 0.1.2

- **CI reparado (P0):** el job `container` tenía `steps:` fusionado con `needs:`.
  Ahora el workflow parsea, aplica permisos mínimos y un `quality-gate`
  fail-closed.
- **Instalación limpia reparada:** el seed demo ya no colisiona en
  `uq_events_org_dedupe`; `/setup` siembra los 10 marcos de cumplimiento.
- **Backup/restore reparado y verificado:** los scripts pasan un DSN válido a
  libpq; restauración aislada con conteos, cadena de auditoría y smoke API.
- **Capacidades cerradas:** outbox `LISTEN/NOTIFY`, soft delete/restore de
  activos, export STIX 2.1/CSV, importadores Nessus/OpenVAS/Trivy y
  `required_sl` IEC 62443.
- **Evidencia E2E real:** Playwright 10/10 sobre 24 rutas, gate responsive
  375/768/1440 y axe-core 0 contrast/0 critical.

## Estado medido

- `143/176` tareas verificadas; `33` bloqueadas; `0` en progreso.
- `81/124` AC verificados; `27` parciales; `16` no verificados.
- Backend `669` tests, edge `92`, frontend `36`; migraciones `16`;
  OpenAPI `308` operaciones / `236` rutas.
- pip-audit, bandit, gitleaks y npm audit limpios.

## Qué sigue fuera de alcance

Cloud/CSPM, legal hold, particiones/retención, A4, runtime durable de agentes,
tracker NIS2, ETSI/CPE, Firefox/WebKit, Docker/K8s runtime, benchmarks 5k/100k,
air-gap y revisión externa independiente.

## Veredicto

**PILOT READY** para un piloto controlado con entorno aislado y riesgos
residuales aceptados. **No** PRODUCTION READY. Detalle en
`.factory/RELEASE_READINESS.md` y `.factory/reports/FINAL_RELEASE_REPORT.md`.
