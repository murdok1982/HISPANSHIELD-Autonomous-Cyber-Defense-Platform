# EXECUTIVE SUMMARY — HISPANSHIELD 0.1.2

## Qué estaba mal

- Las cifras de estado no coincidían: 128/172 vs 109/150 tareas, 44 vs 47
  aplazadas, 23 vs 24 pantallas, 284 vs 283 operaciones OpenAPI y 0 AC marcados
  pese a tareas “verificadas”.
- El README y la matriz de compatibilidad anunciaban EDR, cloud CSPM,
  importadores Nessus/OpenVAS/Trivy, OIDC/SAML y A4 sin implementación real.
- Faltaban outbox transaccional, SSE, `Idempotency-Key`, cursor pagination,
  `/setup`, invitaciones y endpoints de política de contraseñas.
- La cadena de auditoría era SHA-256 sin clave; un administrador de PostgreSQL
  podía recomputarla.
- La plantilla Kubernetes parecía producción pero contenía
  `ghcr.io/example`, `CHANGE_ME` y hosts de ejemplo.

## Qué se ha corregido

- Reconciliación medida con `scripts/factory_metrics.py` y
  `scripts/ac_traceability.py`: 138/176 tareas, 70/124 AC verificados, 32
  parciales, 22 no verificados.
- Auditoría HMAC v3 con rotación de clave y checkpoints firmados; producción
  exige `HS_AUDIT_REQUIRE_HMAC=true`.
- Outbox transaccional con leases, reintentos, DLQ y consumidor de
  notificaciones; SSE con `Last-Event-ID`; cursor pagination; `Idempotency-Key`
  en incidentes/imports; `/setup`; invitaciones single-use; política de
  contraseñas; sesiones activas en UI.
- Manifiesto Kubernetes convertido en plantilla renderizable con gate que
  rechaza placeholders, `:latest`, variables sin renderizar y ausencia de
  controles de seguridad.
- Documentación corregida: README, matriz de compatibilidad, roadmap,
  implementation-status, CHANGELOG, SPEC, TASKS, REPO_INVENTORY y
  RELEASE_READINESS.

## Qué está realmente operativo y probado

Backend 650 tests, edge 92, frontend 36, `tsc`/`vite build`, `ruff`, `mypy`,
bandit, pip-audit, npm audit, render+validación K8s. Ver
`.factory/EVIDENCE/`.

## Qué no se ha podido probar

Playwright E2E, Docker/K8s runtime, restauración de backup, gitleaks en esta
ola, benchmarks de 5k/100k y revisión independiente real.

## Riesgos que permanecen

Outbox sin `LISTEN/NOTIFY`/tabla `jobs`; cloud CSPM/importadores/legal
hold/particiones/A4/agente durable ausentes; clave HMAC y PostgreSQL en las
mismas manos siguen permitiendo forja; revisión independiente pendiente.

## Recomendación

**0.1.2 release candidate para laboratorio/piloto controlado.** No es GA, no
está certificado y no debe etiquetarse `PRODUCTION READY`.
