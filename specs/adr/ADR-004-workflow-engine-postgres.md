# ADR-004: Workflow engine durable en PostgreSQL (sin Temporal)

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-002`, `ADR-003`, `ADR-004` (SOAR), `specs/domains/soar.md`

## Contexto

SOAR exige ejecuciones que sobrevivan a reinicios, reintentos con backoff, aprobaciones con timeout, compensación y reanudación exacta. Temporal no está disponible y añade un servicio con estado y una curva operativa alta para un despliegue air-gapped pequeño.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Temporal | Motor maduro, signals, historial | Servicio extra, cluster, base de datos propia, operación |
| Celery + Redis | Conocido | Redis no disponible; sin durabilidad fuerte ni reanudación exacta |
| APScheduler en memoria | Simple | Pierde estado al reiniciar |
| **Motor propio sobre PostgreSQL (elegido)** | Durable, transaccional, sin servicio extra, auditable | Funcionalidad acotada; requiere tests de caos |

## Decisión

Tablas `jobs`, `executions`, `execution_steps`; claim con `FOR UPDATE SKIP LOCKED`; leases de 60 s con heartbeat; reanudación desde el último `step_key` completado; idempotencia por `UNIQUE(execution_id, step_key)`; backoff exponencial con jitter; compensación LIFO declarada en el playbook.

## Consecuencias

**Positivas**
- Estado y ejecución en la misma BD que el resto del dominio (una transacción, un backup).
- Depurable con SQL; auditable paso a paso.
- Sin dependencia operativa adicional.

**Negativas**
- Sin signals avanzados, child workflows ni historial event-sourced completo.
- El motor es código propio: riesgo de bugs; mitigado con `test_workflow_suite.py` (crash en cada paso, doble entrega, lease expirado, compensación).
- El throughput está limitado por la BD; suficiente para el volumen esperado (≤200 ejecuciones concurrentes).

**Métricas de reversión**
- Si se requieren workflows de >100 pasos o >10k ejecuciones/h, evaluar Temporal.
- Si la tasa de ejecuciones atascadas >0.1%, revisar diseño de leases.

## Verificación

`test_workflow_resume.py` (matar worker), `test_approvals.py`, `test_compensation.py`, `test_concurrency_limits.py`, reconciliación de `running` sin lease >5 min.
