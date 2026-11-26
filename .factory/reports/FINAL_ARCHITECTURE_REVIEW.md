# FINAL ARCHITECTURE REVIEW — 0.1.2

## Decisión

Se conserva el monolito modular FastAPI + PostgreSQL + React SPA + edge gateway.
No se han introducido Kafka, Redis, RabbitMQ ni microservicios. La durabilidad
se resolvió con PostgreSQL (outbox, leases, DLQ), que es la decisión correcta
hasta demostrar límites medidos.

## Cambios estructurales

- `app/services/outbox.py` + `models/operations.py` + migración `0012`.
- `app/modules/events/stream.py` (SSE) y `useEventStream.ts`.
- `app/core/idempotency.py` + migración `0013`.
- `app/core/audit.py` v3 + `audit_checkpoints` (migración `0011`).
- `app/modules/setup/` e invitaciones (migración `0014`).
- `deploy/k8s/render.sh` + `scripts/validate_deploy.py`.

## Deuda estructural que sigue abierta

- No existe capa `repository.py`; el SQL vive en routers/services.
- `LISTEN/NOTIFY` y tabla `jobs` separada no existen (`TASK-008` en progreso).
- No hay particiones mensuales de eventos/auditoría.
- FTS GIN no se usa en las búsquedas (`LIKE`).
- `assets` sigue actuando como shared kernel sin interfaz versionada.
- Soft delete genérico y UUIDv7 siguen sin implementarse.

## Veredicto

Arquitectura coherente y operable para RC. **No** se declara lista para alta
disponibilidad ni para escala empresarial sin las pruebas de carga y las
particiones pendientes.
