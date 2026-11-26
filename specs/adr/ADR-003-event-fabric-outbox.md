# ADR-003: Event fabric con transactional outbox + LISTEN/NOTIFY

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-002`, `ADR-004`, `ADR-005`

## Contexto

La plataforma necesita propagar eventos de dominio (alerta creada, activo actualizado, ejecución completada, acción autónoma) a consumidores internos, SSE y métricas, sin perder eventos y sin un broker externo (Kafka/Redpanda no disponibles ni deseables en air-gap).

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Kafka/Redpanda | Throughput, retención, ecosistema | Servicio con estado, JVM, operación compleja en air-gap |
| Solo polling de tabla | Simple | Latencia (hasta el intervalo), carga constante |
| **Outbox + NOTIFY (elegido)** | Atomicidad con la transacción, baja latencia, sin broker | Throughput limitado por `NOTIFY`; requiere dispatcher |
| Cola en memoria | Rápido | Pérdida al reiniciar |

## Decisión

`outbox_events` se escribe en la **misma transacción** que el cambio de dominio. Un dispatcher publica `NOTIFY hs_events, '<event_id>'`; consumidores in-process y el SSE leen por `seq`. Entrega **at-least-once** con deduplicación por `event_id` en cada consumidor.

## Consecuencias

**Positivas**
- 0 eventos perdidos en commit (atomicidad real).
- Sin servicio extra que desplegar, respaldar o proteger.
- Latencia de propagación <100 ms en operación normal.

**Negativas**
- `NOTIFY` no escala a decenas de miles de eventos/s por canal; se mitiga con batch y con polling `SKIP LOCKED` cuando la profundidad supera un umbral.
- Los consumidores deben ser idempotentes; se prueba con doble entrega.
- El outbox requiere limpieza (retención 7 días) y monitorización de profundidad.

**Métricas de reversión**
- Profundidad de outbox >10k sostenida o latencia >5 s → activar modo polling y evaluar broker.
- Si se requiere multi-nodo con fan-out masivo, migrar a NATS/Kafka manteniendo el contrato de eventos.

## Verificación

`test_outbox_atomicity.py` (rollback de transacción no deja evento), `test_sse_stream.py`, métrica `hs_outbox_pending`, test de doble entrega idempotente.
