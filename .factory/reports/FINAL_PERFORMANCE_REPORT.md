# FINAL PERFORMANCE REPORT — 0.1.2

## Estado: NOT RUN

No se han ejecutado benchmarks reproducibles en esta ola. No se publican cifras
p50/p95/p99, throughput ni memoria porque no se midieron.

## Metodología preparada para la siguiente ola

- Hardware y versión de PostgreSQL documentados por ejecución.
- Datasets: 1.000 / 10.000 activos; 100.000 / 1.000.000 eventos.
- Escenarios: búsqueda de eventos, activos, correlación, RAG, dashboards,
  ingesta sostenida y concurrencia de API/workers.
- Métricas: p50/p95/p99, errores, throughput, memoria, backlog de outbox.
- Antes/después por índice o cambio de query; sin optimización sin medición.

## Observaciones estáticas

- `LIKE '%q%'` no usa el índice GIN FTS creado.
- Cursor pagination evita `OFFSET` profundo en assets/events.
- Outbox añade una escritura por evento de dominio y un poll de 1 s.
- SSE mantiene una conexión por cliente y una sesión corta por poll.

Estas observaciones no sustituyen una medición.
