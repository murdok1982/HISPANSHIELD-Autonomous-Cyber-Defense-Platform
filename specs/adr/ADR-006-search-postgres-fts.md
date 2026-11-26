# ADR-006: Búsqueda con PostgreSQL FTS + pg_trgm (sin OpenSearch)

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-002`, `specs/architecture/data-architecture.md §6`

## Contexto

El SIEM debe permitir búsquedas por texto y filtros tipados sobre eventos, activos, incidentes e indicadores. OpenSearch/Elasticsearch no están disponibles y añaden un clúster con estado, otra copia de los datos (riesgo de fuga y de desincronización) y una superficie de ataque considerable.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| OpenSearch | Aggregations, escalado, relevancia | Clúster, duplicación de datos, operación, seguridad |
| Búsqueda `LIKE`/`ILIKE` | Trivial | Sin relevancia, lenta a escala |
| **FTS + pg_trgm (elegido)** | Integrado, transaccional, una copia de datos | Sin aggregations avanzadas; techo de volumen |

## Decisión

`tsvector` generado con configuración `spanish` (+ fallback `simple` para identificadores), índice GIN, `websearch_to_tsquery`, `pg_trgm` para nombres/hostnames. Filtros tipados (`class_uid`, `severity`, `INET`, rangos temporales) combinados con FTS. Límites: `limit ≤200` en API, rango ≤90 días sin filtro adicional, `422 query_too_broad`.

## Consecuencias

**Positivas**
- Una sola copia de los datos: no hay desincronización ni fuga por índice secundario.
- Búsqueda consistente con la transacción (evento visible al commit).
- Menos servicios que operar y asegurar en air-gap.

**Negativas**
- Sin aggregations tipo Elasticsearch; los resúmenes se calculan en SQL o en aplicación.
- p95 degrada con volumen; se mitiga con particiones, índices y guard de consultas.
- Relevancia lingüística limitada; aceptable para consola SOC.

**Métricas de reversión**
- p95 >1 s sostenido con 5M eventos → evaluar OpenSearch o motor columnar.
- Necesidad de aggregations en tiempo real sobre >10 dimensiones → evaluar alternativa.

## Verificación

`test_event_search.py` (1M eventos, p95), `test_rule_dsl.py` (no se traduce a SQL concatenado), `EXPLAIN (ANALYZE, BUFFERS)` documentado, test de `query_too_broad`.
