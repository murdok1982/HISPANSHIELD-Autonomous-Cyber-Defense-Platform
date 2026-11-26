# ADR-002: PostgreSQL 18 como sistema de registro único

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-003`, `ADR-004`, `ADR-005`, `ADR-006`

## Contexto

El producto necesita consistencia transaccional entre dominio y eventos, búsqueda de texto, colas durables, auditoría encadenada, almacenamiento de vectores y datos semi-estructurados. El entorno verificado solo ofrece PostgreSQL 18 (socket `/tmp/opencode`, puerto 55432, trust auth). Redis, OpenSearch, Qdrant y Kafka no están disponibles.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Poliglot persistence (PG + Redis + OS + Qdrant + Kafka) | Mejor por caso de uso | 4-5 servicios que operar, respaldar y asegurar en air-gap |
| SQLite | Cero operación | Sin concurrencia real, sin `SKIP LOCKED`, sin FTS avanzado, sin particiones |
| **PostgreSQL único (elegido)** | ACID, JSONB, FTS, particiones, `LISTEN/NOTIFY`, `SKIP LOCKED`, `float4[]` | Escalado vertical; límites en búsqueda/vectores a gran escala |

## Decisión

PostgreSQL 18 como único almacén durable. Acceso con SQLAlchemy 2.0 **sync** + psycopg3; migraciones con Alembic. Tipos nativos: `JSONB`, `INET`, `TSVECTOR`, `float4[]`, `NUMERIC`, `TIMESTAMPTZ`, `CITEXT`.

**Por qué sync:** simplifica depuración, evita `greenlet` y problemas de contexto async en workers; el rendimiento se obtiene con pool dimensionado y workers separados. Las rutas de alta concurrencia usan SQL directo cuando aporta valor.

## Consecuencias

**Positivas**
- Un solo sistema que respaldar, restaurar y securizar.
- Transacciones que abarcan dominio + outbox + auditoría.
- Menos superficie de ataque y menos configuración en air-gap.

**Negativas**
- La BD es punto único de fallo (mitigado con réplica y backups probados).
- `sync` requiere threadpool y límites de pool cuidados.
- FTS y vectores tienen techo (documentado y con plan de migración).

**Métricas de reversión**
- Búsqueda p95 >1 s sostenido a 5M eventos → evaluar OpenSearch.
- RAG >500 ms con 200k chunks → evaluar pgvector/Qdrant.
- CPU de BD >80% con 16 vCPU → particionar por org o escalar verticalmente.

## Verificación

`test_migrations.py`; `EXPLAIN` de consultas críticas; bench de ingesta y búsqueda; `test_health.py` con BD caída.
