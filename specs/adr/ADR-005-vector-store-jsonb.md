# ADR-005: Vector store en JSONB/`float4[]` con numpy (sin Qdrant)

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-002`, `ADR-010`, `specs/architecture/ai-architecture.md`

## Contexto

El RAG debe buscar sobre documentación operativa (políticas, procedimientos, manuales) por organización. El volumen esperado es de miles a decenas de miles de chunks por organización, no millones. Qdrant/pgvector no están disponibles en el entorno verificado; añadir un servicio vectorial incrementa la superficie y la operación en air-gap.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Qdrant | ANN rápido, filtros, escalado | Servicio extra, otro backup, otra seguridad |
| pgvector | Integrado en PG, ANN | Extensión no garantizada en todas las instalaciones |
| **`float4[]` + numpy (elegido)** | Cero dependencias nuevas, transaccional, simple | O(n) por consulta; memoria |
| Búsqueda léxica solo | Simple | Sin semántica; peor recuperación |

## Decisión

`document_chunks.embedding float4[]` con `dimension` y `organization_id`; búsqueda coseno en proceso con numpy, batch, `top_k ≤20`, filtrada por organización. Abstracción en `ai/vector_store.py` para permitir pgvector/Qdrant sin cambiar contratos.

## Consecuencias

**Positivas**
- Sin servicio adicional; el índice vive en la misma BD y se respalda igual.
- Consistencia transaccional con documentos y chunks.
- Implementación comprensible y auditable.

**Negativas**
- Coste O(n) por consulta; con 200k chunks × 768 dims (~600 MB) se logra ≤300 ms en batch, pero no escala a millones.
- Consumo de memoria en el worker de IA.
- Sin ANN; no hay índice aproximado.

**Límites y reversión**
- Límite duro: 200k chunks/org (`HISPANSHIELD_RAG_MAX_CHUNKS`); al superarlo se rechaza con causa.
- Si p95 >500 ms o se supera el límite de forma recurrente → migrar a pgvector (si está disponible) o Qdrant.
- La interfaz `VectorStore` aísla el cambio; los contratos de API no cambian.

## Verificación

`test_vector_store.py` (dimensión, coseno, orden), `test_rag_citations.py`, bench con 200k chunks, test de aislamiento por org en la búsqueda.
