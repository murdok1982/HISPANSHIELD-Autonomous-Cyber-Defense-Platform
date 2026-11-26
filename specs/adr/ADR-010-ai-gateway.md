# ADR-010: AI gateway local-first con estado honesto

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-005`, `specs/architecture/ai-architecture.md`, `specs/security/autonomy-policy.md`

## Contexto

La IA aporta valor en triaje, resumen, explicación y borradores. Pero el producto se despliega en organismos donde enviar telemetría a un proveedor externo puede ser ilegal o inaceptable, y en el entorno de verificación no hay ningún LLM en ejecución. Además, un modelo que "alucina" una acción o un dato es un riesgo operativo.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Solo cloud (OpenAI/Azure) | Calidad, cero operación | Soberanía, coste, dependencia, air-gap imposible |
| Solo local obligatorio | Soberanía | Requiere GPU; instalación más pesada |
| Sin IA | Simplicidad | Pierde diferenciación y asistencia |
| **Gateway multi-proveedor local-first (elegido)** | Soberanía por defecto, flexibilidad, funciona sin IA | Complejidad de abstracción y de evaluación |

## Decisión

`AIProvider` con implementaciones `ollama`, `vllm_openai_compat` y `openai_compat` (opt-in). Router por perfil con fallback, presupuesto por org/run, RAG con citas, agentes durables, MCP con allowlist, guardrails anti prompt-injection. **Sin proveedor → `503 ai_unavailable`**, nunca contenido fabricado. La IA no tiene autoridad de acción.

## Consecuencias

**Positivas**
- Despliegue air-gapped plenamente funcional (con o sin IA).
- El cliente decide dónde infiere; se audita.
- La ausencia de IA no degrada detección, autonomía ni cumplimiento.
- El modelo no puede ejecutar: el riesgo de prompt injection se acota al broker.

**Negativas**
- La calidad depende del modelo local disponible.
- Mantener adaptadores y evaluaciones por modelo.
- La evaluación de cambios de modelo añade proceso (`eval gate`).

**Métricas de reversión**
- Si el 80% de las instalaciones no configura IA, simplificar la superficie (mantener RAG y desactivar agentes).
- Si un proveedor externo se vuelve requisito contractual, habilitar opt-in con DPA y control de región (ya soportado).

## Verificación

`test_ai_unavailable.py`, `test_ai_routing.py`, `test_rag_citations.py`, `test_prompt_injection.py`, `test_ai_budget.py`, `test_model_eval_gate.py`.
