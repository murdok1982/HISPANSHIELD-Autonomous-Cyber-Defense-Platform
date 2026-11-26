# DOMINIO: AGENTES DE IA Y AI GATEWAY

- **Código:** `AIG`
- **Ruta de implementación:** `backend/app/ai/{providers,router,budget,chat,embeddings,vector_store,documents,rag,guardrails}`, `backend/app/ai/{agents,mcp}`, `backend/app/api/v1/{ai,agents,mcp}.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-61..AC-69`

---

## 1. OBJETIVO

Proporcionar asistencia de IA útil y controlada —triaje, resumen, explicación, búsqueda semántica, generación de reglas y borradores de informe— sobre modelos locales o proveedores aprobados, con citas verificables, presupuesto, aislamiento de contenido no confiable y **cero autoridad** para ejecutar acciones.

## 2. CONTEXTO

En un organismo europeo, enviar telemetría a un proveedor externo puede ser inviable legalmente. Por tanto: local-first (Ollama/vLLM en el perímetro), externo solo con opt-in explícito. En el entorno de verificación no hay LLM: la plataforma debe funcionar y decirlo con honestidad (`503 ai_unavailable`), sin respuestas simuladas.

El riesgo principal no es que el modelo se equivoque: es que un contenido malicioso (correo, documento, alerta) induzca una acción. Por eso el modelo **propone** y el broker de autonomía **decide**, con allowlist de tools y política independiente del texto generado.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-AIG-001` | Proveedores | `ollama`, `vllm_openai_compat`, `openai_compat`; `base_url`, `model`, `api_key_enc`, `timeout`, `max_tokens`, `enabled`, `data_region`. |
| `REQ-AIG-002` | Health | Cada proveedor expone `healthy/degraded/unavailable` con última comprobación y error; `/ai/providers/{id}/test` ejecuta una llamada mínima. |
| `REQ-AIG-003` | Routing | Perfiles `fast`, `balanced`, `deep`; selección por perfil con fallback ordenado; registro de proveedor/modelo usado y `fallback_used`. |
| `REQ-AIG-004` | Presupuesto | Tokens y coste por org/día y por run; al superar → `429 ai_budget_exceeded` con `resets_at`; contabilidad por llamada. |
| `REQ-AIG-005` | Chat | `POST /ai/chat` con `messages[]`, `task_profile`, `context_refs[]`; devuelve `answer`, `citations[]`, `usage`, `provider`, `model`. |
| `REQ-AIG-006` | RAG | Documentos con chunking (tokens), embeddings de dimensión fija, búsqueda coseno por org, `top_k ≤ 20`, citas con `document_id`, `chunk_id`, `score`, `snippet`. |
| `REQ-AIG-007` | Agentes | Definición con `system_prompt_version`, `allowed_tools[]`, `max_steps ≤ 12`, `budget`, `requires_approval_for[]`; runs durables con `step_log`. |
| `REQ-AIG-008` | MCP | Registro de servidores/tools con JSON Schema de entrada/salida y `risk_level`; broker valida allowlist + esquema + política antes de invocar. |
| `REQ-AIG-009` | Guardrails | Detección de instrucciones de override, delimitación de contenido no confiable, prohibición de revelar system prompt, redacción de secretos en logs. |
| `REQ-AIG-010` | Evaluación | Cambio de modelo/proveedor requiere registro de evaluación (`eval_run`) con casos y resultado; sin eval → `409 eval_required`. |
| `REQ-AIG-011` | Honestidad | Sin proveedor habilitado, cualquier endpoint de inferencia devuelve `503 ai_unavailable` con `providers_configured`. Nunca texto de plantilla presentado como IA. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-AIG-01` | Chat: primer token ≤3 s p95 con modelo local en hardware de referencia; timeout total configurable (default 60 s). |
| `NFR-AIG-02` | RAG: búsqueda sobre 200k chunks ≤300 ms (numpy, batch). |
| `NFR-AIG-03` | 0 llamadas a proveedores externos sin opt-in registrado. |
| `NFR-AIG-04` | Coste y tokens contabilizados con error ≤1% respecto al `usage` del proveedor. |
| `NFR-AIG-05` | Un run interrumpido se reanuda sin duplicar tool-calls (`step_key` idempotente). |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `autonomy` | Dominio | Toda tool-call con efecto pasa por política |
| `mcp` registry | Integración | Tools y esquemas |
| `documents` | Plataforma | Almacenamiento y chunking |
| `core/crypto.py` | Interna | Cifrado de API keys |
| `numpy` | Externa | Similitud coseno |
| Ollama/vLLM | Externa opcional | Inferencia local |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET/POST | `/api/v1/ai/providers` | `admin`+ | `ProviderConfig` | `200/201` (sin secreto) |
| POST | `/api/v1/ai/providers/{id}/test` | `admin`+ | — | `200 {state, latency_ms}` / `503` |
| GET | `/api/v1/ai/models` | `admin`+ | — | `200 [{provider, model, profile, context_window, cost}]` |
| POST | `/api/v1/ai/chat` | `analyst`+ | `ChatRequest` | `200 {answer, citations[], usage}` |
| POST | `/api/v1/ai/rag/query` | `analyst`+ | `RagQuery` | `200 {answer, citations[]}` |
| GET/POST | `/api/v1/ai/documents` | `admin`+ | multipart | `200/201` |
| POST | `/api/v1/ai/documents/{id}/reindex` | `admin`+ | — | `202` |
| GET/POST | `/api/v1/agents` | `analyst`+ | `AgentCreate` | `200/201` |
| POST | `/api/v1/agents/{id}/runs` | `analyst`+ | `{input, context_refs[]}` | `202 {run_id}` |
| GET | `/api/v1/agents/{id}/runs/{run_id}` | `analyst`+ | — | `200 {state, steps[], tool_calls[]}` |
| GET/POST | `/api/v1/mcp/servers` | `admin`+ | `McpServerCreate` | `200/201` |
| GET | `/api/v1/mcp/tools` | `admin`+ | — | `200 [{name, schema, risk_level}]` |
| POST | `/api/v1/mcp/tools/{name}/invoke` | `admin`+ | `{input, agent_run_id?}` | `200 {result}` / `403 tool_not_allowed` |

**Respuesta de chat (ejemplo):**
```json
{
  "answer": "El host 10.10.4.12 muestra 3 intentos de RDP fallidos desde 198.51.100.23 en los últimos 10 minutos...",
  "citations": [
    {"document_id": "0192...", "chunk_id": "0192...-03", "score": 0.82, "snippet": "regla rdp_bruteforce ..."},
    {"source": "event", "event_id": "0192...", "score": 1.0}
  ],
  "usage": {"prompt_tokens": 1204, "completion_tokens": 210, "cost_usd": 0.0},
  "provider": "ollama",
  "model": "llama3.1:8b-instruct-q5_K_M",
  "fallback_used": false
}
```

## 7. CASOS DE USO

1. **Triaje asistido:** el analista pide "resume este incidente y sugiere próximos pasos"; recibe resumen con citas a eventos y activos.
2. **Explicación de regla:** pide explicar el DSL de una regla; el agente responde citando la documentación indexada.
3. **Borrador de informe:** genera un borrador de post-incidente a partir del timeline; el humano revisa y firma.
4. **Búsqueda semántica:** "¿qué incidentes implicaron movimiento lateral en OT?" devuelve chunks de informes con score.
5. **Tool con aprobación:** el agente propone `isolate_host`; el broker exige política y aprobación; el LLM no ejecuta nada.
6. **Sin IA:** el operador ve `UNAVAILABLE` y sigue trabajando con reglas y datos deterministas.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| Sin proveedor | `503 ai_unavailable`, `providers_configured: 0` |
| Proveedor timeout | Fallback si existe; si no, `503 ai_timeout` |
| Respuesta del modelo > `max_tokens` | Truncado controlado y `finish_reason=length` |
| Embedding de dimensión incorrecta | `422 embedding_dimension_mismatch` |
| Documento >10 MB | `413 payload_too_large` |
| Documento binario no soportado | `415 unsupported_media_type` |
| Pregunta sin contexto suficiente | Respuesta "no hay evidencia suficiente" + `citations: []` (no invención) |
| Prompt con secreto | Redacción en log y advertencia; no se envía a proveedor externo si `redact_external=true` |
| Presupuesto agotado | `429 ai_budget_exceeded` |
| Tool no permitida | `403 tool_not_allowed`, auditoría del intento |
| Tool input inválido | `422` sin invocar el servidor MCP |
| Run interrumpido | Reanuda desde último paso; `step_key` evita duplicado |
| Modelo cambiado sin eval | `409 eval_required` |
| Prompt injection en documento RAG | Contenido delimitado y marcado `untrusted`; guardrail detecta y bloquea tool-call |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Prompt injection indirecta | Documento/evento con instrucciones | Delimitación, marcado `untrusted`, guardrails, sin autoridad de acción |
| Exfiltración de contexto | Preguntas que extraen system prompt o datos de otra org | Aislamiento por org en RAG, filtro de salida, pruebas de fuga |
| Tool abuse | Modelo invoca tool destructiva | Allowlist + política + aprobación + blast radius |
| Coste descontrolado | Bucle de agente | `max_steps`, presupuesto por run/org, timeout |
| Fuga de API keys | Config o logs | Fernet, `has_secret`, redacción |
| Modelo comprometido | Pesos maliciosos | Procedencia del modelo documentada; eval gate; sin salida a red |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-61` | Sin proveedor → 503 honesto | `backend/tests/integration/test_ai_unavailable.py` |
| `AC-62` | Routing con fallback | `backend/tests/integration/test_ai_routing.py` |
| `AC-63` | RAG con citas verificables | `backend/tests/integration/test_rag_citations.py` |
| `AC-64` | Dimensión validada | `backend/tests/unit/test_vector_store.py` |
| `AC-65` | Prompt injection sin tool-call | `backend/tests/security/test_prompt_injection.py` |
| `AC-66` | MCP allowlist | `backend/tests/security/test_mcp_allowlist.py` |
| `AC-67` | Presupuesto | `backend/tests/integration/test_ai_budget.py` |
| `AC-68` | Redacción en logs | `backend/tests/security/test_ai_log_redaction.py` |
| `AC-69` | Run durable | `backend/tests/integration/test_agent_durability.py` |
| `AC-AIG-10` | Eval gate en cambio de modelo | `backend/tests/integration/test_model_eval_gate.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** chunking, coseno, validación de dimensión, guardrails, parseo de tool-calls.
- **Integración:** provider fake local (servidor HTTP de prueba en tests, no en runtime), routing, presupuesto, RAG, MCP, runs.
- **Seguridad:** corpus de prompt injection (directa, indirecta, exfiltración, role-play, encoding), allowlist, aislamiento RAG.
- **E2E:** `/ai/agents` y `/ai/models` con estado `UNAVAILABLE`.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_ai_*.py tests/security/test_prompt_injection.py tests/security/test_mcp_allowlist.py`.
2. Respuesta `503 ai_unavailable` con `providers_configured: 0`.
3. Respuesta RAG con citas y verificación de que los `chunk_id` existen y coinciden.
4. Informe del corpus de prompt injection (casos, resultado, 0 bypass).
5. `step_log` de un run reanudado.
