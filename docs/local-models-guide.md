# GUÍA DE MODELOS LOCALES

- **Documento:** `docs/local-models-guide.md`
- **Estado:** `APPROVED` v1.0
- **Arquitectura:** `specs/architecture/ai-architecture.md`, `ADR-010`
- **Principio:** la IA es asistiva y opcional. Sin modelo, el producto funciona y lo dice.

---

## 1. QUÉ HACE LA IA EN HISPANSHIELD

| Función | Sin IA | Con IA local |
| :--- | :--- | :--- |
| Detección | ✅ Reglas deterministas | ✅ Igual (la IA no detecta por sí sola) |
| Autonomía | ✅ Política determinista | ✅ Igual (la IA no decide) |
| Resumen de incidente | Manual | Borrador asistido con citas |
| Explicación de regla | Documentación | Asistente con RAG |
| Búsqueda semántica | FTS | RAG sobre documentos |
| Borrador de informe | Plantilla | Borrador asistido |
| Triaje sugerido | Prioridad calculada | Sugerencia adicional |

**Nunca:** la IA no aprueba, no ejecuta, no autoriza y no inventa datos. Si no hay contexto, responde "no hay evidencia suficiente".

---

## 2. REQUISITOS DE HARDWARE

| Escenario | CPU | RAM | GPU | Modelo típico | Latencia |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Sin IA | 8 vCPU | 16 GB | — | — | — |
| Resumen/triaje CPU | 8 vCPU | 32 GB | — | 7-8B Q4 | 3-8 s |
| Asistencia fluida CPU | 16 vCPU | 64 GB | — | 3-4B Q5 | 2-4 s |
| GPU recomendada | 16 vCPU | 64 GB | 12-16 GB VRAM | 8B Q5 / 13B Q4 | <2 s |
| GPU alta | 32 vCPU | 128 GB | 24 GB+ VRAM | 13-32B | <1.5 s |

**Embeddings:** CPU suficiente para lotes pequeños (≤300 ms/consulta con 200k chunks). GPU acelera la indexación.

---

## 3. OPCIONES DE DESPLIEGUE

### 3.1 Ollama (recomendado para air-gap)

```bash
# Instalación (en máquina con red, antes del air-gap)
curl -fsSL https://ollama.com/install.sh | sh

# Modelo de chat
ollama pull llama3.1:8b-instruct-q5_K_M
# Modelo de embeddings
ollama pull nomic-embed-text

# Verificación
curl -s http://127.0.0.1:11434/api/tags | jq
```

**Air-gap:** copiar `~/.ollama/models` al destino y arrancar con `OLLAMA_MODELS=/var/lib/ollama/models`. Verificar hashes de los blobs.

### 3.2 vLLM (OpenAI-compatible, GPU)

```bash
python -m vllm.entrypoints.openai.api_server \
  --model /models/Mistral-7B-Instruct-v0.3 \
  --served-model-name mistral-7b \
  --max-model-len 32768 \
  --port 8001
```

### 3.3 Proveedor externo (opt-in)

Solo con habilitación explícita del `owner`, región permitida y DPA. La UI muestra advertencia y cada llamada se audita. Bloqueado si `data_region='eu'` y no hay `external_ai_opt_in`.

---

## 4. CONFIGURACIÓN EN HISPANSHIELD

```bash
HISPANSHIELD_AI_PROVIDER=ollama
HISPANSHIELD_AI_BASE_URL=http://127.0.0.1:11434
HISPANSHIELD_AI_CHAT_MODEL=llama3.1:8b-instruct-q5_K_M
HISPANSHIELD_AI_EMBED_MODEL=nomic-embed-text
HISPANSHIELD_AI_EMBED_DIM=768
HISPANSHIELD_AI_DAILY_TOKEN_BUDGET=2000000
HISPANSHIELD_RAG_MAX_CHUNKS=200000
```

O por UI: `/ai/models` → registrar proveedor → probar → asignar perfiles (`fast`, `balanced`, `deep`, `embed`).

---

## 5. SELECCIÓN DE MODELO

| Perfil | Requisito | Candidatos |
| :--- | :--- | :--- |
| `fast` | Baja latencia, contexto ≥8k | Llama 3.2 3B, Qwen2.5 3B |
| `balanced` | Contexto ≥32k, tool-calls | Llama 3.1 8B, Mistral 7B Instruct, Qwen2.5 7B |
| `deep` | Contexto ≥64k, razonamiento | Qwen2.5 14B/32B, Mixtral 8x7B (si hardware) |
| `embed` | Dimensión fija, multilingüe | nomic-embed-text (768), bge-m3 (1024) |

**Criterios:** licencia permisiva, soporte español, tool-calling fiable, tamaño compatible con hardware, y evaluación con el corpus interno.

---

## 6. EVALUACIÓN OBLIGATORIA ANTES DE CAMBIAR DE MODELO

```bash
python -m app.services.model_eval --provider ollama --model <nuevo> --suite smoke
```

| Suite | Casos | Criterio |
| :--- | :--- | :--- |
| `smoke` | 20 preguntas con contexto | ≥80% correctas con cita |
| `citations` | 10 consultas RAG | 100% citas válidas |
| `refusal` | 5 preguntas sin contexto | 100% "no hay evidencia" |
| `injection` | 10 prompts maliciosos | 0 tool-calls, 0 fuga |
| `latency` | 20 llamadas | p95 dentro del SLO |

Sin `eval_run` registrado → `409 eval_required` al activar el modelo.

---

## 7. RAG: DOCUMENTOS

| Aspecto | Regla |
| :--- | :--- |
| Formatos | PDF, TXT, MD, HTML (extracción de texto) |
| Tamaño | ≤10 MB por documento |
| Chunking | ≈800 tokens, overlap 80 |
| Metadatos | título, versión, clasificación, propietario |
| Borrado | Elimina chunks y reindexa; auditoría |
| Límite | 200k chunks por organización |

**Calidad:** documentos actualizados y con estructura clara; evitar PDFs escaneados sin OCR (no soportado en 1.0).

---

## 8. PROBLEMAS FRECUENTES

| Síntoma | Causa | Solución |
| :--- | :--- | :--- |
| `503 ai_unavailable` | Proveedor no configurado o caído | Verificar `base_url`, `ollama ps`, `/ai/providers/{id}/test` |
| Respuestas lentas | Modelo demasiado grande para CPU | Usar modelo menor o GPU |
| Respuesta sin citas | Contexto vacío o umbral alto | Revisar documentos indexados y `score` |
| "No hay evidencia suficiente" siempre | Embeddings de otro modelo/dimensión | Reindexar con el modelo actual |
| `422 embedding_dimension_mismatch` | Dimensión distinta | Reindexar; no mezclar modelos |
| `429 ai_budget_exceeded` | Presupuesto agotado | Ajustar límite o usar modelo local |
| Fuga de secreto en log | Redacción no aplicada | Revisar `guardrails` y patrón; incidente |
| Modelo responde en otro idioma | Prompt/system | Ajustar instrucción; evaluar modelo con mejor español |

---

## 9. SEGURIDAD

1. El modelo no tiene credenciales de acción.
2. Los documentos se marcan como contenido no confiable.
3. Los secretos se redactan antes de cualquier envío externo.
4. Los modelos se verifican por hash antes de cargar.
5. Sin descarga de modelos en runtime en air-gap.
6. Todo run se registra con proveedor, modelo, tokens y coste.

---

## 10. CHECKLIST

- [ ] Hardware dimensionado.
- [ ] Modelo descargado y verificado por hash.
- [ ] Proveedor registrado y `test` exitoso.
- [ ] Perfiles asignados.
- [ ] Embeddings con dimensión correcta.
- [ ] Documentos indexados y citas verificadas.
- [ ] Evaluación `smoke` superada.
- [ ] Presupuesto configurado.
- [ ] Estado `UNAVAILABLE` probado (detener el modelo y verificar la UI).
