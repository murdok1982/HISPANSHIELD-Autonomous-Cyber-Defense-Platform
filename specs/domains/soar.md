# DOMINIO: SOAR (PLAYBOOKS Y EJECUCIONES DURABLES)

- **Código:** `SOAR`
- **Ruta de implementación:** `backend/app/workflow/`, `backend/app/models/playbooks.py`, `backend/app/services/{playbooks,executions,approvals}.py`, `backend/app/api/v1/{playbooks,executions,approvals}.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-43..AC-49`

---

## 1. OBJETIVO

Automatizar la respuesta con playbooks explícitos, versionados y durables, que sobrevivan a reinicios, respeten aprobaciones humanas, puedan revertirse y nunca ejecuten efectos laterales en simulación.

## 2. CONTEXTO

Un SOAR sin durabilidad es un script: si el worker muere a mitad, el estado del mundo queda indeterminado. Un SOAR sin aprobaciones es un riesgo. Un SOAR sin dry-run es imposible de probar. Este dominio resuelve las tres cosas sobre PostgreSQL, sin Temporal, con un motor propio pequeño y auditable (`ADR-004`).

El playbook es un **DAG** de nodos tipados. Cada nodo declara su acción, sus parámetros, su política de reintento, su acción de compensación y, si aplica, su requisito de aprobación. La versión publicada es inmutable.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-SOAR-001` | Modelo | `playbook{id, org, name, description, status, current_version}` + `playbook_version{version, dag JSONB, created_by, published_at, changelog}`. |
| `REQ-SOAR-002` | DAG | Nodos: `trigger`, `action`, `condition`, `approval`, `delay`, `parallel`, `end`. Validación: exactamente un `trigger`, alcanzabilidad, sin ciclos, sin huérfanos, tipos de arista coherentes. |
| `REQ-SOAR-003` | Publicación | `publish` valida DAG + esquemas de parámetros de cada acción contra el catálogo; crea versión inmutable; activa. |
| `REQ-SOAR-004` | Ejecución | `execution{id, org, playbook_version, state, trigger_ref, started_at, finished_at, requested_by, dry_run}`; estados `queued/running/waiting_approval/succeeded/failed/denied/cancelled/rolled_back/halted`. |
| `REQ-SOAR-005` | Durabilidad | Cada paso se persiste en `execution_steps` antes y después; claim por lease 60 s con heartbeat; si expira, otro worker reclama y reanuda desde el último paso `succeeded`. |
| `REQ-SOAR-006` | Idempotencia | `UNIQUE(execution_id, step_key)`; el adaptador recibe `idempotency_key` y debe ser idempotente o declarar lo contrario. |
| `REQ-SOAR-007` | Retry | `max_attempts=3` por defecto; backoff exponencial con jitter; errores `retryable` vs `fatal` clasificados por el adaptador. |
| `REQ-SOAR-008` | Aprobaciones | Nodo `approval` con `approvers[]` (roles o usuarios), `timeout_minutes` (default 60), `require_all` (default false), `on_deny` branch. Timeout → `denied`. |
| `REQ-SOAR-009` | Compensación | Cada `action` declara `compensate` (acción inversa + parámetros); al fallar, se ejecutan en LIFO las compensaciones de pasos `succeeded`. Idempotentes. |
| `REQ-SOAR-010` | Dry-run | `dry_run=true` recorre el DAG, evalúa condiciones y registra `would_execute`, sin invocar adaptadores (contador de llamadas = 0). |
| `REQ-SOAR-011` | Concurrencia | `max_concurrent_executions` por org (default 20, configurable ≤50); excedente `queued` con posición. |
| `REQ-SOAR-012` | Timeline | Cada transición y paso genera evento inmutable con `at`, `actor`, `state`, `detail`; consultable y exportable. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-SOAR-01` | Reanudación tras crash en ≤60 s desde el reinicio del worker. |
| `NFR-SOAR-02` | Overhead del motor ≤50 ms por paso (sin contar la acción). |
| `NFR-SOAR-03` | 200 ejecuciones concurrentes en un nodo sin corrupción de estado. |
| `NFR-SOAR-04` | Ninguna ejecución queda en `running` sin lease activo >5 min (job de reconciliación). |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `autonomy` | Dominio | Toda acción pasa por política antes de ejecutarse |
| `connectors` | Integración | Adaptadores y capacidades |
| `incidents` | Dominio | Trigger `incident.created`, resultados en timeline |
| `core/events.py` | Interna | `execution.*` para SSE |
| `core/audit.py` | Interna | Auditoría de ejecución y aprobación |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET/POST | `/api/v1/playbooks` | `analyst`+ | `PlaybookCreate` | `200/201` |
| GET/PATCH | `/api/v1/playbooks/{id}` | `analyst`+ | `PlaybookUpdate` | `200` |
| POST | `/api/v1/playbooks/{id}/versions` | `admin`+ | `{dag, changelog}` | `201 {version}` |
| POST | `/api/v1/playbooks/{id}/publish` | `admin`+ | `{version}` | `200` |
| POST | `/api/v1/playbooks/{id}/validate` | `analyst`+ | `{dag}` | `200 {valid, errors[]}` |
| POST | `/api/v1/playbooks/{id}/execute` | `responder`+ | `{input, dry_run, incident_id?}` | `202 {execution_id}` |
| GET | `/api/v1/executions` | `responder`+ | `?state&playbook_id&cursor` | `200` |
| GET | `/api/v1/executions/{id}` | `responder`+ | — | `200 {execution, steps[], approvals[]}` |
| POST | `/api/v1/executions/{id}/cancel` | `responder`+ | `{reason}` | `202` |
| POST | `/api/v1/executions/{id}/compensate` | `responder`+ | `{reason}` | `202` |
| GET | `/api/v1/approvals` | `admin`+ | `?status` | `200` |
| POST | `/api/v1/approvals/{id}/decide` | `admin`+ | `{decision: approve|deny, comment?}` | `200` |

**DAG (ejemplo abreviado):**
```json
{
  "nodes": [
    {"id": "t1", "type": "trigger", "on": "alert.created", "filter": {"severity_gte": 3}},
    {"id": "a1", "type": "action", "action": "block_ip", "params": {"ip": "$trigger.src_ip", "duration_minutes": 60},
     "retry": {"max_attempts": 3, "retryable": ["timeout", "5xx"]},
     "compensate": {"action": "unblock_ip", "params": {"ip": "$trigger.src_ip"}}},
    {"id": "ap1", "type": "approval", "approvers": ["role:admin"], "timeout_minutes": 30, "on_deny": "end"},
    {"id": "a2", "type": "action", "action": "create_ticket", "params": {"title": "$incident.title"}},
    {"id": "e1", "type": "end"}
  ],
  "edges": [{"from": "t1", "to": "a1"}, {"from": "a1", "to": "ap1"}, {"from": "ap1", "to": "a2"}, {"from": "a2", "to": "e1"}]
}
```

## 7. CASOS DE USO

1. **Contención con aprobación:** alerta P1 → playbook `contain_host` → nodo approval a `admin` → aislamiento → ticket. Si nadie aprueba en 30 min, `denied` y se notifica.
2. **Crash del worker:** la ejecución está en el paso 3; el worker muere; otro reclama el lease y continúa sin repetir el bloqueo de IP (idempotencia).
3. **Fallo con rollback:** se deshabilita un usuario y falla el aislamiento del host; se rehabilita el usuario y el estado final es `rolled_back`.
4. **Dry-run en diseño:** el ingeniero prueba un playbook nuevo contra un incidente histórico; ve `would_execute` sin tocar producción.
5. **Compensación manual:** un operador decide revertir una contención exitosa porque fue un falso positivo; `POST /compensate` ejecuta las inversas.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| DAG con dos triggers | `422 multiple_triggers` |
| Nodo inalcanzable | `422 unreachable_nodes` con IDs |
| Ciclo | `422 dag_cycle` con la ruta |
| Acción no existe en catálogo | `422 unknown_action` |
| Parámetro requerido ausente | `422 missing_param` con `node_id` y `param` |
| Ejecutar versión `draft` | `409 version_not_published` |
| Ejecución con org suspendida | `403 organization_suspended` |
| Aprobar dos veces | `409 already_decided` |
| Aprobar propia solicitud (mismo usuario, único aprobador) | `403 separation_of_duties` |
| Cancelar ejecución `succeeded` | `409 invalid_state` |
| Compensar sin pasos compensables | `409 nothing_to_compensate` |
| Worker muere con lease activo | Reconciliación a los 5 min; reanuda |
| Acción tarda más que el timeout del paso | `fatal timeout`, compensación |
| Dry-run con nodo approval | Se auto-simula `approved` y se registra `simulated` |
| Límite de concurrencia alcanzado | `queued` con `position`, no error |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Playbook destructivo sin control | Publicar acción peligrosa sin aprobación | Validación exige `approval` para acciones de riesgo alto (`risk_level` del catálogo) |
| Ejecución duplicada | Reintento del cliente | `Idempotency-Key` en execute + `execution_id` único |
| Escalada vía aprobación | Aprobar sin rol | RBAC + separación de funciones |
| Estado inconsistente | Crash a mitad | Persistencia por paso + compensación |
| Abuso de dry-run | Confundir simulación con ejecución real | `dry_run` explícito, UI con banner, auditoría distinta |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-43` | DAG inválido rechazado | `backend/tests/unit/test_playbook_dag.py` |
| `AC-44` | Reanudación tras crash | `backend/tests/integration/test_workflow_resume.py::test_kill_worker_and_resume` |
| `AC-45` | Retry con backoff | `backend/tests/unit/test_retry_policy.py` |
| `AC-46` | Timeout de aprobación → deny | `backend/tests/integration/test_approvals.py::test_timeout_denies` |
| `AC-47` | Compensación LIFO | `backend/tests/integration/test_compensation.py` |
| `AC-48` | Dry-run sin llamadas | `backend/tests/integration/test_dry_run.py` |
| `AC-49` | Límite de concurrencia | `backend/tests/integration/test_concurrency_limits.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** DAG (ciclos, huérfanos, triggers), retry policy, evaluación de condiciones.
- **Integración:** ejecución completa, crash/resume, aprobaciones, compensación, dry-run, concurrencia.
- **Caos:** matar worker en cada paso (parametrizado), doble entrega, lease expirado.
- **E2E:** `/soar` y `/playbooks/designer`.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_workflow_*.py tests/integration/test_compensation.py`.
2. Log de reanudación: paso 1 `succeeded` una sola vez, paso 2 reanudado.
3. Timeline de una ejecución con aprobación y timeout.
4. Prueba de dry-run con contador de llamadas a adaptador = 0.
5. Resultado del test de concurrencia con estados `queued/running`.
