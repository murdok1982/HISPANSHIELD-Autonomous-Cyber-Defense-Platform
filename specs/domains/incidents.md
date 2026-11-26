# DOMINIO: GESTIÓN DE INCIDENTES

- **Código:** `INC`
- **Ruta de implementación:** `backend/app/models/incidents.py`, `backend/app/services/{incidents,incident_timeline,evidence}.py`, `backend/app/api/v1/incidents.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-55..AC-58`, `AC-60`

---

## 1. OBJETIVO

Gestionar el ciclo de vida completo de un incidente de seguridad —desde la detección hasta el cierre y el informe— con severidad justificada, SLA medible, timeline inmutable, evidencias íntegras y trazabilidad de las acciones humanas y autónomas ejecutadas durante la respuesta.

## 2. CONTEXTO

Una alerta es un hecho técnico; un incidente es una unidad de gestión con impacto, responsables y plazos. La plataforma debe permitir que un turno pequeño trabaje con claridad, que el CISO vea cumplimiento de SLA, y que un auditor reconstruya qué pasó, quién lo decidió y qué se ejecutó. El timeline es la fuente de verdad narrativa; las acciones autónomas se insertan automáticamente, no se transcriben a mano.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-INC-001` | Creación | Desde alerta (`promote`), desde correlación, o manual. Campos: `title`, `summary`, `severity`, `category`, `asset_ids[]`, `alert_ids[]`, `assignee`, `watchers[]`. |
| `REQ-INC-002` | Severidad | Matriz: impacto (`low/medium/high/critical`) × urgencia (`low/medium/high/critical`) → `P1..P5`. Ajuste por criticidad del activo y datos personales afectados. Cambio requiere `reason`. |
| `REQ-INC-003` | Estados | `new → triage → contained → eradicated → recovered → closed`; `reopened` desde `closed` con motivo; `merged_into` al fusionar. |
| `REQ-INC-004` | Timeline | Entradas tipadas (`created`, `state_changed`, `comment`, `evidence_added`, `action_executed`, `escalated`, `sla_warning`) inmutables, con `at`, `actor`, `detail`. |
| `REQ-INC-005` | SLA | `sla_response_at`, `sla_resolve_at` por severidad (P1 15 min/4 h; P2 30 min/8 h; P3 4 h/3 d; P4 1 d/10 d; P5 5 d/30 d). Alertas al 75% y 100%; `sla_breached` persistido. |
| `REQ-INC-006` | Evidencias | Adjuntos ≤50 MB, MIME validado por magic bytes, SHA-256, autor, descripción; descarga auditada; integridad verificable. |
| `REQ-INC-007` | Acciones | Las acciones autónomas/playbooks vinculadas se reflejan con `action_id`, estado y resultado, sin edición manual. |
| `REQ-INC-008` | Merge/split | Fusionar conserva timeline y evidencias con referencia al incidente origen; dividir crea nuevo incidente y mueve entradas seleccionadas dejando rastro. |
| `REQ-INC-009` | Informe | Al cerrar (o bajo demanda) genera informe con resumen, timeline, evidencias, acciones, MTTR/MTTD, causa raíz y recomendaciones; hash de contenido. |
| `REQ-INC-010` | Notificación | Marca `nis2_notifiable` y `gdpr_personal_data` para alimentar el tracker de cumplimiento. |

## 4. REQUISITOS NO FUNCTIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-INC-01` | Listado de incidentes p95 <300 ms con 50k incidentes. |
| `NFR-INC-02` | Timeline de 5.000 entradas carga paginada ≤1 s. |
| `NFR-INC-03` | Subida de evidencia de 50 MB ≤10 s en red local. |
| `NFR-INC-04` | Job de SLA cada minuto, sin duplicar notificaciones. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `siem` (alertas) | Dominio | Origen |
| `assets` | Dominio | Impacto |
| `autonomy`/`soar` | Dominio | Acciones ejecutadas |
| `compliance` | Dominio | NIS2/GDPR |
| `forensics` | Dominio | Caso y legal hold |
| `evidence` storage | Plataforma | Volumen con permisos 0600 |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET/POST | `/api/v1/incidents` | `viewer`+ / `responder`+ | `IncidentCreate` | `200/201` |
| GET/PATCH | `/api/v1/incidents/{id}` | `viewer`+ / `responder`+ | `IncidentUpdate` | `200` |
| POST | `/api/v1/incidents/{id}/state` | `responder`+ | `{state, reason?}` | `200` |
| POST | `/api/v1/incidents/{id}/timeline` | `responder`+ | `{type, detail}` | `201` |
| GET | `/api/v1/incidents/{id}/timeline` | `viewer`+ | `?cursor` | `200` |
| POST | `/api/v1/incidents/{id}/evidence` | `responder`+ | multipart | `201 {evidence}` |
| GET | `/api/v1/evidence/{id}` | `responder`+ | — | `200` binario + `X-Content-SHA256` |
| POST | `/api/v1/incidents/{id}/merge` | `admin`+ | `{source_ids[]}` | `200` |
| POST | `/api/v1/incidents/{id}/split` | `admin`+ | `{timeline_ids[], title, severity}` | `201` |
| POST | `/api/v1/incidents/{id}/report` | `responder`+ | `{format}` | `202 {report_id}` |
| GET | `/api/v1/incidents/{id}/metrics` | `viewer`+ | — | `200 {mttd,mttr,sla}` |

**Transiciones permitidas:**
```text
new → triage
triage → contained | closed(false_positive)
contained → eradicated | triage
eradicated → recovered | contained
recovered → closed
closed → reopened (reason required)
any → merged_into (via merge)
```

## 7. CASOS DE USO

1. **Ransomware en servidor crítico:** alerta P1 → incidente P1 → contención autónoma A3 verificada → erradicación manual → recuperación → informe con MTTR.
2. **Falso positivo:** el analista cierra como `false_positive` con motivo; la regla se marca para revisión.
3. **Incidente multi-activo:** se vinculan 4 activos y 12 alertas; el timeline muestra el orden real.
4. **Notificación NIS2:** se marca `nis2_notifiable`; el tracker crea hitos de 24 h/72 h/1 mes.
5. **Auditoría:** el auditor reconstruye el incidente y verifica que cada acción tiene `decision_id` y resultado.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| `closed → triage` sin `reopen` | `409 invalid_transition` |
| Cerrar con evidencias pendientes de subida | `409 uploads_pending` |
| Evidencia con MIME falso (`.exe` como `.pdf`) | `415 unsupported_media_type` |
| Evidencia >50 MB | `413 payload_too_large` |
| Descarga por `viewer` | `403` + auditoría de intento |
| Merge de incidentes de distinta org | `404` |
| Split sin entradas seleccionadas | `422 empty_selection` |
| Cambio de severidad sin motivo | `422 reason_required` |
| SLA vencido y luego cerrado | `sla_breached=true` se conserva |
| Informe de incidente abierto | `409 incident_not_closed` (salvo `force` con rol `admin`) |
| Evidencia alterada en disco | `409 evidence_integrity_failed` + cuarentena |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Manipulación del relato | Editar timeline | Append-only; corrección por entrada nueva, no por edición |
| Evidencia falsa | Subida de fichero manipulado | SHA-256, autor, cadena de custodia, verificación |
| Fuga de evidencias | Descarga sin permiso | RBAC, auditoría, nombres UUID, almacenamiento fuera de webroot |
| Cierre prematuro | Presión operativa | Motivo obligatorio, SLA conservado, revisión por `auditor` |
| Borrado de incidente | Limpiar rastro | No hay `DELETE`; solo `closed` y retención con legal hold |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-55` | Severidad P1 y SLA calculados | `backend/tests/unit/test_incident_severity.py` |
| `AC-56` | Máquina de estados + timeline | `backend/tests/integration/test_incident_state_machine.py` |
| `AC-57` | Evidencia con hash e integridad | `backend/tests/security/test_evidence_integrity.py` |
| `AC-58` | Acceso a evidencia restringido | `backend/tests/security/test_evidence_access.py` |
| `AC-60` | Informe con MTTR y hash | `backend/tests/integration/test_incident_report.py` |
| `AC-INC-05` | Merge preserva timeline | `backend/tests/integration/test_incident_merge.py` |
| `AC-INC-06` | SLA breach detectado | `backend/tests/integration/test_incident_sla.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** matriz de severidad, transiciones, cálculo de SLA/MTTR.
- **Integración:** creación desde alerta, timeline, evidencias, merge/split, informe, notificaciones.
- **Seguridad:** acceso a evidencias, integridad, aislamiento, límites de subida.
- **E2E:** `/incidents` completo con estados y permisos.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_incident_*.py tests/security/test_evidence_*.py`.
2. Timeline exportado de un incidente de laboratorio.
3. Manifiesto SHA-256 de evidencias.
4. Informe generado con hash y verificación.
5. Test de transición inválida (`409`).
