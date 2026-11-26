# DOMINIO: GESTIÓN DE VULNERABILIDADES

- **Código:** `VUL`
- **Ruta de implementación:** `backend/app/models/vulnerabilities.py`, `backend/app/services/{vulnerabilities,scoring,risk_exceptions}.py`, `backend/app/integrations/vuln_importers/`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-27..AC-32`

---

## 1. OBJETIVO

Convertir hallazgos heterogéneos de múltiples escáneres en una cartera priorizada, deduplicada y explicable, con SLA por severidad, estado auditable y excepciones controladas, de modo que el equipo remedie primero lo que realmente reduce riesgo.

## 2. CONTEXTO

Un mismo CVE puede llegar desde Nessus, OpenVAS, Trivy y un conector cloud con IDs distintos. Sin dedupe, el operador ve 4 hallazgos donde hay 1. Sin scoring contextual, prioriza por CVSS bruto e ignora criticidad del activo, exposición y explotación activa (KEV/EPSS). Este dominio resuelve ambas cosas y produce una decisión defendible ante auditoría: por qué P0 y por qué 24 horas.

El scoring es **determinista y versionado**: mismo input + misma versión de fórmula ⇒ mismo output. Se expone el desglose para que el analista pueda discutirlo, no solo aceptarlo.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-VUL-001` | Ingesta | `vulnerability` (catálogo CVE/CWE) + `vulnerability_instance` (activo, puerto, evidencia, fuente). Campos: `cve_id`, `cvss_base`, `cvss_vector`, `cwe_ids[]`, `kev bool`, `epss numeric(5,4)`, `severity`, `title`, `description`, `remediation`. |
| `REQ-VUL-002` | Dedupe | Fingerprint `sha256(org|asset_id|cve_id|port|protocol|normalized_title)`. Si existe: actualiza `last_seen`, añade `source`, conserva estado. |
| `REQ-VUL-003` | Scoring | `risk_score = clamp(0..100, 100 * (0.35*n_cvss + 0.20*n_kev + 0.15*n_epss + 0.20*n_exposure + 0.10*n_criticality) - penalty_controls)`. Versión `scoring_v1`; `score_breakdown` con cada factor, peso y valor. |
| `REQ-VUL-004` | Prioridad y SLA | P0 `≥85` → 24 h; P1 `70..84` → 72 h; P2 `50..69` → 14 d; P3 `25..49` → 30 d; P4 `<25` → 90 d. `sla_due_at = detected_at + plazo`. |
| `REQ-VUL-005` | Estados | `open → triaged → in_progress → fixed → verified → closed`; `open ↔ reopened`; `false_positive` y `risk_accepted` como terminales condicionados. Transiciones validadas. |
| `REQ-VUL-006` | Excepciones | `risk_acceptance` con `justification ≥40`, `approved_by` distinto del solicitante, `expires_at ≤365 d`, `compensating_controls[]`; job revierte a `open` al caducar y notifica. |
| `REQ-VUL-007` | Importadores | Nessus (`.nessus` XML), OpenVAS (XML/JSON), Trivy (JSON). Normalizan a `vulnerability_instance`; `207` con `imported/skipped/failed`. |
| `REQ-VUL-008` | Falso positivo | Requiere `evidence_id` (captura, salida de escáner, ticket) y `reviewed_by`; sin evidencia → `422`. |
| `REQ-VUL-009` | Reapertura | `fixed → reopened` exige `reason` y nueva observación (fecha > `resolved_at`). |
| `REQ-VUL-010` | Exportación | CSV/JSON con filtros y `score_breakdown`; auditoría de exportación. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-VUL-01` | Ingesta de 20.000 hallazgos ≤ 90 s con dedupe. |
| `NFR-VUL-02` | Recálculo de scores de 50k instancias ≤ 120 s, idempotente. |
| `NFR-VUL-03` | Listado priorizado p95 < 350 ms con 100k instancias. |
| `NFR-VUL-04` | Job de caducidad de excepciones cada hora con auditoría. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `assets` | Dominio | Criticidad y exposición |
| `attack-surface` | Dominio | `exposed=true` |
| `threat-intelligence` | Dominio | KEV/EPSS y actores |
| `incidents` | Dominio | Vinculación de explotación |
| `evidence` | Dominio | Falsos positivos y aceptaciones |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET | `/api/v1/vulnerabilities` | `viewer`+ | `?severity&status&priority&asset_id&sla_breached&cursor` | `200 {data[],meta}` |
| GET | `/api/v1/vulnerabilities/{id}` | `viewer`+ | — | `200 {instance, asset, score_breakdown, timeline}` |
| PATCH | `/api/v1/vulnerabilities/{id}/status` | `responder`+ | `{status, reason?, evidence_id?, resolved_at?}` | `200` |
| PATCH | `/api/v1/vulnerabilities/{id}/assignee` | `responder`+ | `{assignee}` | `200` |
| POST | `/api/v1/vulnerabilities/{id}/exception` | `admin`+ | `{justification, expires_at, compensating_controls[]}` | `201` |
| POST | `/api/v1/vulnerabilities/{id}/false-positive` | `analyst`+ | `{evidence_id, reason}` | `200` |
| POST | `/api/v1/vulnerabilities/import` | `analyst`+ | multipart + `?source=` | `207` |
| GET | `/api/v1/vulnerabilities/export` | `analyst`+ | filtros + `format` | `200` |
| GET | `/api/v1/vulnerabilities/stats` | `viewer`+ | — | `200 {by_severity, by_status, sla_compliance, trend_30d}` |

**`score_breakdown` (ejemplo):**
```json
{
  "formula_version": "scoring_v1",
  "risk_score": 100,
  "priority": "P0",
  "factors": [
    {"name": "cvss", "raw": 10.0, "normalized": 1.0, "weight": 0.35, "contribution": 35.0},
    {"name": "kev", "raw": true, "normalized": 1.0, "weight": 0.20, "contribution": 20.0},
    {"name": "epss", "raw": 0.94, "normalized": 0.94, "weight": 0.15, "contribution": 14.1},
    {"name": "exposure", "raw": "internet", "normalized": 1.0, "weight": 0.20, "contribution": 20.0},
    {"name": "criticality", "raw": 5, "normalized": 1.0, "weight": 0.10, "contribution": 10.0}
  ],
  "penalties": [{"name": "compensating_control", "value": 0, "reason": "none_applied"}],
  "sla_hours": 24,
  "computed_at": "2026-11-26T10:00:00Z"
}
```

## 7. CASOS DE USO

1. **Priorización diaria:** el jefe de SOC abre la vista ordenada por `risk_score`; ve 3 P0 con KEV y exposición a Internet; asigna y sigue el SLA.
2. **Dedupe multi-escáner:** Nessus y Trivy reportan la misma CVE en el mismo contenedor; aparece una sola instancia con `sources: ["nessus","trivy"]`.
3. **Aceptación de riesgo:** un servidor legacy no puede parchearse; el `admin` acepta el riesgo 90 días con control compensatorio (WAF) y justificación; al caducar vuelve a `open`.
4. **Falso positivo:** una regla de escáner reporta una CVE inexistente en la versión instalada; el analista adjunta evidencia y lo marca; el estado queda auditado.
5. **Explotación real:** un incidente confirma explotación de una CVE; el sistema eleva prioridad a P0 y enlaza incidente ↔ vulnerabilidad.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| `cvss_base` fuera de 0..10 | `422`, campo `cvss_base` |
| CVE con formato inválido | `422`, campo `cve_id` (patrón `^CVE-\d{4}-\d{4,7}$`) |
| Mismo fingerprint con distinta severidad de fuente | Prevalece la mayor; se guarda `source_severities[]` |
| `fixed` sin `resolved_at` | `422 resolved_at_required` |
| `resolved_at` futuro | `422 invalid_resolved_at` |
| `fixed → closed` sin verificación | `409 verification_required` (rol `responder` confirma) |
| Excepción con `expires_at` >365 d | `422 max_exception_365d` |
| Excepción autoaprobada por el solicitante | `403 separation_of_duties` |
| Falso positivo sin evidencia | `422 evidence_required` |
| Reapertura sin nueva observación | `409 no_new_evidence` |
| Import de fichero corrupto | `422 parse_error` con línea y causa; nada parcialmente escrito |
| SLA ya vencido en la creación | Se marca `sla_breached=true` y se alerta |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Ocultación de vulnerabilidades | Bajar criticidad o aceptar riesgo masivamente | Auditoría, límite de excepciones por org/día, alerta si >10% aceptadas |
| Manipulación de scoring | Cambiar fórmula sin control | Fórmula versionada, cambio requiere ADR + test de regresión |
| Ingesta maliciosa | Fichero de escáner con XML externo | Parser seguro, XXE deshabilitado, tamaño límite |
| Fuga de inventario de fallos | Export sin permiso | RBAC + auditoría de export |
| Fatiga de excepciones | Aceptaciones permanentes | Caducidad máxima 365 d, revisión obligatoria |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-27` | Scoring P0 con breakdown y SLA 24 h | `backend/tests/unit/test_risk_scoring.py::test_known_exploited_internet_facing` |
| `AC-28` | Dedupe multi-fuente | `backend/tests/integration/test_vuln_dedupe.py` |
| `AC-29` | Máquina de estados | `backend/tests/unit/test_vuln_state_machine.py` |
| `AC-30` | Excepción con justificación y caducidad | `backend/tests/integration/test_risk_acceptance.py` |
| `AC-31` | Importadores normalizan | `backend/tests/integration/test_vuln_importers.py` |
| `AC-32` | Falso positivo exige evidencia | `backend/tests/integration/test_vuln_false_positive.py` |
| `AC-VUL-07` | Caducidad revierte a `open` | `backend/tests/integration/test_risk_acceptance.py::test_expiry_reopens` |

## 11. ESTRATEGIA DE TEST

- **Unit:** fórmula con casos tabla (cvss, kev, epss, exposición, criticidad, penalizaciones), máquina de estados.
- **Integración:** dedupe, importadores con fixtures reales anonimizados, excepciones, job de caducidad, enlace a activo/incidente.
- **Rendimiento:** 100k instancias, listado y recálculo.
- **E2E:** `/vulnerabilities` con breakdown, SLA y excepción.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/unit/test_risk_scoring.py tests/integration/test_vuln_*.py`.
2. Tabla de casos del scoring con `expected` vs `actual`.
3. Fixtures `.nessus`, OpenVAS y Trivy con salida `207`.
4. Log del job de caducidad revirtiendo una excepción.
5. `EXPLAIN` del listado priorizado.
