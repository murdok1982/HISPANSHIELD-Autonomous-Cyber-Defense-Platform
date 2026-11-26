# DOMINIO: SUPERFICIE DE ATAQUE (ASM)

- **Código:** `ASM`
- **Ruta de implementación:** `backend/app/models/attack_surface.py`, `backend/app/services/{attack_surface,asm_scope,jobs}.py`, `backend/app/integrations/stix.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-22..AC-26`

---

## 1. OBJETIVO

Mantener una imagen actualizada y legalmente acotada de lo que la organización expone a Internet y a redes no confiables (hosts, puertos, servicios, TLS, banners), detectar cambios de exposición y convertir la exposición no autorizada en hallazgos accionables, sin realizar actividades ofensivas.

## 2. CONTEXTO

La superficie de ataque se alimenta de observaciones importadas de escáneres autorizados, de CMDB y de conectores. La plataforma **no escanea por sí misma** en la release 1.0: normaliza, deduplica, compara y evalúa. El guard de alcance es un control legal y operativo: solo se procesan rangos declarados por la organización, y cualquier observación fuera de ellos se rechaza o se marca como no autorizada sin escanear nada.

El valor está en el **diff**: qué apareció, qué cambió (certificado, banner, servicio) y qué debería haberse cerrado y sigue abierto.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-ASM-001` | Observación | `{host, ip, port, protocol(tcp/udp), service, banner_hash, tls{fingerprint,issuer,subject,expires_at}, first_seen, last_seen, status, authorized}`. Dedupe por `(org, ip, port, protocol)`. |
| `REQ-ASM-002` | Importación | CSV/JSON de escáner; normaliza `ip`, `port`, `service`, `tls`; idempotente por clave natural; `207` con contadores. |
| `REQ-ASM-003` | Diff | Comparación con la observación previa: `new` (no existía), `changed` (banner/TLS/servicio), `closed` (no aparece en la nueva importación y supera la ventana de gracia). Se persiste `exposure_diff` con `before/after`. |
| `REQ-ASM-004` | Alcance | La org declara `ranges[]` CIDR; todo `ip` observado se valida contra ellos. Fuera de alcance: `422 target_out_of_scope` en import; si llega por conector, se registra `rejected` y no se crea observación. |
| `REQ-ASM-005` | Autorización | Cada rango tiene `authorized_from`, `authorized_by`, `evidence_ref` (documento de autorización). Sin autorización vigente, las observaciones se marcan `authorized=false` y generan hallazgo. |
| `REQ-ASM-006` | Hallazgo | Exposición no autorizada o servicio de alto riesgo (p.ej. RDP/SMB/DB expuestos) genera `finding` con severidad derivada, enlace a activo si existe y a control de cumplimiento. |
| `REQ-ASM-007` | Export | STIX 2.1 (`infrastructure`, `ipv4-addr`, `x-hispanshield-exposure`) y CSV; round-trip preservando `ip/port/protocol`. |
| `REQ-ASM-008` | Jobs | Descubrimiento/import asíncrono con `Idempotency-Key`; reintentos; estado consultable (`queued/running/succeeded/failed/partial`). |
| `REQ-ASM-009` | Ciclo de vida | Observación `closed` conserva histórico 400 días; `deleted` solo por retención. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-ASM-01` | Import de 50.000 observaciones ≤ 60 s. |
| `NFR-ASM-02` | Diff de 50.000 observaciones ≤ 10 s. |
| `NFR-ASM-03` | Cálculo de alcance con `ipaddress` en memoria, sin resolución DNS externa. |
| `NFR-ASM-04` | Export STIX de 10.000 objetos ≤ 15 s y ≤ 200 MB. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `assets` | Dominio | Enlace por IP/ARN |
| `vulnerabilities` | Dominio | Exposición como factor de riesgo |
| `compliance` | Dominio | Mapeo de exposiciones a controles |
| `core/events.py` | Interna | `exposure.diff_created` |
| `integrations/stix.py` | Integración | Serialización |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET | `/api/v1/attack-surface` | `viewer`+ | `?status&port&service&authorized&cursor` | `200 {data[],meta}` |
| GET | `/api/v1/attack-surface/diffs` | `viewer`+ | `?since&change_type` | `200 {data[],meta}` |
| POST | `/api/v1/attack-surface/import` | `admin`+ | multipart CSV/JSON + `Idempotency-Key` | `207 {created,updated,closed,rejected[]}` |
| POST | `/api/v1/attack-surface/ranges` | `admin`+ | `{cidr, label, authorized_from, authorized_until, evidence_ref}` | `201` |
| GET | `/api/v1/attack-surface/ranges` | `viewer`+ | — | `200` |
| GET | `/api/v1/attack-surface/export?format=stix2.1|csv` | `analyst`+ | filtros | `200` fichero |
| GET | `/api/v1/jobs/{id}` | `viewer`+ | — | `200 {state, progress, errors[]}` |

**Ejemplo `exposure_diff`:**
```json
{
  "id": "0192f1...",
  "observation_id": "0192f0...",
  "change_type": "changed",
  "before": {"service": "nginx/1.24.0", "tls": {"issuer": "R3", "expires_at": "2026-12-01T00:00:00Z"}},
  "after":  {"service": "nginx/1.27.1", "tls": {"issuer": "R3", "expires_at": "2027-03-01T00:00:00Z"}},
  "detected_at": "2026-11-26T09:00:00Z"
}
```

## 7. CASOS DE USO

1. **Alta de alcance:** el `admin` declara `203.0.113.0/24` con referencia al contrato de autorización y vigencia de 12 meses.
2. **Import mensual:** se importa el resultado de un escáner externo; el sistema detecta 14 nuevos puertos, 3 servicios cambiados y 2 cerrados.
3. **Exposición no autorizada:** un conector reporta una IP fuera de rango; se registra `rejected` y se alerta de posible error de configuración o de activo shadow IT.
4. **Servicio crítico expuesto:** aparece RDP en 3389 sobre un activo crítico 5; se crea finding `P1` y se propone acción de bloqueo (sujeta a política).
5. **Informe al regulador:** se exporta la superficie actual en STIX para anexar al expediente.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| IP fuera de todo rango | `422 target_out_of_scope` con `ip` y rangos declarados |
| Rango solapado | `409 range_overlap` con el rango existente |
| CIDR inválido | `422 validation_error` |
| Rango caducado | Observaciones nuevas → `authorized=false` + hallazgo |
| Import sin `Idempotency-Key` | `400 idempotency_key_required` |
| Reenvío con misma clave y cuerpo distinto | `409 idempotency_conflict` |
| `port=0` o `>65535` | `422`, campo `port` |
| Protocolo distinto de tcp/udp | `422`, campo `protocol` |
| Banner idéntico | Sin diff, solo `last_seen` |
| Servicio desaparece una sola vez | `status=unchanged` hasta superar 2 importaciones o 7 días (ventana de gracia configurable) |
| Export sin observaciones | `200` con bundle vacío válido (`objects: []`) |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Escaneo no autorizado | Configurar rangos ajenos | Autorización con evidencia, auditoría, guard de alcance, alerta a `owner` |
| Envenenamiento de exposición | Import falso para ocultar un servicio | Solo `admin` importa; `source` y `imported_by` auditados; diffs inmutables |
| Fuga de topología | Export sin control | Permisos y auditoría de export |
| DoS por import | Fichero enorme | Límites de tamaño/filas, streaming, timeout |
| Suplantación de IP | Datos de escáner no firmados | Se documenta confianza en la fuente; hash de fichero importado |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-22` | Cambio de banner genera diff `changed` | `backend/tests/integration/test_asm_diff.py::test_banner_change_diff` |
| `AC-23` | Exposición no autorizada genera hallazgo | `backend/tests/integration/test_asm_authorization.py` |
| `AC-24` | Fuera de alcance rechazado, sin job | `backend/tests/security/test_asm_scope_guard.py` |
| `AC-25` | Export STIX round-trip | `backend/tests/integration/test_asm_export.py::test_stix_roundtrip` |
| `AC-26` | Job idempotente | `backend/tests/integration/test_jobs_idempotency.py` |
| `AC-ASM-06` | Ventana de gracia para `closed` | `backend/tests/integration/test_asm_grace_window.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** validación CIDR, comparación de banners/TLS, cálculo de severidad de exposición, serialización STIX.
- **Integración:** import, diff, cierre con ventana, export, jobs.
- **Seguridad:** scope guard, idempotencia, aislamiento, límites de tamaño.
- **E2E:** `/attack-surface` con diffs y aviso de alcance.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_asm_*.py tests/security/test_asm_scope_guard.py`.
2. Ejemplo de `exposure_diff` antes/después.
3. Bundle STIX exportado y reimportado con conteo idéntico.
4. Log de rechazo por `target_out_of_scope` con IP y rango.
5. Bench de import de 50k observaciones.
