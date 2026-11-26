# DOMINIO: SEGURIDAD CLOUD

- **Código:** `CLD`
- **Ruta de implementación:** `backend/app/services/{cloud,cspm}.py`, `backend/app/api/v1/cloud.py`, `backend/app/integrations/cloud/`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-85..AC-87`

---

## 1. OBJETIVO

Descubrir y evaluar la postura de seguridad de las cuentas cloud de la organización mediante credenciales de solo lectura cifradas, reglas CSPM con evidencia, mapeo a controles normativos y estados honestos cuando el proveedor no responde.

## 2. CONTEXTO

Los organismos operan cargas en nubes europeas y, a veces, en más de un proveedor. La plataforma no despliega agentes: usa APIs de solo lectura para inventario, configuración y logs de auditoría. La credencial es el activo más sensible del dominio: se cifra, se rota y nunca se devuelve.

El CSPM de la release 1.0 es un conjunto de reglas deterministas sobre recursos normalizados (no un motor de grafos completo). Cada regla declara su control asociado y produce evidencia reproducible.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-CLD-001` | Onboarding | Cuenta con `provider (aws|azure|gcp)`, `account_id`, `display_name`, `regions[]`, credenciales (role/secret) cifradas, `last_used_at`, `rotated_at`. |
| `REQ-CLD-002` | Solo lectura | Validación de permisos: la credencial debe poder listar/describir y **no** mutar; si tiene permisos de escritura, se marca `over_privileged=true` y se genera finding. |
| `REQ-CLD-003` | Inventario | Recursos normalizados `{resource_id, type, region, tags, config_hash, public, encrypted, logging}`; upsert idempotente. |
| `REQ-CLD-004` | Reglas CSPM | Regla = `{id, title, severity, resource_types[], predicate, control_refs[], remediation}`; evaluación produce `pass/fail/error` con `evidence`. |
| `REQ-CLD-005` | Findings | `fail` puede crear `vulnerability_instance`/finding con `risk_score` y mapeo a control (ISO 27001 A.8.9, ENS op.acc.6, etc.). |
| `REQ-CLD-006` | Degradación | Proveedor caído/timeout → `degraded`, scan `partial`, `as_of` del último dato; nunca `pass` inventado. |
| `REQ-CLD-007` | Audit logs | Ingesta de logs cloud normalizados a OCSF y enviados al SIEM. |
| `REQ-CLD-008` | Rotación | Rotación de credenciales con re-cifrado transaccional y periodo de gracia; auditoría de cada uso. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-CLD-01` | Inventario de 10.000 recursos ≤5 min por cuenta. |
| `NFR-CLD-02` | Evaluación de 200 reglas sobre 10k recursos ≤2 min. |
| `NFR-CLD-03` | Credencial nunca en claro en memoria más allá de la llamada; nunca en logs. |
| `NFR-CLD-04` | Rate limits del proveedor respetados con backoff y presupuesto de llamadas. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `connectors` | Integración | Registro, salud, secretos |
| `assets` | Dominio | Recursos cloud como activos |
| `vulnerabilities` | Dominio | Findings |
| `compliance` | Dominio | Mapeo de controles |
| `siem` | Dominio | Audit logs |
| `core/crypto.py` | Interna | Cifrado |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET/POST | `/api/v1/cloud/accounts` | `admin`+ | `CloudAccountCreate` | `200/201` (`has_secret`) |
| POST | `/api/v1/cloud/accounts/{id}/verify` | `admin`+ | — | `200 {read_only:true, over_privileged:false}` |
| POST | `/api/v1/cloud/accounts/{id}/scan` | `admin`+ | `{regions?}` | `202 {scan_id}` |
| GET | `/api/v1/cloud/accounts/{id}/posture` | `viewer`+ | `?severity` | `200 {score, results[], as_of, state}` |
| GET | `/api/v1/cloud/resources` | `viewer`+ | `?type&public&region` | `200` |
| GET | `/api/v1/cloud/findings` | `viewer`+ | `?severity&control` | `200` |
| PATCH | `/api/v1/cloud/accounts/{id}` | `admin`+ | `{rotate_secret, regions}` | `200` |

## 7. CASOS DE USO

1. **Onboarding AWS:** se registra una cuenta con role de solo lectura; la verificación confirma `read_only=true`; se lanza el primer scan.
2. **Bucket público:** la regla `s3_public_read` falla; se crea finding P2 con ARN, evidencia y control ISO/ENS.
3. **Sobreprivilegio:** la credencial puede borrar objetos; se marca `over_privileged` y se genera finding P1.
4. **Proveedor caído:** el scan devuelve timeout; el estado es `partial` y la UI muestra `as_of` del último scan completo.
5. **Auditoría:** el auditor exporta findings por control para el expediente.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| Credencial con permisos de escritura | `200 {over_privileged:true}` + finding; no se bloquea el onboarding |
| Credencial inválida | `422 invalid_credentials` (sin detalles del proveedor) |
| Cuenta duplicada | `409 account_exists` |
| Región no soportada | `422 unsupported_region` |
| Scan concurrente | `409 scan_in_progress` |
| Timeout parcial | `partial` con `errors[]` por región |
| Regla con recurso borrado | `skip` con `resource_missing` |
| Rotación durante scan | El scan usa la credencial anterior hasta terminar; nueva para el siguiente |
| Logs cloud con PII | Redacción configurable antes de ingestar |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Robo de credencial cloud | API o logs | Fernet, `has_secret`, redacción, rotación |
| Escalada por credencial excesiva | Rol con escritura | Verificación read-only y finding |
| SSRF en endpoint de proveedor | `base_url` manipulada | Allowlist de dominios por proveedor |
| Datos inventados | Fallo del proveedor | Estado `degraded/partial` con `as_of` |
| Fuga de inventario cloud | Export sin permiso | RBAC y auditoría |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-85` | Secreto cifrado y nunca devuelto | `backend/tests/security/test_connector_secret_storage.py` |
| `AC-86` | Regla CSPM con evidencia y control | `backend/tests/integration/test_cspm_rules.py` |
| `AC-87` | Proveedor caído → degradado honesto | `backend/tests/integration/test_cloud_degraded_state.py` |
| `AC-CLD-04` | Read-only verificado | `backend/tests/integration/test_cloud_readonly.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** predicados de reglas, normalización de recursos.
- **Integración:** onboarding, verificación, scan, findings, rotación, degradación.
- **Seguridad:** cifrado, no fuga, SSRF, aislamiento.
- **E2E:** `/cloud` con estados y `as_of`.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_cspm_rules.py tests/integration/test_cloud_degraded_state.py tests/security/test_connector_secret_storage.py`.
2. Respuesta de `GET /cloud/accounts/{id}` mostrando `has_secret:true` sin valor.
3. Resultado de scan con `pass/fail` y evidencia por recurso.
4. Estado `partial` con `errors[]` y `as_of`.
5. Log de rotación de credencial.
