# DOMINIO: SEGURIDAD IoT

- **Código:** `IOT`
- **Ruta de implementación:** `backend/app/services/{iot,firmware}.py`, `backend/app/api/v1/iot.py`, `frontend/src/screens/IotOtSecurity.tsx`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-79..AC-81`

---

## 1. OBJETIVO

Inventariar y evaluar dispositivos IoT con su contexto físico (zona, protocolo, firmware), aplicar la checklist ETSI EN 303 645, detectar firmware vulnerable o en fin de vida y garantizar que ninguna acción autónoma se ejecute sobre dispositivos sin telemetría fresca o fuera de su zona autorizada.

## 2. CONTEXTO

Cámaras, sensores, PLC ligeros, medidores y pasarelas IoT suelen tener firmware no actualizable, credenciales por defecto y protocolos sin cifrar. No se puede desplegar un agente: la visibilidad llega por inventario, escaneo pasivo importado y telemetría de red. La política de autonomía debe tratarlos como clase de riesgo distinta: un "aislar" mal aplicado puede dejar sin vigilancia una instalación.

ETSI EN 303 645 aporta 13 provisiones verificables que se usan como checklist por dispositivo, no como certificación.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-IOT-001` | Registro | Activo `kind=iot` con `attributes{protocol, vendor, model, firmware_version, mac, eol_status, managed_by}`; `zone_id` obligatoria de tipo `iot` o `ot`. |
| `REQ-IOT-002` | Protocolos | Catálogo: `mqtt`, `mqtts`, `coap`, `dtls`, `zigbee`, `zwave`, `lorawan`, `modbus`, `bacnet`, `https`, `proprietary`. Protocolo no soportado → `422 unsupported_protocol`. |
| `REQ-IOT-003` | ETSI checklist | 13 provisiones (`no universal default passwords`, `implement means to manage vulnerabilities`, `keep software updated`, `securely store sensitive data`, `communicate securely`, `minimise exposed attack surface`, `ensure software integrity`, `ensure data is protected`, `minimise input validation`, `ensure availability`, `minimise processing of PII`, `ensure install/maintenance`, `validate input data`). Estado `pass/fail/unknown/na` + evidencia. |
| `REQ-IOT-004` | Firmware | `firmware_inventory` con versión, hash, fecha, fuente; match CVE por CPE o por proveedor+producto+versión; resultado `vulnerability_instance`. |
| `REQ-IOT-005` | EOL | `eol_status ∈ {supported, approaching_eol, eol, unknown}` con `eol_date`; EOL eleva riesgo y bloquea A3+ por defecto. |
| `REQ-IOT-006` | Frescura | `last_seen`; si `now - last_seen > stale_threshold (24h)` → `stale=true`; la política deniega acciones (`deny stale_telemetry`). |
| `REQ-IOT-007` | Aislamiento por zona | La política evalúa `zone.kind` y `zone.isolation_level`; una acción de cuarentena solo puede aplicar a la zona declarada. |
| `REQ-IOT-008` | Credenciales por defecto | Si el dispositivo está marcado `default_credentials_suspected=true`, se crea finding P1 y se sugiere rotación. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-IOT-01` | Registro/actualización ≤200 ms p95. |
| `NFR-IOT-02` | Match de firmware contra catálogo CVE (50k entradas) ≤2 s por dispositivo, batch de 1.000 ≤5 min. |
| `NFR-IOT-03` | La UI de mapa Purdue/zonas renderiza 2.000 dispositivos sin bloquear el hilo principal. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `assets` | Dominio | Tabla base y zonas |
| `vulnerabilities` | Dominio | Instancias de CVE |
| `autonomy` | Dominio | Frescura, zona, EOL |
| `compliance` | Dominio | ETSI EN 303 645 |
| `siem` | Dominio | Telemetría de red |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET | `/api/v1/iot/devices` | `viewer`+ | `?zone_id&protocol&eol_status&stale` | `200 {data[],meta}` |
| POST | `/api/v1/assets/{id}/iot` | `admin`+ | `IotProfile` | `201` |
| PATCH | `/api/v1/iot/devices/{id}` | `admin`+ | `IotUpdate` | `200` |
| GET | `/api/v1/iot/devices/{id}/etsi` | `viewer`+ | — | `200 {provisions[13], score}` |
| PATCH | `/api/v1/iot/devices/{id}/etsi/{provision}` | `admin`+ | `{status, evidence_id?, note?}` | `200` |
| POST | `/api/v1/iot/devices/{id}/firmware` | `admin`+ | `{version, hash, released_at, source}` | `201` |
| GET | `/api/v1/iot/devices/{id}/firmware/vulns` | `viewer`+ | — | `200 {matches[]}` |
| GET | `/api/v1/iot/summary` | `viewer`+ | — | `200 {by_zone, by_protocol, eol, stale, etsi_score}` |

## 7. CASOS DE USO

1. **Alta de cámara IP:** el `admin` crea el activo, asigna zona `perimetro`, protocolo `https`, firmware `2.4.1`; la checklist ETSI queda en `unknown`.
2. **Firmware vulnerable:** la versión coincide con una CVE crítica conocida; se crea instancia y el dispositivo pasa a riesgo alto.
3. **EOL:** el fabricante declara fin de soporte; se marca `eol`, se eleva criticidad y se bloquea autonomía A3.
4. **Sensor caído:** sin telemetría 26 h; la UI muestra `stale`; una solicitud de cuarentena se deniega con `stale_telemetry`.
5. **Auditoría ETSI:** el auditor revisa las 13 provisiones con evidencias y detecta 4 `fail`.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| Zona de tipo `it` para IoT | `422 invalid_zone_kind` |
| Protocolo no listado | `422 unsupported_protocol` |
| `firmware_version` vacía | `422`, campo obligatorio para IoT |
| CPE ambiguo (múltiples matches) | Se crean todas las instancias candidatas con `confidence` y se marca `needs_review` |
| `last_seen` futuro | `422 invalid_last_seen` |
| Cambio de zona con acciones activas | `409 active_actions` |
| ETSI `pass` sin evidencia | `422 evidence_required` |
| Dispositivo duplicado por MAC | `409 duplicate_mac` con `existing_id` |
| 13 provisiones incompletas | Score ETSI = `unknown_ratio` y no se declara cumplimiento |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Botnet IoT | Credenciales por defecto | Detección, finding P1, rotación sugerida |
| Movimiento lateral | Zona plana | Zonas y política de aislamiento |
| Acción dañina | Cuarentena masiva de sensores | Blast radius, zona, frescura, aprobación |
| Inventario falso | Alta de dispositivos para desviar política | Solo `admin`, auditoría, dedupe por MAC |
| Fuga de firmware | Hash y versión expuestos | Sin binario almacenado; solo metadatos |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-79` | Registro con zona/protocolo y ETSI inicializada | `backend/tests/integration/test_iot_registration.py` |
| `AC-80` | Firmware→CVE y EOL | `backend/tests/integration/test_firmware_cve.py` |
| `AC-81` | Stale bloquea autonomía | `backend/tests/autonomy/test_stale_sensor.py` |
| `AC-IOT-04` | Política evalúa zona | `backend/tests/autonomy/test_zone_isolation.py` |
| `AC-IOT-08` | ETSI `pass` exige evidencia | `backend/tests/integration/test_etsi_evidence.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** validación de protocolos, cálculo de score ETSI, match CPE, frescura.
- **Integración:** alta, checklist, firmware, CVE, resumen.
- **Autonomía:** stale, zona, EOL.
- **E2E:** `/iot-ot` con mapa y badges.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/integration/test_iot_registration.py tests/integration/test_firmware_cve.py tests/autonomy/test_stale_sensor.py`.
2. Checklist ETSI de un dispositivo con 13 filas y evidencias.
3. Ejemplo de finding por credenciales por defecto.
4. Captura de mapa de zonas con `stale`.
