# DOMINIO: SEGURIDAD OT (ICS/SCADA)

- **Código:** `OTC`
- **Ruta de implementación:** `backend/app/services/{ot,ot_baseline}.py`, `backend/app/api/v1/ot.py`, `backend/app/autonomy/safety.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-82..AC-84`

---

## 1. OBJETIVO

Modelar la red industrial conforme a Purdue e IEC 62443, vigilar la integridad del proceso mediante líneas base de protocolo, y garantizar que ninguna acción —humana o autónoma— pueda afectar a una función de seguridad física sin interlocks, doble aprobación y trazabilidad.

## 2. CONTEXTO

En OT, la disponibilidad y la seguridad física prevalecen sobre la confidencialidad. Un `block_ip` mal dirigido puede aislar el servidor SCADA del PLC; una escritura de registro puede abrir una válvula. Por tanto, el diseño invierte la comodidad: se exige contexto (nivel Purdue, zona, criticidad, `safety_function`), se bloquea por defecto y se audita cada decisión.

La detección se basa en líneas base de tráfico por protocolo (Modbus/TCP, DNP3, OPC-UA) y en la observación de funciones de escritura no vistas, cambios de modo y accesos desde niveles superiores no esperados.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-OTC-001` | Modelo | Activo `kind=ot` con `purdue_level 0..5`, `zone_id`, `safety_function bool`, `protocols[]`, `vendor/model`, `firmware`. |
| `REQ-OTC-002` | Zonas/conductos | Zona IEC 62443 con `sl_target (1..4)`; conducto entre zonas con `required_sl`, `protocols[]`, `direction`, `justification`. Sin `required_sl` → `422`. |
| `REQ-OTC-003` | Safety interlock | Si `safety_function=true` o `purdue_level ≤1`, acciones de escritura → `deny safety_interlock` salvo A4 + doble aprobación + ventana de mantenimiento aprobada. |
| `REQ-OTC-004` | Línea base | Por activo y protocolo: funciones observadas, registros, periodicidad, peers habituales; ventana de aprendizaje mínima 7 días. |
| `REQ-OTC-005` | Anomalía | Escritura no observada, cambio de modo, nuevo peer, función de diagnóstico inusual → alerta con `protocol`, `function_code`, `src`, `dst`, severidad por Purdue. |
| `REQ-OTC-006` | Evaluación de cumplimiento | Zona/conducto con `sl_target` vs controles aplicados → `gap` con severidad. |
| `REQ-OTC-007` | Frescura | Igual que IoT: sin telemetría fresca, no hay acción autónoma. |
| `REQ-OTC-008` | Catálogo de acciones OT | `read_only_probe`, `notify_operator`, `isolate_zone_segment` (A4), `block_ot_flow` (A3 con aprobación). Prohibidas escrituras a PLC en release 1.0. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-OTC-01` | Evaluación de política OT ≤20 ms p95 (camino crítico). |
| `NFR-OTC-02` | Actualización de línea base de 100k flujos ≤5 min por ciclo. |
| `NFR-OTC-03` | 0 acciones de escritura hacia PLC en release 1.0 (verificado por catálogo y test). |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `assets`/`zones` | Dominio | Base y zonas |
| `siem` | Dominio | Flujos y eventos de red |
| `autonomy` | Dominio | Safety interlock y broker |
| `compliance` | Dominio | IEC 62443 |
| `iot` | Dominio | Dispositivos de borde |

## 6. CONTRATOS

| Método | Endpoint | Rol | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| GET | `/api/v1/ot/assets` | `viewer`+ | `?purdue_level&zone_id&protocol` | `200` |
| POST | `/api/v1/assets/{id}/ot` | `admin`+ | `OtProfile` | `201` |
| GET/POST | `/api/v1/ot/conduits` | `admin`+ | `{from_zone,to_zone,required_sl,protocols,direction}` | `200/201` |
| GET | `/api/v1/ot/baseline/{asset_id}` | `analyst`+ | `?protocol` | `200 {functions[], peers[], periodicity}` |
| POST | `/api/v1/ot/baseline/{asset_id}/learn` | `admin`+ | `{window_days}` | `202` |
| GET | `/api/v1/ot/anomalies` | `analyst`+ | `?since&severity` | `200` |
| GET | `/api/v1/ot/posture` | `viewer`+ | — | `200 {zones[], conduits[], gaps[]}` |
| POST | `/api/v1/ot/maintenance-window` | `owner` | `{from,to,reason,zone_ids[]}` | `201` |

## 7. CASOS DE USO

1. **Modelado de planta:** se crean zonas `nivel0`, `nivel1`, `dmz-industrial` con `sl_target` y conductos con `required_sl=3`.
2. **Anomalía de escritura:** un flujo Modbus `write_single_register` desde nivel 3 a nivel 1 no visto en 30 días genera alerta P1.
3. **Intento de contención:** el `responder` pide `block_ot_flow`; la política exige A3+ y aprobación; se ejecuta con ventana y verificación.
4. **Safety interlock:** se solicita escritura sobre PLC con `safety_function=true`; se deniega incluso con A4 si no hay ventana de mantenimiento aprobada.
5. **Auditoría IEC 62443:** se detecta que un conducto `required_sl=3` no tiene control compensatorio; se registra gap.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| `purdue_level=6` | `422`, rango 0..5 |
| Zona OT sin `sl_target` | `422 required_sl_missing` |
| Conducto duplicado | `409 conduit_exists` |
| Conducto sin protocolos | `422 protocols_required` |
| Acción de escritura PLC | `403 action_not_supported` (release 1.0) |
| `safety_function=true` sin ventana | `deny safety_interlock` |
| Línea base con <7 días de datos | Estado `learning`; anomalías no concluyentes (no alertan como P1) |
| Telemetría stale | `deny stale_telemetry` |
| Aislamiento de segmento con tráfico de seguridad | `deny critical_service_impact` salvo A4 + owner |
| Cambio de nivel Purdue con acciones activas | `409 active_actions` |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| Impacto físico | Acción de contención mal dirigida | Safety interlock, zonas, blast radius, A4, ventana |
| Manipulación de proceso | Escritura no autorizada | Detección de función no observada, prohibición de escrituras |
| Movimiento IT→OT | Falta de segmentación | Conductos IEC 62443, evaluación de postura |
| Sabotaje interno | Cambio de línea base | Aprendizaje solo `admin`, auditoría, ventana mínima |
| DoS de visibilidad | Sensor caído | Estado stale y bloqueo de autonomía |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-82` | Safety interlock deniega escritura | `backend/tests/autonomy/test_ot_safety_interlock.py` |
| `AC-83` | Anomalía de protocolo con contexto | `backend/tests/integration/test_ot_anomaly.py` |
| `AC-84` | Conducto sin `required_sl` rechazado; gap detectado | `backend/tests/integration/test_iec62443_zones.py` |
| `AC-OTC-05` | Baseline `learning` no alerta P1 | `backend/tests/integration/test_ot_baseline_learning.py` |
| `AC-OTC-08` | Catálogo sin escrituras PLC | `backend/tests/unit/test_ot_action_catalog.py` |

## 11. ESTRATEGIA DE TEST

- **Unit:** validación Purdue, conductos, catálogo de acciones, severidad por nivel.
- **Integración:** baseline, anomalías, postura, ventanas.
- **Autonomía:** interlock, stale, blast radius, A4.
- **E2E:** `/iot-ot` con mapa Purdue y anomalías.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/autonomy/test_ot_safety_interlock.py tests/integration/test_ot_*.py`.
2. Modelo de zonas/conductos con `sl_target` y gaps.
3. Alerta de anomalía con `function_code` y niveles.
4. Denegación de escritura PLC con `reason` y `decision_id`.
5. Test que demuestra 0 acciones de escritura disponibles en el catálogo.
