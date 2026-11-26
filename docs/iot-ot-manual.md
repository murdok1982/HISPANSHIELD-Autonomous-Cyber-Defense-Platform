# MANUAL IoT / OT

- **Documento:** `docs/iot-ot-manual.md`
- **Estado:** `APPROVED` v1.0
- **Audiencia:** responsable de OT, ingeniero de red industrial, analista SOC con foco OT
- **Pantallas:** `/iot-ot`, `/network`, `/assets`, `/compliance`

---

## 1. PRINCIPIO

En OT, **la disponibilidad y la seguridad física prevalecen**. La plataforma observa, correlaciona y contiene de forma limitada; **no escribe en PLCs** en la versión 1.0. Toda acción que pueda afectar a un proceso requiere contexto, interlocks y, en su caso, doble aprobación.

---

## 2. MODELO DE DATOS

### 2.1 Zonas

| Campo | Obligatorio | Notas |
| :--- | :--- | :--- |
| `name` | Sí | Único por organización |
| `kind` | Sí | `it`, `dmz`, `iot`, `ot`, `cloud` |
| `purdue_level` | OT | 0..5 |
| `sl_target` | OT | Nivel de seguridad IEC 62443 (1..4) |
| `isolation_level` | Recomendado | `strict`, `standard`, `shared` |

### 2.2 Activos IoT

| Campo | Regla |
| :--- | :--- |
| `protocol` | Del catálogo (`mqtt`, `mqtts`, `coap`, `lorawan`, `https`, …) |
| `firmware_version` | Obligatorio |
| `zone_id` | Obligatorio, de tipo `iot`/`ot` |
| `mac` | Opcional; dedupe |
| `eol_status` | `supported`, `approaching_eol`, `eol`, `unknown` |

### 2.3 Activos OT

| Campo | Regla |
| :--- | :--- |
| `purdue_level` | 0..5, obligatorio |
| `safety_function` | Booleano; si `true`, acciones de escritura denegadas |
| `protocols` | Modbus, DNP3, OPC-UA (visibilidad) |
| `vendor` / `model` / `firmware` | Recomendados |

---

## 3. ONBOARDING

```text
1. Crear zonas (IT → DMZ → OT nivel 1/2/3).
2. Declarar conductos entre zonas con required_sl y protocolos.
3. Importar inventario (CSV) o registrar manualmente.
4. Asignar criticidad (5 para funciones de seguridad/servicio esencial).
5. Marcar safety_function y protocols.
6. Verificar telemetría (eventos de red) y frescura.
7. Ejecutar aprendizaje de línea base (≥7 días).
```

---

## 4. ETSI EN 303 645 (IoT)

13 provisiones evaluadas por dispositivo con estado `pass/fail/unknown/na` y evidencia:

| # | Provisión | Verificación típica |
| :--- | :--- | :--- |
| 1 | Sin contraseñas por defecto universales | Inventario + política de cambio |
| 2 | Gestión de vulnerabilidades | Proceso de parcheo documentado |
| 3 | Software actualizado | Versión y fecha; EOL |
| 4 | Datos sensibles almacenados de forma segura | Cifrado en reposo |
| 5 | Comunicaciones seguras | TLS/DTLS habilitado |
| 6 | Superficie de ataque minimizada | Puertos/servicios abiertos |
| 7 | Integridad del software | Firma/verificación |
| 8 | Protección de datos personales | Minimización |
| 9 | Resiliencia ante interrupciones | Recuperación |
| 10 | Validación de entrada | Configuración segura |
| 11 | Telemetría de seguridad | Logs enviados |
| 12 | Facilidad de instalación/mantenimiento | Procedimiento |
| 13 | Validación de datos de entrada | Filtrado |

**Regla:** `pass` sin evidencia es `422`; el score no declara cumplimiento si hay `unknown`.

---

## 5. IEC 62443 (OT)

| Elemento | Regla |
| :--- | :--- |
| Zona | `sl_target` obligatorio; sin él, no se evalúa |
| Conducto | `required_sl` obligatorio; `protocols[]`, `direction`, justificación |
| Evaluación | Compara `sl_target` con controles aplicados; sin control → `gap` |
| Acciones | Solo sobre flujos/segmentos, nunca escritura de proceso |

```text
Zona A (SL2) --conducto (required_sl=3, modbus)--> Zona B (SL3)
Si no hay control compensatorio → gap de severidad alta
```

---

## 6. LÍNEA BASE Y ANOMALÍAS

| Fase | Duración | Comportamiento |
| :--- | :--- | :--- |
| `learning` | ≥7 días | Recoge funciones, registros, peers, periodicidad; anomalías no concluyentes |
| `active` | — | Compara y alerta desviaciones |

**Anomalías típicas:** escritura no observada, cambio de modo, nuevo peer, función de diagnóstico inusual, acceso desde nivel superior no esperado.

Severidad por Purdue:
| Origen → Destino | Severidad base |
| :--- | :--- |
| Nivel 3 → Nivel 1 con escritura | Alta |
| Internet/DMZ → Nivel 3 | Alta |
| Nivel 2 → Nivel 1 lectura inusual | Media |
| Nivel 1 → Nivel 0 | Crítica (si aplica) |

---

## 7. ACCIONES PERMITIDAS Y PROHIBIDAS

| Acción | Estado | Requisito |
| :--- | :--- | :--- |
| `notify_operator` | ✅ | — |
| `read_only_probe` | ✅ | A0/A1 |
| `block_ot_flow` | ✅ | A3 + contexto + verificación |
| `isolate_zone_segment` | ✅ | A4 + doble aprobación + ventana + safety |
| `write_plc_register` | ❌ | No soportado |
| `snmp_set` | ❌ | No soportado |
| `modbus_write` / `dnp3_control` / `opcua_write` | ❌ | No soportado |

**Interlock:** si `safety_function=true` o `purdue_level ≤1`, una acción de escritura se deniega sin importar el nivel de autonomía.

---

## 8. RESPUESTA A INCIDENTE OT

1. **No** ejecutar acciones de escritura.
2. Notificar al responsable de planta y verificar estado físico.
3. Evaluar alcance (activos, flujos, zonas).
4. Si se requiere aislamiento: A4, doble aprobación, ventana, verificación.
5. Preservar evidencia (flujos, logs, capturas).
6. Coordinar recuperación con ingeniería de procesos.
7. Documentar en el incidente y evaluar notificación NIS2.

---

## 9. FRESCURA Y DEGRADACIÓN

| Situación | Efecto |
| :--- | :--- |
| `last_seen` > 24 h | `stale=true`; autonomía denegada (`stale_telemetry`) |
| Sensor caído | UI con badge y `as_of`; no se muestran ceros como datos |
| Baseline en `learning` | No se alerta como P1; se informa |
| Conector OT degradado | Estado visible; sin acciones |

---

## 10. CHECKLIST DE OPERACIÓN

- [ ] Zonas y conductos declarados con `sl_target`/`required_sl`.
- [ ] Inventario IoT con protocolo, firmware y zona.
- [ ] Inventario OT con Purdue y `safety_function`.
- [ ] Checklist ETSI con evidencias (no `pass` vacío).
- [ ] Línea base completada (≥7 días).
- [ ] Telemetría fresca verificada.
- [ ] Acciones OT probadas solo en laboratorio.
- [ ] Ventanas de mantenimiento documentadas.
