# MANUAL DE AUDITORÍA

- **Documento:** `docs/audit-manual.md`
- **Estado:** `APPROVED` v1.0
- **Audiencia:** auditor interno/externo, DPO, responsable de cumplimiento
- **Pantallas:** `/audit`, `/compliance`, `/forensics`, `/reports`

---

## 1. QUÉ PUEDE VERIFICAR UN AUDITOR

| Afirmación | Cómo se verifica | Evidencia |
| :--- | :--- | :--- |
| "Las acciones están registradas" | Cadena de auditoría + `decision_id` | `/audit`, `/audit/verify` |
| "Nadie alteró los registros" | Verificación de hash encadenado | `valid:true` + `seq` |
| "El control X está implantado" | Evidencia aprobada y vigente | `/compliance` |
| "La evidencia no fue manipulada" | SHA-256 + manifiesto | `/forensics`, export |
| "Los accesos a evidencia están trazados" | Custodia | `custody_entries` |
| "Las acciones autónomas fueron autorizadas" | Decisión de política y aprobaciones | `/audit/actions/{id}` |
| "El informe corresponde a la evaluación" | Hash de contenido | `/reports/{id}` |

---

## 2. ROL DEL AUDITOR

- Rol `auditor`: lectura de auditoría, cumplimiento, evidencias e informes; **sin** capacidad de mutar dominio.
- Puede aprobar evidencias de control (separación de funciones: no las suyas).
- Cuenta con TTL y revocación al finalizar la auditoría.
- Todo acceso suyo queda registrado.

**Limitación deliberada:** el auditor no puede ejecutar acciones ni cambiar políticas; si necesita una prueba de ejecución, la solicita al equipo con registro.

---

## 3. VERIFICACIÓN DE LA CADENA DE AUDITORÍA

```http
GET /api/v1/audit/verify?from=1&to=1000000
```

```json
{"valid": true, "checked_entries": 84213, "first_seq": 1, "last_seq": 84213}
```

En caso de fallo:
```json
{"valid": false, "first_invalid_seq": 41233, "expected_hash": "…", "actual_hash": "…"}
```

**Procedimiento**
1. Verificar el rango completo al inicio de la auditoría.
2. Registrar el resultado (captura + `request_id`).
3. Si es inválido: detener, preservar, escalar (incidente de seguridad).

---

## 4. MUESTREO DE ACCIONES

| Muestra | Criterio | Qué revisar |
| :--- | :--- | :--- |
| 10 acciones `A3` | Aleatorias del periodo | `decision_id`, política, verificación, resultado |
| 5 acciones `A4` | Todas | Doble aprobación, time-box, interlock |
| 10 accesos a evidencia | Aleatorios | Rol, motivo, custodia |
| 5 cambios de rol | Todos | Aprobador, justificación |
| 3 break-glass | Todos | Ticket, TTL, banner, datos accedidos |
| 5 informes | Aleatorios | Hash y versiones de framework |

**Criterio de fallo:** una acción sin decisión, una aprobación del propio solicitante, un acceso a evidencia sin rol, o un hash que no coincide.

---

## 5. AUDITORÍA DE CUMPLIMIENTO

```text
1. Seleccionar framework y versión (/compliance).
2. Revisar controles aplicables y su estado derivado.
3. Para cada control: abrir evidencia, verificar vigencia y revisor.
4. Revisar gaps y planes de remediación.
5. Generar informe con hash.
6. Verificar el hash del PDF descargado.
```

| Estado del control | Significado | Válido para auditoría |
| :--- | :--- | :---: |
| `compliant` | Evidencia aprobada y vigente | ✅ |
| `partial` | Evidencia parcial o con salvedades | ⚠️ |
| `non_compliant` | Sin evidencia o rechazada | ❌ |
| `evidence_expired` | Evidencia caducada | ❌ |
| `not_applicable` | Justificado y revisado | ✅ (con justificación) |

---

## 6. AUDITORÍA FORENSE

| Paso | Acción |
| :--- | :--- |
| 1 | Abrir caso (`legal_hold` si procede) |
| 2 | Revisar manifiesto de evidencias y hashes |
| 3 | Verificar integridad (`POST /evidence/{id}/verify`) |
| 4 | Revisar timeline reconstruido y sus fuentes |
| 5 | Exportar paquete con `manifest.json` |
| 6 | Verificar el hash del manifiesto y de cada fichero |

**Regla:** si un hash no coincide, la evidencia se marca `quarantined` y no se usa hasta resolver.

---

## 7. INFORME DE AUDITORÍA

Contenido mínimo:
1. Alcance y periodo.
2. Metodología y muestras.
3. Resultado de verificación de cadena.
4. Hallazgos con severidad y evidencia.
5. Controles evaluados y estado.
6. Acciones correctivas propuestas.
7. Fecha, autor y hash del informe.

El informe generado por la plataforma incluye `generated_at`, `framework_versions[]` y `content_hash`; el auditor verifica que coincide con el binario descargado.

---

## 8. HALLAZGOS TÍPICOS Y RESPUESTA

| Hallazgo | Severidad | Acción |
| :--- | :--- | :--- |
| Control sin evidencia vigente | Alta | Remediación con dueño y fecha |
| Evidencia aprobada por el solicitante | Alta | Revisar separación de funciones; reasignar |
| Acción autónoma sin `decision_id` | Crítica | Incidente de seguridad; revisar broker |
| Cadena de auditoría inválida | Crítica | Aislar, preservar, restaurar, investigar |
| Break-glass sin ticket | Alta | Revisar proceso y accesos |
| Excepción de riesgo vencida sin revisión | Media | Job de caducidad + seguimiento |
| `not_applicable` >20% sin justificación | Media | Revisión de aplicabilidad |

---

## 9. ACCESO Y CONFIDENCIALIDAD

- El auditor accede con cuenta propia, MFA y rol `auditor`.
- No recibe exportaciones masivas sin aprobación del `owner`.
- Los datos personales se revisan bajo minimización; se puede seudonimizar.
- La cuenta se revoca al finalizar; se conserva la auditoría de su actividad.

---

## 10. CHECKLIST DE AUDITORÍA

- [ ] Cadena de auditoría verificada al inicio y al cierre.
- [ ] Muestras de acciones A3/A4 documentadas.
- [ ] Accesos a evidencia revisados.
- [ ] Controles con evidencia vigente y revisor distinto.
- [ ] Gaps con plan y dueño.
- [ ] Informe generado y hash verificado.
- [ ] Hallazgos comunicados y registrados.
- [ ] Cuenta de auditor revocada.
