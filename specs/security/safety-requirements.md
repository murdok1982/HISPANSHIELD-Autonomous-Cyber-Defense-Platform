# REQUISITOS DE SEGURIDAD FUNCIONAL (SAFETY)

- **Documento:** `specs/security/safety-requirements.md`
- **Estado:** `APPROVED` v1.0
- **Ámbito:** evitar daño operativo derivado de la propia plataforma (falsos positivos, acciones erróneas, fallos de disponibilidad), distinto de la seguridad frente a atacantes.
- **Normas de referencia:** IEC 61508 (conceptos SIL, adaptados), IEC 62443-3-3 (SL), NIS2 (gestión de riesgo), CRA (seguridad del producto).

---

## 1. CONCEPTO: SAFETY ≠ SECURITY

| Dimensión | Pregunta | Documento |
| :--- | :--- | :--- |
| **Security** | ¿Puede un atacante hacer que la plataforma actúe mal? | `threat-model.md` |
| **Safety** | ¿Puede la plataforma, funcionando "correctamente", causar daño operativo? | este documento |
| **Privacy** | ¿Puede la plataforma exponer o retener datos indebidamente? | `data-protection.md` |

El caso típico de safety: la detección es correcta según la regla, la política permite, el conector responde `200`, y aun así se aísla el servidor equivocado porque el activo estaba mal inventariado. La mitigación no es criptográfica: es de diseño, verificación y reversibilidad.

---

## 2. PELIGROS IDENTIFICADOS

| ID | Peligro | Causa | Consecuencia | Severidad |
| :--- | :--- | :--- | :--- | :--- |
| `HZ-01` | Aislar el host equivocado | Inventario erróneo, IP compartida/NAT | Pérdida de servicio | Alta |
| `HZ-02` | Bloquear IP de infraestructura compartida | CDN, NAT corporativo, DNS público | Corte masivo | Alta |
| `HZ-03` | Deshabilitar cuenta de servicio crítica | Identidad no marcada como servicio | Parada de procesos | Alta |
| `HZ-04` | Cuarentena de fichero legítimo de sistema | Falso positivo de hash | Fallo de aplicación | Media |
| `HZ-05` | Aislar segmento OT | Acción A4 mal aprobada | Impacto físico | Crítica |
| `HZ-06` | Borrado/purga de evidencia necesaria | Retención mal configurada | Pérdida probatoria | Alta |
| `HZ-07` | Saturación por ingesta | Fuente mal configurada | Indisponibilidad del SIEM | Media |
| `HZ-08` | Fatiga de alertas → ignorar la real | Reglas ruidosas | Incidente no atendido | Alta |
| `HZ-09` | Dependencia de IA no disponible | Modelo caído | Pérdida de asistencia (no de función) | Baja |
| `HZ-10` | Rollback fallido | Adaptador no compensa | Estado inconsistente | Alta |
| `HZ-11` | Reloj desincronizado | NTP ausente | TOTP falla, timeline incoherente | Media |
| `HZ-12` | Migración fallida en producción | Sin ensayo | Indisponibilidad | Alta |

---

## 3. REQUISITOS DE SEGURIDAD FUNCIONAL

| ID | Requisito | Verificación |
| :--- | :--- | :--- |
| `SAF-01` | Toda acción con efecto externo debe declarar `verify` y `compensate`; sin ambos, nivel mínimo `A4` y aprobación dual | Validación de catálogo en test |
| `SAF-02` | La verificación debe ser **independiente** del `200 OK` del adaptador: consulta de estado real | Test con adaptador que miente (`200` pero no aplica) debe detectar `failed` |
| `SAF-03` | Blast radius obligatorio y rechazo total (nunca ejecución parcial) | `test_blast_radius.py` |
| `SAF-04` | Cooldown por target para evitar bucles de acción | `test_cooldown.py` |
| `SAF-05` | Toda acción guarda `before_state` suficiente para revertir | Inspección de `action_results` + test de compensación |
| `SAF-06` | Si el rollback falla, se genera alerta P1 y se bloquea nueva autonomía sobre ese target | `test_rollback_failure.py` |
| `SAF-07` | Acciones sobre activos con `criticality=5` requieren `A3+`, verificación y (si disruptivas) A4 | `test_critical_asset_gate.py` |
| `SAF-08` | Acciones sobre OT con `safety_function=true` están prohibidas en 1.0 | `test_ot_safety_interlock.py` |
| `SAF-09` | Con telemetría `stale` (>umbral) no se ejecuta autonomía | `test_stale_sensor.py` |
| `SAF-10` | El sistema debe operar completamente sin IA; la indisponibilidad de IA no degrada detección ni autonomía | Test con proveedor deshabilitado + suite completa |
| `SAF-11` | Toda decisión debe ser reproducible (`inputs_digest` + versión de política) | Test de determinismo ×100 |
| `SAF-12` | Las reglas de detección se prueban contra datos históricos antes de publicar | `POST /detection-rules/{id}/test` |
| `SAF-13` | La supresión de alertas requiere motivo y caducidad; no puede ser indefinida | `test_alert_lifecycle.py` |
| `SAF-14` | Retención y purga respetan `legal_hold` y nunca borran evidencia con custodia | `test_legal_hold.py` |
| `SAF-15` | Cambios de esquema se ensayan con `upgrade`/`downgrade` en BD limpia antes de release | `test_migrations.py` |
| `SAF-16` | El apagado drena trabajo en curso; no se pierde una ejecución aceptada | `test_graceful_shutdown.py` |
| `SAF-17` | El sistema expone estado de degradación con causa y `as_of` antes de permitir acciones | Test de estados degradados |
| `SAF-18` | Límite de acciones por hora/día por org con métricas y alerta al 80% | `test_action_budget.py` |
| `SAF-19` | El break-glass de freeze requiere dos aprobadores y TTL ≤60 min | `test_change_freeze.py` |
| `SAF-20` | Los cambios de criticidad de activos críticos (5→1) generan alerta de seguridad | `test_criticality_downgrade.py` |

---

## 4. BARRERAS DE DEFENSA EN PROFUNDIDAD (independientes)

```text
B1. Inventario validado (dedupe, zona, criticidad, propietario)
B2. Detección con regla versionada y test previo
B3. Contexto de activo (criticidad, exposición, OT/IT, frescura)
B4. Política determinista deny-by-default
B5. Límites (blast radius, budget, cooldown, freeze)
B6. Aprobación humana cuando corresponde
B7. Broker único con allowlist de capacidades
B8. Verificación independiente post-acción
B9. Rollback idempotente
B10. Kill switch humano
B11. Auditoría y revisión posterior
```

**Independencia:** cada barrera debe poder fallar sin que las demás dejen pasar la acción. Un test de "barrera única" desactiva cada capa y verifica que las restantes contienen el daño (`reports/safety-barriers.md`).

---

## 5. MODO SEGURO POR DEFECTO

| Situación | Comportamiento |
| :--- | :--- |
| Organización nueva | `A0`; ninguna acción |
| Sin política aplicable | `deny` |
| Sin telemetría fresca | `deny` |
| Conector con health desconocido | `deny connector_degraded` |
| Verificación no configurada | Acción no publicable |
| Rollback no configurado | Requiere A4 + plan de contingencia |
| Duda de alcance | Se elige la interpretación más restrictiva (constitución) |
| Error inesperado en el broker | `fail-closed`: se deniega y se alerta |

---

## 6. GESTIÓN DE INCIDENTES DE SAFETY

1. Detección: alerta P1 automática si `rollback_failed`, `verification_mismatch_rate > 5%` en 1 h, o kill switch activado.
2. Contención: kill switch del ámbito afectado; bloqueo de autonomía sobre los targets implicados.
3. Diagnóstico: reconstrucción con `decision_id`, `inputs_digest`, `action_results`, logs del adaptador.
4. Corrección: parche, nueva versión de política, test de regresión de safety.
5. Revisión: actualización de este documento y de `threat-model.md` si aplica.

---

## 7. MÉTRICAS DE SAFETY

| Métrica | Objetivo | Fuente |
| :--- | :--- | :--- |
| Acciones con verificación exitosa | ≥98% | `action_results` |
| Acciones revertidas por fallo | ≤2% | `action_results` |
| Rollbacks fallidos | 0 | `action_results` |
| Falsos positivos de detección (muestreo) | ≤5% | revisión semanal |
| Tiempo de halt del kill switch | ≤5 s p100 | medición en test |
| Acciones sobre activos críticos sin verificación | 0 | consulta |
| Ejecuciones perdidas por reinicio | 0 | reconciliación |

---

## 8. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-SAF-02` | Adaptador mentiroso detectado por verificación independiente | `tests/autonomy/test_lying_adapter.py` |
| `AC-SAF-06` | Rollback fallido bloquea autonomía y alerta P1 | `tests/autonomy/test_rollback_failure.py` |
| `AC-SAF-09` | Stale bloquea acción | `tests/autonomy/test_stale_sensor.py` |
| `AC-SAF-10` | Suite completa con IA deshabilitada | `scripts/verify_all.sh --no-ai` |
| `AC-SAF-11` | Determinismo de política ×100 | `tests/autonomy/test_policy_determinism.py` |
| `AC-SAF-15` | Migraciones up/down | `tests/integration/test_migrations.py` |
| `AC-SAF-16` | Drenaje en shutdown | `tests/integration/test_graceful_shutdown.py` |

## 9. EVIDENCIA

1. Informe `reports/safety-barriers.md` con el test de capa única.
2. Resultado de `AC-SAF-10` (operación sin IA).
3. Medición del kill switch con timestamps.
4. Test del adaptador que devuelve éxito falso.
5. Registro de un `rollback_failed` con alerta y bloqueo posterior.
