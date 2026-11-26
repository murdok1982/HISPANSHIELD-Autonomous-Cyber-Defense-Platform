# MANUAL DEL SOC

- **Documento:** `docs/soc-manual.md`
- **Estado:** `APPROVED` v1.0
- **Audiencia:** jefe de SOC, analistas T1/T2, respondedores
- **Pantallas:** `/soc`, `/threats/live`, `/incidents`, `/siem`, `/assets`, `/threat-intel`, `/soar`

---

## 1. MODELO OPERATIVO

| Turno | Personal | Responsabilidad |
| :--- | :--- | :--- |
| T1 | 1-2 analistas | Triaje inicial, descarte justificado, enriquecimiento |
| T2 | 1 analista senior | Investigación, correlación, contención propuesta |
| Respondedor | 1 (puede ser T2) | Ejecución de acciones, comunicación |
| Jefe de turno | 1 | Priorización, aprobaciones, escalado |

**Regla de oro:** ninguna alerta se cierra sin motivo tipificado. "No es nada" no es un motivo.

---

## 2. RUTINA DE TURNO

### Inicio (15 min)
1. Revisar `/soc`: alertas `P1/P2` abiertas y sin asignar.
2. Revisar banner de autonomía y estado del kill switch.
3. Revisar `/integrations`: conectores `degraded`/`failed`.
4. Revisar `/admin`: salud, cola, disco.
5. Revisar `/incidents`: SLA próximos a vencer (75%).

### Durante el turno
- Cola ordenada por `risk_score`, no por hora.
- Toda alerta pasa por: validar → enriquecer → decidir → documentar.
- Las acciones `A3` se revisan post-ejecución; las `A4` requieren dos aprobadores.

### Cierre
1. Alertas abiertas con dueño y nota.
2. Incidentes con timeline actualizado.
3. Handover escrito: riesgos abiertos, acciones ejecutadas, conectores degradados.

---

## 3. TRIAJE DE ALERTAS

```text
1. ¿El activo existe y es correcto? → /assets (drawer)
2. ¿La telemetría es fresca? → badge stale
3. ¿La regla es la adecuada? → ver versión y prueba
4. ¿Hay contexto CTI? → /threat-intel (IOC, actor)
5. ¿Hay vulnerabilidad explotable? → /vulnerabilities
6. Decisión: falso positivo | duplicado | incidente | supresión temporal
```

| Resultado | Acción | Registro |
| :--- | :--- | :--- |
| Falso positivo | Marcar con motivo y evidencia; proponer ajuste de regla | `alert.status=false_positive` + comentario |
| Duplicado | Vincular a la alerta principal | `dedupe_key` |
| Incidente | Promover con severidad | `POST /alerts/{id}/promote` |
| Supresión | Motivo ≥20 caracteres y caducidad ≤30 días | `alert.suppressed` |

**Prohibido:** suprimir sin caducidad, cerrar sin motivo, cambiar severidad sin justificación.

---

## 4. SEVERIDAD Y SLA

| Severidad | Criterio | Respuesta | Resolución |
| :--- | :--- | :--- | :--- |
| `P1` | Impacto crítico, servicio esencial, OT, datos personales masivos | 15 min | 4 h |
| `P2` | Activo crítico comprometido, propagación probable | 30 min | 8 h |
| `P3` | Activo estándar, contención local | 4 h | 3 d |
| `P4` | Bajo impacto, sin evidencia de éxito | 1 d | 10 d |
| `P5` | Informativo | 5 d | 30 d |

La severidad se calcula con la matriz impacto×urgencia y se ajusta por criticidad del activo y datos personales. El cambio manual requiere motivo.

---

## 5. INVESTIGACIÓN (T2)

### Preguntas guía
1. ¿Qué activo? ¿crítico? ¿expuesto a Internet? ¿OT?
2. ¿Qué identidad? ¿privilegiada? ¿MFA? ¿sesiones activas?
3. ¿Qué vector? ¿phishing, explotación, credenciales, insider?
4. ¿Qué alcance? ¿otros activos con el mismo IOC/hash?
5. ¿Qué evidencia? eventos, procesos, conexiones, archivos.
6. ¿Qué contención es proporcional y reversible?

### Consultas útiles (`/siem`)
```text
src_endpoint.ip = "198.51.100.23" AND severity_id >= 3
actor.user.name = "jdoe" AND class_uid = 3002
observables.value = "evil.example" AND time >= now-7d
```
Guardar la consulta con nombre y enlazarla al incidente.

---

## 6. USO DE LA AUTONOMÍA

| Nivel | Qué espera el SOC | Qué debe revisar |
| :--- | :--- | :--- |
| `A0` | Solo alertas | Nada operativo |
| `A1` | Recomendaciones | Validar antes de ejecutar |
| `A2` | Acciones con aprobación | Impacto, blast radius, reversibilidad |
| `A3` | Acciones automáticas | Post-revisión de `verified`/`rolled_back` |
| `A4` | Acciones de alto impacto | Doble aprobación, time-box, plan de contingencia |

**Antes de aprobar una acción:**
1. Leer el resumen de impacto (activos, criticidad, blast radius).
2. Verificar que la acción es reversible o que hay plan.
3. Comprobar que no hay cambio congelado.
4. Aprobar o denegar con motivo; nunca "aprobar todo".

**Si algo va mal:** kill switch (global/org/conector/activo) → verificar halt → rollback → incidente de safety.

---

## 7. PLAYBOOKS FRECUENTES

| Escenario | Playbook | Nivel |
| :--- | :--- | :--- |
| Fuerza bruta RDP | `block_source_ip` + `notify` | `A2` |
| Malware confirmado en host | `isolate_host` + `quarantine_file` | `A3` |
| Credencial comprometida | `disable_user` + `revoke_sessions` | `A2` |
| Phishing masivo | `block_domain` + `search_and_purge` (ticket) | `A3` |
| Exposición cloud | `create_ticket` + `tag_asset` | `A1` |
| Anomalía OT | `notify_operator` + `block_ot_flow` | `A3`/`A4` |

---

## 8. MÉTRICAS DEL TURNO

| Métrica | Objetivo | Dónde |
| :--- | :--- | :--- |
| Alertas sin asignar al cierre | 0 | `/soc` |
| Tiempo medio de triaje | ≤15 min | `/incidents` |
| Falsos positivos | ≤5% (muestreo) | revisión semanal |
| SLA incumplidos | 0 | `/overview` |
| Acciones revertidas | ≤2% | `/audit` |
| Aprobaciones >10 min sin decisión | 0 | `/soar` |

---

## 9. COMUNICACIÓN Y ESCALADO

| Situación | A quién | Plazo |
| :--- | :--- | :--- |
| P1 confirmado | CISO + dirección + DPO (si datos) | 15 min |
| Afectación a servicio esencial | Responsable del servicio | 30 min |
| Posible notificación NIS2 | DPO/legal | 24 h |
| Acción autónoma fallida | Arquitectura + seguridad | 1 h |
| Conector crítico caído | Plataforma | 1 h |

---

## 10. QUÉ NO HACER

1. No cerrar alertas en masa para "limpiar" la cola.
2. No aprobar acciones sin leer el impacto.
3. No desactivar el kill switch sin causa documentada.
4. No ejecutar comandos en sistemas del cliente desde la plataforma (no es un shell).
5. No copiar datos de evidencia fuera de los canales autorizados.
6. No ignorar un badge `stale` o `degraded`.
7. No cambiar reglas en producción sin test previo.

---

## 11. CHECKLIST DE CALIDAD DE TURNO

- [ ] Todas las alertas P1/P2 tienen dueño y decisión.
- [ ] Incidentes con timeline y evidencias.
- [ ] Acciones autónomas revisadas (verificadas o revertidas).
- [ ] Conectores degradados reportados.
- [ ] Handover escrito y leído por el siguiente turno.
- [ ] Sin supresiones sin caducidad.
