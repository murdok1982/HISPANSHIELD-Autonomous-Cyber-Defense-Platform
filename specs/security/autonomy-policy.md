# POLÍTICA DE AUTONOMÍA Y RESPUESTA GOBERNADA

- **Documento:** `specs/security/autonomy-policy.md`
- **Estado:** `APPROVED` v1.0 — **normativo**
- **Implementación:** `backend/app/autonomy/{policy,evaluator,levels,blast_radius,broker,verifier,rollback,kill_switch,budget,change_window,safety}.py`
- **ACs globales:** `AC-70..AC-78`

---

## 1. OBJETIVO

Permitir que la plataforma actúe por sí misma —bloquear, aislar, deshabilitar, poner en cuarentena— sin que ello dependa de la prudencia de un modelo de lenguaje ni de la disponibilidad de un operador, y sin que exista un camino por el que una acción destructiva ocurra sin decisión explícita, límites, verificación y posibilidad de reversión.

## 2. NIVELES DE AUTONOMÍA

| Nivel | Nombre | Qué puede hacer el sistema | Aprobación | Verificación | Rollback |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `A0` | Observe | Detectar, alertar, recomendar. **Ninguna** acción con efecto externo. | — | — | — |
| `A1` | Recommend | Proponer acción con parámetros y simulación; el humano ejecuta. | Humana explícita | Humana | Humana |
| `A2` | Act with approval | Ejecutar tras aprobación de un `admin`/`owner` distinto del solicitante. | 1 aprobador | Automática | Obligatorio |
| `A3` | Act within policy | Ejecutar sin aprobación previa si la política lo permite, con límites y revisión posterior. | 0 (política) | Automática ≤60 s | Obligatorio |
| `A4` | Act on high impact | Acciones disruptivas o no reversibles: segmentos OT, cuentas privilegiadas, cambios masivos. | **2 aprobadores** + time-box ≤30 min | Automática + revisión humana | Obligatorio o plan de contingencia aprobado |

**Regla de acumulación:** un nivel habilita sus capacidades y las inferiores. El nivel efectivo es el mínimo entre: nivel configurado en la organización, nivel de la política aplicable y nivel exigido por la acción.

**Nivel por defecto de una organización nueva: `A0`.** Subir de nivel requiere acción explícita de `owner`, con confirmación escrita y auditoría.

---

## 3. CATÁLOGO DE ACCIONES

| Acción | Clase | Nivel mínimo | Reversible | Verificación | Compensación | Blast radius por defecto |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `notify_operator` | comunicación | `A0` | Sí | entrega registrada | — | sin límite |
| `create_ticket` | proceso | `A1` | Sí | ticket existe | cerrar ticket | 100 |
| `enrich_asset` | datos | `A1` | Sí | campo actualizado | restaurar valor previo | 1 |
| `tag_asset` | datos | `A1` | Sí | etiqueta presente | quitar etiqueta | 50 |
| `block_ip` | red | `A2` | Sí | regla presente + tráfico 0 | `unblock_ip` | 1 IP / 10 |
| `unblock_ip` | red | `A2` | Sí | regla ausente | re-bloquear | 1 |
| `disable_user` | identidad | `A2` | Sí | login falla / estado disabled | `enable_user` | 1 |
| `revoke_sessions` | identidad | `A2` | No (re-login) | sesiones 0 | — (re-auth) | 1 usuario |
| `quarantine_file` | endpoint | `A2` | Sí | hash en cuarentena | `restore_file` | 1 fichero |
| `isolate_host` | endpoint | `A3` | Sí | host sin red salvo mgmt | `unisolate_host` | 1 host / 5 |
| `block_domain` | red | `A3` | Sí | resolución falla | `unblock_domain` | 1 dominio |
| `block_ot_flow` | OT | `A3` | Sí | flujo ausente | `restore_ot_flow` | 1 flujo |
| `isolate_zone_segment` | OT | `A4` | Parcial | segmento aislado | `restore_segment` | 1 segmento |
| `disable_privileged_account` | identidad | `A4` | Sí | cuenta disabled | `enable_account` | 1 |
| `bulk_block_ips` | red | `A4` | Sí | N reglas | `bulk_unblock` | 50 |
| `write_plc_register` | OT | **prohibido** | No | — | — | — |
| `shell_command` | host | **prohibido** | No | — | — | — |

Cualquier acción no listada → `403 action_not_supported`. Las acciones prohibidas no pueden habilitarse por configuración en 1.0.

---

## 4. ESQUEMA DE POLÍTICA

```json
{
  "id": "0192b0...",
  "organization_id": "0192a0...",
  "name": "contain-endpoint-compromise",
  "version": 4,
  "priority": 100,
  "enabled": true,
  "match": {
    "action_types": ["isolate_host", "quarantine_file"],
    "asset_kinds": ["host", "cloud_resource"],
    "asset_criticality_max": 4,
    "asset_tags_any": ["soc-managed", "workstation"],
    "purdue_level_max": null,
    "safety_function": false,
    "telemetry_max_age_seconds": 900,
    "connector_capabilities_all": ["host.isolate"],
    "source": ["detection_rule", "agent", "human"]
  },
  "requirements": {
    "autonomy_level": "A3",
    "approvals": 0,
    "dual_approval": false,
    "time_box_minutes": null,
    "change_freeze_exempt": false,
    "break_glass_only": false
  },
  "limits": {
    "max_targets": 5,
    "max_actions_per_hour": 10,
    "max_actions_per_day": 40,
    "cooldown_seconds": 300
  },
  "verification": {
    "required": true,
    "timeout_seconds": 60,
    "criterion": "host.network_isolated == true"
  },
  "rollback": {"required": true, "on_verification_failure": true, "on_operator_request": true},
  "notify": ["soc@example.eu"],
  "created_by": "0192u1...",
  "created_at": "2026-11-20T09:00:00Z",
  "published_at": "2026-11-20T09:05:00Z"
}
```

**Validación:** `match` no puede quedar vacío (evita "allow all"); `limits.max_targets` obligatorio; `verification.required=true` para cualquier acción con `reversible=false`; `A4` exige `dual_approval=true` y `time_box_minutes ≤30`.

---

## 5. ORDEN DE EVALUACIÓN (determinista)

```text
1. ¿Existe kill switch activo (global | org | connector | asset)?        → deny autonomy_halted
2. ¿La organización está activa y el nivel de autonomía ≥ requerido?      → deny autonomy_level_insufficient
3. ¿La acción existe y está permitida en el catálogo?                     → deny action_not_supported
4. ¿El conector declara la capacidad y está healthy?                      → deny connector_incapable | connector_degraded
5. ¿La telemetría del target es fresca (< umbral)?                        → deny stale_telemetry
6. ¿Safety interlock OT satisfecho?                                       → deny safety_interlock
7. ¿Ventana de cambio congelado? (salvo break_glass aprobado)             → deny change_freeze
8. ¿Blast radius dentro del límite?                                       → deny blast_radius_exceeded
9. ¿Presupuesto horario/diario disponible?                                → deny rate_limit_exceeded
10. ¿Cooldown del target respetado?                                       → deny cooldown_active
11. Seleccionar política de mayor prioridad que case; si ninguna → deny no_matching_policy
12. ¿Requiere aprobación (A2, A4, o política)?                            → require_approval
13. allow
```

El resultado se persiste **antes** de cualquier ejecución:

```json
{
  "decision_id": "0192c1...",
  "decision": "deny",
  "reason": "blast_radius_exceeded",
  "policy_id": "0192b0...",
  "policy_version": 4,
  "action_type": "isolate_host",
  "targets": ["0192as..."],
  "evaluated_at": "2026-11-26T10:12:00Z",
  "matched_rules": [{"policy_id": "0192b0...", "priority": 100, "matched": false, "failed_condition": "limits.max_targets"}],
  "inputs_digest": "sha256:..."
}
```

`inputs_digest` permite reproducir la decisión: mismo digest + misma versión de política ⇒ mismo resultado (test de determinismo).

---

## 6. EJECUCIÓN: EL BROKER

```text
ActionRequest
  → evaluate() → decision
  → si require_approval: crear approval, estado waiting_approval, notificar
  → si allow:
       action = actions.create(state=executing, decision_id)
       for each target (secuencial, no paralelo salvo acción atómica):
           re-check kill switch (obligatorio por paso)
           connector.execute(action, params, idempotency_key=action.id+target)
           persist action_result(attempt, response_hash, duration)
       verifier.verify() dentro de timeout
       si verified: state=verified, audit
       si failed: rollback.run() → state=rolled_back, audit, alerta
```

**Reglas**
- El broker es el **único** componente con permiso para invocar acciones de conector. Ningún servicio, agente o endpoint llama directamente a un adaptador de acción.
- Re-evaluación de kill switch antes de **cada** target (no solo al encolar) garantiza halt ≤5 s.
- `idempotency_key = action_id + ":" + target_id`.
- Máximo 50 targets por acción (por encima exige dividir en acciones con aprobación).
- Timeout global de acción: 5 min; verificación: 60 s por defecto.

---

## 7. KILL SWITCHES

| Ámbito | Quién | Efecto | Propagación |
| :--- | :--- | :--- | :--- |
| Global | `platform_admin` | Detiene toda autonomía de la instancia | `NOTIFY kill_switch_changed` + caché invalidada |
| Organización | `owner`, `admin` | Detiene autonomía de la org | Igual |
| Conector | `admin` | Detiene acciones que usan ese conector | Igual |
| Activo | `responder`+ | Detiene acciones sobre un activo | Igual |
| Acción individual | `responder`+ | Cancela una acción en curso | Marcado `halted` |

**Contrato de tiempo:** desde la activación hasta el rechazo de la siguiente acción ≤5 s (`AC-74`). Las acciones en curso se marcan `halted` en el siguiente punto de control (antes de cada target/paso). El estado se muestra en topbar y en `/admin`.

Un kill switch **no** puede ser desactivado por un agente ni por un token de servicio. Solo un humano con permiso `killswitch.activate`.

---

## 8. BLAST RADIUS, PRESUPUESTO Y VENTANAS

| Control | Regla | Default |
| :--- | :--- | :--- |
| Blast radius | Máximo de targets por acción; rechazo **total**, nunca parcial | 1 host, 1 IP, 1 usuario, 5 hosts (A3) |
| Presupuesto horario | Acciones permitidas por clase de activo y hora | 10/h |
| Presupuesto diario | Tope diario por org | 40/día |
| Cooldown | Tiempo mínimo entre acciones sobre el mismo target | 300 s |
| Ventana de cambio | Franjas congeladas (fin de semana, cierre fiscal, campaña) | configurable |
| Break-glass | Excepción a freeze con doble aprobación y TTL | ≤60 min |
| Límite de acciones simultáneas | Por org | 5 |

Al exceder cualquier límite: `deny` con `reason` específico y métrica `hs_autonomy_denied_total{reason}`.

---

## 9. VERIFICACIÓN Y ROLLBACK

- **Criterio declarado por acción** (no genérico): `host.network_isolated`, `ip.rule_present`, `user.status == disabled`, `file.quarantined`.
- **Fuente de verificación independiente** del adaptador que ejecutó: consulta de estado, no el `200 OK` de la acción.
- `inconclusive` se trata como fallo (conservador).
- **Rollback** idempotente; si falla, estado `rollback_failed` con alerta P1 y requiere intervención humana.
- Toda acción guarda `before_state` para permitir compensación aunque el adaptador no la soporte nativamente (p.ej. snapshot de regla de firewall).

---

## 10. A4: DOBLE APROBACIÓN Y OT

Requisitos acumulativos para `A4`:
1. `dual_approval=true` con dos aprobadores distintos, ninguno el solicitante, al menos uno `owner`.
2. `time_box_minutes` entre 5 y 30; al expirar, la autorización caduca.
3. Justificación ≥80 caracteres y referencia a incidente.
4. Safety interlock OT satisfecho (si aplica): `safety_function=false` o ventana de mantenimiento aprobada.
5. Kill switch global inactivo.
6. Verificación obligatoria y plan de contingencia documentado.

Sin cualquiera de estos → `deny` con `reason` específico.

---

## 11. MATRIZ DEL LABORATORIO (resumen de `specs/testing/autonomy-lab.md`)

| Escenario | Config | Acción | Resultado esperado |
| :--- | :--- | :--- | :--- |
| `LAB-01` | sin política | `isolate_host` | `deny no_matching_policy` |
| `LAB-02` | A2, acción A3 | `isolate_host` | `deny autonomy_level_insufficient` |
| `LAB-03` | A3, 1 host, reversible | `isolate_host` | `allow` → `verified` |
| `LAB-04` | A3, 50 hosts, límite 10 | `bulk_block_ips` | `deny blast_radius_exceeded` |
| `LAB-05` | A3, verificación falla | `isolate_host` | `rolled_back` + alerta |
| `LAB-06` | kill switch global | cualquier | `deny autonomy_halted` ≤5 s |
| `LAB-07` | freeze activo | `disable_user` | `deny change_freeze` |
| `LAB-08` | freeze + break-glass aprobado | `disable_user` | `allow` con TTL |
| `LAB-09` | 11 acciones en 1 h, límite 10 | `block_ip` | `deny rate_limit_exceeded` |
| `LAB-10` | A4 sin doble aprobación | `isolate_zone_segment` | `deny dual_approval_required` |
| `LAB-11` | OT `safety_function=true` | `write_plc_register` | `deny action_not_supported` |
| `LAB-12` | telemetría 2 h | `isolate_host` | `deny stale_telemetry` |
| `LAB-13` | conector sin capacidad | `block_ip` | `deny connector_incapable` |
| `LAB-14` | agente propone tool destructiva | `hosts.isolate` vía MCP | `require_approval` o `deny`, nunca ejecución directa |
| `LAB-15` | dos acciones sobre mismo target en 60 s | `block_ip` ×2 | segunda `deny cooldown_active` |

---

## 12. FALLOS CONOCIDOS Y MITIGACIONES

| Fallo | Impacto | Mitigación |
| :--- | :--- | :--- |
| Verificación falsa positiva (adaptador dice OK) | Se cree contenido cuando no lo está | Verificación independiente + muestreo + alerta si tasa de verified cae |
| Kill switch no propagado | Acción continúa | Re-check por paso + `NOTIFY` + test de latencia |
| Política demasiado amplia | Acción sobre activo crítico | `match` obligatorio, límites, revisión por `owner`, test de política |
| Aprobación coludida | Dos personas malintencionadas | Separación de solicitante, auditoría, revisión posterior |
| Rollback falla | Estado inconsistente | `rollback_failed` + P1 + runbook manual |
| Fatiga de aprobaciones | Se aprueba sin leer | Resumen de impacto obligatorio, límite de aprobaciones/hora, métricas de tiempo de decisión |

---

## 13. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-70` | Deny sin política, con `decision_id` | `tests/autonomy/test_policy_default_deny.py` |
| `AC-71` | Gating de nivel | `tests/autonomy/test_level_gating.py` |
| `AC-72` | Ejecutar, verificar, revertir | `tests/autonomy/test_execute_verify_rollback.py` |
| `AC-73` | Blast radius sin ejecución parcial | `tests/autonomy/test_blast_radius.py` |
| `AC-74` | Kill switch ≤5 s | `tests/autonomy/test_kill_switch.py::test_global_halt_latency` |
| `AC-75` | Freeze y break-glass | `tests/autonomy/test_change_freeze.py` |
| `AC-76` | Presupuesto por hora | `tests/autonomy/test_action_budget.py` |
| `AC-77` | Auditoría completa de la acción | `tests/autonomy/test_action_audit.py` |
| `AC-78` | A4 doble aprobación y OT | `tests/autonomy/test_a4_dual_approval.py` |
| `AC-82` | Safety interlock OT | `tests/autonomy/test_ot_safety_interlock.py` |

## 14. EVIDENCIA

1. `pytest -q backend/tests/autonomy/` con informe de `reports/autonomy-lab.md`.
2. Decisión JSON `deny` con `matched_rules` y `inputs_digest`.
3. Medición de latencia de kill switch (timestamps) ≤5 s.
4. Acción `rolled_back` con `before_state` y verificación fallida.
5. Test de determinismo: mismo digest ⇒ misma decisión en 100 ejecuciones.
