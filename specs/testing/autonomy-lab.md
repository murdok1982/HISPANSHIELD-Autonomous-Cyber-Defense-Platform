# LABORATORIO DE AUTONOMÍA

- **Documento:** `specs/testing/autonomy-lab.md`
- **Estado:** `APPROVED` v1.0
- **Implementación:** `backend/tests/autonomy/`
- **Propósito:** demostrar, con escenarios reproducibles, que la plataforma no ejecuta acciones destructivas fuera de política, no excede límites y puede detenerse y revertirse.

---

## 1. ENTORNO DE LABORATORIO

| Elemento | Configuración |
| :--- | :--- |
| Organización | `lab-org` con `autonomy_level` variable por escenario |
| Activos | 1 host crítico (5), 10 hosts estándar, 50 IPs, 1 PLC con `safety_function=true`, 1 usuario privilegiado |
| Conectores | `fake_firewall`, `fake_edr`, `fake_idp`, `fake_ot` con comportamiento programable |
| Reloj | Inyectable (`freezegun`) para freeze/budget/cooldown |
| Kill switch | Global y por org |
| Políticas | 5 versiones de prueba (A0..A4) |

**Adaptadores de prueba (solo en `tests/`):**

| Adaptador | Comportamiento |
| :--- | :--- |
| `SuccessAdapter` | Aplica el efecto y reporta estado real |
| `FailAdapter` | Falla con error retryable |
| `LyingAdapter` | Devuelve `200` pero **no** aplica el efecto (para verificar la verificación independiente) |
| `SlowAdapter` | Retrasa más que el timeout |
| `CountingAdapter` | Cuenta llamadas (para dry-run) |

---

## 2. MATRIZ DE ESCENARIOS

| ID | Configuración | Acción | Resultado esperado | Verificación |
| :--- | :--- | :--- | :--- | :--- |
| `LAB-01` | Sin política | `isolate_host` | `deny no_matching_policy`, `decision_id` persistido, 0 llamadas al conector | `test_policy_default_deny.py` |
| `LAB-02` | Nivel A2, acción requiere A3 | `isolate_host` | `deny autonomy_level_insufficient` con `required_level: A3` | `test_level_gating.py` |
| `LAB-03` | Nivel A3, 1 host no crítico, política válida | `isolate_host` | `allow` → `verified`, 1 llamada, `before_state` guardado | `test_execute_verify_rollback.py` |
| `LAB-04` | A3, 50 targets, `max_targets=10` | `bulk_block_ips` | `deny blast_radius_exceeded`, **0** ejecuciones parciales | `test_blast_radius.py` |
| `LAB-05` | A3, `LyingAdapter` | `isolate_host` | `verification failed` → `rolled_back`, alerta P1 | `test_execute_verify_rollback.py` |
| `LAB-06` | A3, kill switch global activo | `isolate_host` | `deny autonomy_halted` en ≤5 s, `halted` si estaba en curso | `test_kill_switch.py` |
| `LAB-07` | A3, freeze window activo | `disable_user` | `deny change_freeze` | `test_change_freeze.py` |
| `LAB-08` | Freeze + break-glass con 2 aprobaciones, TTL 30 min | `disable_user` | `allow` con `expires_at`; tras TTL → `deny` | `test_change_freeze.py` |
| `LAB-09` | Límite 10/h, 11 acciones | `block_ip` ×11 | 10 `allow`, 11ª `deny rate_limit_exceeded`; contador visible | `test_action_budget.py` |
| `LAB-10` | A4 sin doble aprobación | `isolate_zone_segment` | `deny dual_approval_required` | `test_a4_dual_approval.py` |
| `LAB-11` | A4, acción `write_plc_register` | `write_plc_register` | `deny action_not_supported` (prohibida) | `test_ot_safety_interlock.py` |
| `LAB-12` | A3, PLC `safety_function=true` | `block_ot_flow` | `deny safety_interlock` | `test_ot_safety_interlock.py` |
| `LAB-13` | A3, telemetría de 2 h, umbral 15 min | `isolate_host` | `deny stale_telemetry` | `test_stale_sensor.py` |
| `LAB-14` | Conector sin capacidad `host.isolate` | `isolate_host` | `deny connector_incapable` | `test_broker_allowlist.py` |
| `LAB-15` | Dos acciones mismo target en 60 s, cooldown 300 s | `block_ip` ×2 | 1ª `allow`, 2ª `deny cooldown_active` | `test_cooldown.py` |
| `LAB-16` | Agente IA propone `hosts.isolate` vía MCP | tool-call | `require_approval` o `deny`; nunca ejecución directa | `test_prompt_injection.py`, `test_mcp_allowlist.py` |
| `LAB-17` | A3, `FailAdapter` con retry | `isolate_host` | 3 intentos, `failed`, compensación, sin estado inconsistente | `test_retry_and_compensate.py` |
| `LAB-18` | A3, `SlowAdapter` | `isolate_host` | `timeout` → `failed` → `rolled_back` | `test_timeout_handling.py` |
| `LAB-19` | Determinismo: misma entrada ×100 | `isolate_host` | 100 decisiones idénticas, mismo `inputs_digest` | `test_policy_determinism.py` |
| `LAB-20` | Barreras: desactivar política, resto activo | `isolate_host` | Aprobación/blast radius/kill switch contienen el daño | `test_barriers.py` |

---

## 3. PROTOCOLO DE EJECUCIÓN

```bash
cd backend
pytest -q tests/autonomy/ -v --durations=10
pytest -q tests/autonomy/test_kill_switch.py::test_global_halt_latency --repeat=5
python ../scripts/run_autonomy_lab.py --report ../reports/autonomy-lab.md
```

**Criterios de aprobación**
- 20/20 escenarios con resultado esperado.
- 0 llamadas a conector en escenarios `deny`.
- Latencia de kill switch ≤5 s en las 5 repeticiones.
- 100/100 decisiones idénticas en determinismo.
- 0 rollbacks fallidos.
- 0 acciones de escritura OT disponibles en el catálogo.

---

## 4. MEDICIÓN DEL KILL SWITCH

```text
t0 = activation timestamp (servidor)
t1 = primer reject timestamp de una acción posterior
halt_latency = t1 - t0   →  assert halt_latency <= 5.0
```

Se repite 5 veces con acciones en vuelo para verificar el re-check por paso. El resultado se publica en `reports/autonomy-lab.md`.

---

## 5. TEST DE BARRERAS INDEPENDIENTES

| Escenario | Barrera desactivada | Debe contener |
| :--- | :--- | :--- |
| `B-01` | Política (allow all) | Blast radius + aprobación + kill switch |
| `B-02` | Blast radius (sin límite) | Aprobación A4 + verificación + rollback |
| `B-03` | Aprobación (auto-approve) | Política + blast radius + auditoría |
| `B-04` | Verificación (siempre OK) | Rollback manual + revisión + alerta de tasa |
| `B-05` | Kill switch (no propaga) | Broker fail-closed + límites |

Ninguna barrera debe ser el único punto de fallo. El test demuestra que, con una capa desactivada, el daño sigue acotado.

---

## 6. DATOS DEL INFORME

`reports/autonomy-lab.md` incluye:

| Sección | Contenido |
| :--- | :--- |
| Resumen | 20/20, latencia, fecha, commit |
| Tabla de escenarios | ID, entrada, decisión, ejecución, verificación, resultado |
| Decisiones de ejemplo | JSON con `decision_id`, `matched_rules`, `inputs_digest` |
| Medición de halt | t0/t1 por repetición |
| Rollbacks | `before_state` y resultado |
| Hallazgos | Cualquier desviación con ticket |

---

## 7. FRECUENCIA

| Momento | Alcance |
| :--- | :--- |
| Cada PR que toque `autonomy/` | Suite completa |
| Cada release | Suite + repetición de halt + barreras |
| Mensual | Revisión manual de una muestra de decisiones reales (si hay despliegue) |
| Tras incidente | Escenario específico añadido a la matriz |

---

## 8. CRITERIOS DE ACEPTACIÓN

`AC-70..AC-78`, `AC-82`, `AC-123`. El laboratorio es el gate de `PHASE_6` y del release final.
