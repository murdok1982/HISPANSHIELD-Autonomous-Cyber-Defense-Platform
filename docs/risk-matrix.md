# MATRIZ DE RIESGOS

- **Documento:** `docs/risk-matrix.md`
- **Estado:** `APPROVED` v1.0
- **Escala:** Probabilidad `1-5` · Impacto `1-5` · Exposición = P×I
- **Umbrales:** `≥15` crítico (rojo) · `8-14` alto (ámbar) · `4-7` medio (amarillo) · `≤3` bajo (verde)

---

## 1. MAPA DE CALOR

| Impacto ↓ / Prob → | 1 | 2 | 3 | 4 | 5 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **5 Catastrófico** | 5 | 10 | 15 | 20 | 25 |
| **4 Mayor** | 4 | 8 | 12 | 16 | 20 |
| **3 Moderado** | 3 | 6 | 9 | 12 | 15 |
| **2 Menor** | 2 | 4 | 6 | 8 | 10 |
| **1 Insignificante** | 1 | 2 | 3 | 4 | 5 |

---

## 2. RIESGOS DEL PROYECTO

| ID | Riesgo | Categoría | P | I | Exp | Nivel | Owner | Mitigación | Señal de materialización |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- | :--- | :--- | :--- |
| `R-01` | Acción autónoma destructiva no autorizada | Seguridad/Autonomía | 2 | 5 | 10 | Alto | Arquitectura | Deny-by-default, blast radius, aprobaciones, kill switch, rollback | Acción sin `decision_id` o con `deny` ejecutada |
| `R-02` | Fuga cross-tenant | Seguridad | 2 | 5 | 10 | Alto | Arquitectura | Scoping en repositorio, 404 uniforme, suite de aislamiento | Test de aislamiento rojo; ID ajeno en respuesta |
| `R-03` | Contaminación de licencia con producto hermano | Legal | 2 | 4 | 8 | Alto | Dirección | Clean-room, ADR-012, revisión de originalidad | Similitud detectada en revisión |
| `R-04` | Vulnerabilidad HIGH en auth propia | Seguridad | 3 | 4 | 12 | Alto | Seguridad | Tests adversariales, revisión, MFA, rotación | Hallazgo en auditoría |
| `R-05` | Rendimiento de SIEM insuficiente | Técnico | 3 | 3 | 9 | Medio | Arquitectura | Bench temprano, particiones, índices, guard de queries | p95 >1 s; backlog de ingesta |
| `R-06` | Pérdida de eventos aceptados | Datos | 2 | 4 | 8 | Alto | Arquitectura | Outbox, cola durable, `202` tras commit, edge WAL | Discrepancia entre `202` y eventos |
| `R-07` | Corrupción o pérdida de evidencia | Legal/Integridad | 2 | 5 | 10 | Alto | Operaciones | SHA-256, legal hold, backup, verificación | Hash no coincide; backup fallido |
| `R-08` | IA alucina o filtra datos | Seguridad/IA | 3 | 3 | 9 | Medio | Arquitectura | Sin autoridad, citas, aislamiento RAG, guardrails | Respuesta sin cita o con dato de otra org |
| `R-09` | Prompt injection ejecuta acción | Seguridad/IA | 3 | 4 | 12 | Alto | Seguridad | Allowlist MCP, política, aprobación, corpus | Tool-call no autorizada detectada |
| `R-10` | Despliegue no verificable (sin Docker/LLM) | Entrega | 5 | 3 | 15 | **Crítico** | Arquitectura | Validación estática, runbook, dobles en tests, estados honestos | Manifiesto inválido; instrucción no reproducible |
| `R-11` | Fase no cierra (gate rojo recurrente) | Ejecución | 3 | 3 | 9 | Medio | Orquestador | Circuit Breaker, ADR, simplificación | 3/3 fallos en una tarea |
| `R-12` | Deriva de alcance | Gestión | 3 | 3 | 9 | Medio | Producto | Scope con exclusiones, control de cambios | Tareas sin AC |
| `R-13` | Deuda por monolito | Técnico | 2 | 3 | 6 | Medio | Arquitectura | Fronteras estrictas, camino de extracción | Imports cruzados; cambios acoplados |
| `R-14` | Dependencia con licencia incompatible | Legal | 2 | 4 | 8 | Alto | Arquitectura | Allowlist, SBOM, revisión | `check_licenses.py` falla |
| `R-15` | Dependencia con CVE explotable | Seguridad | 3 | 4 | 12 | Alto | Seguridad | `pip-audit`, pin, parcheo | CVE HIGH en auditoría |
| `R-16` | Fatiga de alertas | Operación | 4 | 3 | 12 | Alto | Producto | Dedupe, tuning, supresión con motivo, métricas | Ratio alertas/incidentes alto |
| `R-17` | Error humano en aprobación | Operación | 4 | 3 | 12 | Alto | Producto | Resumen de impacto, límites, separación de funciones | Aprobaciones en <5 s repetidas |
| `R-18` | Exactitud normativa del mapeo | Cumplimiento | 3 | 4 | 12 | Alto | Cumplimiento | Revisión experta, versionado, fuente normativa | Gap detectado por auditor |
| `R-19` | Fuga de secretos en logs/backup | Seguridad | 3 | 5 | 15 | **Crítico** | Seguridad | Redacción probada, cifrado, `gitleaks` | Secreto detectado en log/artefacto |
| `R-20` | Falta de adopción por complejidad | Producto | 3 | 3 | 9 | Medio | Producto | Onboarding guiado, defaults seguros, manuales | Abandono en piloto |
| `R-21` | Insiders con `platform_admin` | Seguridad | 2 | 5 | 10 | Alto | Seguridad | Break-glass con TTL y auditoría, sin acceso por defecto | Acceso sin ticket |
| `R-22` | Reloj desincronizado | Operación | 3 | 2 | 6 | Medio | Operaciones | NTP obligatorio, detección de skew | TOTP falla; timeline incoherente |
| `R-23` | Backup no restaurable | Continuidad | 3 | 5 | 15 | **Crítico** | Operaciones | Drill mensual, verificación de conteos | Drill falla |
| `R-24` | Migración fallida en producción | Continuidad | 2 | 4 | 8 | Alto | Arquitectura | Ensayo up/down, backup previo, rollback | `alembic current != head` |

---

## 3. RIESGOS ACEPTADOS (RESIDUALES)

| ID | Riesgo | Residual | Justificación | Revisión |
| :--- | :--- | :--- | :--- | :--- |
| `RA-01` | Sin federación SAML/OIDC | Medio | Alcance 1.0, interfaz preparada | Cada release |
| `RA-02` | Sin HSM | Medio | Custodia de clave por el cliente | Si un cliente lo exige |
| `RA-03` | Sin HA automática | Medio | Alcance 1.0, RTO documentado | 1.2 |
| `RA-04` | RAG O(n) | Bajo | Volumen acotado | Si se supera el límite |
| `RA-05` | Sin adquisición forense remota | Bajo | Alcance 1.0 | 2.0 |
| `RA-06` | Docker no validado en este entorno | Bajo | Validación estática y runbook | En despliegue real |

---

## 4. PROCESO DE GESTIÓN

1. **Identificación:** revisión de diseño, auditoría, incidente, feedback.
2. **Evaluación:** P×I con justificación; se registra en esta matriz.
3. **Tratamiento:** evitar, mitigar, transferir o aceptar (con aprobación).
4. **Seguimiento:** owner, fecha de revisión, señal de materialización.
5. **Cierre:** solo cuando la mitigación está verificada con test o evidencia.

**Revisión obligatoria:** al cierre de cada fase, tras cada incidente `S1`/`S2`, y antes de cada release.

---

## 5. RIESGOS POR FASE (FOCO)

| Fase | Riesgos dominantes |
| :--- | :--- |
| 0 | `R-10`, `R-19`, `R-24` |
| 1 | `R-02`, `R-04`, `R-21` |
| 2 | `R-05`, `R-13` |
| 3 | `R-05`, `R-06`, `R-16` |
| 4 | `R-07`, `R-18` |
| 5 | `R-01`, `R-11` |
| 6 | `R-01`, `R-17`, `R-09` |
| 7 | `R-08`, `R-09` |
| 8 | `R-06`, `R-14` |
| 9 | `R-18` |
| 10 | `R-12`, `R-16`, `R-20` |
| 11 | `R-10`, `R-23`, `R-15`, `R-19` |

---

## 6. CRITERIOS DE ESCALADO

| Condición | Escalado |
| :--- | :--- |
| Riesgo crítico materializado | CISO + arquitectura en ≤1 h |
| Dos riesgos altos en la misma fase | Revisión de plan de fase |
| Riesgo aceptado sin owner | Se eleva a bloqueante |
| Riesgo con exposición ≥15 sin mitigación | No se avanza de fase |
