# PLAN DE PRUEBAS

- **Documento:** `docs/test-plan.md`
- **Estado:** `APPROVED` v1.0
- **Estrategia:** `specs/testing/strategy.md` · **Matriz AC→test:** `specs/testing/matrix.md` · **Laboratorio:** `specs/testing/autonomy-lab.md`

---

## 1. OBJETIVO Y ALCANCE

Verificar que HISPANSHIELD cumple los 124 criterios de aceptación globales y los criterios de dominio, con evidencia ejecutable, en un entorno reproducible sin dependencias de red externa. Cubre backend, frontend, edge, seguridad, autonomía, rendimiento, accesibilidad y operación.

**Fuera de alcance de este plan:** pruebas de penetración externas con alcance contractual, certificación formal (IEC 62443/ENS), pruebas en hardware OT real.

---

## 2. ENTORNOS

| Entorno | Propósito | Composición |
| :--- | :--- | :--- |
| `local` | Desarrollo y unit/integración | Python 3.12 venv, PostgreSQL 18 `:55432`, Node 22 |
| `ci` | Gates automáticos | Igual + runners; sin Docker |
| `staging` | E2E, caos, rendimiento, drills | Single-node + proxy + datos sintéticos |
| `airgap-sim` | Instalación offline | Sin salida a red; bundle local |
| `lab` | Autonomía y safety | Conectores fake, reloj inyectable |

**Datos:** sintéticos y anonimizados; nunca datos personales reales.

---

## 3. NIVELES Y RESPONSABILIDADES

| Nivel | Responsable | Frecuencia | Bloquea release |
| :--- | :--- | :--- | :---: |
| Unit backend/frontend | `@builder` | Cada commit | Sí |
| Integración | `@builder` | Cada PR | Sí |
| Seguridad | `@redteam-auditor` + `@qa-verifier` | Cada PR que toque superficie | Sí |
| Autonomía | `@qa-verifier` | Cada PR de `autonomy/` | Sí |
| E2E | `@qa-verifier` | Cada PR de frontend; release | Sí (release) |
| Rendimiento | `@qa-verifier` | Release y nightly | Sí (umbral) |
| Caos | `@qa-verifier` | Release | Sí |
| Accesibilidad | `@ui-artisan` + `@qa-verifier` | Cada PR de UI | Sí |
| Air-gap / backup | Operaciones | Release | Sí |

---

## 4. CASOS DE PRUEBA POR ÁREA

### 4.1 Autenticación y tenancy
- Login válido/ inválido / bloqueado / MFA / recovery.
- Rotación de sesión, expiración idle/absoluta, revocación.
- CSRF ausente/incorrecto/válido.
- PAT con scope correcto/incorrecto/expirado.
- Cross-org en cada recurso (list/get/update/delete/export/SSE).
- Matriz RBAC completa (rol × permiso).
- Break-glass: concesión, TTL, expiración, auditoría.

### 4.2 Activos y vulnerabilidades
- Alta válida, validaciones por tipo, duplicados.
- Grafo: ciclos, auto-relación, profundidad.
- Import CSV/JSON parcial, cabeceras inválidas, límites.
- Scoring con tabla de casos (CVSS/KEV/EPSS/exposición/criticidad).
- Dedupe multi-fuente, estados, excepciones, caducidad.
- Importadores Nessus/OpenVAS/Trivy.

### 4.3 SIEM
- Syslog RFC 5424/3164 UDP/TCP, mensaje inválido, oversize.
- Webhook HMAC válido/inválido/expirado/replay, idempotencia.
- OCSF: campos mínimos, mapeo por fuente.
- Inmutabilidad (intento de update/delete).
- Búsqueda: filtros, FTS, guard de consulta, paginación.
- DSL: válido/inválido, campos desconocidos.
- Detección: umbral, ventana, dedupe, supresión.
- Correlación a incidente.
- Retención por partición.

### 4.4 SOAR y autonomía
- DAG: ciclos, huérfanos, triggers, acciones desconocidas.
- Crash/resume en cada paso.
- Aprobación: approve/deny/timeout/autoaprobación.
- Compensación LIFO, doble ejecución.
- Dry-run: 0 llamadas.
- Concurrencia y cola.
- Política: deny por defecto, nivel, blast radius, budget, cooldown, freeze, break-glass.
- Kill switch: latencia ≤5 s, acciones en curso.
- Verificación: adaptador mentiroso, timeout, rollback.
- A4: doble aprobación, time-box, interlock OT.
- Determinismo ×100.

### 4.5 IA
- Sin proveedor → 503.
- Routing y fallback.
- RAG: citas verificables, dimensión, contexto vacío.
- Prompt injection: directa, indirecta, ofuscada, exfiltración.
- MCP: allowlist, esquema, límite de llamadas.
- Presupuesto y redacción de secretos.
- Run durable y reanudación.

### 4.6 Frontend
- 23 rutas, `<h1>`, sin errores de consola, sin 5xx.
- Skeleton/empty/error/degraded.
- Responsive 375/768/1440 sin scroll horizontal.
- axe-core 0 violaciones; teclado; focus visible; reduced motion.
- SSE reconnect y dedupe.
- Confirmación destructiva.
- Command palette.

### 4.7 Operación
- Health/readyz sano y degradado.
- Migraciones up/down.
- Backup/restore drill.
- Air-gap install.
- Graceful shutdown.
- Log hygiene.
- Cadena de auditoría íntegra y manipulada.

---

## 5. CRITERIOS DE ENTRADA Y SALIDA

### Entrada a fase
- Especificación del dominio aprobada.
- Tareas de la fase `- [ ]` con dependencias resueltas.
- Entorno de test operativo.

### Salida de fase (gate)
| Criterio | Umbral |
| :--- | :--- |
| Tests del área | 100% verdes |
| ACs de la fase | 100% con test y evidencia |
| Cobertura backend | ≥80% |
| Hallazgos CRITICAL/HIGH | 0 abiertos |
| Placeholders | 0 |
| Documentación | Actualizada y enlazada |

### Salida de release
- `scripts/verify_all.sh` exit 0.
- E2E completo en 3 navegadores.
- Air-gap y backup/restore verificados.
- `SECURITY_AUDIT.md` APPROVED.
- `reports/acceptance-matrix.md` completo.

---

## 6. GESTIÓN DE DEFECTOS

| Severidad | Definición | SLA de corrección |
| :--- | :--- | :--- |
| `S1` | Bloquea release o compromete seguridad/datos | 24 h |
| `S2` | Función principal inoperable | 72 h |
| `S3` | Defecto con workaround | Próxima release |
| `S4` | Cosmético/documentación | Backlog |

Todo defecto corregido añade test de regresión. Los `S1/S2` se registran también en `SECURITY_AUDIT.md` si son de seguridad.

---

## 7. RIESGOS DEL PLAN

| Riesgo | Mitigación |
| :--- | :--- |
| Flakiness en E2E | Datos deterministas, esperas por condición, reintentos registrados |
| Tests lentos | Paralelización, marcado `perf` fuera de PR |
| Diferencias SQLite/PG | Solo PostgreSQL en integración |
| Sin Docker/LLM | Dobles en `tests/`, validación estática, estados honestos |
| Cobertura ficticia | Revisión de tests críticos, mutación manual |

---

## 8. CALENDARIO (RELATIVO)

| Momento | Actividad |
| :--- | :--- |
| Cada commit | Unit + lint + tipos |
| Cada PR | Integración + seguridad + autonomía (si aplica) + frontend |
| Cierre de fase | Gate completo + evidencia |
| Release candidate | E2E completo + rendimiento + caos + air-gap + backup |
| Mensual | Drill de backup + revisión de flaky + auditoría de dependencias |
| Anual | Simulacro de incidente `S1` + revisión de threat model |
