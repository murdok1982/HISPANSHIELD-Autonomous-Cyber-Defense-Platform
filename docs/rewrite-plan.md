# PLAN DE CONSTRUCCIÓN (REWRITE PLAN)

- **Documento:** `docs/rewrite-plan.md`
- **Estado:** `APPROVED` v1.0
- **Aclaración:** no existe código previo; el término "rewrite" se usa por continuidad estratégica, pero la ejecución es una **construcción greenfield clean-room** (`docs/repository-audit.md`).
- **Backlog ejecutable:** `.factory/TASKS.md` (150 tareas, 12 fases)

---

## 1. ESTRATEGIA

```text
Especificar (specs/) → Congelar contratos → Construir por fases → Verificar por gates → Auditar → Entregar
```

| Etapa | Entregable | Criterio de salida |
| :--- | :--- | :--- |
| E0 Especificación | `specs/`, `.factory/*`, `docs/` | Contratos congelados, ACs con test, backlog ordenado |
| E1 Núcleo | Auth, tenancy, RBAC, design system | Suite de aislamiento y RBAC verde |
| E2 Dominio | Activos, ASM, vulnerabilidades, SIEM | Ingesta→alerta→búsqueda funcional |
| E3 Respuesta | Incidentes, CTI, forense, SOAR | Playbook con aprobación y rollback |
| E4 Autonomía | Política, broker, kill switch | Laboratorio de autonomía 20/20 |
| E5 IA | Gateway, RAG, agentes, MCP | Estado honesto + 0 bypass |
| E6 Superficies | IoT/OT/Cloud/conectores/edge | Store-and-forward y mTLS |
| E7 Cumplimiento | Frameworks, evidencias, informes | 8 frameworks + informe con hash |
| E8 Consola | 23 pantallas, estados, a11y | E2E y axe verdes |
| E9 Endurecimiento | Deploy, backup, air-gap, gates | `verify_all.sh` exit 0 |
| E10 Auditoría | `SECURITY_AUDIT.md`, matriz AC | 0 CRITICAL/HIGH |

---

## 2. PRINCIPIOS DE EJECUCIÓN

1. **Contrato antes que código.** Ninguna tarea empieza sin `Spec Ref` y `Target Files`.
2. **Vertical slices.** Cada fase entrega algo operable, no capas horizontales incompletas.
3. **Gate por fase.** No se avanza con tests rojos, placeholders o ACs sin evidencia.
4. **Sin mocks en producción.** Los dobles viven en `tests/`.
5. **Cambio controlado.** Cualquier desviación del contrato requiere ADR y actualización de `SPEC.md`.
6. **Trazabilidad.** Cada commit referencia `TASK-NNN` y los `AC-XX` que cubre.

---

## 3. FASES, DURACIÓN RELATIVA Y RIESGOS

| Fase | Alcance | Esfuerzo relativo | Riesgo principal | Mitigación |
| :--- | :--- | :--- | :--- | :--- |
| 0 | Scaffolding, seguridad base, DB | 8% | Configuración incorrecta | Tests de migración y headers desde el inicio |
| 1 | Identidad, tenancy, shell | 12% | Aislamiento | Suite parametrizada antes de seguir |
| 2 | Activos, ASM, vulnerabilidades | 12% | Modelo de datos | Scoring testeado, importadores con fixtures |
| 3 | SIEM | 14% | Rendimiento | Bench temprano, particiones |
| 4 | Incidentes, CTI, forense | 10% | Integridad de evidencia | Hash + custodia desde el diseño |
| 5 | SOAR | 10% | Durabilidad | Tests de crash por paso |
| 6 | Autonomía | 10% | Acción destructiva | Laboratorio + barreras independientes |
| 7 | IA | 8% | Indisponibilidad/alucinación | Estado honesto + guardrails |
| 8 | IoT/OT/Cloud/edge | 8% | Protocolos y mTLS | Contrato de conector + tests aislados |
| 9 | Cumplimiento | 6% | Datos normativos | Seed versionado + revisión |
| 10 | Frontend completo | 12% | Craft y estados | `@ui-artisan` + E2E |
| 11 | Endurecimiento y gates | 8% | Deploy no verificable | Validación estática + runbook |

*(Porcentajes orientativos sobre esfuerzo total; no son fechas.)*

---

## 4. HITOS DE DEMOSTRACIÓN

| Hito | Demuestra | Fase |
| :--- | :--- | :--- |
| `D1` | Login+MFA, organización, RBAC, aislamiento | 1 |
| `D2` | Importar activos, ver riesgo y exposición | 2 |
| `D3` | Enviar syslog, ver evento, regla dispara alerta | 3 |
| `D4` | Alerta→incidente→evidencia con hash | 4 |
| `D5` | Playbook con aprobación, crash y reanudación, rollback | 5 |
| `D6` | Acción autónoma permitida, denegada y detenida por kill switch | 6 |
| `D7` | RAG con citas y estado `AI unavailable` | 7 |
| `D8` | Edge offline y reenvío ordenado; CSPM con evidencia | 8 |
| `D9` | Evaluación NIS2 e informe verificable | 9 |
| `D10` | 23 pantallas, WCAG AA, responsive | 10 |
| `D11` | Air-gap, backup/restore, SBOM, auditoría limpia | 11 |

---

## 5. GESTIÓN DE CAMBIOS

| Tipo de cambio | Procedimiento |
| :--- | :--- |
| Nuevo requisito | `requirements.md` + `SPEC.md` AC + `TASKS.md` tarea |
| Cambio de contrato API | ADR + versión + actualización de `rest-contract.md` + tests |
| Cambio de esquema | Migración + `entities.md` + test up/down |
| Cambio de política de autonomía | ADR + actualización de `autonomy-policy.md` + lab |
| Deuda técnica detectada | Tarea con `TASK-NNN` y justificación; no se ignora |
| Bloqueo 3/3 | Circuit Breaker: ADR + replanificación |

---

## 6. RIESGOS DEL PLAN

| Riesgo | Señal temprana | Respuesta |
| :--- | :--- | :--- |
| Deriva de alcance | Tareas sin AC o "mejoras" no pedidas | Rechazo en revisión; volver a `scope.md` |
| Fase que no cierra | Gate rojo recurrente | Circuit Breaker + ADR + simplificación |
| Rendimiento insuficiente | Bench de fase 3 falla | Ajustar índices/particiones antes de seguir |
| Complejidad del motor de workflow | Tests de caos inestables | Simplificar estados; añadir tests deterministas |
| UI inconsistente | Revisiones de tokens fallidas | `@ui-artisan` con checklist y tokens bloqueados |
| Documentación divergente | Enlaces/ACs sin test | `verify_docs_links.sh` y `verify_matrix.py` |

---

## 7. DEFINICIÓN DE TERMINADO (GLOBAL)

1. 150/150 tareas `- [x]` con evidencia.
2. 124/124 ACs globales con test verde.
3. `scripts/verify_all.sh` exit 0.
4. `SECURITY_AUDIT.md` con 0 CRITICAL/HIGH.
5. Air-gap y backup/restore verificados.
6. README con setup reproducible.
7. `docs/implementation-status.md` sin estados `VERIFIED` no sustentados.

---

## 8. TRAZABILIDAD

`specs/product/scope.md §8` → `specs/product/requirements.md` → `.factory/SPEC.md §3` → `.factory/TASKS.md` → `specs/testing/matrix.md` → `reports/acceptance-matrix.md`.
