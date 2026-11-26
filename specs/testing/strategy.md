# ESTRATEGIA DE TESTING

- **Documento:** `specs/testing/strategy.md`
- **Estado:** `APPROVED` v1.0
- **Principio:** un criterio de aceptación sin test ejecutable no es un criterio, es una intención.

---

## 1. PIRÁMIDE ADAPTADA

```text
                 ┌──────────────────────────┐
                 │  E2E (Playwright)  ~40   │  flujos y 23 pantallas
                 ├──────────────────────────┤
                 │ Integración (pytest) ~180│  API + PostgreSQL real
                 ├──────────────────────────┤
                 │ Unit (pytest/vitest) ~350│  lógica pura, validaciones
                 └──────────────────────────┘
        + Especializadas: seguridad, autonomía, rendimiento, caos, contrato
```

| Nivel | Herramienta | Alcance | Aislamiento |
| :--- | :--- | :--- | :--- |
| Unit backend | pytest | Funciones puras, scoring, DSL, DAG, validadores | Sin BD |
| Integración backend | pytest + PostgreSQL 18 local (`:55432`) | Routers, servicios, repositorios, transacciones | Esquema por test (transacción + rollback o BD temporal) |
| Seguridad | pytest (suites dedicadas) | Aislamiento, RBAC, CSRF, SSRF, uploads, prompt injection | Datos multi-org |
| Autonomía | pytest | Política, broker, kill switch, rollback | Dobles de conector controlados |
| Contrato conector | pytest | Manifiesto, errores, idempotencia | Mock HTTP local (solo test) |
| Frontend unit | Vitest + Testing Library | Componentes, hooks, formateo | jsdom |
| E2E | Playwright | 23 pantallas + journeys | App real + BD de test + API real |
| Accesibilidad | axe-core en Playwright | WCAG AA | Igual |
| Rendimiento | pytest-benchmark / script | p95, throughput | Datos sembrados |
| Caos | pytest + reinicio de worker | Reanudación, leases, pérdida de red | Proceso real |

---

## 2. REGLAS

1. **BD real, no SQLite.** Los tests de integración usan PostgreSQL 18 en `HISPANSHIELD_TEST_DATABASE_URL`; SQLite oculta diferencias de tipos, `INET`, `TSVECTOR`, particiones y `SKIP LOCKED`.
2. **Sin mocks en rutas de producción.** Los dobles de prueba viven en `tests/` o `conftest.py`; el código de producción no tiene ramas `if testing`.
3. **Cada test es independiente.** Sin orden implícito; datos creados por fixture y limpiados.
4. **Determinismo.** Sin `sleep` arbitrarios; relojes inyectables (`freezegun` o `Clock` de aplicación) para SLA/TTL.
5. **Fallos legibles.** Un test que falla debe indicar recurso, entrada y expectativa.
6. **Cobertura mínima 80%** en `app/`, sin contar migraciones; no se persigue el 100%.
7. **Sin tests "pendientes".** `skip` requiere justificación y ticket; el gate falla si hay skips sin marcar.
8. **Regresión obligatoria.** Todo bug corregido añade un test que falla antes y pasa después.

---

## 3. ORGANIZACIÓN DE DIRECTORIOS

```text
backend/tests/
├── conftest.py              # engine, sesión, org, usuarios, auth helpers
├── unit/                    # lógica pura
├── integration/             # API + BD
├── security/                # aislamiento, RBAC, CSRF, SSRF, uploads, IA
├── autonomy/                # política, broker, kill switch, rollback, lab
├── performance/             # marcados @pytest.mark.perf (no en CI por defecto)
└── fixtures/                # CSV, STIX, Nessus, eventos, prompts
frontend/
├── src/**/*.test.tsx        # Vitest
└── e2e/                     # Playwright
edge/tests/                  # cola, transporte, mTLS, contrato
```

---

## 4. DATOS DE PRUEBA

| Fixture | Contenido | Uso |
| :--- | :--- | :--- |
| `org_a`, `org_b` | Dos organizaciones con datos cruzados | Aislamiento |
| `users_all_roles` | Un usuario por rol en cada org | Matriz RBAC |
| `assets_mixed` | 50 activos IT/IoT/OT/cloud con criticidad variada | Scoring, política |
| `events_sample` | 1.000 eventos OCSF de 3 fuentes | Búsqueda, detección |
| `stix_bundle` | 3 indicadores + 1 malware + relaciones | CTI |
| `nessus_sample`, `trivy_sample` | Informes reales anonimizados | Importadores |
| `playbooks` | 5 DAG válidos y 5 inválidos | Validación y ejecución |
| `policies` | A0..A4 con límites | Autonomía |
| `prompts_attack` | 40 prompts de inyección | Guardrails |

**Regla de datos:** nunca datos personales reales; los fixtures se anonimizan y se versionan.

---

## 5. GATES Y COMANDOS

| Gate | Comando | Bloquea |
| :--- | :--- | :--- |
| Backend | `ruff check . && mypy --strict app && pytest -q --cov=app --cov-fail-under=80` | Sí |
| Frontend | `npm run typecheck && npm run build && npm run test` | Sí |
| E2E | `npm run test:e2e` | Sí (release) |
| Seguridad | `pip-audit`, `bandit -ll`, `gitleaks`, `npm audit --audit-level=high` | Sí |
| Aislamiento | `pytest -q tests/security/test_tenant_isolation.py` | Sí |
| Autonomía | `pytest -q tests/autonomy/` | Sí |
| Prompt injection | `pytest -q tests/security/test_prompt_injection.py` | Sí |
| SBOM | `scripts/generate_sbom.sh && check_licenses.py` | Sí |
| Air-gap | `scripts/verify_airgap.sh` | Sí (release) |
| Backup | `scripts/backup_restore_drill.sh` | Sí (release) |

`scripts/verify_all.sh` ejecuta todo en orden y devuelve el primer fallo con contexto.

---

## 6. TESTING DE AUTONOMÍA

Ver `specs/testing/autonomy-lab.md`. Resumen:
- Matriz de 15 escenarios con resultado esperado explícito.
- Adaptadores de prueba que simulan éxito, fallo, lentitud y mentira (`200` sin efecto).
- Medición de latencia de kill switch.
- Test de determinismo (misma entrada → misma decisión ×100).
- Test de capas: desactivar una barrera y comprobar que las demás contienen el daño.

---

## 7. TESTING DE SEGURIDAD

| Suite | Qué prueba |
| :--- | :--- |
| `test_tenant_isolation.py` | Cross-org en list/get/update/delete/export/SSE |
| `test_rbac_matrix.py` | Cada celda rol × permiso |
| `test_endpoint_guards.py` | Todo router tiene guard |
| `test_csrf.py` | Ausencia/incorrección de token |
| `test_auth_rate_limit.py` | Bloqueo y no enumeración |
| `test_ssrf_guard.py` | Rangos privados, DNS rebinding, redirects |
| `test_upload_validation.py` | MIME real, tamaño, path traversal |
| `test_webhook_hmac.py` | Firma, timestamp, replay |
| `test_prompt_injection.py` | Corpus directo/indirecto/ofuscado |
| `test_log_hygiene.py` | Sin secretos/PII en logs |
| `test_audit_chain_tamper.py` | Detección de manipulación |

---

## 8. TESTING DE RENDIMIENTO

| Escenario | Carga | Objetivo |
| :--- | :--- | :--- |
| Ingesta | 2.000 ev/s × 10 min | 0 pérdidas, p95 latencia ≤2 s |
| Búsqueda | 1 M eventos | p95 <500 ms |
| Listado activos | 100k activos, 5 filtros | p95 <400 ms |
| Detección | 500 reglas, 2.000 ev/s | retraso ≤10 s |
| API CRUD | 100 rps | p95 <300 ms |
| RAG | 200k chunks | p95 <300 ms |

Los tests `@pytest.mark.perf` no corren en cada commit; sí en release y nightly. Resultados en `reports/perf/`.

---

## 9. TESTING DE CAOS

| Experimento | Resultado esperado |
| :--- | :--- |
| Matar worker de workflow a mitad | Reanudación sin duplicar pasos |
| Cortar red del edge 10 min | Eventos en cola, reenvío ordenado |
| Reiniciar API con requests en vuelo | Cliente recibe error controlado; sin corrupción |
| Llenar disco de evidencias | `503`, sin ficheros parciales |
| Caída de PostgreSQL 30 s | `503`, recuperación sin pérdida confirmada |
| Reloj +5 min | TOTP falla, alerta de skew |
| Outbox bloqueado | Alerta y recuperación sin duplicados |

---

## 10. TESTING DE CONTRATO (conectores)

Cada conector de referencia incluye:
`test_manifest_schema`, `test_config_validation`, `test_secret_not_exposed`, `test_idempotent_push`, `test_error_mapping`, `test_health_state`, `test_action_idempotency`, `test_verify_and_compensate`, `test_rate_limit`, `test_no_ssrf`.

---

## 11. COBERTURA Y CALIDAD

| Métrica | Objetivo | Herramienta |
| :--- | :--- | :--- |
| Cobertura backend | ≥80% | pytest-cov |
| Cobertura frontend (componentes críticos) | ≥70% | Vitest coverage |
| Cobertura AC | 100% de AC con test | matriz de trazabilidad |
| Tests con `skip` | 0 sin justificar | gate |
| Flaky tests | 0 (cuarentena con ticket) | reintentos registrados |

---

## 12. CRITERIOS DE ACEPTACIÓN DEL PROPIO TESTING

1. `scripts/verify_all.sh` exit 0 en un checkout limpio.
2. 100% de `AC-XX` mapeado a test en `specs/testing/matrix.md`.
3. Ningún test depende de red externa.
4. Los tests de seguridad fallan si se introduce una regresión conocida (verificado por mutación manual en revisión).
5. Tiempo total de suite backend ≤10 min; E2E ≤15 min.
