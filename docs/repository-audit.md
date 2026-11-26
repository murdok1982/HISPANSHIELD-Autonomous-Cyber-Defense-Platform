# AUDITORÍA DE REPOSITORIO

- **Documento:** `docs/repository-audit.md`
- **Fecha:** 2026-11-26
- **Autor:** `@architect` (AGENT-00)
- **Propósito:** dejar constancia verificable del estado inicial del workspace, del producto hermano auditado y excluido, del inventario de herramientas y de los riesgos de partida.

---

## 1. ESTADO INICIAL DEL WORKSPACE

| Comprobación | Resultado | Evidencia |
| :--- | :--- | :--- |
| Código fuente existente | **Ninguno** | `find . -type f` solo devuelve ficheros de `.git` |
| Historial git | **0 commits** | `git log` → `does not have any commits yet` |
| Directorios | Esqueleto vacío: `backend/`, `frontend/`, `edge/`, `deploy/`, `docs/`, `infra/`, `scripts/`, `specs/`, `tests/`, `reports/`, `examples/`, `.factory/` | `ls -la` |
| Repositorio git | Inicializado (`.git` presente), sin remoto | `git remote -v` vacío |
| `.factory/` previo | Vacío | `ls -la .factory` |
| `specs/`, `docs/` previos | Vacíos | `ls` |

**Conclusión:** no existe una implementación previa de HISPANSHIELD en este workspace. Cualquier afirmación de "reescritura" se refiere a una **construcción greenfield**, no a la modificación de un código existente.

---

## 2. PRODUCTO HERMANO AUDITADO: `SmartNationDefense`

| Aspecto | Hallazgo |
| :--- | :--- |
| Ubicación | `../SmartNationDefense` (volumen compartido) |
| Licencia | `HISPANSHIELD NON-COMMERCIAL LICENSE v1.0` — uso personal/educativo/evaluación; **prohibido uso comercial** sin licencia de pago |
| Titular | Gustavo Lobato Clara (General Murdok) |
| Dominio | SESIS-FEDERATION (producto distinto, aunque con solapamiento nominal y de temática) |
| Estructura | `backend/`, `frontend/`, `mobile/`, `ml/`, `infra/`, `compliance/`, `docker-compose*.yml`, `Makefile`, `fernet.key` (clave en el repositorio: mala práctica) |
| Riesgo de reutilización | **Alto**: licencia incompatible con uso institucional/comercial; arrastre de decisiones, dependencias y posibles secretos |
| Acción tomada | **Exclusión total.** No se copia código, esquema, nombres de módulos, tests ni documentación. Se registra como referencia de mercado no vinculante (`ADR-012`) |

**Nota de seguridad:** la presencia de `fernet.key` en el repositorio del producto hermano refuerza la decisión de no heredar su configuración; HISPANSHIELD exige clave por entorno y `.gitignore` estricto.

---

## 3. INVENTARIO DE HERRAMIENTAS VERIFICADO

| Herramienta | Versión | Estado | Uso |
| :--- | :--- | :--- | :--- |
| Python | 3.12.16 (`/tmp/opencode/hs-venv`) | Disponible | Backend y edge |
| uv | 0.13.9 | Disponible | Gestión de dependencias |
| PostgreSQL | 18.6 en `/tmp/opencode:55432`, trust auth | En ejecución | BD de desarrollo y tests |
| Node.js | 22.14.0 (`/tmp/opencode/node-v22.14.0-linux-x64/bin`) | Disponible | Build frontend |
| npm | 10.9.2 | Disponible | Dependencias frontend |
| Rust | 1.100.0 | Disponible | No usado en 1.0 (reservado) |
| git | Disponible | Repo inicializado | Control de versiones |
| Docker daemon | **No disponible** | Ausente | Manifiestos solo validación estática |
| Ollama / vLLM | **No en ejecución** | Ausente | IA no testeable en runtime; estado `unavailable` |
| Redis | **No disponible** | Ausente | No usado (decisión de diseño) |
| OpenSearch / Qdrant / Neo4j / Temporal / Keycloak / Vault | **No disponibles** | Ausentes | Excluidos por ADR |

**Implicación:** la verificación runtime se limita a procesos nativos + PostgreSQL. Todo lo que dependa de Docker o de un LLM se valida por tests unitarios/integración con dobles locales (solo en `tests/`) y por validación estática de manifiestos.

---

## 4. RIESGOS DE PARTIDA

| ID | Riesgo | Probabilidad | Impacto | Mitigación |
| :--- | :--- | :--- | :--- | :--- |
| `RA-01` | Contaminación de licencia por similitud con el producto hermano | Media | Alto | Clean-room, ADR-012, revisión de originalidad, sin remoto |
| `RA-02` | Expectativa de "reescritura" sobre un código inexistente | Alta | Medio | Este documento + `rewrite-plan.md` |
| `RA-03` | Manifiestos Docker/k8s no ejecutados | Alta | Medio | Validación estática + runbook + revisión |
| `RA-04` | IA no verificable en runtime | Alta | Medio | Tests con proveedor fake en `tests/`, estado honesto, suite sin IA |
| `RA-05` | PostgreSQL local con trust auth (no representativo de producción) | Media | Medio | Documentar requisitos de producción (auth scram, TLS) |
| `RA-06` | Volumen compartido con otros proyectos (riesgo de ruta y de espacio) | Media | Bajo | Rutas absolutas, backups, `.gitignore` |
| `RA-07` | Dependencias con licencia incompatible | Media | Alto | `check_licenses.py` en gate |
| `RA-08` | Deriva de alcance hacia "otro SIEM" | Media | Medio | Visión y scope con exclusiones explícitas |
| `RA-09` | Documentación que promete más de lo implementado | Media | Alto | `implementation-status.md` con estados honestos |

---

## 5. DECISIONES DERIVADAS DE LA AUDITORÍA

1. **Stack sin servicios no disponibles** (`ADR-001..ADR-006`) para garantizar que todo lo especificado es construible y verificable en este entorno.
2. **Estado honesto de IA** (`ADR-010`): la ausencia de LLM es un caso de primera clase, no un fallo.
3. **Licencia limpia** (`ADR-012`) y allowlist de dependencias.
4. **Un solo PostgreSQL** (`ADR-002`) para reducir superficie y facilitar air-gap.
5. **Documentación de estado** (`implementation-status.md`) que separa `SPECIFIED` de `VERIFIED`.

---

## 6. CONCLUSIÓN

El workspace estaba vacío y sin historial. HISPANSHIELD es una construcción greenfield con decisiones propias, documentadas y verificables. El producto hermano ha sido auditado y **excluido** por licencia y por diferencia de dominio. El entorno permite verificar backend, base de datos y frontend; no permite verificar runtime de Docker ni de IA, lo que se declara explícitamente y se compensa con validación estática, tests con dobles y estados honestos en el producto.
