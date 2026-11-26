# ÍNDICE DE ESPECIFICACIONES (SDD)

Punto de entrada al árbol de especificación de HISPANSHIELD. Orden de lectura recomendado: **constitución → producto → arquitectura → seguridad → dominios → integraciones → contratos → testing → operaciones → ADR**.

| Documento | Contenido |
| :--- | :--- |
| `constitution.md` | 12 artículos normativos: seguridad, soberanía, deny-by-default, autonomía, trazabilidad, honestidad, licencias, operabilidad |
| `product/vision.md` | Problema, propuesta de valor, métricas de éxito, diferenciación, riesgos |
| `product/scope.md` | In/out of scope, límites cuantitativos, supuestos, restricciones, trazabilidad |
| `product/personas.md` | 11 personas, journeys y matriz persona × pantalla |
| `product/requirements.md` | 181 requisitos (`REQ-*`), requisitos de interfaz (`UIR-*`) y catálogo de 23 pantallas |
| `architecture/system-architecture.md` | Componentes, flujo de petición, fronteras de módulo, fallos, capacidad |
| `architecture/security-architecture.md` | Defensa en capas, identidad, autorización, cifrado, supply chain, observabilidad |
| `architecture/data-architecture.md` | ER, convenciones, tenancy, particiones, FTS, vectores, auditoría, backup |
| `architecture/ai-architecture.md` | Proveedores, routing, RAG, agentes, guardrails, modelos locales |
| `architecture/integration-architecture.md` | Ingesta (3 caminos), acciones, resiliencia, versionado |
| `architecture/deployment-architecture.md` | Requisitos, single-node, k8s, air-gap, variables, red, recuperación |
| `security/authorization-model.md` | Matriz rol × permiso, scopes, break-glass, defensa en profundidad |
| `security/autonomy-policy.md` | Niveles A0-A4, catálogo de acciones, política, evaluación, límites, kill switch, rollback |
| `security/threat-model.md` | Activos, actores, STRIDE, árboles de ataque, LINDDUN, riesgos residuales |
| `security/safety-requirements.md` | Peligros operativos, SAF-01..20, barreras independientes, fail-closed |
| `security/data-protection.md` | Catálogo de datos, bases legales, retención, derechos, DPIA/RoPA, brechas |

## Dominios (15)

| Documento | Código | ACs globales |
| :--- | :--- | :--- |
| `domains/identity.md` | IDN | AC-01..08 |
| `domains/organizations.md` | ORG | AC-09..14 |
| `domains/assets.md` | AST | AC-15..21 |
| `domains/attack-surface.md` | ASM | AC-22..26 |
| `domains/vulnerabilities.md` | VUL | AC-27..32 |
| `domains/siem.md` | SIEM | AC-33..42 |
| `domains/soar.md` | SOAR | AC-43..49 |
| `domains/threat-intelligence.md` | CTI | AC-50..54 |
| `domains/incidents.md` | INC | AC-55..58, 60 |
| `domains/forensics.md` | FOR | AC-59 |
| `domains/ai-agents.md` | AIG | AC-61..69 |
| `domains/iot.md` | IOT | AC-79..81 |
| `domains/ot.md` | OTC | AC-82..84 |
| `domains/cloud.md` | CLD | AC-85..87 |
| `domains/compliance.md` | CMP | AC-88..93 |

Cada documento incluye: objetivo, contexto, requisitos funcionales (`REQ-<DOM>-NNN`), no funcionales, dependencias, contratos, casos de uso, casos borde, amenazas, criterios de aceptación, estrategia de test y evidencia requerida.

## Integraciones y contratos

| Documento | Contenido |
| :--- | :--- |
| `integrations/connector-contract.md` | Manifiesto, interfaz, errores, health, circuit breaker, seguridad, ciclo de vida, tests |
| `integrations/mcp-contract.md` | Servidores, tools, `risk_level`, flujo broker→policy→execute, allowlist |
| `integrations/protocol-registry.md` | Protocolos soportados/experimentales/no soportados y sus reglas |
| `integrations/compatibility-matrix.md` | Versiones de plataforma, SO, despliegue, protocolos, cloud, IA, formatos |
| `api/rest-contract.md` | Convenciones, auth, tenancy, errores, catálogo de endpoints, SSE, rate limits |
| `data-models/entities.md` | 40+ entidades con columnas obligatorias, relaciones y validaciones |

## Testing, despliegue y operación

| Documento | Contenido |
| :--- | :--- |
| `testing/strategy.md` | Pirámide, entornos, reglas, datos, gates, caos, cobertura |
| `testing/matrix.md` | Trazabilidad AC → test → tarea (124 ACs globales + dominio) |
| `testing/autonomy-lab.md` | 20 escenarios de laboratorio, medición de kill switch, barreras |
| `deployment/deployment-modes.md` | Single-node, Compose, Kubernetes, air-gap, actualización |
| `operations/runbooks.md` | 10 runbooks con diagnóstico, acción y verificación |
| `operations/backup-restore.md` | Qué se respalda, restore, drill, RPO/RTO, seguridad |
| `operations/incident-response.md` | Respuesta a incidentes del producto, notificación, post-mortem |

## ADR (12)

`ADR-001` monolito modular · `ADR-002` PostgreSQL único · `ADR-003` outbox+NOTIFY · `ADR-004` workflow en PG · `ADR-005` vectores JSONB · `ADR-006` FTS+trgm · `ADR-007` React+Vite · `ADR-008` edge gateway · `ADR-009` auth propio · `ADR-010` IA local-first · `ADR-011` secretos Fernet · `ADR-012` clean-room y licencias.

## Documentos relacionados fuera de `specs/`

| Ruta | Contenido |
| :--- | :--- |
| `.factory/SPEC.md` | Criterios de aceptación `AC-XX` (fuente de verdad) |
| `.factory/ARCHITECTURE.md` | Stack, topología, esquema, API, design system, ADRs índice |
| `.factory/TASKS.md` | 150 tareas atómicas en 12 fases |
| `.factory/SECURITY_AUDIT.md` | Auditoría adversarial (estado `BLOCKED` hasta ejecutarse) |
| `docs/` | Auditoría de repo, plan, estado, C4, manuales operativos, API |

## Reglas de mantenimiento

1. Un cambio de contrato exige ADR y actualización simultánea de `SPEC.md`, el documento de dominio y `testing/matrix.md`.
2. Los IDs (`AC-XX`, `REQ-*`, `ADR-NNN`, `TASK-NNN`, `VULN-XXX`) son estables y no se reutilizan.
3. Ningún documento puede prometer una capacidad fuera de `product/scope.md` sin ADR.
4. La documentación se verifica en el gate: rutas de test existentes y enlaces relativos válidos.
