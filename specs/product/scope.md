# ALCANCE DEL PRODUCTO

- **Documento:** `specs/product/scope.md`
- **Estado:** `APPROVED` v1.0 — delimita qué se construye en la release 1.0 y qué queda explícitamente fuera
- **Regla:** toda funcionalidad no listada en §2 está fuera de alcance hasta que un ADR la incorpore.

---

## 1. DEFINICIÓN DE LA RELEASE 1.0

La release 1.0 es una plataforma **desplegable en un nodo**, operativa en air-gap, con 12 dominios funcionales integrados sobre PostgreSQL, consola de 23 pantallas, autonomía gobernada hasta A4 con kill switch, cumplimiento UE con evidencias y conectores de ingesta. Se entrega con documentación operativa, SBOM y auditoría de seguridad sin hallazgos críticos o altos.

**Criterio de "producto terminado":** un organismo puede instalarlo, conectar dos fuentes reales, detectar un incidente de laboratorio, contenerlo con un playbook aprobado, revertir la acción, y exportar evidencia de cumplimiento sin intervención del fabricante.

---

## 2. IN SCOPE (por dominio, con nivel de profundidad)

### 2.1 Identidad y acceso
- Login local email+password (Argon2id), MFA TOTP, recovery codes, política de contraseñas, bloqueo progresivo.
- Sesiones server-side con cookie `hs_session`, rotación, idle/absolute timeout, revocación.
- CSRF double-submit, PAT Bearer con scopes, auditoría de autenticación.
- **Profundidad:** completa para operación interna; sin federación SAML/OIDC en 1.0 (interfaz preparada).

### 2.2 Organizaciones y tenancy
- Multi-tenant por `organization_id`, 6 roles + `platform_admin`, invitaciones, suspensión, transferencia de ownership.
- `break-glass` auditado para soporte de plataforma.
- **Profundidad:** aislamiento verificado por suite; RLS opcional por feature flag.

### 2.3 Inventario de activos
- IT/IoT/OT/cloud con criticidad 1..5, propietario, etiquetas, zonas, relaciones acíclicas, import CSV/JSON, soft delete/restore.
- Perfiles específicos IoT (protocolo, firmware, ETSI) y OT (Purdue, safety function, zonas/conductos IEC 62443).
- **Profundidad:** inventario operativo con búsqueda y grafo; sin descubrimiento activo de red propio (se importa de escáneres).

### 2.4 Superficie de ataque
- Observaciones de exposición, deduplicación, diffs, autorización de rangos, export STIX/CSV, jobs idempotentes.
- **Profundidad:** pasiva/importada; **no** se realizan escaneos ofensivos desde la plataforma en 1.0.

### 2.5 Vulnerabilidades
- Ingesta CVE/CVSS/CWE/KEV/EPSS, dedupe por fingerprint, scoring determinista explicable, SLA, máquina de estados, excepciones con caducidad.
- Importadores Nessus, OpenVAS, Trivy.
- **Profundidad:** gestión y priorización; sin escaneo propio.

### 2.6 SIEM
- Ingesta syslog UDP/TCP (RFC 5424/3164), webhook HMAC, edge gateway; normalización OCSF; particiones y retención; FTS; reglas DSL con test y versionado; alertas con dedupe; correlación a incidentes; SSE.
- **Profundidad:** detección por reglas y umbrales; sin ML de anomalías en 1.0 (reglas estadísticas básicas permitidas).

### 2.7 SOAR
- Playbooks DAG versionados, ejecuciones durables reanudables, retry/backoff, aprobaciones con timeout, compensación, dry-run, límites de concurrencia, editor visual.
- **Profundidad:** acciones sobre conectores registrados; catálogo inicial de acciones (bloquear IP, aislar host, deshabilitar usuario, cuarentena de fichero, etiquetar activo, crear ticket).

### 2.8 Respuesta autónoma
- Políticas versionadas, `A0..A4`, deny-by-default, blast radius, presupuesto/hora, freeze windows, `break_glass`, verificación, rollback, kill switches (global/org/conector/activo), laboratorio de pruebas.
- **Profundidad:** gobernanza completa; el catálogo de acciones ejecutables depende de las capacidades de cada conector.

### 2.9 Threat intelligence
- Indicadores, actores, campañas, relaciones, TLP, TTL/decay, STIX 2.1 import/export, TAXII 2.1, MISP, matching IOC→evento, whitelist.
- **Profundidad:** consumo y correlación; sin generación propia de inteligencia.

### 2.10 Incidentes y forense
- Ciclo de vida, severidad P1..P5, timeline, SLA, evidencias con SHA-256, informe post-incidente, merge/split.
- Casos forenses con legal hold, manifiesto de integridad, reconstrucción de timeline, exportación.
- **Profundidad:** gestión y evidencia; sin adquisición de memoria/disco remota.

### 2.11 IA
- AI gateway multi-proveedor local-first, health, routing con fallback, presupuesto, chat, embeddings, RAG con citas, agentes durables, MCP con allowlist, defensas anti prompt-injection.
- **Profundidad:** asistiva; funciona plenamente sin IA.

### 2.12 Cloud
- Onboarding de cuentas read-only, credenciales cifradas, rotación, CSPM con reglas y evidencias, mapeo a controles, ingesta de audit logs.
- **Profundidad:** evaluación de postura; sin remediación cloud automatizada en 1.0 (queda como acción de catálogo futuro).

### 2.13 Cumplimiento
- 8 frameworks, controles versionados, mapeos, evaluaciones con score y gaps, evidencias con vigencia y revisor, informes con hash, tracker NIS2 (24 h/72 h/1 mes), RoPA/DPIA.
- **Profundidad:** soporte a la auditoría; no sustituye asesoría legal.

### 2.14 Plataforma
- API REST `/api/v1`, SSE, auditoría encadenada, settings, feature flags, métricas, health, backup/restore, air-gap, logs estructurados, manifiestos compose/k8s, proxy con TLS.
- **Profundidad:** operación single-node y k8s; sin HA automática gestionada por el producto.

### 2.15 Frontend
- 23 pantallas, design system con tokens, estados loading/empty/error/degraded, responsive 375/768/1440, WCAG AA, command palette, i18n español.
- **Profundidad:** consola operativa completa; sin app móvil nativa.

---

## 3. OUT OF SCOPE (exclusiones explícitas)

| # | Exclusión | Motivo | Workaround documentado |
| :--- | :--- | :--- | :--- |
| `O-01` | Microservicios y bus de eventos externo (Kafka/Redpanda) | Coste operativo y air-gap | Monolito modular + outbox (`ADR-001`, `ADR-003`) |
| `O-02` | Temporal, Redis, OpenSearch, Qdrant, Neo4j, Keycloak, Vault | No disponibles/necesarios | Workflow en PostgreSQL, FTS, JSONB vectors, RBAC propio, Fernet |
| `O-03` | Entrenamiento/fine-tuning de LLM | GPU y gobernanza de datos | Inferencia local + RAG + prompts versionados |
| `O-04` | Explotación ofensiva o pentest automatizado | Legal/riesgo | Validación pasiva y simulación |
| `O-05` | Sustitución de EDR/XDR | Producto distinto | Conector EDR como fuente |
| `O-06` | Escaneo de vulnerabilidades propio (authenticated/unauthenticated) | Complejidad y riesgo | Importadores Nessus/OpenVAS/Trivy |
| `O-07` | Descubrimiento activo de red (nmap-like) | Riesgo legal | Importación de inventario/observaciones |
| `O-08` | Adquisición forense remota de memoria/disco | Requiere agente endpoint | Exportación de artefactos y manifiestos |
| `O-09` | Federación SAML/OIDC, SCIM | Alcance 1.0 | Interfaces `auth/providers.py` preparadas |
| `O-10` | Facturación, licenciamiento por asiento, marketplace | Modelo institucional | Licencia por despliegue (`docs/license-policy.md`) |
| `O-11` | App móvil nativa | Coste | Web responsive 375px |
| `O-12` | Alta disponibilidad automática multi-región | Complejidad | Réplica PostgreSQL documentada + RTO/RPO |
| `O-13` | SOAR con acciones destructivas sin política | Viola constitución | Broker + aprobaciones + kill switch |
| `O-14` | Reutilización de código de `SmartNationDefense` | Licencia no comercial | Clean-room (`ADR-012`) |
| `O-15` | Runtime Docker validado en este entorno | Sin daemon | Manifiestos autorados y validados estáticamente |
| `O-16` | ML de detección de anomalías entrenado | Datos y MLOps | Reglas, umbrales y baseline de protocolos OT |
| `O-17` | Soporte multi-idioma completo | Foco | Español en UI; API/identificadores en inglés; i18n preparada |
| `O-18` | Cumplimiento certificado (no somos organismo certificador) | Legal | Mapeo y evidencia para el auditor del cliente |

---

## 4. LÍMITES CUANTITATIVOS DE LA RELEASE 1.0

| Dimensión | Límite soportado | Comportamiento al exceder |
| :--- | :--- | :--- |
| Organizaciones por instancia | 50 | Degradación controlada; se documenta escalado |
| Usuarios por organización | 500 | Igual |
| Activos por organización | 200.000 | Búsqueda con cursor; import por lotes |
| Eventos calientes (90 días) | 50 M | Retención y particiones; `422` en queries amplias |
| Ingesta sostenida | 2.000 ev/s single-node | Backpressure y `429`/`503` explícito |
| Chunks RAG por organización | 200.000 | `413`/`422` con causa y guía |
| Ejecuciones concurrentes por org | 20 (configurable) | Encolado con posición |
| Acciones autónomas por hora | 10 por clase de activo (configurable) | `deny rate_limit_exceeded` |
| Evidencia por fichero | 50 MB | `413` |
| Adjuntos por incidente | 100 | `422` |

---

## 5. DEPENDENCIAS EXTERNAS ACEPTADAS

| Dependencia | Obligatoria | Modo offline | Nota |
| :--- | :--- | :--- | :--- |
| PostgreSQL 18 | Sí | Instalado localmente | Único estado durable |
| Reverse proxy (Caddy/nginx) | Recomendado | Sí | TLS y estáticos |
| Ollama / vLLM | No | Modelo descargado previamente | IA local opcional |
| Proveedor IA externo | No | N/A | Solo opt-in explícito |
| MISP / TAXII remoto | No | N/A | Feeds CTI opcionales |
| Fuentes syslog/EDR/cloud | No | N/A | Sin ellas hay funcionalidad reducida pero honesta |

---

## 6. SUPUESTOS

1. El cliente proporciona PostgreSQL 18 o acepta el incluido en el despliegue de referencia.
2. El cliente gestiona la clave `HISPANSHIELD_SECRET_KEY` en su gestor de secretos o proceso de arranque seguro.
3. El reloj del servidor está sincronizado (NTP); TOTP y auditoría dependen de ello.
4. Los certificados TLS y, si aplica, la CA de mTLS son provistos por el cliente.
5. Las fuentes de datos permiten conectividad desde la plataforma (o desde el edge gateway).
6. El cliente acepta que la IA es asistiva y no sustituye decisiones humanas en acciones A4.

---

## 7. RESTRICCIONES

| ID | Restricción | Implicación |
| :--- | :--- | :--- |
| `C-01` | Sin servicios cloud obligatorios | Todo debe funcionar en air-gap |
| `C-02` | Un único PostgreSQL por instancia | Diseño de colas, búsqueda y vectores sobre él |
| `C-03` | Python 3.12 y Node 22 | Versiones fijadas en build |
| `C-04` | Sin Docker en el entorno de verificación | Manifiestos validados estáticamente; tests nativos |
| `C-05` | Licencias permisivas | Allowlist en `docs/license-policy.md` |
| `C-06` | Datos en la UE | `data_region` por organización; sin replicación externa |
| `C-07` | Acciones OT limitadas por seguridad física | Interlocks y A4 con doble aprobación |
| `C-08` | Documentación en español | Identificadores técnicos en inglés |

---

## 8. TRAZABILIDAD ALCANCE → REQUISITOS

| Bloque de alcance | Requisitos | ACs |
| :--- | :--- | :--- |
| §2.1 Identidad | `REQ-IDN-001..008` | `AC-01..AC-08` |
| §2.2 Organizaciones | `REQ-ORG-001..006` | `AC-09..AC-14` |
| §2.3 Activos | `REQ-AST-001..007` | `AC-15..AC-21` |
| §2.4 Superficie | `REQ-ASM-001..005` | `AC-22..AC-26` |
| §2.5 Vulnerabilidades | `REQ-VUL-001..006` | `AC-27..AC-32` |
| §2.6 SIEM | `REQ-SIEM-001..010` | `AC-33..AC-42` |
| §2.7 SOAR | `REQ-SOAR-001..007` | `AC-43..AC-49` |
| §2.8 Autonomía | `REQ-AUT-001..009` | `AC-70..AC-78` |
| §2.9 CTI | `REQ-CTI-001..005` | `AC-50..AC-54` |
| §2.10 Incidentes/Forense | `REQ-INC-001..006`, `REQ-FOR-001..004` | `AC-55..AC-60` |
| §2.11 IA | `REQ-AIG-001..009` | `AC-61..AC-69` |
| §2.12 Cloud | `REQ-CLD-001..003` | `AC-85..AC-87` |
| §2.13 Cumplimiento | `REQ-CMP-001..006` | `AC-88..AC-93` |
| §2.14 Plataforma | `REQ-PLT-001..007` | `AC-110..AC-116` |
| §2.15 Frontend | `REQ-UI-001..010` | `AC-94..AC-103` |
| IoT/OT | `REQ-IOT-001..004`, `REQ-OTC-001..004` | `AC-79..AC-84` |
| Integraciones | `REQ-INT-001..006` | `AC-104..AC-109` |
| Gates | `REQ-QA-001..008` | `AC-117..AC-124` |
