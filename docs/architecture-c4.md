# ARQUITECTURA C4

- **Documento:** `docs/architecture-c4.md`
- **Estado:** `APPROVED` v1.0
- **Notación:** C4 (Contexto, Contenedores, Componentes) + secuencias + despliegue
- **Fuente:** `.factory/ARCHITECTURE.md`, `specs/architecture/*`

---

## 1. C4 NIVEL 1 — CONTEXTO

```mermaid
flowchart TB
  U1["Operador SOC\n(analista, jefe de turno)"]
  U2["CISO / RSSI"]
  U3["DPO / Auditor"]
  U4["Operador de plataforma"]
  HS["HISPANSHIELD\nPlataforma de ciberdefensa"]
  S1["Fuentes de telemetría\nfirewall, EDR, AD, cloud"]
  S2["Feeds CTI\nMISP, TAXII"]
  S3["Modelos IA locales\nOllama / vLLM"]
  S4["Sistemas de acción\nfirewall, EDR, IdP, ticketing"]
  S5["Autoridades\nNIS2 / CRA / GDPR"]

  U1 -->|"investiga, responde"| HS
  U2 -->|"postura, informes"| HS
  U3 -->|"evidencias, auditoría"| HS
  U4 -->|"opera, mantiene"| HS
  S1 -->|"syslog, webhook, API"| HS
  S2 -->|"STIX/TAXII"| HS
  HS -->|"inferencia local"| S3
  HS -->|"acciones gobernadas"| S4
  HS -->|"evidencia de cumplimiento"| S5
```

| Actor/Sistema | Relación | Protocolo |
| :--- | :--- | :--- |
| Operadores | Uso de consola | HTTPS |
| Fuentes de telemetría | Ingesta | Syslog, HTTPS webhook, mTLS edge |
| Feeds CTI | Ingesta | TAXII 2.1, MISP API |
| Modelos IA | Inferencia | HTTP local |
| Sistemas de acción | Respuesta | HTTPS con allowlist |
| Autoridades | Reporting | Informes PDF/JSON con hash |

---

## 2. C4 NIVEL 2 — CONTENEDORES

```mermaid
flowchart TB
  subgraph Browser
    SPA["SPA React 19\n(Vite build)"]
  end
  subgraph Perimeter
    PROXY["Reverse proxy\nTLS · HSTS · CSP · estáticos"]
  end
  subgraph App["Aplicación (monolito modular)"]
    API["API FastAPI\n/api/v1 · SSE"]
    WK1["worker-ingest"]
    WK2["worker-detection"]
    WK3["worker-workflow"]
    WK4["worker-scheduler"]
    WK5["worker-ai"]
  end
  subgraph Data
    PG[("PostgreSQL 18\nsystem of record")]
    EVID[("Volumen evidencias")]
  end
  subgraph EdgeSites["Sedes"]
    EDGE["hispanshield-edge\nSQLite WAL"]
  end
  SPA --> PROXY --> API
  API --> PG
  WK1 --> PG
  WK2 --> PG
  WK3 --> PG
  WK4 --> PG
  WK5 --> PG
  API --> EVID
  EDGE -->|mTLS| PROXY
```

| Contenedor | Tecnología | Responsabilidad | Escalado |
| :--- | :--- | :--- | :--- |
| SPA | React 19 + Vite | Consola de 23 pantallas | Estático |
| Proxy | Caddy/nginx | TLS, cabeceras, estáticos | 2 |
| API | FastAPI/Uvicorn | Contratos REST/SSE, auth, casos de uso | Horizontal |
| worker-ingest | Python | Syslog/webhook/edge → OCSF | Por cola |
| worker-detection | Python | Reglas y correlación | Por cola |
| worker-workflow | Python | Playbooks y acciones | Por cola |
| worker-scheduler | Python | Jobs periódicos | 1 (advisory lock) |
| worker-ai | Python | Runs de agentes y embeddings | Por cola |
| PostgreSQL | 18 | Dominio, colas, eventos, auditoría, vectores | Vertical + réplica |
| Evidencias | FS | Ficheros con hash | Volumen |
| Edge | Python+SQLite | Buffer y reenvío | 1 por sede |

---

## 3. C4 NIVEL 3 — COMPONENTES DE LA API

```mermaid
flowchart LR
  HTTP["Routers /api/v1"] --> DEPS["deps: sesión, org, permisos"]
  DEPS --> SVC["Services (dominio)"]
  SVC --> REPO["Repositories (SQL scoped)"]
  SVC --> CORE["Core: audit, events, crypto, ratelimit"]
  SVC --> INT["Integrations (conectores, STIX, OCSF)"]
  SVC --> WF["Workflow engine"]
  SVC --> AUT["Autonomy broker"]
  SVC --> AI["AI gateway"]
  REPO --> PG[("PostgreSQL")]
  CORE --> PG
  WF --> PG
  AUT --> PG
  AI --> PG
```

| Componente | Responsabilidad | Prohibición |
| :--- | :--- | :--- |
| Routers | Validar, autorizar, delegar | Lógica de negocio |
| deps | Identidad, org, permisos | Acceso a datos de dominio |
| Services | Reglas, transacciones, eventos | SQL directo (usa repos) |
| Repositories | Consultas scoped | Reglas de negocio |
| Core | Auditoría, outbox, crypto, límites | Conocer dominio |
| Integrations | Protocolos y mapeos | Autorizar |
| Workflow | Durabilidad y pasos | Ejecutar sin broker |
| Autonomy | Política y ejecución | Parsear protocolos |
| AI | Inferencia y RAG | Ejecutar acciones |

---

## 4. SECUENCIA: INGESTA → ALERTA → INCIDENTE

```mermaid
sequenceDiagram
  participant FW as Firewall
  participant ED as Edge
  participant API as API
  participant ING as worker-ingest
  participant DB as PostgreSQL
  participant DET as worker-detection
  participant UI as Consola
  FW->>ED: syslog
  ED->>API: POST /edge/ingest (mTLS, sequence)
  API->>DB: insert events (OCSF) + outbox
  API-->>ED: 202 highest_sequence
  DB-->>ING: NOTIFY
  ING->>DET: evaluar reglas
  DET->>DB: alert (dedupe_key)
  DB-->>UI: SSE alert.created
  UI->>API: POST /alerts/{id}/promote
  API->>DB: incident + timeline + outbox
  API-->>UI: 201 incident
```

**Invariantes:** el `202` solo se devuelve tras commit; el edge no borra hasta `202`; la alerta es deduplicada; el incidente conserva `alert_ids`.

---

## 5. SECUENCIA: ACCIÓN AUTÓNOMA GOBERNADA

```mermaid
sequenceDiagram
  participant TR as Trigger (alerta/agente)
  participant AUT as Policy Engine
  participant BR as Broker
  participant CN as Conector
  participant VR as Verifier
  participant RB as Rollback
  participant AU as Audit
  TR->>AUT: ActionRequest
  AUT->>AUT: evaluate (kill switch, nivel, blast, budget, freeze)
  AUT-->>TR: decision (deny/allow/require_approval)
  AUT->>AU: policy.decision
  alt allow
    AUT->>BR: execute(action_id)
    BR->>CN: execute(idempotency_key)
    CN-->>BR: result
    BR->>VR: verify(criterion)
    alt verified
      VR-->>BR: ok
      BR->>AU: action.verified
    else failed
      VR-->>BR: failed
      BR->>RB: rollback
      RB->>AU: action.rolled_back
    end
  else require_approval
    AUT->>AU: approval.requested
  end
```

---

## 6. DESPLIEGUE (SINGLE-NODE)

```mermaid
flowchart TB
  INET["Red institucional"] --> PROXY["Caddy :443\nTLS + HSTS"]
  PROXY --> WEB["/ → SPA estático"]
  PROXY --> API["/api → 127.0.0.1:8000"]
  API --> PG[("PostgreSQL :5432")]
  W["workers ×5"] --> PG
  API --> EV[("/var/lib/hispanshield/evidence")]
  EDGE["Sedes"] -->|mTLS 8443| PROXY
  MET["Prometheus (opcional)"] --> API
```

| Nodo | Rol | Réplicas |
| :--- | :--- | :--- |
| `hs-core-01` | API, workers, PostgreSQL, proxy | 1 |
| `hs-edge-<sede>` | Edge gateway | 1 (activo/pasivo) |
| `hs-backup` | Almacenamiento offline | — |

---

## 7. DESPLIEGUE (KUBERNETES)

```mermaid
flowchart LR
  ING["Ingress + TLS"] --> API["Deployment/api (2-4)"]
  ING --> WEB["Deployment/web (2)"]
  API --> PGS["PostgreSQL (StatefulSet/servicio)"]
  WI["Deployment/worker-ingest (2)"] --> PGS
  WD["Deployment/worker-detection (2)"] --> PGS
  WW["Deployment/worker-workflow (2)"] --> PGS
  WS["StatefulSet/scheduler (1)"] --> PGS
  WA["Deployment/worker-ai (1)"] --> PGS
  API --> PVC[("PVC evidencias RWX")]
  NP["NetworkPolicy: solo ingress→api"] -.-> API
```

---

## 8. LÍMITES Y DECISIONES VISIBLES

| Límite | Implicación |
| :--- | :--- |
| Un PostgreSQL | Punto único; mitigado con backup y réplica |
| Sin broker | Outbox/NOTIFY; techo de throughput |
| Sin servicio vectorial | RAG O(n) acotado |
| Sin IdP externo | Auth propia; sin SSO en 1.0 |
| IA opcional | Producto funcional sin LLM |
| Edge por sede | Sin HA nativa |

---

## 9. MANTENIMIENTO DEL DOCUMENTO

Actualizar al cambiar: contenedores, fronteras, flujo de acción o topología de despliegue. Cada cambio requiere ADR y actualización de `ARCHITECTURE.md §2`.
