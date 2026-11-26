# MATRIZ DE COMPATIBILIDAD

- **Documento:** `specs/integrations/compatibility-matrix.md`
- **Estado:** `APPROVED` v1.0
- **Regla:** toda fila marcada `unsupported` es una exclusión declarada, no un fallo silencioso.

---

## 1. PLATAFORMA DE EJECUCIÓN

| Componente | Versión mínima | Versión recomendada | Versión máxima probada | Estado |
| :--- | :--- | :--- | :--- | :--- |
| Python (backend/edge) | 3.12.0 | 3.12.16 | 3.12.x | `supported` |
| PostgreSQL | 16 | 18.6 | 18.x | `supported` (16/17 con `pg_trgm` y particiones) |
| Node.js (build frontend) | 20.11 LTS | 22.14 | 22.x | `supported` |
| npm | 10 | 10.9 | 10.x | `supported` |
| Navegador Chromium | 120 | última estable | última | `supported` |
| Firefox (ESR) | 115 | 128 ESR | última | `supported` |
| Safari / WebKit | 17 | 18 | última | `supported` |
| Edge (Chromium) | 120 | última | última | `supported` |
| IE 11 | — | — | — | `unsupported` |
| Safari < 16 | — | — | — | `unsupported` |

---

## 2. SISTEMA OPERATIVO DEL SERVIDOR

| SO | Versión | Estado | Notas |
| :--- | :--- | :--- | :--- |
| Ubuntu Server LTS | 22.04 / 24.04 | `supported` | Referencia de despliegue |
| Debian | 12 | `supported` | |
| RHEL / Rocky / Alma | 9 | `supported` | SELinux en modo enforcing documentado |
| SUSE SLE | 15 SP5 | `experimental` | |
| Windows Server | 2022 | `unsupported` | Sin runtime soportado |
| Alpine (contenedor) | 3.19 | `supported` | Imagen de referencia |
| Kubernetes | 1.28+ | `supported` | Manifiestos en `deploy/k8s` |

---

## 3. DESPLIEGUE

| Modo | Estado | Requisitos | Limitaciones |
| :--- | :--- | :--- | :--- |
| Single-node (systemd + PostgreSQL local) | `supported` | 8 vCPU / 16 GB / 200 GB SSD | Sin HA; RTO documentado |
| Single-node air-gapped | `supported` | Bundle offline + NTP local | Sin feeds externos; IA local opcional |
| Docker Compose | `supported` (manifiesto) | Docker Engine 24+ / Compose v2 | No validado en este entorno (sin daemon) |
| Kubernetes (on-prem) | `supported` (manifiesto) | K8s 1.28+, StorageClass RWX para evidencias | Sin operador propio |
| Kubernetes (air-gapped) | `supported` | Registro espejo + imágenes firmadas | |
| Multi-región activo/activo | `unsupported` | — | Fuera de alcance 1.0 |
| Serverless / FaaS | `unsupported` | — | Incompatible con soberanía y estado durable |

---

## 4. PROTOCOLOS DE INGESTA

| Protocolo | Versión | Estado | Notas |
| :--- | :--- | :--- | :--- |
| Syslog RFC 5424 | 2009 | `supported` | UDP/TCP |
| Syslog RFC 3164 | — | `supported` | Modo compatibilidad |
| CEF sobre syslog | ArcSight CEF 0.x | `experimental` | Mapeo parcial |
| LEEF | 1.0/2.0 | `experimental` | |
| JSON webhook | — | `supported` | HMAC + idempotencia |
| NDJSON | — | `supported` | |
| OCSF | 1.3+ | `supported` | Esquema nativo |
| STIX | 2.1 | `supported` | Import/export |
| TAXII | 2.1 | `supported` | Polling |
| MISP API | 2.4.x | `supported` | |
| OTLP (logs) | 1.x | `unsupported` | Fase 2 |
| Kafka | — | `unsupported` | Sin broker |
| SNMP traps | v2c/v3 | `unsupported` | Fase 2 |
| NetFlow/IPFIX | v9/v10 | `unsupported` | Fase 2 |
| gRPC streaming | — | `unsupported` | Fase 2 |

---

## 5. PROTOCOLOS INDUSTRIALES (VISIBILIDAD)

| Protocolo | Puerto típico | Estado | Uso en 1.0 |
| :--- | :--- | :--- | :--- |
| Modbus/TCP | 502 | `supported` (pasivo/import) | Detección de funciones y baseline |
| DNP3 | 20000 | `supported` (pasivo/import) | Baseline y anomalías |
| OPC-UA | 4840 | `supported` (pasivo/import) | Baseline |
| S7comm | 102 | `experimental` | Solo importación de metadatos |
| BACnet | 47808 | `experimental` | |
| EtherNet/IP | 44818 | `experimental` | |
| PROFINET | — | `unsupported` | Requiere captura L2 |
| Escritura OT (cualquiera) | — | `unsupported` | Prohibido en 1.0 |

---

## 6. PROVEEDORES CLOUD

| Proveedor | Servicios cubiertos | Estado | Notas |
| :--- | :--- | :--- | :--- |
| AWS | IAM, S3, EC2, CloudTrail, Security Hub (lectura) | `supported` | Rol cross-account de solo lectura |
| Azure | Entra ID, Storage, VMs, Activity Log, Defender (lectura) | `supported` | Service Principal |
| GCP | IAM, GCS, Compute, Cloud Audit Logs | `supported` | Service Account |
| OpenStack | — | `experimental` | API parcial |
| VMware vSphere | — | `unsupported` | Fase 2 |

---

## 7. PROVEEDORES DE IA

| Proveedor | Protocolo | Estado | Nota |
| :--- | :--- | :--- | :--- |
| Ollama | HTTP `/api/chat`, `/api/embeddings` | `supported` | Recomendado air-gap |
| vLLM | OpenAI-compatible `/v1` | `supported` | GPU opcional |
| llama.cpp server | OpenAI-compatible | `experimental` | |
| OpenAI | `/v1` | `supported` (opt-in) | Requiere habilitación por `owner` |
| Azure OpenAI | `/v1` | `supported` (opt-in) | |
| Anthropic | `/v1/messages` | `experimental` | Adaptador específico |
| Hugging Face Inference | HTTP | `unsupported` | Sin control de residencia |
| Bedrock | — | `unsupported` | Fase 2 |

---

## 8. IDENTIDAD

| Mecanismo | Estado | Notas |
| :--- | :--- | :--- |
| Password local + Argon2id | `supported` | |
| TOTP RFC 6238 | `supported` | |
| Recovery codes | `supported` | |
| PAT Bearer con scopes | `supported` | |
| OIDC authorization code | `experimental` | Interfaz, sin UI en 1.0 |
| SAML2 | `unsupported` | Fase 2 |
| LDAP bind | `unsupported` | Fase 2 |
| SCIM 2.0 | `experimental` | Provisión saliente |

---

## 9. NAVEGADOR — FUNCIONALIDAD

| Funcionalidad | Chromium 120+ | Firefox 115+ | WebKit 17+ |
| :--- | :--- | :--- | :--- |
| SSE (live stream) | ✅ | ✅ | ✅ |
| Command palette | ✅ | ✅ | ✅ |
| Drag & drop DAG | ✅ | ✅ | ✅ (con fallback teclado) |
| Descarga de evidencias | ✅ | ✅ | ✅ |
| Clipboard API | ✅ | ✅ | ✅ (requiere gesto) |
| `prefers-reduced-motion` | ✅ | ✅ | ✅ |

**Fallback obligatorio:** el diseñador de playbooks debe poder editarse sin arrastrar (formulario de nodos y aristas) para accesibilidad y navegadores restrictivos.

---

## 10. FORMATOS DE FICHERO SOPORTADOS

| Formato | Uso | Estado | Límite |
| :--- | :--- | :--- | :--- |
| CSV (UTF-8) | Import activos/observaciones | `supported` | 10 MB |
| JSON | Import/export | `supported` | 10 MB |
| XML Nessus `.nessus` | Vulnerabilidades | `supported` | 50 MB |
| XML OpenVAS | Vulnerabilidades | `supported` | 50 MB |
| JSON Trivy | Vulnerabilidades | `supported` | 50 MB |
| STIX 2.1 JSON | CTI | `supported` | 50 MB |
| PDF | Evidencias/informes | `supported` | 50 MB |
| PNG/JPEG | Evidencias | `supported` | 50 MB |
| ZIP | Export forense (salida) | `supported` | — |
| PCAP | Forense | `unsupported` | Sin analizador |
| DOCX/XLSX | Evidencias | `experimental` | Sin extracción de contenido |

---

## 11. POLÍTICA DE SOPORTE

| Ventana | Compromiso |
| :--- | :--- |
| Versión actual (N) | Soporte completo y parches de seguridad |
| N-1 | Parches de seguridad |
| N-2 | Solo migración asistida documentada |
| Anteriores | No soportadas |

**CRA:** se publica política de soporte de actualizaciones con fecha de fin por release en `SECURITY.md` y `docs/license-policy.md`.
