# MATRIZ DE COMPATIBILIDAD (RESUMEN DE PRODUCTO)

- **Documento:** `docs/compatibility-matrix.md`
- **Estado:** `APPROVED` v1.0
- **Detalle técnico completo:** `specs/integrations/compatibility-matrix.md`
- **Regla:** `unsupported` es una exclusión declarada; la plataforma responde con error explícito, nunca con fallback silencioso.

---

## 1. SERVIDOR

| Elemento | Soportado | Notas |
| :--- | :--- | :--- |
| Ubuntu Server 22.04 / 24.04 | ✅ | Referencia |
| Debian 12 | ✅ | — |
| RHEL / Rocky / Alma 9 | ✅ | SELinux documentado |
| SUSE SLE 15 SP5 | ⚠️ Experimental | — |
| Windows Server | ❌ | Sin runtime |
| Python | 3.12.x | 3.12.16 verificado |
| PostgreSQL | 16, 17, 18 | 18.6 verificado |
| Node (build) | 20.11 LTS, 22.x | 22.14 verificado |
| Kubernetes | 1.28+ | Manifiestos incluidos |
| Docker Engine | 24+ | Manifiestos incluidos; no validado en este entorno |

---

## 2. NAVEGADORES

| Navegador | Versión mínima | Estado |
| :--- | :--- | :--- |
| Chrome / Edge (Chromium) | 120 | ✅ |
| Firefox | 115 ESR | ✅ |
| Safari / WebKit | 17 | ✅ |
| IE 11 | — | ❌ |

**Nota de accesibilidad:** el diseñador de playbooks tiene edición sin arrastrar para teclado y navegadores restrictivos.

---

## 3. DESPLIEGUE

| Modo | Estado | Limitación |
| :--- | :--- | :--- |
| Single-node systemd | ✅ | Sin HA |
| Docker Compose | ✅ (manifiesto) | No ejecutado en este entorno |
| Kubernetes on-prem | ✅ (manifiesto) | Sin operador propio |
| Air-gapped | ✅ | Requiere bundle offline |
| Multi-región activo/activo | ❌ | Fuera de alcance 1.0 |

---

## 4. INGESTA

| Fuente | Protocolo | Estado |
| :--- | :--- | :--- |
| Firewall / router | Syslog RFC 5424/3164 | ✅ |
| Aplicaciones | Webhook JSON/NDJSON firmado | ✅ |
| Sedes remotas | Edge gateway mTLS | ✅ |
| OCSF nativo | HTTPS | ✅ |
| CEF / LEEF | Syslog | ⚠️ Experimental |
| Splunk HEC | HTTPS | ⚠️ Experimental |
| Kafka | — | ❌ |
| SNMP traps / NetFlow | — | ❌ (fase 2) |
| gRPC streaming | — | ❌ (fase 2) |

---

## 5. THREAT INTELLIGENCE

| Fuente | Estado |
| :--- | :--- |
| STIX 2.1 (import/export) | ✅ |
| TAXII 2.1 | ✅ |
| MISP 2.4.x | ✅ |
| Feeds propietarios vía webhook | ✅ (con mapeo) |

---

## 6. CLOUD

| Proveedor | Estado | Credencial |
| :--- | :--- | :--- |
| AWS | ✅ | Rol cross-account read-only |
| Azure | ✅ | Service Principal |
| GCP | ✅ | Service Account |
| OpenStack | ⚠️ Experimental | API parcial |
| vSphere | ❌ | Fase 2 |

---

## 7. IA

| Proveedor | Estado | Notas |
| :--- | :--- | :--- |
| Ollama (local) | ✅ | Recomendado air-gap |
| vLLM (local, OpenAI-compatible) | ✅ | GPU |
| llama.cpp server | ⚠️ Experimental | — |
| OpenAI / Azure OpenAI | ✅ (opt-in) | Requiere habilitación y región |
| Anthropic | ⚠️ Experimental | Adaptador específico |
| Sin IA | ✅ | Producto funcional; estado `UNAVAILABLE` |

---

## 8. IDENTIDAD

| Mecanismo | Estado |
| :--- | :--- |
| Password local + Argon2id | ✅ |
| TOTP + recovery codes | ✅ |
| PAT con scopes | ✅ |
| OIDC | ⚠️ Experimental (interfaz) |
| SAML2 / LDAP / SCIM | ❌ / ❌ / ⚠️ |

---

## 9. FORMATOS

| Formato | Uso | Estado | Límite |
| :--- | :--- | :--- | :--- |
| CSV | Activos/observaciones | ✅ | 10 MB |
| JSON | Import/export | ✅ | 10 MB |
| Nessus `.nessus` | Vulnerabilidades | ✅ | 50 MB |
| OpenVAS XML | Vulnerabilidades | ✅ | 50 MB |
| Trivy JSON | Vulnerabilidades | ✅ | 50 MB |
| STIX 2.1 | CTI | ✅ | 50 MB |
| PDF / PNG / JPEG | Evidencias | ✅ | 50 MB |
| ZIP | Export forense (salida) | ✅ | — |
| PCAP | — | ❌ | Sin analizador |

---

## 10. VENTANA DE SOPORTE

| Versión | Soporte completo | Parches de seguridad | Fin de soporte |
| :--- | :--- | :--- | :--- |
| 1.0.x | 12 meses | 36 meses | Publicado por release |
| 1.1.x | 12 meses | 36 meses | — |
| N-2 | Migración asistida | — | — |

**CRA:** la fecha de fin de soporte de cada release se publica en `SECURITY.md` y en las notas de release.

---

## 11. CÓMO REPORTAR INCOMPATIBILIDAD

1. Verificar esta matriz y la versión exacta.
2. Recoger: versión de HISPANSHIELD, SO, navegador/proveedor, mensaje de error con `request_id`.
3. Abrir incidencia con el canal de soporte definido en el contrato.
4. Si es una fuente no soportada, se evalúa como extensión (nuevo conector) con prioridad de roadmap.
