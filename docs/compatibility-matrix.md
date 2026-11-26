# MATRIZ DE COMPATIBILIDAD (RESUMEN DE PRODUCTO)

- **Documento:** `docs/compatibility-matrix.md`
- **Estado:** `APPROVED` v1.1 (reconciliado con código; las filas ✅ implican prueba o implementación real, no solo una interfaz)
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
| Kubernetes | 1.28+ | Plantilla renderizable + validación estática; sin ejecución en clúster en este entorno |
| Docker Engine | 24+ | Compose incluido; build/runtime **no ejecutado** en este entorno |

---

## 2. NAVEGADORES

| Navegador | Versión mínima | Estado |
| :--- | :--- | :--- |
| Chrome / Edge (Chromium) | 120 | ✅ (suite E2E existe; no re-ejecutada en esta ola) |
| Firefox | 115 ESR | ⚠️ No verificado (proyecto Playwright definido, no ejecutado) |
| Safari / WebKit | 17 | ⚠️ No verificado (proyecto Playwright definido, no ejecutado) |
| IE 11 | — | ❌ |

**Nota de accesibilidad:** el diseñador de playbooks tiene edición sin arrastrar para teclado y navegadores restrictivos.

---

## 3. DESPLIEGUE

| Modo | Estado | Limitación |
| :--- | :--- | :--- |
| Single-node systemd | ✅ | Sin HA |
| Docker Compose | ⚠️ Manifiesto | Build/runtime no ejecutado en este entorno |
| Kubernetes on-prem | ⚠️ Plantilla | `render.sh` + `validate_deploy.py`; sin clúster real |
| Air-gapped | ❌ No verificado | Requiere bundle offline y prueba `--no-index` |
| Multi-región activo/activo | ❌ | Fuera de alcance 1.0 |

---

## 4. INGESTA

| Fuente | Protocolo | Estado |
| :--- | :--- | :--- |
| Firewall / router | Syslog RFC 5424/3164 | ✅ |
| Aplicaciones | Webhook JSON/NDJSON firmado | ✅ |
| Sedes remotas | Edge gateway mTLS | ✅ |
| OCSF nativo | HTTPS | ✅ |
| CEF / LEEF | Syslog | ✅ (parser y tests) |
| Splunk HEC | HTTPS | ❌ No implementado (solo conector genérico) |
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
| AWS | ❌ | Sin cuentas cloud/CSPM; `/cloud` deriva postura del inventario |
| Azure | ❌ | Sin cuentas cloud/CSPM |
| GCP | ❌ | Sin cuentas cloud/CSPM |
| OpenStack | ❌ | Sin cuentas cloud/CSPM |
| vSphere | ❌ | Fase 2 |

---

## 7. IA

| Proveedor | Estado | Notas |
| :--- | :--- | :--- |
| Ollama (local) | ✅ | Recomendado air-gap |
| vLLM (local, OpenAI-compatible) | ✅ | GPU |
| llama.cpp server | ✅ | Endpoint OpenAI-compatible |
| OpenAI-compatible externo | ✅ (opt-in) | Requiere habilitación, HTTPS y región EU |
| Anthropic | ❌ | Sin adaptador específico |
| Sin IA | ✅ | Producto funcional; estado `UNAVAILABLE` |

---

## 8. IDENTIDAD

| Mecanismo | Estado |
| :--- | :--- |
| Password local + Argon2id | ✅ |
| TOTP + recovery codes | ✅ (single-use, Argon2id, rotación) |
| PAT con scopes | ✅ |
| Invitaciones single-use (72 h) | ✅ |
| OIDC | ❌ (el adaptador Keycloak es de conector, no login SSO) |
| SAML2 / LDAP / SCIM | ❌ / ❌ / ❌ |

---

## 9. FORMATOS

| Formato | Uso | Estado | Límite |
| :--- | :--- | :--- | :--- |
| CSV | Activos/observaciones | ✅ | 10 MB |
| JSON | Import/export | ✅ | 10 MB |
| Nessus `.nessus` | Vulnerabilidades | ✅ `POST /vulnerabilities/import` | 20 MB |
| OpenVAS XML | Vulnerabilidades | ✅ `POST /vulnerabilities/import` | 20 MB |
| Trivy JSON | Vulnerabilidades | ✅ `POST /vulnerabilities/import` | 20 MB |
| STIX 2.1 | CTI / ASM export | ✅ import CTI + export ASM | 50 MB |
| PDF / PNG / JPEG | Evidencias | ✅ | 50 MB |
| ZIP | Export forense (salida) | ❌ No implementado (export JSON/CSV) | — |
| PCAP | — | ❌ | Sin analizador |

---

## 10. VENTANA DE SOPORTE

| Versión | Soporte completo | Parches de seguridad | Fin de soporte |
| :--- | :--- | :--- | :--- |
| 0.1.x | Sin compromiso GA | 36 meses tras GA | Release candidate |
| 1.0.x | 12 meses | 36 meses | No publicado |
| N-2 | Migración asistida | — | — |

**CRA:** la fecha de fin de soporte de cada release se publica en `SECURITY.md` y en las notas de release.

---

## 11. CÓMO REPORTAR INCOMPATIBILIDAD

1. Verificar esta matriz y la versión exacta.
2. Recoger: versión de HISPANSHIELD, SO, navegador/proveedor, mensaje de error con `request_id`.
3. Abrir incidencia con el canal de soporte definido en el contrato.
4. Si es una fuente no soportada, se evalúa como extensión (nuevo conector) con prioridad de roadmap.
