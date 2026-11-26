# REGISTRO DE PROTOCOLOS

- **Documento:** `specs/integrations/protocol-registry.md`
- **Estado:** `APPROVED` v1.0
- **Ámbito:** protocolos de ingesta, de acción y de federación soportados por el core y el edge.

---

## 1. MODELO DE REGISTRO

Cada protocolo se declara con: identificador, capa, dirección, transporte, autenticación, formato, límites, estado de soporte y versión mínima. Un protocolo no registrado no puede usarse: el conector falla en el registro (`422 unsupported_protocol`), no en runtime.

```json
{
  "key": "syslog_rfc5424",
  "layer": "application",
  "direction": "ingest",
  "transport": ["udp", "tcp"],
  "auth": ["network_allowlist", "tls_optional"],
  "encoding": "utf-8",
  "max_message_bytes": 65536,
  "support": "supported",
  "since": "1.0.0",
  "ocsf_mapping": "syslog_v1",
  "notes": "RFC 3164 también aceptado en modo compatibilidad"
}
```

`support ∈ {supported, deprecated, experimental, unsupported}`. `unsupported` existe para declarar explícitamente lo que **no** se soporta y evitar fallbacks silenciosos (`AC-109`).

---

## 2. PROTOCOLOS DE INGESTA

| Key | Transporte | Auth | Formato | Límites | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `syslog_rfc5424` | UDP/TCP | allowlist de red, TLS opcional | RFC 5424 | 64 KB/msg, 10k msg/min/conector | `supported` |
| `syslog_rfc3164` | UDP/TCP | allowlist | RFC 3164 | 64 KB/msg | `supported` |
| `http_webhook_json` | HTTPS | HMAC-SHA256 + timestamp | JSON | 10 MB, 500 ev/lote | `supported` |
| `http_webhook_ndjson` | HTTPS | HMAC-SHA256 | NDJSON | 10 MB | `supported` |
| `edge_mtls_batch` | HTTPS | mTLS + HMAC | JSON batch con `sequence` | 5 MB, 1.000 ev/lote | `supported` |
| `taxii21_poll` | HTTPS | Basic/Bearer | STIX 2.1 | 50 MB/página | `supported` |
| `misp_feed` | HTTPS | API key | JSON MISP | 50 MB | `supported` |
| `cloud_audit_pull` | HTTPS | Role/Service Principal/OAuth | Vendor JSON | rate limit del proveedor | `supported` |
| `ocsf_json` | HTTPS | HMAC | OCSF nativo | 10 MB | `supported` |
| `cef_syslog` | UDP/TCP | allowlist | CEF sobre syslog | 64 KB | `experimental` |
| `leef_syslog` | UDP/TCP | allowlist | LEEF | 64 KB | `experimental` |
| `splunk_hec` | HTTPS | Token | JSON | 10 MB | `experimental` |
| `kafka_topic` | Kafka | SASL/TLS | JSON/Avro | — | `unsupported` (sin broker) |
| `opensearch_bulk` | HTTPS | API key | Bulk NDJSON | — | `unsupported` (sin OpenSearch) |
| `snmp_trap` | UDP | community/v3 | ASN.1 | 4 KB | `unsupported` (fase 2) |
| `netflow_ipfix` | UDP | — | IPFIX v10 | 1.500 bytes/datagrama | `unsupported` (fase 2) |
| `grpc_stream` | gRPC | mTLS | Protobuf | — | `unsupported` (fase 2) |

---

## 3. PROTOCOLOS DE ACCIÓN (SALIDA)

| Key | Transporte | Auth | Semántica | Idempotente | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `rest_json_action` | HTTPS | Bearer/Basic/mTLS | POST/PATCH idempotente | Según endpoint (`Idempotency-Key`) | `supported` |
| `firewall_api` | HTTPS | API key/token | `ip.block`, `ip.unblock` | Sí (por IP) | `supported` |
| `edr_api` | HTTPS | OAuth2 | `host.isolate`, `host.unisolate`, `file.quarantine` | Sí (por host/fichero) | `supported` |
| `idp_api` | HTTPS | Bearer/OAuth2 | `user.disable`, `user.enable`, `session.revoke` | Sí (por usuario) | `supported` |
| `ticketing_api` | HTTPS | Token | `ticket.create`, `ticket.comment` | Sí (`external_id`) | `supported` |
| `email_smtp` | SMTP | STARTTLS + auth | Notificación | No | `supported` (solo notificación) |
| `ssh_command` | SSH | Clave | Comando shell | **No** | `unsupported` (prohibido por riesgo) |
| `snmp_set` | UDP | v3 | Escritura OT | No | `unsupported` |
| `modbus_write` | TCP | — | Escritura PLC | No | `unsupported` (release 1.0) |
| `dnp3_control` | TCP | — | Control OT | No | `unsupported` |
| `opcua_write` | TCP | Certificado | Escritura OT | No | `unsupported` |
| `kubernetes_api` | HTTPS | Token | Escala/borrado | Parcial | `unsupported` (fase 2) |
| `scim_provision` | HTTPS | Bearer | Alta/baja de identidad | Sí | `experimental` |

**Regla:** cualquier protocolo con `idempotente=false` y `direction=action` obliga a `A4` + doble aprobación + verificación obligatoria. Los protocolos OT de escritura están explícitamente `unsupported` en 1.0.

---

## 4. PROTOCOLOS DE IDENTIDAD Y FEDERACIÓN

| Key | Estado | Nota |
| :--- | :--- | :--- |
| `local_password_argon2id` | `supported` | Auth propia |
| `totp_rfc6238` | `supported` | MFA |
| `oidc_authorization_code` | `experimental` | Interfaz preparada, no UI en 1.0 |
| `saml2_web_sso` | `unsupported` | Fase 2 |
| `scim2` | `experimental` | Provisión de usuarios |
| `ldap_bind` | `unsupported` | Fase 2 |

---

## 5. PROTOCOLOS DE TRANSPORTE SEGURO

| Key | Uso | Regla |
| :--- | :--- | :--- |
| `https_tls12_plus` | Todo tráfico saliente | TLS ≥1.2 (preferido 1.3), verificación de certificado obligatoria |
| `mtls` | Edge→core, acciones de alto riesgo | Certificado de cliente emitido por CA del cliente; `require_client_cert` |
| `hmac_sha256` | Webhooks y edge | Firma sobre cuerpo crudo + timestamp |
| `sftp` | Intercambio de ficheros | `experimental`, solo salida, con host key verificada |
| `smb` | — | `unsupported` |
| `ftp` | — | `unsupported` (sin cifrado) |

---

## 6. MATRIZ DE DIRECCIÓN Y CAPACIDAD

| Protocolo | Ingesta | Acción | Descubrimiento | Notas |
| :--- | :--- | :--- | :--- | :--- |
| `syslog_rfc5424` | ✅ | — | — | Fuente principal |
| `http_webhook_json` | ✅ | — | — | Fuente flexible |
| `edge_mtls_batch` | ✅ | — | — | Sedes con conectividad intermitente |
| `taxii21_poll` | ✅ | — | — | CTI |
| `misp_feed` | ✅ | — | — | CTI |
| `cloud_audit_pull` | ✅ | — | ✅ | Postura + logs |
| `rest_json_action` | — | ✅ | — | Base de acciones |
| `firewall_api` | — | ✅ | — | Contención de red |
| `edr_api` | ✅ | ✅ | — | Endpoint |
| `idp_api` | ✅ | ✅ | — | Identidad |
| `ticketing_api` | — | ✅ | — | Gestión |
| `modbus_write` / `dnp3_control` / `opcua_write` | — | ❌ | — | Prohibido 1.0 |

---

## 7. NEGOCIACIÓN Y VERSIONADO

- El `protocol_key` incluye versión mayor cuando el formato cambia de forma incompatible (`syslog_rfc5424` es estable; `cloud_audit_pull` usa versión de API del proveedor en la config).
- Un conector declara `min_core_version` y `max_core_version`; el registro rechaza incompatibilidades.
- Un protocolo `deprecated` sigue funcionando con aviso y fecha de retirada; nunca se retira sin ADR y ventana de migración ≥2 releases.

---

## 8. CRITERIOS DE ACEPTACIÓN

| AC | Criterio |
| :--- | :--- |
| `AC-109` | Protocolo no soportado reportado como `unsupported`, sin fallback |
| `AC-PROTO-02` | `POST` con protocolo `unsupported` → `422 unsupported_protocol` |
| `AC-PROTO-03` | Acción OT de escritura no aparece en catálogo ejecutable |
| `AC-PROTO-04` | mTLS rechaza cliente sin certificado cuando se exige |

## 9. EVIDENCIA

1. `pytest -q backend/tests/unit/test_protocol_registry.py`.
2. Salida de `GET /api/v1/protocols` con estados.
3. Test de rechazo de protocolo no soportado.
4. Test de mTLS (`edge/tests/test_mtls.py`).
