# FINAL FUNCTIONAL AUDIT — 0.1.3

## Verificado por ejecución (669 backend / 92 edge / 36 frontend)

Identidad y tenancy, MFA + recovery codes, sesiones activas, invitaciones,
`/setup`, RBAC, activos/relaciones/zonas, vulnerabilidades CVE/KEV/EPSS,
superficie de ataque con autorización, ingesta JSON/CEF/LEEF/syslog, OCSF,
detección/correlación, alertas, incidentes/timeline/evidencias, STIX/TAXII/MISP/
OpenCTI, SOAR durable, policy engine A0–A3, kill switches, AI gateway/RAG/
agentes/MCP, IoT/OT pasivo, conectores (12 adaptadores), edge WAL/HMAC,
cumplimiento (10 marcos), informes HTML/MD, SSE, outbox con `LISTEN/NOTIFY`,
idempotencia, cursor pagination, auditoría HMAC, soft delete/restore de activos,
export STIX 2.1, importadores Nessus/OpenVAS/Trivy e IEC 62443 `required_sl`.

## Parcial o no verificado (no se anuncia como soportado)

Cloud/CSPM, legal hold, particiones/retención, A4, reanudación durable de
agentes, OIDC/SAML login, PDF forense, checkpoint WORM, FTS en todas las
búsquedas, benchmarks 5k/100k, Firefox/WebKit, Docker/K8s runtime, air-gap y
revisión externa independiente. El E2E cubre los flujos núcleo existentes, pero
no crea un activo, ingesta un evento y ejecuta un playbook en el mismo test;
por eso AC-119 sigue `PARTIAL`.

## Matriz

`.factory/AC_TRACEABILITY.md`: **81 VERIFIED, 27 PARTIAL, 16 NOT_VERIFIED**
(124 AC).
