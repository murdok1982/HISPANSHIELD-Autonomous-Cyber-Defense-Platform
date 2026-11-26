# FINAL FUNCTIONAL AUDIT — 0.1.2

## Verificado por ejecución (650 backend / 92 edge / 36 frontend)

Identidad y tenancy, MFA + recovery codes, sesiones activas, invitaciones,
`/setup`, RBAC, activos/relaciones/zonas, vulnerabilidades CVE/KEV/EPSS,
superficie de ataque con autorización, ingesta JSON/CEF/LEEF/syslog, OCSF,
detección/correlación, alertas, incidentes/timeline/evidencias, STIX/TAXII/MISP/
OpenCTI, SOAR durable, policy engine A0–A3, kill switches, AI gateway/RAG/
agentes/MCP, IoT/OT pasivo, conectores (12 adaptadores), edge WAL/HMAC,
cumplimiento (10 marcos, 105 controles), informes HTML/MD, SSE, outbox,
idempotencia, cursor pagination y auditoría HMAC.

## Parcial o no verificado (no se anuncia como soportado)

- Cloud/CSPM (AWS/Azure/GCP/OpenStack), importadores Nessus/OpenVAS/Trivy,
  legal hold, particiones, A4, reanudación durable de agentes, OIDC/SAML login,
  PDF/ZIP forense, checkpoint WORM, FTS real, benchmarks 5k/100k, E2E
  Playwright, Docker/K8s runtime, restore de backup, air-gap.

## Matriz

`.factory/AC_TRACEABILITY.md`: 70 VERIFIED, 32 PARTIAL, 22 NOT_VERIFIED.
