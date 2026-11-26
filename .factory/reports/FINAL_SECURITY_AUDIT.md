# FINAL SECURITY AUDIT — 0.1.2

- **Estado:** 0 CRITICAL / 0 HIGH abiertos en el código añadido y en el baseline
  re-verificado; residuales MEDIUM/LOW aceptados y documentados.
- **No es una revisión independiente real:** el mismo auditor re-verificó. El
  gate F queda en `PENDING_INDEPENDENT_REVIEW` para un release GA.

## Controles verificados

- Tenant isolation (404 cross-org) en suites de assets, incidents, AI, MCP,
  connectors, forensics, compliance, events.
- CSRF, scopes PAT, sesiones idle/absolutas, MFA replay, recovery codes single
  use, break-glass dual cuando existe segundo admin.
- SSRF con DNS pinning, metadata IP bloqueada, redirects deshabilitados,
  allowlist de redes privadas.
- Ingesta HMAC v2 con nonce y dedupe persistente.
- Autonomía fail-closed con presupuesto, cooldown, freeze, blast radius y kill
  switches.
- Auditoría HMAC v3, rotación y checkpoints firmados.
- SSE con autorización y filtro por tenant; `Idempotency-Key` ligado a
  tenant+actor+payload+path.

## Residuales

1. HMAC + PostgreSQL en las mismas manos permiten forja; checkpoints necesitan
   export externo/WORM.
2. `allow_legacy_hmac` debilita replay si se habilita; deshabilitado por defecto.
3. Ruta legacy `/ingest/{token}` expone el token a logs de proxy; deprecada y
   redactada por la app.
4. Egress K8s sin CIDR.
5. Sin pentest fresco ni gitleaks en esta ola.

Ver `.factory/SECURITY_AUDIT.md` §9 y `.factory/SECURITY_FINDINGS.md`.
