# ADR-009: Autenticación propia (sesión + Bearer + Argon2id + TOTP)

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-011`, `specs/security/authorization-model.md`, `specs/domains/identity.md`

## Contexto

Keycloak no está disponible y añade un servicio Java con su propia BD, tema, backups y superficie. El número de usuarios por instancia es acotado (≤500 por organización) y el despliegue es air-gapped. NIS2 y ENS exigen MFA, control de sesión, trazabilidad y revocación inmediata.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Keycloak | Estándar, federación, OIDC/SAML | Servicio pesado, otra BD, operación, tema y bugs propios |
| Auth0/cloud IdP | Gestionado | Inviable en air-gap y por soberanía |
| Librería (Authlib) + OIDC propio | Estándar | Sin IdP que federar; complejidad sin beneficio |
| **Auth propia (elegida)** | Control total, sin servicio extra, trazable | Superficie propia que auditar |

## Decisión

Auth en la aplicación: Argon2id para passwords, TOTP + recovery codes, sesiones server-side con hash de token y rotación, CSRF double-submit, PAT con scopes, RBAC por organización. Interfaz `auth/providers.py` preparada para OIDC futuro sin reescribir el dominio.

## Consecuencias

**Positivas**
- Sin servicio adicional; todo el estado en la misma BD y backup.
- Revocación inmediata y auditoría granular.
- Control exacto de la experiencia (MFA obligatorio por rol/org).

**Negativas**
- La seguridad del auth es responsabilidad del proyecto; se compensa con tests adversariales y revisión externa.
- Sin federación SAML/OIDC en 1.0 (riesgo residual `R-01`).
- Sin SSO corporativo; el usuario mantiene credenciales locales.

**Métricas de reversión**
- Si un cliente exige federación SAML/OIDC como requisito contractual, implementar `OIDCProvider` sobre la interfaz existente y mantener auth local como fallback.
- Si aparecen dos vulnerabilidades `HIGH` en 12 meses en el módulo, evaluar delegar en IdP.

## Verificación

`test_auth_login.py`, `test_auth_mfa.py`, `test_csrf.py`, `test_api_tokens.py`, `test_session_lifecycle.py`, `test_auth_rate_limit.py`, revisión en `SECURITY_AUDIT.md`.
