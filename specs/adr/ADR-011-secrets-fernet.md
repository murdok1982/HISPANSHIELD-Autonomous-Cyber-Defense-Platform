# ADR-011: Secretos con Fernet desde el entorno (sin Vault)

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-002`, `ADR-009`, `specs/security/data-protection.md`

## Contexto

La plataforma almacena secretos de conectores, claves de API de proveedores IA y secretos TOTP. Vault no está disponible y su operación (unseal, HA, políticas) es desproporcionada para un despliegue single-node air-gapped. A la vez, guardar secretos en claro en la BD es inaceptable.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Vault | Gestión completa, rotación, auditoría | Servicio extra, complejidad, unseal, otra BD |
| KMS cloud | Gestionado | Inviable en air-gap/soberanía |
| Cifrado a nivel de disco solo | Simple | No protege ante acceso a la BD o backup |
| **Fernet con clave de entorno (elegido)** | Cifrado autenticado, simple, sin servicio | La seguridad depende de la custodia de la clave |

## Decisión

`cryptography.Fernet` (AES-128-CBC + HMAC-SHA256) con clave en `HISPANSHIELD_SECRET_KEY`; envelope por valor con `key_version`; rotación mediante re-cifrado transaccional; la clave nunca se almacena en la BD ni en logs. El arranque falla si falta en producción. Interfaz `KeyProvider` para integrar HSM/KMS en el futuro.

## Consecuencias

**Positivas**
- Secretos cifrados y autenticados en reposo sin servicio adicional.
- Rotación soportada sin downtime (re-cifrado por lotes).
- Implementación pequeña y auditable.

**Negativas**
- Compromiso de la clave compromete todos los secretos; se mitiga con custodia externa (gestor de secretos del cliente), permisos `0600`, rotación y separación del backup.
- Sin HSM: riesgo residual `R-02`.
- La rotación de la clave requiere job y verificación.

**Métricas de reversión**
- Si el cliente exige HSM/FIPS 140-2 nivel 3, implementar `Pkcs11KeyProvider` sobre la interfaz.
- Si se detecta la clave en un log o backup, incidente `S1` y rotación inmediata.

## Verificación

`test_connector_secret_storage.py` (cifrado en BD, `has_secret`, no fuga), `test_ai_log_redaction.py`, prueba de rotación, arranque sin clave en producción → falla con mensaje claro.
