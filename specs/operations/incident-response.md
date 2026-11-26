# RESPUESTA A INCIDENTES DE SEGURIDAD DEL PRODUCTO

- **Documento:** `specs/operations/incident-response.md`
- **Estado:** `APPROVED` v1.0
- **Ámbito:** incidentes que afectan a HISPANSHIELD como producto (vulnerabilidad, compromiso, fuga, defecto de seguridad), distintos de los incidentes de ciberdefensa del cliente (dominio `INC`).
- **Referencias:** NIS2 art. 23, CRA (obligaciones de notificación), GDPR art. 33/34.

---

## 1. FASES

```text
PREPARACIÓN → DETECCIÓN → CLASIFICACIÓN → CONTENCIÓN → ERRADICACIÓN → RECUPERACIÓN → NOTIFICACIÓN → POST-MORTEM
```

| Fase | Objetivo | Responsable |
| :--- | :--- | :--- |
| Preparación | Runbooks, contactos, canal seguro, accesos de emergencia | Seguridad |
| Detección | Alerta, divulgación, hallazgo de auditoría | Cualquiera |
| Clasificación | Severidad, alcance, tenants afectados | Seguridad + arquitectura |
| Contención | Parche, configuración, kill switch de funcionalidad | Ingeniería |
| Erradicación | Corrección de causa raíz | Ingeniería |
| Recuperación | Restauración, verificación, monitorización | Operaciones |
| Notificación | Cliente, autoridad, titulares | Dirección + legal |
| Post-mortem | ADR, test de regresión, lecciones | Arquitectura |

---

## 2. CLASIFICACIÓN

| Severidad | Criterios | Plazo de triaje | Plazo de mitigación |
| :--- | :--- | :--- | :--- |
| `S1` Crítico | RCE, bypass de autonomía, fuga cross-tenant, compromiso de claves | 1 h | 72 h |
| `S2` Alto | Escalada de privilegios, SSRF con impacto, fuga de secretos | 4 h | 14 días |
| `S3` Medio | XSS almacenado limitado, DoS, información de topología | 1 día | 30 días |
| `S4` Bajo | Defecto de robustez, mensaje verboso, dependencia con CVE no explotable | 3 días | 90 días |

**Regla HISPANSHIELD:** cualquier bypass del broker de autonomía, del kill switch o del aislamiento multi-tenant es `S1` por definición.

---

## 3. CONTENCIÓN

| Situación | Acción inmediata |
| :--- | :--- |
| Bypass de política/autonomía | Kill switch global; deshabilitar acciones afectadas; revisar `policy_decisions` |
| Fuga cross-tenant | Deshabilitar endpoint/export afectado; preservar logs; identificar tenants |
| Secreto comprometido | Rotar `SECRET_KEY` o credencial; invalidar sesiones/tokens |
| RCE o inyección | Aislar instancia; parche; revisar integridad de datos y auditoría |
| Dependencia comprometida | Bloquear versión; rebuild desde lockfile; SBOM diff |
| Cadena de auditoría alterada | Aislar; preservar; restaurar desde backup; investigar acceso |

---

## 4. NOTIFICACIÓN

| Destinatario | Cuándo | Plazo | Contenido |
| :--- | :--- | :--- | :--- |
| Cliente afectado | Confirmación de impacto | ≤24 h | Descripción, impacto, mitigación, contacto |
| Autoridad NIS2 | Incidente significativo | ≤24 h (alerta), ≤72 h (notificación), ≤1 mes (final) | Según plantilla del regulador |
| Autoridad CRA | Vulnerabilidad explotada en producto | Según reglamento | Detalle técnico y parche |
| Autoridades GDPR | Brecha de datos personales | ≤72 h | Naturaleza, categorías, medidas |
| Titulares | Alto riesgo | Sin dilación | Descripción y recomendaciones |

La plataforma aporta el tracker (`REQ-CMP-013`) para los plazos; la decisión legal es del cliente.

---

## 5. POST-MORTEM (OBLIGATORIO S1/S2)

| Sección | Contenido |
| :--- | :--- |
| Resumen | Qué pasó, cuándo, impacto |
| Cronología | Detección → contención → recuperación (UTC) |
| Causa raíz | Técnica y de proceso (5 whys) |
| Detección | ¿Cómo se detectó? ¿Tiempo? ¿Se pudo antes? |
| Impacto | Tenants, datos, disponibilidad, cumplimiento |
| Acciones correctivas | Con dueño y fecha; test de regresión |
| ADR | Si hay cambio arquitectónico |
| Actualizaciones | `threat-model.md`, `SECURITY_AUDIT.md`, `safety-requirements.md` |

**Regla:** ninguna acción correctiva se cierra sin test que falle antes y pase después.

---

## 6. CONTACTOS Y CANALES

| Rol | Responsabilidad | Canal |
| :--- | :--- | :--- |
| Responsable de seguridad | Coordinación | Canal cifrado |
| Arquitectura | Diagnóstico técnico | Canal cifrado |
| Operaciones | Contención y recuperación | Runbook |
| Legal / DPO | Notificaciones | Directo |
| Dirección | Decisión y comunicación | Directo |
| Cliente (CISO) | Interlocución | Contacto designado en contrato |

**Regla:** no se usa el propio HISPANSHIELD comprometido como único canal de coordinación; se dispone de canal alternativo.

---

## 7. EVIDENCIA Y CADENA DE CUSTODIA

1. Preservar logs, `policy_decisions`, `action_results`, auditoría y artefactos.
2. Calcular hashes y registrar custodia.
3. No reconstruir ni "limpiar" antes de preservar.
4. Exportar con manifiesto (`forensics`).
5. Mantener el acceso restringido al equipo de respuesta.

---

## 8. CRITERIOS DE ACEPTACIÓN (DEL PROCESO)

1. Todo `S1` tiene post-mortem en ≤14 días.
2. Toda acción correctiva tiene test de regresión.
3. Las notificaciones cumplen plazos documentados.
4. `SECURITY_AUDIT.md` y `threat-model.md` se actualizan tras el incidente.
5. Se realiza un simulacro anual de incidente `S1` con el equipo.
