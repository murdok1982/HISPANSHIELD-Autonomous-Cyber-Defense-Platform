# PROTECCIÓN DE DATOS (GDPR / NIS2)

- **Documento:** `specs/security/data-protection.md`
- **Estado:** `APPROVED` v1.0
- **Ámbito:** tratamiento de datos personales y de datos sensibles de seguridad en la plataforma.
- **Rol:** HISPANSHIELD es **encargado del tratamiento** (processor) respecto a los datos que el cliente introduce; el cliente es **responsable** (controller). Para sus propios datos de cuenta y telemetría de producto, el fabricante actúa como responsable.

---

## 1. CATÁLOGO DE DATOS

| Categoría | Ejemplos | Naturaleza | Base legal (cliente) | Retención por defecto |
| :--- | :--- | :--- | :--- | :--- |
| Identidad de usuario | email, nombre, hash de password, TOTP | Personal | Ejecución de contrato / interés legítimo | Vida de la cuenta + 30 d |
| Telemetría de seguridad | IP origen/destino, usuario de dominio, hostname | Personal potencial | Interés legítimo (seguridad) / obligación legal | 90 d caliente / 400 d frío |
| Evidencias de incidente | Capturas, logs, ficheros | Personal potencial / sensible | Interés legítimo / defensa jurídica | Según caso + legal hold |
| Datos de RRHH en investigaciones | Nombres, correos, actividad | Personal | Obligación legal / defensa | Según legal hold |
| Auditoría | actor, IP, acción | Personal | Obligación legal (NIS2) | 1 año mínimo, configurable |
| Informes de cumplimiento | Postura, gaps | Agregado | Obligación legal | 5 años |
| Metadatos de IA | prompts, respuestas, tokens | Personal potencial | Interés legítimo | 30 d, redactado |
| Documentos RAG | Políticas, procedimientos | Según contenido | Según contenido | Hasta borrado |

---

## 2. PRINCIPIOS APLICADOS

| Principio GDPR | Implementación |
| :--- | :--- |
| **Licitud, lealtad, transparencia** | RoPA por organización, aviso de privacidad del cliente, registro de finalidades |
| **Limitación de finalidad** | Los eventos se usan para detección/respuesta/cumplimiento; no para marketing ni perfilado |
| **Minimización** | Se almacenan campos necesarios; el contenido de comunicaciones no se captura por defecto |
| **Exactitud** | Corrección de identidad y de activos; el timeline no se edita pero admite entradas correctoras |
| **Limitación del plazo** | Retención configurable por clase; purga por partición; legal hold prevalece |
| **Integridad y confidencialidad** | Cifrado en tránsito, secretos cifrados, RBAC, auditoría, hash de evidencias |
| **Responsabilidad proactiva** | Evidencias de cumplimiento, DPIA, auditoría verificable |

---

## 3. BASES LEGALES Y DECISIONES

| Tratamiento | Base legal típica | Observaciones |
| :--- | :--- | :--- |
| Autenticación y gestión de cuentas | Ejecución de contrato / interés legítimo | Necesario para el servicio |
| Detección de incidentes de seguridad | Interés legítimo + obligación NIS2 | Documentar en RoPA del cliente |
| Notificación a autoridades | Obligación legal (NIS2 art. 23) | Plazos 24 h/72 h/1 mes |
| Investigación forense | Interés legítimo / defensa jurídica | Legal hold y minimización |
| Analítica de producto (fabricante) | Consentimiento / interés legítimo | Solo metadatos agregados; opt-in |
| IA con proveedor externo | Consentimiento explícito del `owner` | Opt-in registrado y auditable |

---

## 4. RETENCIÓN Y PURGA

| Clase | Default | Configurable | Mecanismo |
| :--- | :--- | :--- | :--- |
| Eventos calientes | 90 d | 30–365 d | Partición mensual |
| Eventos fríos | 400 d | 90–730 d | Export a almacenamiento frío (opcional) |
| Alertas | 400 d | 90–730 d | Purga por lotes |
| Incidentes | 5 años | 1–10 años | Cierre + retención |
| Evidencias | Según caso | legal hold prevalece | Hash + custodia |
| Auditoría | 1 año | 1–10 años | Append-only |
| Logs de aplicación | 30 d | 7–90 d | Rotación |
| Conversaciones IA | 30 d | 7–90 d | Redactadas |
| Documentos RAG | Hasta borrado | — | Borrado con reindexado |

**Regla:** la purga se ejecuta por job auditado, con conteo y rangos. Nunca se purga una fila con `legal_hold`; se registra `skipped_legal_hold`.

---

## 5. DERECHOS DE LOS TITULARES

| Derecho | Implementación | Plazo objetivo |
| :--- | :--- | :--- |
| Acceso | Export de datos del usuario y de sus eventos (JSON) por `admin`/DPO | 7 días |
| Rectificación | Corrección de perfil y de metadatos de activo | 7 días |
| Supresión | Anonimización de identidad en eventos (no borrado de evidencia con legal hold) | 30 días |
| Limitación | Marca de `processing_restricted` en identidad; se excluye de nuevas correlaciones | 7 días |
| Portabilidad | Export estructurado (JSON/CSV) | 30 días |
| Oposición | Exclusión de analítica de producto | 7 días |
| No decisiones automatizadas | Las acciones A2/A3/A4 tienen revisión humana; A0/A1 no afectan derechos | — |

**Anonimización vs. borrado:** en telemetría de seguridad, el borrado completo puede destruir evidencia de un ataque. La práctica: seudonimizar (`user_hash`) manteniendo la integridad analítica, salvo obligación legal de borrado.

---

## 6. TRANSFERENCIAS INTERNACIONALES

| Escenario | Permitido | Condición |
| :--- | :--- | :--- |
| Todo el procesamiento en la UE (default) | Sí | `data_region='eu'` |
| Proveedor IA externo en la UE | Sí con opt-in | Contrato + DPA + evaluación |
| Proveedor IA externo fuera de la UE | **No por defecto** | Requiere decisión explícita del `owner`, base legal y garantías; la UI advierte |
| Soporte remoto del fabricante | Solo con break-glass | TTL, auditoría, sin export de datos |
| Feeds CTI fuera de la UE | Metadatos de IOC (no personales) | Evaluación caso a caso |

El sistema **bloquea** el envío a proveedores marcados fuera de la región si `organization.data_region='eu'` y no hay `external_ai_opt_in=true` con justificación.

---

## 7. SEGURIDAD DEL TRATAMIENTO

| Medida | Implementación | Verificación |
| :--- | :--- | :--- |
| Cifrado en tránsito | TLS 1.2+ (1.3 preferido), mTLS edge | Test de cabeceras/config |
| Cifrado en reposo (secretos) | Fernet con clave externa | `test_connector_secret_storage.py` |
| Cifrado en reposo (datos) | Volumen cifrado (LUKS) provisto por el cliente | Documentado en runbook |
| Control de acceso | RBAC + tenancy + break-glass | `test_rbac_matrix.py` |
| Minimización | Campos opcionales, redacción | Revisión de esquema |
| Seudonimización | `user_hash` configurable | Test de export |
| Integridad | SHA-256 evidencias, cadena de auditoría | `test_evidence_integrity.py`, `test_audit_chain_tamper.py` |
| Disponibilidad | Backups, RPO/RTO | Drill |
| Resiliencia | Reanudación de jobs | `test_workflow_resume.py` |

---

## 8. DPIA (EVALUACIÓN DE IMPACTO)

Se requiere DPIA cuando concurran: (a) tratamiento a gran escala de datos de seguridad de personas, (b) monitorización sistemática, (c) datos de categorías especiales, (d) decisiones automatizadas con efecto. En la práctica, la mayoría de despliegues en OIV requerirán DPIA.

**Contenido mínimo del registro DPIA en la plataforma:**
- Descripción del tratamiento y finalidad.
- Necesidad y proporcionalidad.
- Categorías de datos y titulares.
- Riesgos para derechos y libertades.
- Medidas técnicas y organizativas.
- Responsable de la aprobación y fecha de revisión.
- Estado: `draft | approved | review_due`.

---

## 9. RoPA (REGISTRO DE ACTIVIDADES)

Campos obligatorios por entrada: nombre de la actividad, finalidad, base legal, categorías de titulares, categorías de datos, destinatarios, transferencias, plazo de supresión, medidas de seguridad, responsable y encargado.

La plataforma valida que no exista una entrada sin base legal ni plazo, y marca entradas con revisión vencida.

---

## 10. NOTIFICACIÓN DE BRECHAS

| Plazo | Acción | Responsable |
| :--- | :--- | :--- |
| ≤24 h | Alerta interna, evaluación inicial, activación de respuesta | `owner` + DPO |
| ≤72 h | Notificación a la autoridad de control (si procede) | DPO |
| ≤1 mes | Informe final (NIS2) | DPO + CISO |
| Sin dilación | Comunicación a titulares si alto riesgo | DPO |

La plataforma aporta el tracker (`REQ-CMP-013`) con hitos, evidencias y estado; no sustituye la decisión legal.

---

## 11. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-DP-01` | Export de datos de un titular completo y en plazo | `tests/integration/test_gdpr_export.py` |
| `AC-DP-02` | Purga respeta legal hold | `tests/integration/test_legal_hold.py` |
| `AC-DP-03` | Redacción de PII en logs | `tests/security/test_log_hygiene.py` |
| `AC-DP-04` | Bloqueo de IA externa sin opt-in en región `eu` | `tests/security/test_ai_region_block.py` |
| `AC-DP-05` | RoPA sin base legal rechazado | `tests/integration/test_gdpr_registry.py` |
| `AC-DP-06` | Retención configurable aplicada por clase | `tests/integration/test_retention_job.py` |

## 12. EVIDENCIA

1. `pytest -q tests/integration/test_gdpr_*.py tests/security/test_ai_region_block.py`.
2. Export de ejemplo anonimizado con manifiesto.
3. Log de purga con conteos y `skipped_legal_hold`.
4. Copia de RoPA/DPIA de ejemplo con validación.
5. Test de bloqueo de proveedor externo sin opt-in.
