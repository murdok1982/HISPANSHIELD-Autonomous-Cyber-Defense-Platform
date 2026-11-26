# MANUAL DE RESPUESTA A INCIDENTES

- **Documento:** `docs/incident-response-manual.md`
- **Estado:** `APPROVED` v1.0
- **Audiencia:** respondedores, jefe de SOC, CISO, DPO
- **Marco:** NIS2 (art. 23), GDPR (art. 33/34), ENS, buenas prácticas SANS/NCSC

---

## 1. CICLO DE VIDA

```text
PREPARACIÓN → DETECCIÓN → TRIAJE → CONTENCIÓN → ERRADICACIÓN → RECUPERACIÓN → CIERRE → LECCIONES
```

| Fase | Objetivo | Salida |
| :--- | :--- | :--- |
| Preparación | Playbooks, contactos, accesos, formación | Checklist |
| Detección | Alerta o reporte | Incidente creado |
| Triaje | Severidad, alcance, impacto | `P1..P5`, dueño |
| Contención | Detener propagación | Acción verificada |
| Erradicación | Eliminar causa | Evidencia |
| Recuperación | Restaurar servicio | Servicio verificado |
| Cierre | Informe y evidencia | Informe con hash |
| Lecciones | Mejora | Acciones con dueño |

---

## 2. PRIMEROS 15 MINUTOS (P1)

1. **Crear/confirmar incidente** con severidad y activos afectados.
2. **Asignar dueño** y comunicar en el canal de incidentes.
3. **Preservar evidencia** antes de tocar nada (hashes, exportación).
4. **Evaluar contención inmediata** (aislar host, bloquear IP, revocar sesión) con blast radius.
5. **Verificar** que la contención funcionó (no confiar en el `200`).
6. **Abrir timeline** con hora UTC y actor.
7. **Notificar** a CISO; evaluar NIS2/GDPR.

**Regla:** no se apaga ni se reinstala nada antes de preservar la evidencia mínima (procesos, conexiones, cuentas, logs).

---

## 3. PLAYBOOKS TÁCTICOS

### 3.1 Ransomware

| Paso | Acción | Nivel | Verificación |
| :--- | :--- | :--- | :--- |
| 1 | Identificar alcance (hosts con cifrado/nota) | — | Lista de activos |
| 2 | Aislar hosts afectados | `A3` | Host sin red salvo gestión |
| 3 | Revocar sesiones y credenciales sospechosas | `A2` | Login falla |
| 4 | Bloquear C2/IOC | `A2` | Regla presente |
| 5 | Preservar muestras y logs | — | Hash + custodia |
| 6 | Evaluar backups y restore | — | Backup íntegro |
| 7 | Erradicar (reimage) y restaurar | — | Servicio verificado |
| 8 | Notificar (NIS2 si significativo) | — | Tracker |

**Prohibido:** pagar rescate sin decisión de dirección y legal; restaurar sobre infraestructura no erradicada.

### 3.2 Phishing / compromiso de credenciales

1. Identificar usuarios afectados y correos.
2. Revocar sesiones y forzar cambio de contraseña + MFA.
3. Bloquear dominio/URL remitente.
4. Buscar reglas de correo maliciosas y reenvíos.
5. Revisar accesos posteriores (cloud, VPN, correo).
6. Comunicar a usuarios con plantilla aprobada.

### 3.3 Insider malicioso

1. Preservar evidencia sin alertar al sujeto (coordinación con RRHH/legal).
2. Limitar accesos de forma gradual y auditada.
3. Revisar exportaciones y accesos a evidencias.
4. Documentar cadena de custodia.
5. Coordinar comunicación con legal; no confrontar sin plan.

### 3.4 Exposición cloud

1. Identificar recurso y datos expuestos.
2. Cerrar exposición (política/ACL) con evidencia.
3. Evaluar acceso durante la ventana (logs).
4. Rotar credenciales si aplica.
5. Notificar si hubo datos personales.

### 3.5 Incidente OT

1. **No** ejecutar acciones de escritura (no soportadas).
2. Notificar al responsable de planta; verificar safety.
3. Aislar segmento solo con `A4` + doble aprobación + ventana.
4. Preservar capturas/flujos.
5. Coordinar con ingeniería de procesos.

Ver `docs/iot-ot-manual.md`.

---

## 4. CONTENCIÓN: CATÁLOGO Y LÍMITES

| Acción | Nivel | Reversible | Cuidado |
| :--- | :--- | :--- | :--- |
| `block_ip` | A2 | Sí | No bloquear CDN/NAT compartido |
| `isolate_host` | A3 | Sí | No aislar DC/servidor de gestión sin plan |
| `disable_user` | A2 | Sí | No deshabilitar cuentas de servicio sin inventario |
| `revoke_sessions` | A2 | No (re-login) | Avisar al usuario |
| `quarantine_file` | A2 | Sí | Verificar que no es binario de sistema |
| `block_ot_flow` | A3 | Sí | Requiere contexto Purdue |
| `isolate_zone_segment` | A4 | Parcial | Impacto físico; doble aprobación |

**Antes de contener:** comprobar blast radius, criticidad, horario y dependencias.

---

## 5. EVIDENCIA Y TIMELINE

| Elemento | Cómo |
| :--- | :--- |
| Timeline | `POST /incidents/{id}/timeline` con tipo y detalle |
| Evidencia | Adjuntar con descripción; hash automático |
| Acciones | Se registran automáticamente con `action_id` y `decision_id` |
| Decisiones | `policy_decisions` consultables |
| Exportación | Informe al cierre con hash |

**Regla:** el timeline no se edita; se corrige con una entrada nueva que referencia la anterior.

---

## 6. NOTIFICACIÓN NIS2

| Hito | Plazo desde conocimiento | Contenido mínimo |
| :--- | :--- | :--- |
| Alerta temprana | 24 h | Afectación transfronteriza, causa probable |
| Notificación | 72 h | Evaluación inicial, severidad, indicadores, medidas |
| Informe final | 1 mes | Causa raíz, impacto, medidas, lecciones |

El tracker (`/compliance` → NIS2) crea los hitos y alerta. La decisión de notificar es del responsable legal; la plataforma aporta evidencia.

---

## 7. COMUNICACIÓN

| Audiencia | Mensaje | Restricciones |
| :--- | :--- | :--- |
| Dirección | Impacto, estado, decisiones necesarias | Sin tecnicismos |
| Usuarios | Qué hacer, qué no hacer | Sin detalles explotables |
| Clientes/ciudadanos | Si afecta a servicio | Aprobado por comunicación |
| Autoridades | Según plantilla | Plazos legales |
| Prensa | Solo dirección | Nunca detalles técnicos |

**Prohibido:** especular públicamente, atribuir a un actor sin evidencia, compartir IOCs internos.

---

## 8. CIERRE

Checklist:
- [ ] Causa raíz identificada (o hipótesis documentada).
- [ ] Contención verificada y sostenida 24 h.
- [ ] Servicio restaurado y monitorizado.
- [ ] Evidencias con hash y custodia.
- [ ] Timeline completo.
- [ ] Informe generado y revisado.
- [ ] Notificaciones realizadas o decisión documentada.
- [ ] Acciones de mejora con dueño y fecha.
- [ ] Lecciones compartidas con el equipo.

---

## 9. MÉTRICAS

| Métrica | Objetivo |
| :--- | :--- |
| MTTD | ≤5 min (laboratorio) / según fuente |
| MTTA (reconocimiento) | ≤15 min P1 |
| MTTR | ≤4 h P1 |
| % incidentes con informe | 100% P1/P2 |
| % acciones verificadas | ≥98% |
| Rollbacks fallidos | 0 |

---

## 10. ERRORES FRECUENTES

1. Contener sin medir impacto (aislar un DC).
2. Confiar en el `200` del conector sin verificar.
3. Borrar logs "para limpiar".
4. Notificar tarde por no tener el tracker.
5. No documentar decisiones denegadas (son evidencia).
6. Escalar a la autoridad sin base legal evaluada.
7. Reabrir el servicio sin erradicar la causa.
