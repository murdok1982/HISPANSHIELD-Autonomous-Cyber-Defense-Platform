# VISIÓN DE PRODUCTO

- **Producto:** HISPANSHIELD — Autonomous Cyber Defence Platform
- **Documento:** `specs/product/vision.md`
- **Estado:** `APPROVED` v1.0
- **Audiencia:** dirección de producto, arquitectura, responsables de seguridad (CISO/RSSI), equipos SOC, integradores

---

## 1. DECLARACIÓN DE VISIÓN

> Dar a las administraciones públicas y a los operadores de infraestructuras críticas europeas una plataforma de ciberdefensa que puedan **desplegar en su propio perímetro**, **entender sin cajas negras** y **gobernar hasta la última acción automática**, sin depender de nubes extranjeras ni de licencias que les impidan operar.

HISPANSHIELD convierte la telemetría dispersa (red, endpoint, nube, IoT, OT), el inventario y el conocimiento de amenazas en decisiones de defensa trazables. La automatización no sustituye al operador: amplía su alcance bajo políticas explícitas, con verificación y reversión.

---

## 2. PROBLEMA

| # | Problema | Consecuencia para el organismo | Evidencia de mercado |
| :--- | :--- | :--- | :--- |
| `P-1` | Herramientas fragmentadas: SIEM, escáner, CMDB, SOAR y compliance en silos | Contexto partido, MTTR alto, analistas copiando datos entre consolas | Los SOC pequeños operan 8-15 herramientas sin integración real |
| `P-2` | Dependencia de SaaS extranjero | Riesgo legal (GDPR, secretos oficiales), latencia, corte de servicio por decisión política | Requisitos de soberanía crecientes en AAPP y OIV |
| `P-3` | Automatización opaca | Miedo a que un playbook aísle un servidor crítico; se desactiva la automatización | SOAR con poca adopción en entornos regulados |
| `P-4` | Presión normativa creciente | NIS2, CRA, ENS y GDPR exigen evidencia, plazos y responsabilidad demostrable | Sanciones y auditorías con exigencia de pruebas |
| `P-5` | Escasez de analistas | Plantillas pequeñas, turnos 24x7 imposibles | Brecha de talento sostenida en ciberseguridad |
| `P-6` | IT/OT/IoT tratados por separado | Un incidente empieza en IT y afecta a OT sin visión unificada | Incidentes reales con impacto físico |
| `P-7` | Herramientas que "inventan" datos cuando falta una fuente | Decisiones sobre datos falsos | Interfaces que muestran ceros o datos de demo en producción |

---

## 3. PROPUESTA DE VALOR

1. **Soberanía operativa real:** despliegue on-premise o air-gapped, IA local opcional, cero dependencia de servicios externos para funcionar.
2. **Contexto unificado:** un activo, sus vulnerabilidades, sus eventos, su exposición, su criticidad y su cumplimiento viven en el mismo grafo lógico.
3. **Autonomía gobernada:** niveles `A0..A4`, política deny-by-default, blast radius, aprobaciones, kill switch y rollback verificable.
4. **Evidencia para el regulador:** mapeo a NIS2/CRA/GDPR/ENS/ISO 27001/27002/IEC 62443/ETSI EN 303 645 con evidencias, vigencia y trazabilidad.
5. **Honestidad de estado:** si algo no está disponible, se dice; nunca se simula.
6. **Operable por equipos pequeños:** instalación en un nodo, un PostgreSQL, sin broker ni caché externos; consola pensada para turnos.

---

## 4. PRINCIPIOS DE PRODUCTO

| Principio | Traducción en el producto |
| :--- | :--- |
| `Soberanía` | Todo corre dentro del perímetro; proveedores externos solo con opt-in auditado |
| `Explicabilidad` | Cada score, alerta y decisión muestra sus factores y su versión de regla/política |
| `Control` | El operador puede detener toda autonomía con un interruptor visible y verificable |
| `Reversibilidad` | Acciones con rollback declarado; lo irreversible exige A4 y doble aprobación |
| `Trazabilidad` | Cadena de auditoría íntegra; evidencias con hash |
| `Honestidad` | Estados `degraded`/`unavailable` con causa y `as_of`; sin datos de relleno |
| `Densidad útil` | UI de consola SOC: mucha información, jerarquía clara, cero decoración |
| `Portabilidad` | Air-gap, single-node, Kubernetes; sin servicios propietarios obligatorios |

---

## 5. PERSONAS Y ESCENARIOS DE REFERENCIA (resumen)

| Persona | Necesidad primaria | Valor que recibe |
| :--- | :--- | :--- |
| CISO / RSSI de organismo | Demostrar postura y cumplimiento | Panel ejecutivo + informes con evidencia e integridad |
| Jefe de SOC | Priorizar y coordinar respuesta | Cola priorizada, SLA, playbooks con aprobación |
| Analista SOC | Investigar rápido y con contexto | Búsqueda unificada, correlación, grafo de activos |
| Responsable de OT | Proteger procesos físicos | Modelo Purdue, interlocks, baseline de protocolos |
| DPO / Cumplimiento | Responder a auditoría | RoPA, DPIA, evidencias con vigencia, tracker NIS2 |
| Operador de plataforma | Mantener el servicio | Salud, backups, air-gap, kill switches |
| Auditor externo | Verificar sin alterar | Rol `auditor` de solo lectura con cadena de custodia |

Detalle completo en `specs/product/personas.md`.

---

## 6. MÉTRICAS DE ÉXITO

| ID | Métrica | Objetivo a 12 meses | Método de medida |
| :--- | :--- | :--- | :--- |
| `M-01` | Tiempo medio de detección (MTTD) en escenarios de laboratorio | ≤ 5 min desde el evento | `specs/testing/autonomy-lab.md` + escenarios sintéticos |
| `M-02` | Tiempo medio de contención con playbook aprobado | ≤ 15 min | Timeline de incidentes |
| `M-03` | % de alertas con contexto de activo y exposición | ≥ 95% | Consulta a BD de alertas |
| `M-04` | Acciones autónomas con verificación exitosa | ≥ 98% | `action_results` |
| `M-05` | Acciones autónomas revertidas por fallo de verificación | ≤ 2% y 100% registradas | `action_results` |
| `M-06` | Cobertura de controles con evidencia vigente (NIS2/ENS) | ≥ 80% en el primer trimestre de uso | Módulo de cumplimiento |
| `M-07` | Tiempo de instalación air-gapped | ≤ 2 h en un nodo | `scripts/verify_airgap.sh` cronometrado |
| `M-08` | Defectos de aislamiento multi-tenant | 0 | Suite de aislamiento |
| `M-09` | Satisfacción de analistas (SUS interno) | ≥ 75 | Encuesta semestral |
| `M-10` | Coste de infraestructura por 1.000 eventos/s | ≤ 1 nodo de 16 vCPU / 64 GB | Bench de ingesta |

---

## 7. NO OBJETIVOS (visión)

- No somos un EDR: integramos EDR como fuente.
- No somos un proveedor de TI: no gestionamos parque ni helpdesk.
- No somos un servicio gestionado (MSSP) en esta versión: el producto se instala y opera por el cliente o su integrador.
- No entrenamos modelos fundacionales: usamos modelos locales o proveedores aprobados.
- No hacemos explotación ofensiva automatizada.
- No sustituimos la decisión legal del organismo sobre notificación de incidentes: la facilitamos y documentamos.

---

## 8. DIFERENCIACIÓN

| Criterio | SIEM/SOAR SaaS típico | Herramienta open source ensamblada | HISPANSHIELD |
| :--- | :--- | :--- | :--- |
| Soberanía | Depende del proveedor | Varía, normalmente sin soporte | On-prem/air-gap de serie |
| Autonomía | Playbooks sin gobernanza formal | Scripts sin política ni rollback | `A0..A4` + política + verificación + rollback |
| Cumplimiento UE | Mapeos genéricos | Manual | NIS2/CRA/GDPR/ENS/IEC 62443/ETSI con evidencias |
| IT/OT/IoT | Módulos separados o ausentes | Integraciones frágiles | Modelo unificado con Purdue y zonas |
| IA | Cloud por defecto | Experimental | Local-first, opcional, con citas y presupuesto |
| Honestidad de estado | Datos de demo mezclados | Errores silenciosos | Estados explícitos, cero datos fabricados |
| Operación | Requiere equipo plataforma | Requiere ensamblaje | Un nodo + PostgreSQL; runbooks incluidos |

---

## 9. RIESGOS DE PRODUCTO

| Riesgo | Impacto | Mitigación |
| :--- | :--- | :--- |
| Percepción de "otro SIEM" | Baja adopción | Foco en autonomía gobernada + cumplimiento UE como cuña |
| Complejidad de configuración inicial | Abandono en onboarding | Setup guiado, seed de frameworks, valores por defecto seguros |
| Falsa confianza en la IA | Decisiones erróneas | IA asistiva, citas obligatorias, sin autoridad de acción |
| Acción autónoma dañina | Impacto operativo y reputacional | Deny-by-default, blast radius, aprobaciones, kill switch, rollback |
| Deuda por monolito | Escalado limitado | Fronteras de módulo estrictas y camino de extracción documentado |
| Dependencia de PostgreSQL | Punto único | Backups verificados, RPO/RTO documentados, réplica opcional |

---

## 10. CRITERIOS DE ÉXITO DEL PRIMER DESPLIEGUE

1. Instalación air-gapped completada por el equipo del cliente siguiendo `docs/operations-runbook.md`, sin asistencia del fabricante.
2. Ingesta de al menos dos fuentes reales (syslog de firewall y un conector cloud/EDR) con eventos normalizados y búsqueda operativa.
3. Un playbook con aprobación ejecutado de extremo a extremo sobre un activo de laboratorio, con rollback verificado.
4. Una evaluación de NIS2 o ENS completada con evidencias y un informe exportado con hash verificable.
5. Cero hallazgos `CRITICAL`/`HIGH` abiertos en la auditoría previa a la entrega.
6. El cliente puede activar el kill switch y demostrar que la autonomía se detiene en ≤5 s.
