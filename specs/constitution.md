# CONSTITUCIÓN TÉCNICA DE HISPANSHIELD

- **Versión:** `1.0.0`
- **Estado:** `RATIFICADA` (base inmutable de decisiones; cambios solo por enmienda)
- **Ámbito:** todo artefacto de código, especificación, despliegue y documentación del producto
- **Autoridad:** este documento prevalece sobre cualquier otra especificación en caso de conflicto. `SPEC.md` prevalece sobre documentos de dominio; los ADR prevalecen sobre decisiones informales.
- **Idioma:** documentación en español; identificadores, contratos y código en inglés.

---

## PREÁMBULO

HISPANSHIELD es una plataforma de ciberdefensa para administraciones públicas y operadores de infraestructuras críticas de la Unión Europea. Su fallo puede tener consecuencias sobre servicios esenciales; su mal uso puede convertirse en un arma. Por tanto, el proyecto se rige por restricciones más estrictas que un producto comercial convencional: soberanía del dato, minimización de privilegios, reversibilidad de acciones, trazabilidad demostrable y verificación ejecutable de cada afirmación.

Esta constitución define los principios que ningún agente, humano o automático, puede violar, y los mecanismos que los hacen exigibles.

---

## ARTÍCULO 1 — PRIMACÍA DE LA SEGURIDAD Y DE LA VERIFICACIÓN

1.1. Ninguna funcionalidad se considera terminada por el hecho de existir en el código. Se considera terminada cuando un test automatizado demuestra su comportamiento y un comando reproducible lo confirma.

1.2. Un `AC-XX` sin test ejecutable es una hipótesis, no un criterio de aceptación. `@qa-verifier` no puede marcarlo `[x]` sin salida de comando con exit code 0.

1.3. La ausencia de evidencia se registra como ausencia. Queda prohibido declarar verificado lo no ejecutado, incluido lo que "debería funcionar".

1.4. Todo defecto de seguridad con severidad `CRITICAL` o `HIGH` bloquea la entrega, con independencia del calendario, la demo o la presión comercial.

---

## ARTÍCULO 2 — SOBERANÍA Y LOCALIDAD DEL DATO

2.1. Por defecto, ningún dato de la organización sale del perímetro desplegado. La inferencia de IA es local o no es.

2.2. El uso de proveedores externos de IA requiere: (a) habilitación explícita por un `owner`, (b) registro del proveedor y del modelo, (c) advertencia visible en la UI, (d) auditoría de cada llamada con metadatos (sin contenido sensible cuando la política lo impida).

2.3. Toda función de detección, correlación y respuesta autónoma es determinista y operable sin IA. La IA es asistiva, nunca requisito de funcionamiento.

2.4. Los datos se almacenan en la región declarada por la organización (`organizations.data_region`). El producto no replica datos entre regiones sin orden explícita y auditada.

---

## ARTÍCULO 3 — DENY-BY-DEFAULT Y MÍNIMO PRIVILEGIO

3.1. Toda autorización deniega por defecto. Un permiso existe solo si está declarado en la matriz de `specs/security/authorization-model.md` y aplicado en el servidor.

3.2. Toda entidad de dominio pertenece a una organización. Toda consulta filtra por `organization_id`. La ausencia del filtro es un defecto `CRITICAL`.

3.3. La identidad del usuario nunca se toma del cliente (body, query o cabecera no firmada). Se resuelve desde la sesión o el token verificado.

3.4. `platform_admin` no es un superusuario de datos. El acceso cross-org requiere `break-glass` con justificación, TTL máximo 60 minutos y auditoría.

3.5. La autorización se evalúa en el servidor incluso si la UI ya oculta la acción. La UI es una ayuda, no un control.

---

## ARTÍCULO 4 — AUTONOMÍA GOBERNADA

4.1. Ninguna acción con efecto externo se ejecuta sin una decisión de política persistida (`decision_id`, `policy_version`, reglas aplicadas).

4.2. Los niveles de autonomía son acumulativos y explícitos: `A0` observar, `A1` recomendar, `A2` actuar con aprobación, `A3` actuar dentro de política sobre acciones reversibles, `A4` actuar con doble aprobación y time-box sobre acciones de alto impacto.

4.3. Toda acción declara, antes de ejecutarse: blast radius máximo, criterio de verificación, procedimiento de rollback y ventana temporal.

4.4. El kill switch prevalece sobre cualquier política. Su efecto debe ser observable en ≤5 segundos.

4.5. El modelo de lenguaje no es autoridad. No aprueba, no autoriza y no ejecuta: propone; el broker decide y ejecuta.

4.6. Las acciones `A3`/`A4` requieren telemetría fresca. Con datos `stale`, la decisión es `deny`.

---

## ARTÍCULO 5 — TRAZABILIDAD E INTEGRIDAD

5.1. Toda acción humana o autónoma relevante produce una entrada de auditoría con actor, recurso, resultado, `request_id` y hash encadenado.

5.2. Los eventos SIEM son inmutables. La retención se implementa por eliminación de particiones completas, nunca por `UPDATE`/`DELETE` de filas.

5.3. Las evidencias se identifican por SHA-256 y su alteración debe ser detectable.

5.4. La cadena de auditoría debe ser verificable de extremo a extremo; una alteración se reporta con el primer `seq` inconsistente.

5.5. Los logs operativos no contienen secretos ni PII innecesaria; la redacción se prueba, no se asume.

---

## ARTÍCULO 6 — HONESTIDAD DEL ESTADO

6.1. Prohibido fabricar datos. No hay mocks, datos de ejemplo ni respuestas sintéticas en rutas de producción.

6.2. Si un conector, sensor o proveedor no responde, la API devuelve un estado explícito (`degraded`, `unavailable`) con causa y `as_of`, y la UI lo muestra.

6.3. Un cero solo significa cero cuando se ha medido. La ausencia de datos se representa como ausencia, nunca como valor neutro.

6.4. Las estimaciones (p.ej. `total_estimate` en búsquedas) se etiquetan como tales.

---

## ARTÍCULO 7 — REVERSIBILIDAD Y SEGURIDAD OPERACIONAL

7.1. Toda acción autónoma debe poder revertirse o, si no es reversible, requiere nivel `A4`, doble aprobación y justificación explícita.

7.2. Las acciones sobre OT respetan el modelo Purdue, las zonas/conductos IEC 62443 y los interlocks de seguridad física. Una acción que pueda afectar a una función de seguridad se deniega por defecto.

7.3. Las ventanas de cambio congelado bloquean acciones disruptivas salvo `break_glass` auditado.

7.4. El sistema impone límites de blast radius, frecuencia y coste; no confía en la prudencia del operador ni del agente.

---

## ARTÍCULO 8 — CALIDAD DEL CÓDIGO Y DE LA INTERFAZ

8.1. Python: `ruff` y `mypy --strict` sin errores. TypeScript: `strict` sin `any` implícito ni `@ts-ignore` injustificado.

8.2. Prohibidos `TODO`, `FIXME`, `NotImplementedError`, funciones vacías, endpoints sin implementar y componentes que muestran datos falsos.

8.3. Toda vista con datos implementa estados de carga (skeleton estructural), vacío (con CTA) y error (con reintento). Sin excepciones.

8.4. La accesibilidad WCAG 2.2 AA es un requisito funcional, no un extra. El color nunca es el único portador de significado.

8.5. El diseño usa los tokens de `ARCHITECTURE.md §5`. Un color, espaciado o radio fuera de token es un defecto de revisión.

---

## ARTÍCULO 9 — LICENCIAS Y CADENA DE SUMINISTRO

9.1. El producto es un desarrollo clean-room. No se copia código, esquema, nombres de módulos ni documentación de `SmartNationDefense` ni de ningún producto con licencia incompatible.

9.2. Dependencias de runtime permitidas: MIT, BSD-2/3, Apache-2.0, ISC, PSF, MPL-2.0 (con revisión). Prohibidas: AGPL, SSPL, BSL, Commons Clause y cualquier licencia no comercial o de campo de uso restringido.

9.3. Toda dependencia nueva requiere justificación y entrada en `docs/license-policy.md`.

9.4. Cada release produce SBOM CycloneDX, checksums y, cuando el entorno lo permita, firma de artefactos.

9.5. Las vulnerabilidades del propio producto se gestionan con divulgación responsable y plazos de parcheo documentados (`SECURITY.md`).

---

## ARTÍCULO 10 — OPERABILIDAD EN CONDICIONES ADVERSAS

10.1. El producto debe instalarse y operar sin acceso a Internet (air-gapped), sin servicios de terceros y con un único PostgreSQL.

10.2. La pérdida de un worker no pierde trabajo aceptado: las colas son durables y las ejecuciones reanudables.

10.3. Un backup debe poder restaurarse en una instancia limpia con procedimiento probado y verificable.

10.4. El sistema expone salud, métricas y causa de degradación sin requerir observabilidad externa.

10.5. El apagado es ordenado: deja de aceptar trabajo, drena lo en curso y cierra recursos.

---

## ARTÍCULO 11 — DOCUMENTACIÓN COMO PARTE DEL PRODUCTO

11.1. Un cambio de comportamiento sin actualización de `SPEC.md`, del documento de dominio y de la matriz de tests está incompleto.

11.2. Los identificadores (`AC-XX`, `REQ-XXX-NNN`, `ADR-NNN`, `TASK-NNN`, `VULN-XXX`) son estables y no se reutilizan.

11.3. Los manuales operativos describen procedimientos ejecutables, con comandos exactos y resultados esperados, no intenciones.

11.4. La documentación no promete capacidades no implementadas. Las hojas de ruta se etiquetan como tales.

---

## ARTÍCULO 12 — CONTROL DE CAMBIOS Y ENMIENDAS

12.1. Un cambio arquitectónico requiere ADR aceptado en `specs/adr/` y actualización del índice en `ARCHITECTURE.md §7`.

12.2. Un cambio en un `AC-XX` requiere ADR y actualización simultánea de `SPEC.md`, documento de dominio y matriz de tests.

12.3. Tres fallos consecutivos de una misma tarea activan el Circuit Breaker: diagnóstico de causa raíz, ADR y replanificación. No se reintenta la misma solución una cuarta vez.

12.4. Esta constitución se enmienda por propuesta escrita, análisis de impacto y aprobación del rol de arquitectura; la enmienda se versiona y se registra en el historial.

---

## MECANISMOS DE EXIGIBILIDAD

| Mecanismo | Qué garantiza | Dónde se ejecuta |
| :--- | :--- | :--- |
| `scripts/verify_all.sh` | Build, tipos, lint, tests, E2E, SBOM, seguridad | Gate de cada fase y gate final |
| `backend/tests/security/test_tenant_isolation.py` | Artículo 3.2 | Gate de fase 1 y final |
| `backend/tests/autonomy/` | Artículos 4 y 7 | Gate de fase 6 y final |
| `backend/tests/security/test_prompt_injection.py` | Artículo 4.5 | Gate de fase 7 y final |
| `frontend/e2e/{a11y,responsive,states}.spec.ts` | Artículo 8 | Gate de fase 10 |
| `scripts/generate_sbom.sh` + `check_licenses.py` | Artículo 9 | Gate final |
| `scripts/backup_restore_drill.sh` + `verify_airgap.sh` | Artículo 10 | Gate final |
| `.factory/SECURITY_AUDIT.md` | Artículos 1.4, 3, 5 | Gate final |

## CONFLICTOS Y JERARQUÍA NORMATIVA

1. Legislación aplicable (NIS2, CRA, GDPR, ENS) y contratos con el cliente.
2. Esta constitución.
3. `.factory/SPEC.md` (criterios de aceptación).
4. `specs/security/*` (modelo de autorización, autonomía, protección de datos).
5. `specs/architecture/*` y ADR aceptados.
6. `specs/domains/*` y `specs/integrations/*`.
7. `docs/*` (material operativo y explicativo).

Ante ambigüedad, se elige la interpretación más restrictiva en seguridad y se documenta la decisión.
