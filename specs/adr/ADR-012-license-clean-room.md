# ADR-012: Clean-room rewrite y política de licencias

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `docs/repository-audit.md`, `docs/license-policy.md`, `specs/constitution.md` Art. 9

## Contexto

El directorio del proyecto estaba vacío al inicio (sin código fuente, sin historial de commits). Existe un producto hermano en el mismo volumen, `SmartNationDefense`, con licencia **no comercial** (`HISPANSHIELD NON-COMMERCIAL LICENSE v1.0`, autor Gustavo Lobato Clara) y un dominio funcional distinto (SESIS-FEDERATION). El nombre comercial y algunas ideas de dominio se solapan, lo que crea riesgo de contaminación de licencia y de arrastre de decisiones no auditadas.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Reutilizar/portar el producto hermano | Ahorro de tiempo | Licencia no comercial incompatible con uso institucional/comercial; producto distinto; deuda heredada |
| Copiar fragmentos "sin atribución" | Ninguno lícito | Violación de licencia y de la constitución |
| **Clean-room (elegido)** | Licencia limpia, decisiones propias, trazabilidad | Mayor esfuerzo inicial |

## Decisión

1. HISPANSHIELD se construye desde cero: sin copiar código, esquemas, nombres de módulos, tests ni documentación de `SmartNationDefense`.
2. El producto hermano se trata como **referencia de mercado no vinculante**; no se abre durante la implementación salvo para la auditoría de licencia documentada en `docs/repository-audit.md`.
3. Allowlist de licencias para dependencias: MIT, BSD-2/3, Apache-2.0, ISC, PSF, MPL-2.0 (con revisión). Prohibidas AGPL, SSPL, BSL, Commons Clause y cualquier licencia no comercial o de campo de uso restringido.
4. Toda dependencia nueva pasa por `scripts/check_licenses.py` y queda registrada en el SBOM.

## Consecuencias

**Positivas**
- Cero riesgo de contaminación de licencia.
- Arquitectura y decisiones propias, documentadas y auditables.
- Libertad para licenciar el producto según el modelo institucional que se defina.

**Negativas**
- Esfuerzo inicial mayor (todo se diseña e implementa).
- Riesgo de repetir errores que el producto hermano ya resolvió; se compensa con revisión de dominio y ADRs.
- Hay que demostrar originalidad si se cuestiona; el historial git y los ADRs son la evidencia.

**Reglas de cumplimiento**
- Prohibido `git remote` al repositorio hermano.
- Prohibido copiar ficheros; revisión de PR con checklist de originalidad.
- Si se descubre una similitud no intencionada, se reescribe y se documenta.

## Verificación

1. `docs/repository-audit.md` con inventario y conclusión de exclusión.
2. `docs/license-policy.md` con allowlist y procedimiento.
3. `scripts/check_licenses.py` en el gate (`AC-121`).
4. Historial git sin commits heredados.
5. Revisión de originalidad en la auditoría final (`TASK-150`).
