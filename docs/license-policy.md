# POLÍTICA DE LICENCIAS Y CADENA DE SUMINISTRO

- **Documento:** `docs/license-policy.md`
- **Estado:** `APPROVED` v1.0
- **Base:** `ADR-012`, `specs/constitution.md` Art. 9
- **Aplicación:** toda dependencia de runtime, build, test o herramienta incluida en el repositorio.

---

## 1. PRINCIPIOS

1. **Clean-room.** HISPANSHIELD no deriva de `SmartNationDefense` ni de ningún producto con licencia incompatible.
2. **Permisividad por defecto.** Solo licencias que permitan uso institucional, modificación, distribución y operación comercial sin restricciones de campo de uso.
3. **Trazabilidad.** Toda dependencia queda registrada en el SBOM y verificada en el gate.
4. **Sin sorpresas.** Una licencia nueva requiere revisión explícita antes de entrar en el árbol de dependencias.
5. **Cumplimiento CRA.** Se documenta la política de soporte y actualizaciones del producto.

---

## 2. ALLOWLIST

| Licencia | Permitida | Condiciones |
| :--- | :---: | :--- |
| MIT | ✅ | Conservar aviso de copyright |
| BSD-2-Clause / BSD-3-Clause | ✅ | Conservar aviso; no endosar |
| Apache-2.0 | ✅ | Conservar NOTICE; patent grant |
| ISC | ✅ | Conservar aviso |
| Python Software Foundation (PSF-2.0) | ✅ | — |
| MPL-2.0 | ⚠️ | Solo si no se modifica el código cubierto; si se modifica, publicar esas modificaciones |
| LGPL-2.1/3.0 | ⚠️ | Solo enlace dinámico, sin modificar; documentar |
| EPL-2.0 | ⚠️ | Revisión legal caso a caso |
| Unlicense / CC0 | ✅ | — |
| CC-BY-4.0 (documentación) | ✅ | Atribución |

## 3. DENYLIST

| Licencia | Motivo |
| :--- | :--- |
| AGPL-3.0 | Obligación de liberar el servicio completo en red |
| SSPL | Restricción de uso como servicio |
| BSL 1.1 / Business Source | Restricción temporal/comercial |
| Commons Clause | Prohíbe venta del software |
| Elastic License 2.0 | Restricción de servicio gestionado |
| Non-commercial / research-only | Incompatible con uso institucional |
| Proprietary sin contrato | Riesgo legal y de continuidad |
| WTFPL / dominios públicos ambiguos | Falta de garantías; revisión |

---

## 4. PROCEDIMIENTO PARA NUEVA DEPENDENCIA

```text
1. Justificar necesidad (¿se puede resolver con stdlib o código propio?).
2. Identificar licencia exacta (no solo del metapaquete; revisar transitivas).
3. Verificar mantenimiento (última release, issues abiertos, CVEs).
4. Ejecutar check_licenses.py y pip-audit/npm audit.
5. Registrar en este documento y en el SBOM.
6. Revisar en PR con checklist.
```

**Criterios de rechazo automático:** licencia en denylist, sin mantenimiento >24 meses con CVE abierta, tamaño desproporcionado, binarios opacos sin fuente.

---

## 5. INVENTARIO DE DEPENDENCIAS DIRECTAS (PREVISTO)

### Backend (Python)

| Paquete | Licencia | Uso |
| :--- | :--- | :--- |
| fastapi | MIT | API |
| uvicorn | BSD-3 | Servidor ASGI |
| sqlalchemy | MIT | ORM |
| psycopg | LGPL-3.0 (dinámico) | Driver PostgreSQL |
| alembic | MIT | Migraciones |
| pydantic / pydantic-settings | MIT | Validación/config |
| argon2-cffi | MIT | Hashing |
| pyotp | MIT | TOTP |
| cryptography | Apache-2.0/BSD-3 | Fernet |
| httpx | BSD-3 | Cliente HTTP |
| numpy | BSD-3 | Vectores |
| pyparsing | MIT | DSL |
| prometheus-client | Apache-2.0 | Métricas |
| pytest, pytest-cov | MIT | Testing |
| ruff | MIT | Lint |
| mypy | MIT | Tipos |
| bandit | Apache-2.0 | SAST |
| pip-audit | Apache-2.0 | CVE |

### Frontend (Node)

| Paquete | Licencia | Uso |
| :--- | :--- | :--- |
| react / react-dom | MIT | UI |
| react-router | MIT | Rutas |
| @tanstack/react-query | MIT | Caché de servidor |
| uplot | MIT | Series temporales |
| lucide-react | ISC | Iconos |
| vite | MIT | Build |
| typescript | Apache-2.0 | Tipos |
| vitest | MIT | Tests |
| @playwright/test | Apache-2.0 | E2E |
| @axe-core/playwright | MPL-2.0 | Accesibilidad |

### Edge

| Paquete | Licencia | Uso |
| :--- | :--- | :--- |
| httpx | BSD-3 | Transporte |
| pyyaml | MIT | Config |
| pytest | MIT | Tests |

**Nota:** `psycopg` es LGPL; se usa como biblioteca dinámica sin modificación, lo que la allowlist permite con documentación. Si se requiere evitar LGPL, alternativa: `pg8000` (BSD).

---

## 6. SBOM Y ARTEFACTOS

| Elemento | Formato | Frecuencia | Ubicación |
| :--- | :--- | :--- | :--- |
| SBOM backend | CycloneDX JSON | Cada release | `reports/sbom.json` |
| SBOM frontend | CycloneDX JSON | Cada release | `reports/sbom-frontend.json` |
| Licencias | JSON con paquete/versión/licencia | Cada release | `reports/licenses.json` |
| Checksums | SHA-256 | Cada release | `reports/release/checksums.txt` |
| Firma | cosign (opcional) | Cada release | `reports/release/` |

Comando: `bash scripts/generate_sbom.sh && python scripts/check_licenses.py`.

---

## 7. OBLIGACIONES DEL CRA

| Obligación | Implementación |
| :--- | :--- |
| Gestión de vulnerabilidades | `pip-audit`, `npm audit`, parcheo con SLA |
| SBOM | CycloneDX por release |
| Actualizaciones de seguridad | Ventana de soporte publicada |
| Divulgación responsable | `SECURITY.md` con contacto y plazos |
| Seguridad por diseño | Threat model, SDD, tests de seguridad |
| Documentación de usuario | Manuales y runbooks |
| Plazo de soporte | N, N-1, N-2 documentado en compatibilidad |

**Ventana de soporte 1.0:** 36 meses desde la release, con parches de seguridad; se publica fecha de fin por versión.

---

## 8. CUMPLIMIENTO Y VERIFICACIÓN

| Control | Comando | Evidencia |
| :--- | :--- | :--- |
| Licencias | `python scripts/check_licenses.py` | `reports/licenses.json` sin denylist |
| CVE Python | `pip-audit -r backend/requirements.txt` | exit 0, sin HIGH/CRITICAL |
| CVE Node | `npm audit --audit-level=high` | exit 0 |
| SBOM | `scripts/generate_sbom.sh` | CycloneDX válido |
| Originalidad | Revisión de PR + `docs/repository-audit.md` | Checklist firmado |

---

## 9. EXCEPCIONES

Una excepción requiere:
1. Justificación técnica (no hay alternativa viable).
2. Evaluación legal del riesgo.
3. Aprobación de arquitectura y dirección.
4. Registro con fecha de revisión y plan de sustitución.
5. Aislamiento del componente para facilitar su reemplazo.

Sin los cinco puntos, la dependencia no entra.

---

## 10. CRITERIOS DE ACEPTACIÓN

`AC-121` (SBOM + licencias), `AC-120` (CVE/SAST), `ADR-012`. Evidencia: `reports/licenses.json`, `reports/sbom.json`, salida de `check_licenses.py`.
