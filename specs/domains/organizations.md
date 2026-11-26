# DOMINIO: ORGANIZACIONES Y TENANCY

- **Código:** `ORG`
- **Ruta de implementación:** `backend/app/services/{organizations,memberships}.py`, `backend/app/core/tenancy.py`, `backend/app/api/v1/organizations.py`
- **Estado:** `SPECIFIED`
- **ACs globales:** `AC-09..AC-14`

---

## 1. OBJETIVO

Garantizar que cada organización opera en un espacio de datos estrictamente aislado, con roles y permisos explícitos, ciclo de vida controlado y ninguna vía —ni por API, ni por filtro, ni por exportación— para leer o mutar datos de otra organización.

## 2. CONTEXTO

Una instancia puede alojar varias organizaciones (p.ej. un organismo y sus entidades dependientes, o un integrador que opera varios clientes en laboratorio). El aislamiento no puede depender de la UI ni de la buena fe del cliente: se aplica en el servidor, en la capa de repositorio, con pruebas que recorren todos los recursos.

La organización es también la unidad de: políticas de autonomía, retención, presupuesto de IA, cuotas de conectores, claves de cifrado lógicas (`key_version`) y región de datos.

## 3. REQUISITOS FUNCIONALES

| ID | Requisito | Detalle verificable |
| :--- | :--- | :--- |
| `REQ-ORG-001` | Bootstrap | `POST /setup` solo si `count(organizations)==0`, en una transacción: org + user `owner` + membership `owner` + settings por defecto + auditoría. Segundo intento → `409 setup_completed`. |
| `REQ-ORG-002` | Scoping | Toda tabla de dominio lleva `organization_id NOT NULL`. Todo repositorio lo exige como parámetro keyword-only. Prohibido `SELECT` sin filtro en `repositories/`. |
| `REQ-ORG-003` | Resolución de org | Rutas org-scoped exigen `X-Organization-Id`; se valida formato UUID y membership activa; org suspendida → `403 organization_suspended`. |
| `REQ-ORG-004` | Roles | `owner`, `admin`, `responder`, `analyst`, `viewer`, `auditor`; un usuario puede tener varios roles en la misma org (unión de permisos); `auditor` reduce permisos de escritura. |
| `REQ-ORG-005` | Invitaciones | Token de 32 bytes, hash en BD, TTL 72 h, un solo uso, rol asignado; email verificado al aceptar; aceptación crea membership y audita. |
| `REQ-ORG-006` | Ciclo de vida | Suspender (bloquea acceso, conserva datos), reactivar, soft delete con confirmación por `slug` exacto, purga a 30 días con job y auditoría. |
| `REQ-ORG-007` | Guard de último owner | No se puede eliminar, suspender ni degradar al último `owner` activo de una org. |
| `REQ-ORG-008` | Settings de org | Retención, MFA obligatorio, niveles de autonomía máximos, presupuesto IA, zona horaria, `data_region`, feature flags. Validados por esquema. |
| `REQ-ORG-009` | Break-glass | `platform_admin` solicita acceso temporal a una org con justificación ≥40 chars y TTL ≤60 min; se audita y se muestra banner al usuario. |

## 4. REQUISITOS NO FUNCIONALES

| ID | Requisito |
| :--- | :--- |
| `NFR-ORG-01` | Resolución de org + membership ≤15 ms p95 (cache por request, invalidada por cambio de membership). |
| `NFR-ORG-02` | Suite de aislamiento cubre el 100% de recursos listables y obtenibles por ID. |
| `NFR-ORG-03` | Cambio de rol efectivo en ≤5 s en todas las sesiones del usuario (invalidación por evento). |
| `NFR-ORG-04` | Purga de organización con >100k filas completa en ≤10 min sin bloquear la operación de otras orgs. |

## 5. DEPENDENCIAS

| Dependencia | Tipo | Nota |
| :--- | :--- | :--- |
| `identity` | Dominio | Usuarios y sesiones |
| `core/audit.py` | Interna | Cambios de membership y settings |
| `core/events.py` | Interna | `org.membership_changed` para invalidar caché |
| `jobs` | Plataforma | Purga programada |

## 6. CONTRATOS

| Método | Endpoint | Rol mínimo | Entrada | Salida |
| :--- | :--- | :--- | :--- | :--- |
| POST | `/api/v1/setup` | público (solo vacío) | `{org_name, org_slug, sector, admin_email, admin_name, password}` | `201 {organization, user}` |
| GET | `/api/v1/organizations` | autenticado | — | `200 [{id, name, slug, role, status}]` |
| POST | `/api/v1/organizations` | `platform_admin` | `OrgCreate` | `201` |
| GET | `/api/v1/organizations/{id}` | miembro | — | `200 {org, settings, counts}` |
| PATCH | `/api/v1/organizations/{id}` | `admin` | `OrgUpdate` | `200` |
| DELETE | `/api/v1/organizations/{id}` | `owner` | `{confirm_slug, reason}` | `204` (soft delete) |
| GET | `/api/v1/organizations/{id}/members` | `viewer`+ | query | `200 [{user, roles[], status, last_active_at}]` |
| POST | `/api/v1/organizations/{id}/members` | `admin` | `{email, roles[], message?}` | `201 {invitation, expires_at}` |
| PATCH | `/api/v1/organizations/{id}/members/{user_id}` | `admin` | `{roles[]}` | `200` |
| DELETE | `/api/v1/organizations/{id}/members/{user_id}` | `admin` | — | `204` |
| POST | `/api/v1/invitations/{token}/accept` | autenticado | — | `200 {membership}` |
| GET/PATCH | `/api/v1/organizations/{id}/settings` | `admin` | `OrgSettings` | `200` |

**Errores de tenancy (uniformes):** `404 not_found` para recurso de otra org; `403 organization_forbidden` si no hay membership y la ruta es de organización; nunca se devuelve el nombre de la org ajena.

## 7. CASOS DE USO

1. **Alta inicial:** instalación limpia → `/setup` → owner creado → onboarding con checklist (crear zona, conectar fuente, invitar analista).
2. **Organización con entidades dependientes:** un ministerio crea orgs hijas por dirección general; cada una con sus activos, y un `platform_admin` supervisa la instancia sin ver datos.
3. **Invitación de analista:** `admin` invita con rol `analyst`; el invitado acepta, se le fuerza MFA si la org lo exige.
4. **Salida de empleado:** `admin` suspende membership; sus sesiones se revocan; sus PAT se desactivan; el contenido creado permanece atribuido.
5. **Soporte:** el integrador necesita diagnosticar un problema; solicita break-glass con justificación; el cliente ve el banner y la auditoría registra el acceso.

## 8. CASOS BORDE

| Escenario | Comportamiento |
| :--- | :--- |
| `X-Organization-Id` de una org donde el usuario fue eliminado | `403 organization_forbidden` (no 404, la org existe pero no hay membership) |
| Cabecera ausente | `400 organization_header_required` |
| Cabecera con UUID inválido | `400 validation_error` con `path=header.X-Organization-Id` |
| Invitación a email ya miembro | `409 already_member` |
| Invitación expirada | `410 invitation_expired` |
| Aceptar invitación con email distinto | `403 invitation_email_mismatch` |
| Degradar al último owner | `422 last_owner_guard` |
| Borrar org con ejecuciones en curso | `409 executions_running` con lista de IDs |
| Borrar org con legal hold | `409 legal_hold_active` |
| Reactivar org soft-deleted dentro de 30 días | `200` y datos intactos |
| `platform_admin` sin break-glass | `403 break_glass_required` |
| Cambio de rol mientras hay request en vuelo | La request en vuelo termina con permisos previos; las siguientes usan el nuevo rol |

## 9. AMENAZAS ESPECÍFICAS

| Amenaza | Vector | Control |
| :--- | :--- | :--- |
| IDOR cross-tenant | Manipular IDs o filtros | Filtro obligatorio en repositorio + 404 uniforme + suite parametrizada |
| Escalada de rol | `PATCH` de membership con rol superior | Matriz RBAC; `admin` no puede crear `owner`; solo `owner` transfiere ownership |
| Enumeración de organizaciones | Timing o mensajes | Respuesta uniforme, sin existencia en errores |
| Break-glass abusivo | Uso reiterado sin justificación | TTL, auditoría, alerta a `owner`, lista de accesos en `/audit` |
| Fuga por exportación | Export STIX/CSV sin scope | Export siempre scoped por org y auditado |
| Purga incompleta | Datos huérfanos en tablas hijas | Purga transaccional con verificación de conteo por tabla y evidencia |

## 10. CRITERIOS DE ACEPTACIÓN

| AC | Criterio | Test |
| :--- | :--- | :--- |
| `AC-09` | Setup único y transaccional | `backend/tests/integration/test_setup.py::test_first_run_bootstrap_idempotent` |
| `AC-10` | Cross-org → 404 | `backend/tests/security/test_tenant_isolation.py::test_cross_org_read_returns_404` |
| `AC-11` | Cabecera obligatoria y membership | `backend/tests/security/test_tenant_isolation.py::test_header_required_and_membership_enforced` |
| `AC-12` | Matriz RBAC exacta | `backend/tests/security/test_rbac_matrix.py` |
| `AC-13` | Invitación de un solo uso | `backend/tests/integration/test_invitations.py` |
| `AC-14` | Soft delete con confirmación | `backend/tests/integration/test_org_lifecycle.py::test_soft_delete_requires_confirmation` |
| `AC-ORG-07` | Guard de último owner | `backend/tests/integration/test_org_members.py::test_last_owner_guard` |

## 11. ESTRATEGIA DE TEST

- **Unit:** validación de settings, resolución de permisos por unión de roles, reducción de `auditor`.
- **Integración:** setup, invitaciones, cambios de rol, suspensión, borrado, break-glass.
- **Seguridad:** matriz completa rol×endpoint; aislamiento por recurso (listar, obtener, actualizar, borrar, exportar, streaming SSE); intento de inyección de `organization_id` en body.
- **Carga:** 50 orgs × 200 activos, consultas con `X-Organization-Id` aleatorio, sin degradación.

## 12. EVIDENCIA REQUERIDA

1. `pytest -q tests/security/test_tenant_isolation.py tests/security/test_rbac_matrix.py` con informe de celdas cubiertas.
2. Tabla de cobertura rol×endpoint generada por el test.
3. Ejemplo de auditoría de `org.member.role_changed` con actor y valores antes/después.
4. Salida del test de guard de último owner.
5. Registro de break-glass con TTL y justificación.
