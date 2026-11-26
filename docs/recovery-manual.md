# MANUAL DE RECUPERACIÓN

- **Documento:** `docs/recovery-manual.md`
- **Estado:** `APPROVED` v1.0
- **Objetivos:** RPO ≤15 min (con WAL) / ≤24 h (solo dump); RTO ≤4 h
- **Referencia técnica:** `specs/operations/backup-restore.md`

---

## 1. ESCENARIOS DE RECUPERACIÓN

| ID | Escenario | Impacto | Estrategia | RTO |
| :--- | :--- | :--- | :--- | :--- |
| `RC-01` | Corrupción de una tabla | Parcial | Restaurar tabla desde dump a BD temporal y copiar | 1-2 h |
| `RC-02` | Pérdida total del host | Total | Instalación limpia + restore completo | 3-4 h |
| `RC-03` | Borrado accidental de evidencias | Parcial | Restaurar desde copia + verificar hash | 1 h |
| `RC-04` | Ransomware en el host | Total | Restaurar desde backup offline inmutable | 4-8 h |
| `RC-05` | Corrupción de auditoría | Integridad | Restaurar rango anterior + investigar | 2 h |
| `RC-06` | Migración fallida | Parcial/total | Rollback de app + `downgrade` o restore | 1-4 h |
| `RC-07` | Pérdida de la clave `SECRET_KEY` | Secretos | Restaurar clave del gestor; sin ella, secretos irrecuperables | 1 h |

---

## 2. DECISIÓN: REPARAR vs RESTAURAR

```text
¿Se puede identificar y aislar el daño?
├── Sí, una tabla/fichero → reparación selectiva (RC-01/RC-03)
└── No, o hay corrupción estructural → restauración completa (RC-02)
¿Hay sospecha de compromiso?
├── Sí → restaurar desde backup anterior al compromiso + rotar credenciales
└── No → restaurar el más reciente verificado
```

**Regla:** si hay compromiso, no se restaura sobre el mismo host sin reconstruirlo.

---

## 3. PROCEDIMIENTO GENERAL

```text
1. Declarar incidente y activar kill switch de autonomía.
2. Preservar evidencia (logs, BD actual, hashes) antes de tocar.
3. Identificar el backup verificado más reciente y su hash.
4. Preparar entorno limpio (misma versión mayor de PostgreSQL).
5. Restaurar BD y evidencias.
6. Verificar migraciones, conteos, auditoría y hashes.
7. Arrancar servicios y ejecutar smoke tests.
8. Revisar integridad de datos y de acciones.
9. Comunicar recuperación y reactivar autonomía de forma gradual.
```

---

## 4. RESTAURACIÓN SELECTIVA DE TABLA (`RC-01`)

```bash
# 1. BD temporal
sudo -u postgres createdb hs_restore_tmp
sudo -u postgres pg_restore -d hs_restore_tmp --table=assets /backup/db.dump

# 2. Validar
psql -d hs_restore_tmp -c "select count(*) from assets;"

# 3. Copiar (con transacción y backup previo de la tabla)
psql -d hispanshield <<'SQL'
BEGIN;
CREATE TEMP TABLE assets_bak AS SELECT * FROM assets;
DELETE FROM assets;
INSERT INTO assets SELECT * FROM dblink('dbname=hs_restore_tmp', 'select * from assets')
  AS t(id uuid, organization_id uuid, name varchar, kind varchar, criticality smallint,
       owner_email citext, owner_user_id uuid, zone_id uuid, tags text[], attributes jsonb,
       risk_score numeric, source varchar, first_seen timestamptz, last_seen timestamptz,
       deleted_at timestamptz, created_at timestamptz, updated_at timestamptz,
       created_by uuid, updated_by uuid, row_version integer);
COMMIT;
SQL
```

**Alternativa recomendada:** exportar la tabla a CSV desde la BD temporal e importar con `\copy` (evita depender de `dblink`).

---

## 5. RESTAURACIÓN COMPLETA (`RC-02`)

```bash
sudo systemctl stop hispanshield-api hispanshield-worker-*
sudo -u postgres dropdb --if-exists hispanshield
sudo -u postgres createdb hispanshield -O hispanshield
sudo -u hispanshield pg_restore -d hispanshield --clean --if-exists /backup/db.dump
sudo rsync -a --delete /backup/evidence/ /var/lib/hispanshield/evidence/
sudo chown -R hispanshield:hispanshield /var/lib/hispanshield/evidence
sudo -u hispanshield /opt/hispanshield/.venv/bin/alembic current
sudo systemctl start hispanshield-api hispanshield-worker-*
curl -fsS localhost:8000/readyz
```

---

## 6. VERIFICACIÓN POST-RECUPERACIÓN

| Comprobación | Criterio | Comando |
| :--- | :--- | :--- |
| Migración | `current == head` del backup | `alembic current` |
| Conteos | Coinciden con manifiesto | `verify_restore.sh` |
| Auditoría | Cadena válida | `GET /audit/verify` |
| Evidencias | 10 hashes aleatorios OK | `verify_restore.sh` |
| Secretos | Descifran y conectores funcionan | `POST /connectors/{id}/test` |
| Login | Usuario de prueba accede | UI |
| Búsqueda | Evento reciente visible | `/siem` |
| Autonomía | Políticas cargadas, kill switch estado correcto | `/admin` |

---

## 7. RECUPERACIÓN DE AUDITORÍA (`RC-05`)

1. Aislar la instancia (modo mantenimiento).
2. Identificar `first_invalid_seq` con `GET /audit/verify`.
3. Exportar el rango afectado y el hash esperado.
4. Restaurar desde backup anterior al `seq` (pérdida acotada y documentada).
5. Reinsertar entradas posteriores solo si su hash puede reconstruirse con evidencia; si no, registrar el gap explícitamente.
6. Abrir incidente de seguridad y notificar según proceda.

**Nunca** "reparar" la cadena recalculando hashes sin evidencia: destruye el valor probatorio.

---

## 8. RECUPERACIÓN DE SECRETOS (`RC-07`)

| Situación | Acción |
| :--- | :--- |
| Clave disponible en gestor | Restaurar variable y reiniciar |
| Clave perdida, backup con secretos cifrados | **Irrecuperable**; rotar todos los secretos de conectores y MFA de admin |
| Clave comprometida | Rotar clave, re-cifrar secretos, invalidar sesiones/tokens |

Procedimiento de rotación de clave: `key_version` nueva, job de re-cifrado por lotes, verificación de descifrado, retirada de la clave antigua tras confirmar.

---

## 9. COMUNICACIÓN

| Momento | Mensaje |
| :--- | :--- |
| Inicio | "Recuperación en curso, servicio en modo mantenimiento" |
| Progreso | "BD restaurada, verificando integridad" |
| Fin | "Servicio restaurado, datos verificados hasta <fecha>" |
| Si hay pérdida | Comunicar el rango exacto y el impacto |

---

## 10. POST-RECUPERACIÓN

1. Post-mortem con causa raíz.
2. Acciones correctivas con dueño y test de regresión.
3. Actualizar backups/procedimiento si falló algo.
4. Revisar si el RTO/RPO se cumplió.
5. Registrar en el libro de operaciones.

---

## 11. CHECKLIST

- [ ] Backup verificado (hash y `pg_restore --list`).
- [ ] Evidencia preservada antes de restaurar.
- [ ] Restauración en entorno limpio.
- [ ] Conteos y auditoría verificados.
- [ ] Secretos operativos.
- [ ] Smoke tests superados.
- [ ] Autonomía reactivada de forma gradual.
- [ ] Comunicación realizada.
- [ ] Post-mortem abierto.
