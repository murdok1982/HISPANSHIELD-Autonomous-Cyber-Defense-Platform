# BACKUP Y RESTAURACIÓN

- **Documento:** `specs/operations/backup-restore.md`
- **Estado:** `APPROVED` v1.0
- **Objetivos:** RPO ≤15 min (con WAL) / ≤24 h (solo dump); RTO ≤4 h
- **Scripts:** `scripts/backup.sh`, `scripts/restore.sh`, `scripts/backup_restore_drill.sh`

---

## 1. QUÉ SE RESPALDA

| Elemento | Método | Frecuencia | Retención | Verificación |
| :--- | :--- | :--- | :--- | :--- |
| PostgreSQL | `pg_dump -Fc` | Diario 02:00 | 30 diarios + 12 mensuales | `pg_restore --list` + conteo |
| WAL (opcional) | Archiving continuo | Continuo | 7 días | `pg_archivecleanup` |
| Evidencias | `rsync`/snapshot incremental | Diario | Según política | Hash de muestra |
| Configuración | `/etc/hispanshield/env` cifrado | En cada cambio | 10 versiones | Descifrado de prueba |
| Claves | Gestor del cliente | En rotación | — | **No** se respaldan en claro en el backup |
| SBOM/artefactos | Repositorio de release | Por release | 5 años | Checksum |

**Advertencia crítica:** un backup sin `HISPANSHIELD_SECRET_KEY` no permite recuperar secretos de conectores ni MFA. La clave se custodia por el cliente fuera del backup.

---

## 2. BACKUP

```bash
sudo -u hispanshield /opt/hispanshield/scripts/backup.sh \
  --out /var/backups/hispanshield/$(date +%F) \
  --include-evidence
```

**Contenido generado**
```text
2026-11-26/
├── db.dump                 # pg_dump -Fc
├── evidence/               # copia de evidencias (o manifiesto si --no-evidence)
├── manifest.json           # rutas, tamaños, sha256, versión, migración
├── checksums.sha256
└── meta.json               # commit, versión, fecha, operador
```

**Reglas**
- Comprimir y cifrar el conjunto (`age`/`gpg`) antes de salir del host.
- Verificar `pg_restore --list` y hash antes de considerar el backup válido.
- Almacenar fuera del host (NAS, almacenamiento offline) con acceso restringido.
- Registrar en el libro de backups: fecha, tamaño, hash, resultado.

---

## 3. RESTAURACIÓN

```bash
# 1. Instancia limpia con la misma versión mayor de PostgreSQL
sudo systemctl stop hispanshield-api hispanshield-worker-*

# 2. Restaurar
sudo -u postgres dropdb --if-exists hispanshield
sudo -u postgres createdb hispanshield -O hispanshield
sudo -u hispanshield pg_restore -d hispanshield --clean --if-exists /backup/db.dump

# 3. Evidencias
sudo rsync -a --delete /backup/evidence/ /var/lib/hispanshield/evidence/
sudo chown -R hispanshield:hispanshield /var/lib/hispanshield/evidence

# 4. Verificar integridad
sudo -u hispanshield /opt/hispanshield/.venv/bin/alembic current
sudo -u hispanshield /opt/hispanshield/scripts/verify_restore.sh --manifest /backup/manifest.json

# 5. Arrancar
sudo systemctl start hispanshield-api hispanshield-worker-*
curl -fsS localhost:8000/readyz
```

**Verificación obligatoria**
| Comprobación | Criterio |
| :--- | :--- |
| Migración | `alembic current == head` del backup |
| Conteos | `organizations`, `users`, `assets`, `events`, `incidents` coinciden con `manifest.json` |
| Auditoría | `GET /audit/verify` → `valid:true` |
| Evidencias | 10 hashes aleatorios coinciden |
| Login | Un usuario de prueba inicia sesión |
| Conectores | Secretos descifran correctamente (test de conexión) |

---

## 4. DRILL AUTOMATIZADO

```bash
bash scripts/backup_restore_drill.sh --source /var/backups/hispanshield/latest
```

**Salida esperada**
```text
[ok] dump readable
[ok] restore into scratch db
[ok] counts match (orgs=3 users=41 assets=18234 events=1204432 incidents=87)
[ok] audit chain valid
[ok] evidence sample hashes match (10/10)
[ok] app starts and /readyz 200
DRILL PASSED in 00:07:41
```

Se ejecuta mensualmente en staging y antes de cada release mayor. El resultado se archiva en `reports/drills/`.

---

## 5. ESCENARIOS DE RECUPERACIÓN

| Escenario | Estrategia | RTO estimado |
| :--- | :--- | :--- |
| Corrupción de una tabla | Restaurar tabla desde dump a BD temporal y copiar | 1-2 h |
| Pérdida total del host | Instalación limpia + restore | 3-4 h |
| Borrado accidental de evidencias | Restaurar desde copia + verificar hash | 1 h |
| Ransomware en el host | Restaurar desde backup offline inmutable | 4-8 h |
| Corrupción de auditoría | Restaurar rango anterior + investigar | 2 h |
| Migración fallida | Rollback de app + `downgrade` o restore | 1-4 h |

---

## 6. RETENCIÓN Y ALMACENAMIENTO

| Nivel | Retención | Ubicación |
| :--- | :--- | :--- |
| Diario | 30 días | NAS local |
| Semanal | 12 semanas | NAS local |
| Mensual | 12 meses | Almacenamiento offline |
| Anual | 5 años (cumplimiento) | Offline inmutable |

**Regla 3-2-1:** 3 copias, 2 medios, 1 fuera de la instalación. Para OIV, la copia offline debe estar protegida contra ransomware (WORM/inmutable).

---

## 7. SEGURIDAD DEL BACKUP

| Control | Regla |
| :--- | :--- |
| Cifrado | Obligatorio en reposo y en tránsito |
| Claves | Custodiadas por el cliente; nunca junto al backup |
| Acceso | Solo operadores autorizados; auditoría de acceso |
| Integridad | `checksums.sha256` + verificación en restore |
| Prueba | Drill mensual; sin drill no se considera válido |
| Borrado | Destrucción segura al final de retención, con registro |

---

## 8. CRITERIOS DE ACEPTACIÓN

`AC-113` (drill exit 0), `NFR-12` (RPO/RTO). Evidencia: salida del drill + `reports/drills/<fecha>.md`.
