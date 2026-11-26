# RUNBOOK DE OPERACIONES

- **Documento:** `docs/operations-runbook.md`
- **Estado:** `APPROVED` v1.0
- **Audiencia:** operador de plataforma, integrador, SRE
- **Detalle de incidentes:** `specs/operations/runbooks.md` · **Backup:** `specs/operations/backup-restore.md`

---

## 1. ANTES DE EMPEZAR

| Requisito | Verificación |
| :--- | :--- |
| Python 3.12 | `python3.12 --version` |
| PostgreSQL 18 | `pg_isready -h 127.0.0.1 -p 5432` |
| Node 22 (solo build) | `node -v` |
| Clave Fernet | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| Certificado TLS | Provisto por el cliente |
| NTP | `timedatectl status` → sincronizado |
| Disco | ≥200 GB libres |

**Rutas no estándar en este entorno de verificación:**
```bash
export PATH=/tmp/opencode/node-v22.14.0-linux-x64/bin:$PATH
source /tmp/opencode/hs-venv/bin/activate
export HS_DATABASE_URL="postgresql+psycopg://postgres@/hispanshield?host=/tmp/opencode&port=55432"
```

---

## 2. INSTALACIÓN (SINGLE-NODE)

```bash
# 1. Usuario y directorios
sudo useradd -r -s /bin/false hispanshield || true
sudo mkdir -p /opt/hispanshield /var/lib/hispanshield/evidence /etc/hispanshield
sudo chown -R hispanshield:hispanshield /opt/hispanshield /var/lib/hispanshield

# 2. Código y dependencias
sudo -u hispanshield git clone <repo> /opt/hispanshield/app
cd /opt/hispanshield/app/backend
sudo -u hispanshield python3.12 -m venv /opt/hispanshield/.venv
sudo -u hispanshield /opt/hispanshield/.venv/bin/pip install -r requirements.lock

# 3. Entorno
sudo install -m 600 /dev/null /etc/hispanshield/env
# editar con los valores del cliente (ver §3)

# 4. Base de datos
sudo -u postgres createuser hispanshield --pwprompt
sudo -u postgres createdb hispanshield -O hispanshield

# 5. Migraciones
sudo -u hispanshield env $(cat /etc/hispanshield/env | xargs) \
  /opt/hispanshield/.venv/bin/alembic upgrade head

# 6. Frontend
cd /opt/hispanshield/app/frontend && npm ci && npm run build

# 7. Servicios
sudo systemctl daemon-reload
sudo systemctl enable --now hispanshield-api hispanshield-worker-ingest \
  hispanshield-worker-detection hispanshield-worker-workflow \
  hispanshield-worker-scheduler hispanshield-worker-ai
```

---

## 3. VARIABLES DE ENTORNO

```bash
HS_ENV=production
HS_AUDIT_REQUIRE_HMAC=true
HS_AUDIT_HMAC_KEY=<48+ random bytes, outside the database>
HS_AUDIT_HMAC_KEY_ID=k1
HS_AUDIT_HMAC_PREVIOUS_KEYS=
HS_DATABASE_URL=postgresql+psycopg://hispanshield:***@127.0.0.1:5432/hispanshield
HS_SECRET_KEY=<base64 32 bytes>
HS_ALLOWED_ORIGINS=https://hispanshield.example.eu
HS_EVIDENCE_PATH=/var/lib/hispanshield/evidence
HS_SESSION_IDLE_MINUTES=30
HS_SESSION_ABSOLUTE_HOURS=12
HS_REQUIRE_MIGRATIONS=true
HS_EDGE_REQUIRE_MTLS=true
HS_AI_PROVIDER=none
HS_LOG_LEVEL=INFO
```

**Nunca** versionar este fichero. Permisos `0600`, propietario `hispanshield`.

---

## 4. VERIFICACIÓN POST-INSTALACIÓN

```bash
curl -fsS https://hispanshield.example.eu/healthz | jq
curl -fsS https://hispanshield.example.eu/readyz | jq
curl -sI https://hispanshield.example.eu | grep -Ei 'strict-transport|content-security|x-frame'
```

| Comprobación | Esperado |
| :--- | :--- |
| `/healthz` | `200 {"status":"ok","version":"0.1.2"}` |
| `/readyz` | `200` con DB, migraciones, `queue_depth` y `outbox.pending` |
| HSTS | presente |
| CSP | presente, sin `unsafe-eval` |
| Login | flujo completo con MFA |
| Auditoría | `GET /api/v1/organizations/current/audit/verify` → `valid:true`, esquemas v1/v2/v3 |

---

## 5. OPERACIÓN DIARIA

| Tarea | Comando/Acción | Frecuencia |
| :--- | :--- | :--- |
| Salud | `/readyz`, `/metrics` | Continua (monitor) |
| Backups | `scripts/backup.sh` | Diaria 02:00 |
| Cola | `hs_queue_depth` y `outbox.pending`/`dead_letter` | Continua |
| Conectores | `/connectors/{id}/health` | Continua |
| Retención | job automático | Diaria |
| Revisión de alertas de seguridad | panel `/audit` | Diaria |
| Checkpoint de auditoría firmado | `POST /organizations/current/audit/checkpoints` y export externo/WORM | Diaria |
| Dead-letter outbox | `GET /api/v1/outbox/stats`; inspeccionar `last_error` | Diaria |
| Drill de restore | `backup_restore_drill.sh` | Mensual |
| Parches | `pip-audit`, `npm audit` | Semanal |

---

## 6. INCIDENTES OPERATIVOS FRECUENTES

| Síntoma | Diagnóstico rápido | Acción | Runbook |
| :--- | :--- | :--- | :--- |
| `/readyz` 503 | `pg_isready`, `df -h` | Reiniciar PG / liberar disco | `RB-01`, `RB-03` |
| Ingesta atrasada | `hs_queue_depth`, errores | Escalar worker / deshabilitar conector | `RB-02` |
| Conector en fallo | `/health` | Rotar secreto / deshabilitar | `RB-04` |
| Acción autónoma rara | `policy_decisions` | Kill switch + rollback | `RB-05` |
| Auditoría inválida | `/audit/verify` | Aislar, preservar, restaurar | `RB-06` |
| Fallo tras upgrade | `alembic current` | Rollback / restore | `RB-07` |

---

## 7. ACTUALIZACIÓN

```bash
# 1. Backup y verificación
sudo -u hispanshield /opt/hispanshield/scripts/backup.sh --out /var/backups/hispanshield/pre-upgrade

# 2. Activar kill switch de autonomía (recomendado)
curl -X POST -H "..." https://.../api/v1/autonomy/kill-switches -d '{"scope":"global","reason":"upgrade"}'

# 3. Drenar
sudo systemctl stop hispanshield-worker-{ingest,detection,workflow,ai}

# 4. Desplegar y migrar
cd /opt/hispanshield/app && sudo -u hispanshield git fetch && git checkout <tag>
sudo -u hispanshield /opt/hispanshield/.venv/bin/pip install -r backend/requirements.lock
sudo -u hispanshield env $(cat /etc/hispanshield/env | xargs) \
  /opt/hispanshield/.venv/bin/alembic upgrade head

# 5. Arrancar y verificar
sudo systemctl start hispanshield-worker-{ingest,detection,workflow,ai}
curl -fsS https://.../readyz
```

---

## 8. AIR-GAP

```bash
bash scripts/build_offline_bundle.sh --out /media/usb/bundle
# en destino
bash install_offline.sh --verify-only
bash install_offline.sh
bash scripts/verify_airgap.sh
```

---

## 9. CONTACTOS Y ESCALADO

| Severidad | Ejemplo | Respuesta | Escalado |
| :--- | :--- | :--- | :--- |
| P1 | Servicio caído, acción destructiva, cadena inválida | 15 min | CISO + arquitectura |
| P2 | Ingesta detenida, conector crítico | 1 h | Responsable de plataforma |
| P3 | Degradación parcial | 4 h | Operador |
| P4 | Consulta lenta | 1 día | Backlog |

---

## 10. CHECKLIST DE ACEPTACIÓN OPERATIVA

- [ ] Instalación reproducible en <2 h por el cliente.
- [ ] `/readyz` verde y cabeceras de seguridad presentes.
- [ ] Backup ejecutado y drill superado.
- [ ] Air-gap verificado.
- [ ] Al menos una fuente real ingiriendo.
- [ ] Un playbook ejecutado con aprobación y rollback probado.
- [ ] Kill switch probado con latencia medida.
- [ ] Informe de cumplimiento generado y hash verificado.
