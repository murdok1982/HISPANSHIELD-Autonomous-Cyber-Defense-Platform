# MODOS DE DESPLIEGUE

- **Documento:** `specs/deployment/deployment-modes.md`
- **Estado:** `APPROVED` v1.0
- **Arquitectura:** `specs/architecture/deployment-architecture.md`
- **Runbook:** `docs/operations-runbook.md`

---

## 1. SELECCIÓN DEL MODO

| Criterio | Single-node | Compose | Kubernetes | Air-gapped |
| :--- | :---: | :---: | :---: | :---: |
| Organismo pequeño (<300 activos) | ✅ | ✅ | — | ✅ |
| OIV con alta ingesta | ✅ (16 vCPU) | ✅ | ✅ | ✅ |
| Requisito de HA | — | — | ✅ (parcial) | ✅ |
| Sin Internet | ✅ | ✅ | ✅ | ✅ |
| Equipo de plataforma reducido | ✅ | ✅ | — | ✅ |
| Multi-tenant (varias orgs) | ✅ | ✅ | ✅ | ✅ |

**Recomendación por defecto:** single-node con systemd para administraciones sin equipo Kubernetes; k8s cuando ya exista plataforma.

---

## 2. SINGLE-NODE (REFERENCIA)

### 2.1 Preparación

```bash
# 1. Sistema
sudo apt install -y postgresql-18 caddy python3.12 python3.12-venv
sudo systemctl enable --now postgresql

# 2. Base de datos
sudo -u postgres createuser hispanshield --pwprompt
sudo -u postgres createdb hispanshield -O hispanshield

# 3. Aplicación
sudo useradd -r -s /bin/false hispanshield
sudo mkdir -p /opt/hispanshield /var/lib/hispanshield/evidence
sudo chown -R hispanshield:hispanshield /opt/hispanshield /var/lib/hispanshield
```

### 2.2 Variables

```bash
sudo install -m 600 /dev/null /etc/hispanshield/env
sudo tee /etc/hispanshield/env >/dev/null <<'EOF'
HISPANSHIELD_ENV=production
HISPANSHIELD_DATABASE_URL=postgresql+psycopg://hispanshield:CHANGE@127.0.0.1:5432/hispanshield
HISPANSHIELD_SECRET_KEY=BASE64_32_BYTES
HISPANSHIELD_ALLOWED_ORIGINS=https://hispanshield.example.eu
HISPANSHIELD_EVIDENCE_PATH=/var/lib/hispanshield/evidence
HISPANSHIELD_REQUIRE_MIGRATIONS=true
HISPANSHIELD_TRUSTED_PROXIES=127.0.0.1
EOF
```

Generación de la clave: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.

### 2.3 Migración y arranque

```bash
sudo -u hispanshield /opt/hispanshield/.venv/bin/alembic upgrade head
sudo systemctl daemon-reload
sudo systemctl enable --now hispanshield-api hispanshield-worker-{ingest,detection,workflow,scheduler,ai}
sudo systemctl reload caddy
curl -fsS https://hispanshield.example.eu/readyz
```

### 2.4 Verificación

| Comprobación | Comando | Esperado |
| :--- | :--- | :--- |
| Salud | `curl /healthz` | `200 {"db":"ok","migrations":"current"}` |
| Preparación | `curl /readyz` | `200` |
| TLS | `curl -I https://...` | HSTS presente |
| Versión | `curl /api/v1/meta` | Versión de build |

---

## 3. DOCKER COMPOSE

```bash
cp deploy/compose/.env.example deploy/compose/.env
# editar secretos
docker compose -f deploy/compose/docker-compose.yml up -d
docker compose -f deploy/compose/docker-compose.yml ps
```

| Servicio | Imagen | Healthcheck |
| :--- | :--- | :--- |
| `postgres` | `postgres:18-alpine` | `pg_isready` |
| `api` | `hispanshield/api:1.0.0` | `/healthz` |
| `worker` | `hispanshield/api:1.0.0` (comando distinto) | proceso vivo |
| `web` | `hispanshield/web:1.0.0` | `wget -q --spider` |
| `proxy` | `caddy:2-alpine` | — |

**Limitación:** sin daemon Docker en el entorno de verificación; los manifiestos se validan con `docker compose config -q` y revisión estática.

---

## 4. KUBERNETES

```bash
kubectl apply -k deploy/k8s/overlays/onprem
kubectl -n hispanshield rollout status deploy/api
kubectl -n hispanshield get pods
```

| Requisito | Detalle |
| :--- | :--- |
| StorageClass | `RWX` para evidencias si hay >1 réplica de API |
| Secret | `hispanshield-secrets` con `SECRET_KEY` y `DATABASE_URL` |
| Ingress | TLS con certificado del cliente |
| NetworkPolicy | Solo ingress→api; workers sin ingress |
| Recursos | requests/limits definidos; HPA por CPU y cola |

---

## 5. AIR-GAPPED

```bash
# En máquina con Internet (misma arquitectura/versión)
bash scripts/build_offline_bundle.sh --out /media/usb/hispanshield-bundle

# En destino sin red
tar -xzf hispanshield-bundle.tar.gz
bash install_offline.sh --verify-only
bash install_offline.sh
bash scripts/verify_airgap.sh
```

**Contenido del bundle:** ruedas Python, `node_modules` o build estático, fuentes, migraciones, SBOM, checksums, modelos IA (opcional), imágenes OCI (opcional).

**Verificación air-gap:** el script falla si detecta cualquier intento de conexión saliente (excepto loopback) durante instalación y arranque.

---

## 6. ACTUALIZACIÓN

```text
1. Anunciar ventana y activar kill switch de autonomía (recomendado).
2. Backup completo (scripts/backup.sh) y verificar hash.
3. Drenar: systemctl stop workers (el API sigue sirviendo lectura).
4. Desplegar nueva versión (paquete o imagen).
5. alembic upgrade head.
6. Arrancar workers y API.
7. Smoke tests: /readyz, login, búsqueda, una acción dry-run.
8. Desactivar kill switch si todo es correcto.
9. Registrar en el libro de cambios.
```

**Rollback:** redesplegar versión anterior; si la migración no es reversible, restaurar backup (RTO ≤4 h).

---

## 7. MATRIZ DE DECISIÓN DE INCIDENTES OPERATIVOS

| Síntoma | Acción inmediata | Runbook |
| :--- | :--- | :--- |
| `/readyz` 503 por BD | Verificar PostgreSQL, pool, disco | `operations/runbooks.md#db-down` |
| Cola crece sin parar | Añadir worker, revisar errores de conector | `#queue-backlog` |
| Disco lleno | Purga de particiones, ampliar volumen | `#disk-full` |
| Conector en bucle de fallos | Deshabilitar conector, revisar credenciales | `#connector-loop` |
| Acción autónoma sospechosa | Kill switch + revisar `decision_id` | `#autonomy-incident` |
| Cadena de auditoría inválida | Aislar instancia, preservar evidencia, escalar | `#audit-invalid` |
| Tras actualización no arranca | Rollback de versión, revisar migración | `#upgrade-failure` |

---

## 8. CRITERIOS DE ACEPTACIÓN

`AC-110`, `AC-111`, `AC-113`, `AC-114`, `AC-116`. Cada modo debe documentar: requisitos, instalación, verificación, actualización y rollback.
