# RUNBOOKS DE OPERACIÓN

- **Documento:** `specs/operations/runbooks.md`
- **Estado:** `APPROVED` v1.0
- **Audiencia:** operador de plataforma (`platform_admin`), integrador, SRE
- **Regla:** cada runbook tiene síntoma, diagnóstico, acción, verificación y escalado. Sin acción sin verificación.

---

## RB-01: PostgreSQL no disponible (`db-down`)

**Síntoma:** `/readyz` → `503`, `db: down`; logs `connection refused`; API devuelve `503 dependency_unavailable`.

**Diagnóstico**
```bash
systemctl status postgresql
pg_isready -h 127.0.0.1 -p 5432
sudo -u postgres psql -c "select count(*) from pg_stat_activity;"
df -h /var/lib/postgresql
```

**Acción**
1. Reiniciar servicio: `systemctl restart postgresql`.
2. Si falla por disco: liberar espacio (ver RB-03).
3. Si falla por locks: identificar con `pg_stat_activity` y `pg_terminate_backend` solo con aprobación.
4. Si hay corrupción: restaurar desde backup (`backup-restore.md`).

**Verificación:** `curl -fsS /readyz` → `200`; una consulta de lectura responde.

**Escalado:** DBA/arquitectura si hay corrupción o pérdida de datos.

---

## RB-02: Cola de ingesta crece (`queue-backlog`)

**Síntoma:** `hs_queue_depth{queue="ingest"}` crece >5 min sostenido; latencia evento→búsqueda >10 s.

**Diagnóstico**
```bash
curl -s localhost:8790/metrics | grep hs_queue_depth
psql -c "select state, count(*) from jobs where queue='ingest' group by state;"
psql -c "select last_error->>'code', count(*) from jobs where state='failed' group by 1 order by 2 desc;"
```

**Acción**
1. Si el error dominante es `timeout`/`upstream_5xx`: revisar conector y circuit breaker.
2. Si es `internal_error`: revisar logs por `request_id`, posible bug; deshabilitar conector problemático.
3. Escalar workers: `systemctl start hispanshield-worker-ingest@2` (unit templated) o aumentar réplicas.
4. Si la BD es el cuello de botella: revisar índices y `pg_stat_statements`.

**Verificación:** profundidad decreciente durante 10 min; latencia <2 s p95.

**Escalado:** arquitectura si el backlog supera 100k o hay pérdida.

---

## RB-03: Disco lleno (`disk-full`)

**Síntoma:** `503 storage_full` en subidas; PostgreSQL en solo lectura; alertas de disco >90%.

**Diagnóstico**
```bash
df -h
du -sh /var/lib/hispanshield/evidence/* | sort -h | tail
psql -c "select pg_size_pretty(pg_database_size('hispanshield'));"
psql -c "select relname, pg_size_pretty(pg_total_relation_size(relid)) from pg_catalog.pg_statio_user_tables order by pg_total_relation_size(relid) desc limit 10;"
```

**Acción**
1. **Nunca** borrar ficheros de evidencia con `legal_hold`; verificar antes.
2. Ejecutar job de retención: `python -m app.workers.retention --dry-run` y luego sin `--dry-run`.
3. Archivar particiones antiguas si el cliente tiene almacenamiento frío.
4. Ampliar volumen; mover evidencias a almacenamiento dedicado.
5. Reiniciar PostgreSQL si entró en modo solo lectura.

**Verificación:** `df -h` <80%; subida de evidencia de prueba exitosa; `/readyz` 200.

---

## RB-04: Conector en bucle de fallos (`connector-loop`)

**Síntoma:** `hs_connector_failures_total` crece; estado `degraded`/`failed`; circuit breaker `open`.

**Diagnóstico**
```bash
curl -s -H "X-Organization-Id: $ORG" localhost:8000/api/v1/connectors/$ID/health | jq
psql -c "select last_error, consecutive_failures, next_attempt_at from connector_health where connector_id='$ID';"
```

**Acción**
1. Si `auth_failed`: rotar credencial (`POST /connectors/{id}/rotate-secret`).
2. Si `timeout`: verificar red y salud del destino.
3. Si `schema_mismatch`: revisar versión del conector y compatibilidad.
4. Deshabilitar temporalmente: `PATCH /connectors/{id} {"enabled": false}`.
5. Corregir y probar: `POST /connectors/{id}/test`.

**Verificación:** estado `active` durante 15 min; eventos fluyendo; sin errores nuevos.

---

## RB-05: Acción autónoma sospechosa (`autonomy-incident`)

**Síntoma:** alerta de acción inesperada; operador reporta aislamiento/bloqueo no deseado.

**Acción inmediata (≤5 min)**
1. Activar kill switch del ámbito: `POST /autonomy/kill-switches` (org o global) y `activate`.
2. Identificar acciones en curso: `GET /autonomy/actions?state=executing`.
3. Si procede, compensar: `POST /autonomy/actions/{id}/rollback` (o `compensate` del playbook).
4. Preservar evidencia: no borrar logs ni auditoría; exportar decisión y resultados.

**Diagnóstico**
```bash
psql -c "select * from policy_decisions where id='$DECISION' \gx"
psql -c "select * from action_results where action_id='$ACTION' order by attempt;"
```

**Verificación:** kill switch activo; 0 acciones nuevas; estado del target restaurado.

**Escalado:** CISO + arquitectura; posible incidente de safety (`safety-requirements.md §6`).

---

## RB-06: Cadena de auditoría inválida (`audit-invalid`)

**Síntoma:** `GET /audit/verify` → `valid:false` con `first_invalid_seq`.

**Acción**
1. Aislar la instancia (modo mantenimiento) para evitar más escrituras.
2. Preservar copia del rango afectado y del `entry_hash` esperado.
3. Verificar si hubo acceso directo a BD o restauración parcial.
4. Restaurar desde backup íntegro anterior al `seq` afectado (con aprobación).
5. Abrir incidente de seguridad; notificar según NIS2/CRA si aplica.

**Verificación:** `verify` → `valid:true` con el rango restaurado; auditoría del proceso.

**Escalado:** obligatorio a seguridad y dirección.

---

## RB-07: Fallo tras actualización (`upgrade-failure`)

**Síntoma:** `/readyz` 503; logs de migración; API no arranca.

**Acción**
1. `alembic current` y comparar con `head`.
2. Si la migración falló a medias: `alembic downgrade -1` solo si está soportado; si no, restaurar backup.
3. Redesplegar versión anterior de la aplicación.
4. Revisar logs con `request_id` de arranque.

**Verificación:** `/readyz` 200, smoke tests, versión correcta.

---

## RB-08: Saturación de IA / coste (`ai-budget`)

**Síntoma:** `429 ai_budget_exceeded`; coste diario cerca del límite.

**Acción**
1. Revisar uso: `select org_id, sum(cost_usd) from ai_runs where created_at > now()-interval '1 day' group by 1;`
2. Ajustar presupuesto o cambiar a modelo local (`PATCH /ai/providers`).
3. Si hay bucle: revisar `ai_runs` con muchos pasos y `max_steps`.

**Verificación:** llamadas exitosas; coste dentro de límite.

---

## RB-09: Edge sin reenviar (`edge-stuck`)

**Síntoma:** sede sin eventos; `sequence` no avanza en el core.

**Acción**
1. En el edge: `hispanshield-edge status` (tamaño de cola, último envío, último error).
2. Verificar conectividad y certificado mTLS (`openssl s_client`).
3. Si el certificado expiró: renovar y reiniciar.
4. Si la cola está corrupta: exportar y recrear (pérdida mínima documentada).

**Verificación:** eventos de la sede visibles en el core; `sequence` creciente.

---

## RB-10: Apagado y mantenimiento programado

```bash
sudo systemctl stop hispanshield-worker-ingest hispanshield-worker-detection \
  hispanshield-worker-workflow hispanshield-worker-ai
# esperar drenaje (máx 30 s)
sudo systemctl stop hispanshield-api
sudo systemctl stop caddy
```

**Verificación:** sin procesos huérfanos; jobs en `running` con lease expirado se reanudan al arrancar.

---

## TABLA DE ESCALADO

| Severidad | Ejemplo | Tiempo de respuesta | Escalado |
| :--- | :--- | :--- | :--- |
| P1 | Caída total, cadena inválida, acción destructiva | 15 min | CISO + arquitectura |
| P2 | Ingesta detenida, conector crítico caído | 1 h | Responsable de plataforma |
| P3 | Degradación parcial, un conector | 4 h | Operador |
| P4 | Consulta lenta, cosmético | 1 día | Backlog |
