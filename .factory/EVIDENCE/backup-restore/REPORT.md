# Backup / restore verification — 2026-11-26

- **Source database:** `hispanshield_e2e` (schema `0016_asset_soft_delete`)
- **Restored database:** `hispanshield_restore2` (freshly created, isolated)
- **Backup:** `/tmp/opencode/hs-backup-final/20261126T180634Z` (0700 dir, 0600 files)
- **Commands:**
  - `HS_BACKUP_DIR=/tmp/opencode/hs-backup-final scripts/backup.sh`
  - `CONFIRM_RESTORE=YES scripts/restore.sh <backup>`

## Result: PASS

| Check | Source | Restored |
| :--- | ---: | ---: |
| organizations | 2 | 2 |
| users | 2 | 2 |
| assets | 24 | 24 |
| vulnerabilities | 15 | 15 |
| security_events | 24 | 24 |
| audit_records | 33 | 33 |
| compliance_frameworks | 10 | 10 |
| alembic version | 0016_asset_soft_delete | 0016_asset_soft_delete |

- SHA-256 manifest (`SHA256SUMS`) verified for every artefact.
- Audit chain verification after restore: `hispanshield valid=True checked=1`,
  `demo-nova-iberia valid=True checked=30`.
- API started against the restored database: `/readyz` returned
  `database=ok`, `migrations current/head = 0016_asset_soft_delete`,
  outbox pending=0; login returned HTTP 200; `/compliance/frameworks` returned
  the seeded catalogue.

## Defects found and fixed during this verification

1. `scripts/backup.sh` passed the SQLAlchemy URL (`postgresql+psycopg://`) to
   `pg_dump`, which only accepts libpq DSNs. The script now strips the driver
   suffix. Same fix applied to `pg_restore` in `scripts/restore.sh`.
2. A fresh demo seed failed with `uq_events_org_dedupe` because repeated
   message/host/user tuples produced the same dedupe key. Demo keys now include
   the unique event uid (regression test `test_seed_demo.py`).

## Limitations

- Encryption was exercised as `optional` in development; production requires
  `BACKUP_GPG_RECIPIENT` (already enforced by the script and documented).
- No PITR/WAL archiving was tested; the backup is a logical custom dump.
