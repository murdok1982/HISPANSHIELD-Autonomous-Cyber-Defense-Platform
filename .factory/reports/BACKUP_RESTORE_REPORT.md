# BACKUP / RESTORE REPORT — 0.1.3

- **Status:** PASS
- **Source:** `hispanshield_e2e` (head `0016_asset_soft_delete`)
- **Restored:** `hispanshield_restore2` (isolated, freshly created)
- **Backup:** `/tmp/opencode/hs-backup-final/20261126T180634Z`, mode 0700/0600.

## Verification

1. `scripts/backup.sh` completed with a SHA-256 manifest.
2. `scripts/restore.sh` verified every hash and restored with
   `pg_restore --clean --if-exists`.
3. Row counts matched exactly: organizations 2, users 2, assets 24,
   vulnerabilities 15, security_events 24, audit_records 33,
   compliance_frameworks 10, alembic `0016`.
4. Audit chain after restore: `hispanshield valid=True checked=1`,
   `demo-nova-iberia valid=True checked=30`.
5. API against the restored DB: `/readyz` 200 with `database=ok`,
   migrations current/head, outbox pending 0; login 200; framework catalogue
   returned.

## Defect fixed

The scripts passed `postgresql+psycopg://` to `pg_dump`/`pg_restore`, which only
accept libpq DSNs. The driver suffix is now stripped.

## Not covered

- PITR / WAL archiving.
- Real GPG recipient encryption (production refuses plaintext, but the GPG path
  was not exercised with a real key).
- Restore into a different PostgreSQL major version.

Full detail: `.factory/EVIDENCE/backup-restore/REPORT.md`.
