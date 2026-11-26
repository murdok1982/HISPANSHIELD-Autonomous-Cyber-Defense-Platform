#!/usr/bin/env bash
# Restore a HISPANSHIELD backup. Destructive: requires explicit confirmation.
set -euo pipefail

SOURCE="${1:-}"
if [[ -z "$SOURCE" || ! -d "$SOURCE" ]]; then
  echo "usage: CONFIRM_RESTORE=YES scripts/restore.sh <backup-directory>" >&2
  exit 2
fi
if [[ "${CONFIRM_RESTORE:-}" != "YES" ]]; then
  echo "Refusing to restore without CONFIRM_RESTORE=YES. This overwrites the target database." >&2
  exit 2
fi
: "${HS_DATABASE_URL:?HS_DATABASE_URL is required}"

echo "[restore] verifying manifest"
( cd "$SOURCE" && sha256sum --check SHA256SUMS )

DUMP="${SOURCE}/database.dump"
if [[ ! -f "$DUMP" && -f "${SOURCE}/database.dump.gpg" ]]; then
  DUMP="${SOURCE}/database.dump.decrypted"
  gpg --yes --output "$DUMP" --decrypt "${SOURCE}/database.dump.gpg"
fi
[[ -f "$DUMP" ]] || { echo "database dump not found" >&2; exit 1; }

echo "[restore] restoring database (clean)"
pg_restore --clean --if-exists --no-owner --no-privileges --dbname="$HS_DATABASE_URL" "$DUMP"

if [[ -f "${SOURCE}/evidence.tar.gz" ]]; then
  echo "[restore] restoring evidence"
  tar -C "${HS_EVIDENCE_DIR:-./data}" -xzf "${SOURCE}/evidence.tar.gz"
fi

echo "[restore] verifying audit chain"
python - <<'PY'
import os
from app.core.db import SessionLocal
from app.core.audit import verify_audit_chain
from app.models.core import Organization
from sqlalchemy import select
with SessionLocal() as db:
    orgs = list(db.execute(select(Organization)).scalars())
    for org in orgs:
        result = verify_audit_chain(db, org.id)
        print(f"{org.slug}: valid={result['valid']} checked={result['checked']}")
PY

echo "[restore] complete. Run readiness and a login smoke test before returning to service."
