#!/usr/bin/env bash
# Restore a HISPANSHIELD backup. Destructive: requires explicit confirmation.
set -euo pipefail

umask 077

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

# A backup directory must not be group/world readable (defence in depth against
# an operator restoring from a tampered or exposed copy).
mode="$(stat -c '%a' "$SOURCE" 2>/dev/null || echo 700)"
if [[ "$mode" != "700" && "$mode" != "750" ]]; then
  echo "[restore] WARNING: backup directory permissions are ${mode}; expected 700." >&2
fi

echo "[restore] verifying manifest"
( cd "$SOURCE" && sha256sum --check SHA256SUMS )

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
chmod 700 "$WORKDIR"

DUMP="${SOURCE}/database.dump"
if [[ ! -f "$DUMP" && -f "${SOURCE}/database.dump.gpg" ]]; then
  DUMP="${WORKDIR}/database.dump"
  gpg --yes --output "$DUMP" --decrypt "${SOURCE}/database.dump.gpg"
fi
[[ -f "$DUMP" ]] || { echo "database dump not found" >&2; exit 1; }

EVIDENCE_ARCHIVE="${SOURCE}/evidence.tar.gz"
if [[ ! -f "$EVIDENCE_ARCHIVE" && -f "${SOURCE}/evidence.tar.gz.gpg" ]]; then
  EVIDENCE_ARCHIVE="${WORKDIR}/evidence.tar.gz"
  gpg --yes --output "$EVIDENCE_ARCHIVE" --decrypt "${SOURCE}/evidence.tar.gz.gpg"
fi

echo "[restore] restoring database (clean)"
pg_restore --clean --if-exists --no-owner --no-privileges --dbname="$HS_DATABASE_URL" "$DUMP"

if [[ -f "$EVIDENCE_ARCHIVE" ]]; then
  echo "[restore] restoring evidence"
  tar -C "${HS_EVIDENCE_DIR:-./data}" -xzf "$EVIDENCE_ARCHIVE"
fi

echo "[restore] verifying audit chain"
python - <<'PY'
from sqlalchemy import select
from app.core.audit import verify_audit_chain
from app.core.db import SessionLocal
from app.models.core import Organization

with SessionLocal() as db:
    for org in db.execute(select(Organization)).scalars():
        result = verify_audit_chain(db, org.id)
        print(f"{org.slug}: valid={result['valid']} checked={result['checked']}")
        if not result["valid"]:
            raise SystemExit("Audit chain verification failed after restore")
PY

echo "[restore] complete. Run readiness and a login smoke test before returning to service."
