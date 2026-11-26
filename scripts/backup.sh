#!/usr/bin/env bash
# PostgreSQL + evidence backup with a SHA-256 manifest.
set -euo pipefail

: "${HS_DATABASE_URL:?HS_DATABASE_URL is required}"
BACKUP_ROOT="${HS_BACKUP_DIR:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${BACKUP_ROOT}/${STAMP}"
EVIDENCE_DIR="${HS_EVIDENCE_DIR:-./data/evidence}"
mkdir -p "$TARGET"

echo "[backup] dumping database"
pg_dump --format=custom --no-owner --no-privileges --file="${TARGET}/database.dump" "$HS_DATABASE_URL"

if [[ -d "$EVIDENCE_DIR" ]]; then
  echo "[backup] copying evidence"
  tar -C "$(dirname "$EVIDENCE_DIR")" -czf "${TARGET}/evidence.tar.gz" "$(basename "$EVIDENCE_DIR")"
else
  echo "[backup] no evidence directory at ${EVIDENCE_DIR}; skipping"
fi

echo "[backup] application version"
git rev-parse HEAD > "${TARGET}/git-revision.txt" 2>/dev/null || echo "unknown" > "${TARGET}/git-revision.txt"
python - <<'PY' > "${TARGET}/schedule.json"
import json, datetime
print(json.dumps({"created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "retention_days": 30}, indent=2))
PY

echo "[backup] manifest"
( cd "$TARGET" && sha256sum ./* > SHA256SUMS )

if [[ -n "${BACKUP_GPG_RECIPIENT:-}" ]]; then
  echo "[backup] encrypting manifest + dump with GPG"
  gpg --yes --recipient "$BACKUP_GPG_RECIPIENT" --encrypt "${TARGET}/database.dump"
  rm -f "${TARGET}/database.dump"
fi

echo "[backup] complete: ${TARGET}"
echo "[backup] restore with: CONFIRM_RESTORE=YES scripts/restore.sh ${TARGET}"
