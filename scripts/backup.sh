#!/usr/bin/env bash
# PostgreSQL + evidence backup with a SHA-256 manifest.
#
# Security properties (VULN-020):
#   * umask 077 and an explicit 0700 directory: dumps are never world-readable.
#   * In production (HS_ENV=production) encryption is mandatory; the script
#     refuses to write a plaintext database dump or evidence archive.
#   * The manifest is generated AFTER encryption so it describes the artefacts
#     that actually leave the host.
set -euo pipefail

umask 077

: "${HS_DATABASE_URL:?HS_DATABASE_URL is required}"
BACKUP_ROOT="${HS_BACKUP_DIR:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${BACKUP_ROOT}/${STAMP}"
EVIDENCE_DIR="${HS_EVIDENCE_DIR:-./data/evidence}"
ENCRYPTION_MODE="${HS_BACKUP_ENCRYPTION:-optional}"
if [[ "${HS_ENV:-development}" == "production" ]]; then
  # Production always requires encryption: HS_BACKUP_ENCRYPTION=none is ignored.
  ENCRYPTION_MODE="required"
fi

mkdir -p "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"
mkdir -m 700 "$TARGET"
chmod 700 "$TARGET"

encrypt_artifact() {
  local source="$1"
  gpg --yes --batch --recipient "$BACKUP_GPG_RECIPIENT" --encrypt "$source"
  rm -f "$source"
}

echo "[backup] dumping database"
pg_dump --format=custom --no-owner --no-privileges --file="${TARGET}/database.dump" "$HS_DATABASE_URL"
chmod 600 "${TARGET}/database.dump"

if [[ -d "$EVIDENCE_DIR" ]]; then
  echo "[backup] copying evidence"
  tar -C "$(dirname "$EVIDENCE_DIR")" -czf "${TARGET}/evidence.tar.gz" "$(basename "$EVIDENCE_DIR")"
  chmod 600 "${TARGET}/evidence.tar.gz"
else
  echo "[backup] no evidence directory at ${EVIDENCE_DIR}; skipping"
fi

if [[ -n "${BACKUP_GPG_RECIPIENT:-}" ]]; then
  echo "[backup] encrypting database dump and evidence archive"
  encrypt_artifact "${TARGET}/database.dump"
  [[ -f "${TARGET}/evidence.tar.gz" ]] && encrypt_artifact "${TARGET}/evidence.tar.gz"
elif [[ "$ENCRYPTION_MODE" == "required" ]]; then
  echo "[backup] ERROR: encryption is required (HS_ENV=production or HS_BACKUP_ENCRYPTION=required) but BACKUP_GPG_RECIPIENT is empty." >&2
  echo "[backup] Refusing to leave plaintext tenant data on disk." >&2
  rm -rf "$TARGET"
  exit 1
else
  echo "[backup] WARNING: backup is not encrypted. Set BACKUP_GPG_RECIPIENT for production use." >&2
fi

echo "[backup] application version"
git rev-parse HEAD > "${TARGET}/git-revision.txt" 2>/dev/null || echo "unknown" > "${TARGET}/git-revision.txt"
python - <<'PY' > "${TARGET}/schedule.json"
import datetime, json
print(json.dumps({"created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "retention_days": 30}, indent=2))
PY
chmod 600 "${TARGET}"/*

echo "[backup] manifest"
( cd "$TARGET" && sha256sum ./* > SHA256SUMS )
chmod 600 "${TARGET}/SHA256SUMS"

echo "[backup] complete: ${TARGET}"
echo "[backup] restore with: CONFIRM_RESTORE=YES scripts/restore.sh ${TARGET}"
