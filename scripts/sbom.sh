#!/usr/bin/env bash
# Generate a software bill of materials (SBOM) for backend and frontend.
set -euo pipefail

mkdir -p reports/sbom
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PYTHON="${PYTHON:-python3}"

if command -v cyclonedx-py >/dev/null 2>&1; then
  cyclonedx-py environment --output-file "reports/sbom/python-${STAMP}.json" || true
else
  "$PYTHON" -m pip list --format=json > "reports/sbom/python-${STAMP}.json"
fi

if [[ -f frontend/package-lock.json ]]; then
  if command -v npx >/dev/null 2>&1; then
    ( cd frontend && npx --yes @cyclonedx/cyclonedx-npm --output-file "../reports/sbom/node-${STAMP}.json" ) || cp frontend/package-lock.json "reports/sbom/node-lock-${STAMP}.json"
  else
    cp frontend/package-lock.json "reports/sbom/node-lock-${STAMP}.json"
  fi
fi

( cd reports/sbom && sha256sum ./* > "SHA256SUMS-${STAMP}" )
echo "SBOM written to reports/sbom (${STAMP})"
