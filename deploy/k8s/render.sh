#!/usr/bin/env bash
# Render the Kubernetes template with an operator-owned values file.
#
# Usage:
#   ./deploy/k8s/render.sh deploy/k8s/values.production.env > /tmp/hispanshield.yaml
#   python3 scripts/validate_deploy.py /tmp/hispanshield.yaml
#
# The values file must not be committed with real secrets. Prefer External
# Secrets / Vault and keep only the non-secret values here.
set -euo pipefail

values_file="${1:?usage: render.sh <values.env> [template]}"
template="${2:-$(dirname "$0")/manifests.yaml}"
if [[ ! -f "$values_file" ]]; then
  echo "values file not found: $values_file" >&2
  exit 2
fi
if [[ ! -f "$template" ]]; then
  echo "template not found: $template" >&2
  exit 2
fi

set -a
# shellcheck disable=SC1090
source "$values_file"
set +a

# Optional values may legitimately be empty; required ones must be real.
for name in \
  HS_IMAGE HS_DOMAIN HS_DB_HOST HS_DB_PASSWORD HS_SECRET_KEY HS_ENCRYPTION_KEY \
  HS_AUDIT_HMAC_KEY HS_METRICS_TOKEN HS_BOOTSTRAP_ADMIN_EMAIL HS_BOOTSTRAP_ADMIN_PASSWORD \
  HS_STORAGE_CLASS; do
  value="${!name:-}"
  if [[ -z "$value" ]]; then
    echo "missing required value: $name" >&2
    exit 3
  fi
  if [[ "$value" =~ (CHANGE_ME|REPLACE_ME|example\.eu|ghcr\.io/example) ]]; then
    echo "refusing placeholder value for $name" >&2
    exit 3
  fi
done

export HS_AUDIT_HMAC_PREVIOUS_KEYS="${HS_AUDIT_HMAC_PREVIOUS_KEYS:-}"
export HS_SETUP_TOKEN="${HS_SETUP_TOKEN:-}"
envsubst < "$template"
