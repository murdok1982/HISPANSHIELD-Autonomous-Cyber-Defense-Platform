#!/usr/bin/env bash
# Pull a local model into the configured Ollama runtime (offline-capable afterwards).
set -euo pipefail
MODEL="${1:-qwen2.5:7b-instruct}"
OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"

echo "Pulling ${MODEL} from ${OLLAMA_URL}"
curl --fail --show-error --silent -X POST "${OLLAMA_URL}/api/pull" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"${MODEL}\",\"stream\":false}" | head -c 2000
echo
echo "Verify with: curl ${OLLAMA_URL}/api/tags"
echo "Register the provider in HISPANSHIELD → Model Management (kind: ollama, url: ${OLLAMA_URL})."
