#!/usr/bin/env bash
# Prepare a development environment and print the remaining manual steps.
set -euo pipefail

echo "HISPANSHIELD setup"
python3 --version
node --version 2>/dev/null || echo "Node.js 22 is required for the frontend"

if [[ ! -f .env ]]; then
  cp .env.example .env
  SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')"
  FERNET="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' 2>/dev/null || true)"
  if [[ -n "$FERNET" ]]; then
    python3 - "$SECRET" "$FERNET" <<'PY'
import pathlib, sys
p = pathlib.Path('.env')
text = p.read_text()
text = text.replace('HS_SECRET_KEY=CHANGE_ME_64_BYTES_RANDOM', f'HS_SECRET_KEY={sys.argv[1]}')
text = text.replace('HS_ENCRYPTION_KEY=CHANGE_ME_FERNET_KEY', f'HS_ENCRYPTION_KEY={sys.argv[2]}')
p.write_text(text)
PY
    echo "Generated HS_SECRET_KEY and HS_ENCRYPTION_KEY in .env"
  else
    echo "Install the backend dependencies first to generate a Fernet key."
  fi
else
  echo ".env already exists; not overwritten"
fi

cat <<'EOF'

Next steps:
  1. Edit .env: database URL, allowed origins, bootstrap admin credentials.
  2. python -m venv .venv && source .venv/bin/activate && pip install -e "./backend[dev]"
  3. createdb hispanshield && (cd backend && alembic upgrade head)
  4. (cd frontend && npm ci && npm run build)
  5. python scripts/bootstrap_admin.py
  6. (cd backend && uvicorn app.main:app --host 127.0.0.1 --port 8080)
  7. Optional demo data: HS_SEED_DEMO=true python scripts/seed_demo.py
EOF
