# syntax=docker/dockerfile:1.7
# HISPANSHIELD — single-artifact image: FastAPI + compiled SOC command center.

FROM node:22-alpine AS frontend-build
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HS_ENV=production \
    HS_FRONTEND_DIST=/app/frontend/dist \
    HS_EVIDENCE_DIR=/app/data/evidence

RUN groupadd --system --gid 10001 hispanshield \
 && useradd --system --uid 10001 --gid hispanshield --home /app --shell /usr/sbin/nologin hispanshield

WORKDIR /app
COPY backend/pyproject.toml /app/backend/
COPY backend/app /app/backend/app
COPY backend/migrations /app/backend/migrations
COPY backend/alembic.ini /app/backend/
RUN pip install --no-cache-dir /app/backend \
 && chown -R hispanshield:hispanshield /app
COPY --from=frontend-build --chown=hispanshield:hispanshield /build/frontend/dist /app/frontend/dist

RUN mkdir -p /app/data/evidence && chown -R hispanshield:hispanshield /app/data
USER 10001:10001

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status==200 else 1)"

WORKDIR /app/backend
# Migrations are idempotent; with multiple replicas use a pre-deploy Job instead
# and set HS_RUN_MIGRATIONS=false to avoid concurrent DDL.
CMD ["sh", "-c", "if [ \"${HS_RUN_MIGRATIONS:-true}\" = \"true\" ]; then python -m alembic upgrade head; fi; exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers ${HS_WORKERS:-2} --proxy-headers --forwarded-allow-ips='*'"]
