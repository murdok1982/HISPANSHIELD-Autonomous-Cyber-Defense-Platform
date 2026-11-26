# FINAL DEPLOYMENT REPORT — 0.1.2

## Hecho

- Compose incluye API + worker durable + PostgreSQL + Ollama opcional.
- Kubernetes convertido en plantilla con `render.sh` y valores obligatorios.
- `scripts/validate_deploy.py` rechaza placeholders, `:latest`, variables sin
  renderizar y ausencia de `runAsNonRoot`, `readOnlyRootFilesystem`,
  `allowPrivilegeEscalation: false`, drop ALL, NetworkPolicy, PDB e Ingress.
- CI añade job `deploy-validate` con caso positivo y negativo.
- `/readyz` incluye DB, migraciones, cola de playbooks y backlog de outbox.
- Secretos de producción incluyen HMAC de auditoría.

## No hecho

- Build de imagen Docker y arranque real.
- `kubectl apply`, rollout, TLS, PVC real, NetworkPolicy efectiva.
- Restore de backup en instancia limpia.
- Instalación air-gapped con `--no-index`.

## Conclusión

**PARTIAL**: plantilla validada estáticamente, runtime no probado. No se afirma
alta disponibilidad por tener `replicas: 2`.
