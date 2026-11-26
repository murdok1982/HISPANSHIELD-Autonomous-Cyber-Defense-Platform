# Deployment validation run — 2026-11-26

The Kubernetes manifest is now a **template**, not a deployable production
manifest. Operators render it with their own values and validate the result.

## Render (test-shaped values, no real secrets)

```bash
./deploy/k8s/render.sh /tmp/opencode/k8s-values.env > /tmp/opencode/rendered.yaml
```

Result: exit 0.

## Validate

```bash
python3 scripts/validate_deploy.py /tmp/opencode/rendered.yaml
# PASS: /tmp/opencode/rendered.yaml has no placeholder and required controls are present
```

## Negative gate

```bash
python3 scripts/validate_deploy.py deploy/k8s/manifests.yaml
# FAIL: forbidden unrendered variable found
# exit=1
```

The unrendered template is deliberately refused, so a placeholder manifest
cannot be mistaken for production-ready. CI runs both the positive and negative
cases in the `deploy-validate` job.

## Controls asserted by the validator

- no `CHANGE_ME`, `REPLACE_ME`, `example.eu`, `ghcr.io/example`, `TODO`,
  `:latest`, or unrendered `${VAR}`;
- `runAsNonRoot: true`, `readOnlyRootFilesystem: true`,
  `allowPrivilegeEscalation: false`, drop `ALL` capabilities;
- NetworkPolicy, PodDisruptionBudget and Ingress present;
- API Deployment has `replicas: 2`.

## Not run

Docker build, `kubectl apply`, cluster rollout, TLS issuance, backup/restore in
a cluster. These remain `NOT RUN`/`PARTIAL` in `RELEASE_READINESS.md`.
