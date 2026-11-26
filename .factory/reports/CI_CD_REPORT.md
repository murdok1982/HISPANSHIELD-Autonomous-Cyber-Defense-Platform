# CI/CD recovery report — 0.1.3 remediation

- **Date:** 2026-11-26
- **File:** `.github/workflows/ci.yml`
- **Baseline:** commit `251846c` on `main`

## 1. Blocking defect (P0)

The `container` job was syntactically malformed:

```yaml
container:
  runs-on: ubuntu-latest
  needs: [backend, frontend]    steps:
```

`steps:` was glued to the `needs:` line, so the workflow had no valid step list
for that job (and YAML parsers folded it into a scalar). Fixed to:

```yaml
container:
  runs-on: ubuntu-latest
  needs: [backend, frontend]
  steps:
```

## 2. Additional hardening applied

- Least-privilege workflow permission `contents: read`; `pull-requests: write`
  only on the secret-scan job.
- `workflow_dispatch` added; per-job `timeout-minutes`.
- `load: true` on the image build so the Trivy scan actually sees the image.
- New `quality-gate` job that depends on **all** gates and fails on
  `failure`, `cancelled` or `skipped`. Branch protection should require only
  this check so no optional job can mask a failed mandatory one.
- SBOM, deploy render/validate, secret scan and container scan remain
  fail-closed; no release publication job exists, so a failed gate cannot
  publish an image.

## 3. Validation executed here

| Check | Command | Result |
| :--- | :--- | :--- |
| YAML parse | `python3 -c "yaml.safe_load(open('.github/workflows/ci.yml'))"` | PASS |
| Static workflow lint | `actionlint 1.7.12 .github/workflows/ci.yml` | PASS (0 findings) |
| Job graph | parsed `needs` for `container` and `quality-gate`; hyphenated jobs use index syntax | PASS |
| Local equivalent of backend job | `pytest`, ruff, format, mypy, bandit, pip-audit | PASS |
| Local equivalent of frontend job | `tsc`, `vite build`, `vitest`, `npm audit` | PASS |
| Deploy job | `render.sh values.ci.env` + `validate_deploy.py` | PASS |
| Unrendered template must fail | `validate_deploy.py deploy/k8s/manifests.yaml` | FAIL as expected |

## 4. Limitations

- GitHub Actions itself was **NOT RUN** from this host before the commit; the
  first remote run must be checked after pushing. Every command the workflow
  invokes was executed locally with the same environment contract.
- Docker is not installed on this host, so the container job is **BLOCKED**
  locally; the Dockerfile build is unverified here.
