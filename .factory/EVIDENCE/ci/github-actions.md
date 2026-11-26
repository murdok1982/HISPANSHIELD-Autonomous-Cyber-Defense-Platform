# GitHub Actions remote run — PASS

- **Repository:** murdok1982/HISPANSHIELD-Autonomous-Cyber-Defense-Platform
- **Commit:** `8780113f9b10f5af4189e5dccbb692e68ea1b812`
- **Runs:** [45881513134](https://github.com/murdok1982/HISPANSHIELD-Autonomous-Cyber-Defense-Platform/actions/runs/45881513134), [45881504398](https://github.com/murdok1982/HISPANSHIELD-Autonomous-Cyber-Defense-Platform/actions/runs/45881504398)
- **Date:** 2026-11-26
- **Conclusion:** `success` for every job in both runs.

| Job | Result |
| :--- | :--- |
| backend (ruff, format, mypy, pytest+cov, pip-audit, bandit) | success |
| frontend (tsc/build, vitest, npm audit) | success |
| secret-scan (gitleaks) | success |
| sbom (CycloneDX Python + Node) | success |
| deploy-validate (render + anti-placeholder) | success |
| container (Docker build + Trivy CRITICAL/HIGH gate) | success |
| quality-gate (fail-closed aggregate) | success |

Remote findings fixed before this green run:

1. `aquasecurity/trivy-action@0.28.0` did not resolve; pinned to `v0.36.0`.
2. Shell scripts were `100644`; now `100755` so `./deploy/k8s/render.sh` runs.
3. Trivy flagged fixable HIGH `CVE-2026-124851` in `libzstd1`; the runtime
   Dockerfile now upgrades the package instead of suppressing the gate.

Artifacts uploaded by the run include `backend-security`, `sbom` and the
Docker build record. Node 20 deprecation warnings are non-blocking and come
from upstream actions (`checkout@v4`, `setup-node@v4`, `upload-artifact@v4`).
