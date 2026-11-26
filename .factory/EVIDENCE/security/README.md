# Security scans — 2026-11-26

| Tool | Command | Result | Artefact |
| :--- | :--- | :--- | :--- |
| pip-audit | `python -m pip_audit --skip-editable` | No known vulnerabilities (exit 0) | `pip-audit.txt` |
| bandit | `python -m bandit -q -ll -r app -x tests -f json` | 0 MEDIUM / 0 HIGH | `bandit.json` |
| gitleaks 8.30.1 | `gitleaks detect --source . --config .gitleaks.toml --redact` | 0 leaks across 7 commits | `gitleaks.json`, `gitleaks.log` |
| npm audit | `npm audit --audit-level=high` | 0 vulnerabilities | `npm-audit.txt` |

Notes:

- The XML importers now use `defusedxml` (ADR-014); Bandit B314 is resolved
  rather than suppressed.
- Gitleaks findings were limited to CI/test placeholders
  (`ci-only-*`, `metrics-secret-key-*`, `ci_password`). Only those exact
  patterns were allowlisted; no broad `docs/` or `scripts/` exclusion was
  added beyond the pre-existing documentation allowlist.
- No real credential, token or personal data is stored in this directory.
