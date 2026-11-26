# Frontend verification run — 0.1.3 (2026-11-26)

Node.js 22.14.0 (`/tmp/opencode/node-v22.14.0-linux-x64`). Commands executed
from `frontend/`:

| Command | Result |
| :--- | :--- |
| `node node_modules/typescript/bin/tsc -b --force` | exit 0 |
| `node node_modules/vite/bin/vite.js build` | **built in 7.14s**, route-split chunks |
| `node node_modules/vitest/vitest.mjs run` | **5 files / 36 tests passed** |
| `npm audit --audit-level=high` | **0 vulnerabilities** |
| Playwright core (`--project=chromium-desktop`) | **10 passed** |
| Playwright responsive (`responsive.spec.ts`) | **PASS** 24 routes × 375/768/1440 |
| Playwright axe-core (`a11y.spec.ts`) | **PASS** 0 color-contrast / 0 critical |

Evidence logs: `.factory/EVIDENCE/e2e/playwright-desktop-8081.log` and
`.factory/EVIDENCE/e2e/a11y-responsive.log`.

Notes:

- The E2E server must run with `HS_RATE_LIMIT_ENABLED=false`; the suites reload
  the SPA dozens of times and would otherwise trip the product's own limiter.
- axe-core 4.10.2 is vendored in `frontend/e2e/vendor/` (MPL-2.0, test-only) so
  the gate works offline; it is injected via `addInitScript` because the
  production CSP correctly forbids inline script injection.
- Firefox/WebKit browsers are not installed on this host and were **NOT RUN**.
