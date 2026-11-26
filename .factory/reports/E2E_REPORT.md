# E2E REPORT — 0.1.3

- **Environment:** fresh PostgreSQL DB `hispanshield_e2e` migrated to `0016`,
  bootstrap admin + demo seed, real FastAPI server, production Vite bundle.
- **Browser:** Playwright Chromium 1255 (desktop 1440×900; core suite also
  375×812 mobile project definition).
- **Server:** `HS_RATE_LIMIT_ENABLED=false` (the suites reload the SPA dozens of
  times and would otherwise trip the product's own limiter).

| Suite | Result | Log |
| :--- | :--- | :--- |
| Core (auth, overview, incidents, audit, admin, mobile overflow, screenshots) | **10 passed** | `EVIDENCE/e2e/playwright-desktop-8081.log` |
| All screens (24 routes, 0 console/HTTP errors) | **PASS** | same |
| Responsive 24 routes × 375/768/1440 | **PASS** (0 overflow, nav present) | `EVIDENCE/e2e/a11y-responsive.log` |
| axe-core 4.10.2, 24 routes | **PASS** (0 color-contrast, 0 critical) | same |

## Gaps

- Firefox and WebKit browsers are not installed: **NOT RUN**.
- The core suite does not yet chain create-asset → ingest → alert → incident →
  playbook execution → kill switch; AC-119 remains `PARTIAL`.
- No manual WCAG audit; axe-core is an automated gate, not a certification.
