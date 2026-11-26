# E2E evidence — 0.1.3

- `playwright-desktop-8081.log` — core suite (`all-screens`, `critical-flows`,
  `screenshots`) against a fresh seeded DB: **10 passed**.
- `a11y-responsive.log` — axe-core 24 routes (0 color-contrast / 0 critical) and
  responsive 24 routes × 375/768/1440 (0 overflow): **2 passed**.
- `playwright-desktop.log` — first run on a pre-existing server (10 passed) kept
  as a cross-check; superseded by the 8081 run on the fresh DB.

Environment: PostgreSQL 18 `hispanshield_e2e` at head `0016`, bootstrap admin
`admin@nova-iberia.example`, demo organisation, production Vite bundle, uvicorn
on `127.0.0.1:8081`, `HS_RATE_LIMIT_ENABLED=false` for the test run only.

Not covered: Firefox, WebKit, manual WCAG audit.
