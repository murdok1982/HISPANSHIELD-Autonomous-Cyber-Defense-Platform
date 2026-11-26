# WAVE 0 — Reality & SDD reconciliation (2026-11-26)

All figures below were recomputed from the repository with
`scripts/factory_metrics.py`, `scripts/ac_traceability.py` and the executed test
runs. None was hand-adjusted to match an older document.

| # | Contradiction reported | Recomputed truth | Source |
| :--- | :--- | :--- | :--- |
| 1 | 128/172 vs 109/150 tasks | **138/176** verified, 37 deferred, 1 in progress (4 evolution tasks added; 10 task states corrected with evidence) | `TASKS.md`, `METRICS.json` |
| 2 | 44 vs 47 deferred | **37** `[!]` + **1** `[~]`; stale “47” removed | `TASKS.md` |
| 3 | AC pending while tasks verified | **70 VERIFIED / 32 PARTIAL / 22 NOT_VERIFIED** in a generated matrix; a checked task no longer implies every AC is verified | `AC_TRACEABILITY.md` |
| 4 | Corrected architectural gaps still listed as open | Outbox (partial), SSE, cursor, idempotency, setup, invitations, recovery codes, sessions now closed; LISTEN/NOTIFY/jobs/repository/partitions remain open | `REALITY_CHECK.md`, `REPO_INVENTORY.md` |
| 5 | Open gaps | Cloud CSPM, Nessus/OpenVAS/Trivy importers, soft delete, legal hold, partitions, A4, durable agent resume, FTS use, air-gap | `TASKS.md` |
| 6 | Implemented vs documented features | README and compatibility matrix rewritten to distinguish real adapters from roadmap; cloud/OIDC/A4/importers marked unsupported | `README.md`, `docs/compatibility-matrix.md` |
| 7 | 23 vs 24 screens | **23 navigation screens**, **26 content page components** (23 + Profile + AssetDetail + IncidentDetail), **28 page files** including Login/NotFound | `App.tsx`, `navigation.ts`, metrics |
| 8 | Adapter inventory vs compatibility matrix | **12 real adapters**; matrix now lists only those, plus “not supported” rows | `adapters/__init__.py`, matrix |
| 9 | Autonomy levels vs available actions | Catalogue has **13 actions**, max **A3**; **0 A4 actions**; README/manual say A4 reserved | `services/actions.py`, metrics |
| 10 | Audit findings vs current security | 0 CRITICAL/0 HIGH; VULN-014 residual updated to keyed HMAC v3 + checkpoints; new surfaces reviewed in `SECURITY_AUDIT.md` §9 | `SECURITY_AUDIT.md`, `SECURITY_FINDINGS.md` |

## Additional measured corrections

| Metric | Before | Now |
| :--- | ---: | ---: |
| Backend tests | 519 / 609 (mixed) | **650 collected / executed** |
| Edge tests | 92 | 92 |
| Frontend tests | 36 | 36 |
| OpenAPI ops / paths | 283–284 / 214–215 | **305 / 233** |
| ORM tables | 61 (claimed 59) | **65** |
| Migrations | 10 | **14** |
| Modules / routers | 23 / 23 | **24 / 26** |
| Docs top-level markdown | 29 | 23 (`docs/*.md` by metrics) |

## Method notes

- `pytest --collect-only` may import the app but does not touch PostgreSQL.
- The full backend run used `hispanshield_test` on PostgreSQL 18.6; the database
  had to be created manually (`CREATE DATABASE hispanshield_test`).
- Marketing counts (e.g. “284 endpoints”) are no longer used; OpenAPI is the
  authoritative contract and the snapshot `docs/openapi.json` was regenerated.
