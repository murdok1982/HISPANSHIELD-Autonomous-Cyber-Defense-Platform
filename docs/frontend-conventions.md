# HISPANSHIELD — Frontend conventions (SOC Command Center)

Binding rules for page builders. Read also `src/styles/app.css`,
`src/components/ui/index.tsx`, `src/lib/api.ts`, `src/lib/auth.tsx`,
`src/lib/i18n.tsx` and the existing `src/pages/ExecutiveOverview.tsx` /
`src/pages/Soc.tsx` as reference implementations.

## 1. Stack

React 19 + TypeScript strict + Vite, React Router 7, TanStack Query 5,
lucide-react icons, custom CSS design tokens (no Tailwind, no UI framework).
Charts are hand-built SVG components. Fonts are self-hosted (Sora, Inter,
JetBrains Mono).

## 2. File ownership

- Each team owns only its page files under `src/pages/` and optional helpers
  under `src/components/features/<team>/`.
- **Never edit** `src/App.tsx`, `src/main.tsx`, `src/components/layout/**`,
  `src/components/ui/**`, `src/lib/**`, `src/styles/**`, `package.json`,
  `vite.config.ts`, `tsconfig*`. The orchestrator wires routes.
- Export the page as a named export (e.g. `export function AssetsPage()`), and
  also a default export for lazy-loading compatibility.

## 3. Data access

```ts
import { api, type Page } from "../lib/api";

const query = useQuery({
  queryKey: ["assets", { page, q, kind }],
  queryFn: () => api.get<Page<Asset>>("/assets", { page, page_size: 25, q, kind }),
});
```

- All list endpoints return `{ items, meta }`; details return the entity object.
- Use `enabled` for dependent queries. Use `refetchInterval` only for genuinely
  live views (monitoring, SOC, incidents queue) and pause it when the tab is
  hidden if practical.
- Mutations: `useMutation` + `queryClient.invalidateQueries({ queryKey: [...] })`.
  Show a toast (`useToast`) on success/failure. Never swallow errors.
- API error helper: `isApiError`, `errorMessage` from `../lib/api`.
- Permission gating: `useAuth().can("permission:key")`; hide/disable actions the
  user cannot perform, but the server remains authoritative.

## 4. Mandatory UX states (100% of data views)

- **Loading:** structural skeleton (`PageSkeleton`, `TableSkeleton`, custom card
  skeletons). No blank page, no naked spinner.
- **Empty:** `EmptyState` with icon, clear explanation and a primary CTA when the
  user can act. Distinguish "no data yet" from "no results for filters" and offer
  "clear filters".
- **Error:** `ErrorBanner` with real message + Retry button (`refetch`).
- **Success feedback:** toasts for mutations; inline field errors from
  `ApiError.details` (`{field,message}`).
- **Destructive actions:** `Modal` confirmation; explain blast radius; never
  auto-confirm.
- **Long-running actions:** disable submit, `aria-busy`, show progress state.

## 5. Visual contract

- Use existing primitives: `PageHeader`, `Card`, `Badge`, `SeverityBadge`,
  `StatusBadge`, `Kpi`, `DataTable`, `Pagination`, `Tabs`, `Modal`, `Button`,
  `LinkButton`, `Field`, `Input`, `Select`, `Textarea`, `SearchInput`,
  `ProgressBar`, `ScoreRing`, `AreaChart`, `SeverityBars`, `StatusDot`, `Toast`.
- Palette only through CSS variables (`var(--surface)`, `var(--accent)`, …).
  Never hardcode brand hex values.
- Typography: Sora for headings/numbers, Inter for body, JetBrains Mono for IDs,
  IPs, hashes, timestamps.
- 4px spacing rhythm; cards use `card` + `card-pad`; page sections separated by
  `stack`/`grid-2`/`grid-3`.
- Max 1 primary action per page header; secondary actions default/ghost.
- Icons from lucide-react at 14–16px inside controls, 18–22px in empty states.
- No emojis, no gradients beyond the defined subtle surface gradients, no
  purple AI aesthetic. Dense, calm, operational.

## 6. Responsiveness & accessibility

- Works at 375px, 768px and 1440px without horizontal page scroll. Wide tables
  live inside `.table-wrap` (horizontal scroll inside the card is acceptable).
- Visible `focus-visible`; all icon-only buttons need `aria-label`; forms use
  `Field` with `htmlFor`; dialogs use `Modal` (focus trap, Escape).
- Text contrast must remain ≥4.5:1 in dark and light themes.
- Use semantic landmarks and heading order (`h1` via PageHeader, `h2` in cards).
- `prefers-reduced-motion` is handled globally; do not add essential animation.

## 7. Internationalisation

- Spanish is the default; English must be complete for your pages.
- Use `useI18n()` for shared strings and a local dictionary via
  `usePageCopy({ es: {...}, en: {...} })` for page-specific copy. Do not leave
  hardcoded Spanish-only labels.
- Dates/numbers via `src/lib/format.ts` (`formatDateTime`, `relativeTime`,
  `formatNumber`, `formatCompact`, `formatPercent`, `durationMinutes`).
- Severity/status labels via `SeverityBadge`, `StatusBadge`, `severityKey`.

## 8. Domain rules that must be reflected in the UI

- Demonstration data: if `organization.is_demo` or a row has `is_demo`, show a
  visible `DEMO` badge. Never present demo data as live telemetry.
- AI: if the model/provider is unavailable, show the explicit unavailable state
  and never fabricate output. Agent output is advisory (A0/A1 observation), not
  execution.
- Autonomous defence: show autonomy level, approval requirement, kill-switch
  state, risk and reversibility. Critical actions always require confirmation and
  explain that the policy engine re-evaluates server-side.
- OT/IoT: passive monitoring only; do not offer active scan/reboot/register-write
  actions. Show safety-critical and passive-only flags.
- Compliance: label assessments as "technical self-assessment — not a
  certification".
- Connectors: read capabilities and write capabilities are distinct. Writes are
  executed through defence broker with approval, never directly from the list.
- Forensics: evidence hash and chain of custody visible; downloads are audited.

## 9. Testing

- Add 1–3 focused vitest tests per major page under
  `src/pages/__tests__/<Page>.test.tsx` using Testing Library, mocking `api` with
  `vi.mock("../../lib/api")` and wrapping in a small test provider
  (`QueryClientProvider` + `I18nProvider` + `AuthProvider` is heavy; instead
  extract pure formatters/components or render presentational subcomponents).
- Add `data-testid` to key containers/actions (`page-assets`, `asset-row`,
  `filter-severity`, `submit-create`, …) so Playwright can target them.
- `node node_modules/typescript/bin/tsc -b` must pass for your files.

## 10. API reference

Live OpenAPI: `http://127.0.0.1:8080/api/openapi.json` (server is running in
development). Read Pydantic output schemas before coding; fields are snake_case.
Key prefixes: `/assets`, `/vulnerabilities`, `/attack-surface`, `/threat-intel`,
`/events`, `/siem`, `/incidents`, `/soar`, `/defence`, `/agents`, `/mcp`,
`/iot`, `/ot`, `/posture`, `/forensics`, `/compliance`, `/reports`,
`/connectors`, `/edge`, `/ai`, `/organizations`, `/overview`.

If a response shape is ambiguous, read the owning `backend/app/modules/<domain>/schemas.py`.
