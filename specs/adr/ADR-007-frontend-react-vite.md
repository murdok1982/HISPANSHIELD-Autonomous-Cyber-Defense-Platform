# ADR-007: Frontend React 19 + Vite + tokens CSS propios (sin Tailwind ni SSR)

- **Estado:** `ACCEPTED`
- **Fecha:** 2026-11-26
- **Relacionados:** `ADR-001`, `.factory/ARCHITECTURE.md §5`, `specs/product/requirements.md`

## Contexto

La consola tiene 23 pantallas de alta densidad, requisitos estrictos de contraste y accesibilidad, y debe servirse en air-gap sin CDN. Es una aplicación interna autenticada: el SEO y el render en servidor no aportan valor, mientras que el control fino de densidad, estados y tokens sí.

## Alternativas consideradas

| Alternativa | Pros | Contras |
| :--- | :--- | :--- |
| Next.js (SSR/RSC) | SEO, streaming, ecosistema | Complejidad de servidor Node, dos runtimes, hidratación, sin beneficio interno |
| Tailwind | Velocidad inicial | Dificulta tokens semánticos estrictos y auditoría de contraste; clases utilitarias dispersas |
| Librería de componentes (MUI/Ant) | Componentes listos | Estética genérica, difícil de adaptar a densidad SOC, peso |
| **React 19 + Vite + CSS Modules + tokens (elegido)** | Control total, build estático, tipado, rendimiento | Más trabajo inicial de primitivas |

## Decisión

SPA con Vite, React 19, TypeScript `strict`, react-router 7, TanStack Query 5, CSS Modules sobre custom properties (`tokens.css`), `uplot` para series y SVG propio para grafos, fuentes `.woff2` autoalojadas. Sin Tailwind, sin SSR, sin librería de UI externa.

## Consecuencias

**Positivas**
- Un artefacto estático servible por cualquier proxy; air-gap trivial.
- Tokens como contrato verificable (computed styles en Playwright).
- Control de densidad (32/40/48 px) y de estados sin luchar contra una librería.
- Bundle acotado con code splitting por ruta.

**Negativas**
- Hay que construir y mantener primitivas (DataTable, Modal, CommandPalette…).
- Sin SSR: primera carga depende del bundle (mitigado con splitting y precarga).
- Riesgo de inconsistencia visual; mitigado con `@ui-artisan` y revisión con tokens.

**Métricas de reversión**
- Si el tiempo de construcción de una vista nueva supera 3 días de media, evaluar librería de componentes.
- Si el bundle inicial >500 KB gzip, revisar splitting antes de plantear SSR.

## Verificación

`npm run typecheck`, `npm run build`, `e2e/screens.spec.ts`, `e2e/a11y.spec.ts`, `e2e/responsive.spec.ts`, budget de bundle en CI.
