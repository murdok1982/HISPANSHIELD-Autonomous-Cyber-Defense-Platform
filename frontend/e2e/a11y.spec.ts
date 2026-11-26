import { expect, test, type Page } from "@playwright/test";
import path from "node:path";

/** AC-99: axe-core gate — zero color-contrast and zero critical violations. */

const EMAIL = process.env.HS_E2E_EMAIL ?? "admin@nova-iberia.example";
const PASSWORD = process.env.HS_E2E_PASSWORD ?? "Dev-Str0ng-Pass!2026";
const DEMO_ORG = process.env.HS_E2E_ORG ?? "Ayuntamiento de Nova Iberia (demo)";
const AXE_PATH = path.join(process.cwd(), "e2e", "vendor", "axe.min.js");

const ROUTES = [
  "/",
  "/soc",
  "/monitoring",
  "/incidents",
  "/threat-intel",
  "/siem",
  "/assets",
  "/attack-surface",
  "/vulnerabilities",
  "/soar",
  "/playbook-designer",
  "/agents",
  "/iot-ot",
  "/network",
  "/cloud",
  "/identity",
  "/forensics",
  "/compliance",
  "/integrations",
  "/models",
  "/audit",
  "/organizations",
  "/admin",
  "/profile",
];

type AxeViolation = {
  id: string;
  impact: string | null;
  help: string;
  nodes: { target: string[]; failureSummary?: string }[];
};

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel(/correo corporativo|corporate email/i).fill(EMAIL);
  await page.getByLabel(/^contraseña|^password/i).fill(PASSWORD);
  await page.getByRole("button", { name: /acceder|sign in/i }).click();
  await expect(page.getByRole("heading", { name: /visión ejecutiva|executive overview/i })).toBeVisible();
  const selector = page.getByLabel(/organización activa|active organization/i);
  if (await selector.isVisible().catch(() => false)) {
    const option = selector.locator("option", { hasText: DEMO_ORG });
    if (await option.count()) {
      await Promise.all([
        page.waitForNavigation({ waitUntil: "load" }).catch(() => null),
        selector.selectOption({ label: DEMO_ORG }),
      ]);
      await page.waitForLoadState("domcontentloaded");
      await expect(page.getByRole("heading", { name: /visión ejecutiva|executive overview/i })).toBeVisible();
    }
  }
}

test("axe-core: no color-contrast or critical violations on authenticated routes", async ({ page }) => {
  test.setTimeout(300_000);
  // addInitScript is injected through the automation protocol, so it runs
  // before the app and is not blocked by the production CSP (which forbids
  // inline scripts). addScriptTag would be rejected by script-src 'self'.
  await page.addInitScript({ path: AXE_PATH });
  await signIn(page);
  const failures: string[] = [];

  for (const route of ROUTES) {
    const response = await page.goto(route, { waitUntil: "domcontentloaded" });
    if (!response || response.status() >= 400) {
      failures.push(`${route}: HTTP ${response?.status() ?? "no response"}`);
      continue;
    }
    await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible({ timeout: 10_000 });
    await page.waitForTimeout(250);
    const violations = (await page.evaluate(async () => {
      const axe = (window as unknown as { axe: { run: (context: Document) => Promise<{ violations: unknown[] }> } }).axe;
      const result = await axe.run(document);
      return result.violations;
    })) as AxeViolation[];

    for (const violation of violations) {
      const blocking = violation.id === "color-contrast" || violation.impact === "critical";
      if (!blocking) continue;
      const targets = violation.nodes
        .slice(0, 3)
        .map((node) => node.target.join(" "))
        .join(", ");
      failures.push(`${route}: ${violation.id} (${violation.impact}) ${targets}`);
    }
  }

  expect(failures, failures.join("\n")).toEqual([]);
});
