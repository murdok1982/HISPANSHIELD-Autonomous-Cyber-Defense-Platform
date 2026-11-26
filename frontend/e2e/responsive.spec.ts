import { expect, test, type Page } from "@playwright/test";

/** AC-98: no horizontal overflow at 375/768/1440 across every authenticated route. */

const EMAIL = process.env.HS_E2E_EMAIL ?? "admin@nova-iberia.example";
const PASSWORD = process.env.HS_E2E_PASSWORD ?? "Dev-Str0ng-Pass!2026";
const DEMO_ORG = process.env.HS_E2E_ORG ?? "Ayuntamiento de Nova Iberia (demo)";

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

test("no horizontal overflow on any route at 375/768/1440", async ({ page }) => {
  test.setTimeout(300_000);
  await signIn(page);
  const failures: string[] = [];

  for (const viewport of [
    { name: "mobile", width: 375, height: 812 },
    { name: "tablet", width: 768, height: 1024 },
    { name: "desktop", width: 1440, height: 900 },
  ]) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    for (const route of ROUTES) {
      const response = await page.goto(route, { waitUntil: "domcontentloaded" });
      if (!response || response.status() >= 400) {
        failures.push(`${viewport.name} ${route}: HTTP ${response?.status() ?? "no response"}`);
        continue;
      }
      await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible({ timeout: 10_000 });
      await page.waitForTimeout(150);
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      if (overflow > 1) failures.push(`${viewport.name} ${route}: horizontal overflow ${overflow}px`);
      if ((await page.getByRole("navigation").count()) === 0) {
        failures.push(`${viewport.name} ${route}: primary navigation not accessible`);
      }
    }
  }

  expect(failures, failures.join("\n")).toEqual([]);
});
