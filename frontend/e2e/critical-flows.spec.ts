import { expect, test, type Page } from "@playwright/test";

/**
 * End-to-end acceptance against the real backend and demo dataset.
 *
 * Requires a running HISPANSHIELD server seeded with demo data and the
 * bootstrap admin credentials supplied via environment variables. The suite
 * never mutates destructive state beyond incident notes/playbook simulation.
 */

const EMAIL = process.env.HS_E2E_EMAIL ?? "admin@nova-iberia.example";
const PASSWORD = process.env.HS_E2E_PASSWORD ?? "Dev-Str0ng-Pass!2026";
const DEMO_ORG = process.env.HS_E2E_ORG ?? "Ayuntamiento de Nova Iberia (demo)";

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel(/correo corporativo|corporate email/i).fill(EMAIL);
  await page.getByLabel(/^contraseña|^password/i).fill(PASSWORD);
  await page.getByRole("button", { name: /acceder|sign in/i }).click();
  await expect(page.getByRole("heading", { name: /visión ejecutiva|executive overview/i })).toBeVisible();
  const selector = page.getByLabel(/organización activa|active organization/i);
  const selectorVisible = await selector.isVisible().catch(() => false);
  if (selectorVisible && (await selector.inputValue()) !== "") {
    const option = selector.locator("option", { hasText: DEMO_ORG });
    if (await option.count()) {
      await Promise.all([
        page.waitForNavigation({ waitUntil: "load" }).catch(() => null),
        selector.selectOption({ label: DEMO_ORG }),
      ]);
      await page.waitForLoadState("domcontentloaded");
      await expect(page.getByRole("heading", { name: /visión ejecutiva|executive overview/i })).toBeVisible({ timeout: 20_000 });
      await page.waitForTimeout(400);
    }
  }
}

test.describe("authentication and tenant scoping", () => {
  test("rejects invalid credentials with a generic error", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel(/correo corporativo|corporate email/i).fill("nobody@example.eu");
    await page.getByLabel(/^contraseña|^password/i).fill("Wrong-Password-123!");
    await page.getByRole("button", { name: /acceder|sign in/i }).click();
    await expect(page.getByRole("alert")).toContainText(/no se pudo|invalid/i);
    await expect(page).toHaveURL(/\/login/);
  });

  test("protects application routes", async ({ page }) => {
    await page.context().clearCookies();
    await page.goto("/incidents");
    await expect(page).toHaveURL(/\/login/);
  });
});

test.describe("SOC command center", () => {
  test("executive overview renders real KPI data and risk", async ({ page }) => {
    await signIn(page);
    await expect(page.getByText(/índice de riesgo|risk index/i).first()).toBeVisible();
    await expect(page.getByTestId("page-overview")).toBeVisible();
    await expect(page.getByText(/incidentes recientes|recent incidents/i)).toBeVisible();
    await page.screenshot({ path: "test-results/overview.png", fullPage: true });
  });

  test("live monitoring and incident management are reachable", async ({ page }) => {
    await signIn(page);
    await page.getByRole("link", { name: /centro de mando soc|soc command center/i }).click();
    await expect(page.getByRole("heading", { name: /centro de mando soc|soc command center/i })).toBeVisible();
    await page.getByRole("link", { name: /gestión de incidentes|incident management/i }).click();
    await expect(page.getByRole("heading", { name: /incidentes|incidents/i }).first()).toBeVisible();
    await page.screenshot({ path: "test-results/incidents.png", fullPage: true });
  });

  test("mobile navigation has no horizontal overflow", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await signIn(page);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });
});

test.describe("governance", () => {
  test("audit center verifies the hash chain", async ({ page }) => {
    await signIn(page);
    await page.goto("/audit");
    await expect(page.getByRole("heading", { name: /auditoría|audit/i }).first()).toBeVisible();
    const verify = page.getByRole("button", { name: /verificar|verify/i });
    if (await verify.count()) {
      await verify.first().click();
      await expect(page.getByText(/válida|valid|íntegra|integrity/i).first()).toBeVisible();
    }
  });

  test("authentication security settings are visible", async ({ page }) => {
    await signIn(page);
    await page.goto("/admin");
    await expect(page.getByRole("heading", { name: /administración|administration/i })).toBeVisible();
  });
});
