import { expect, test, type Page } from "@playwright/test";

const EMAIL = process.env.HS_E2E_EMAIL ?? "admin@nova-iberia.example";
const PASSWORD = process.env.HS_E2E_PASSWORD ?? "Dev-Str0ng-Pass!2026";
const DEMO_ORG = process.env.HS_E2E_ORG ?? "Ayuntamiento de Nova Iberia (demo)";

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel(/correo corporativo|corporate email/i).fill(EMAIL);
  await page.getByLabel(/^contraseña|^password/i).fill(PASSWORD);
  await page.getByRole("button", { name: /acceder|sign in/i }).click();
  await expect(page.getByRole("heading", { name: /visión ejecutiva|executive overview/i })).toBeVisible({ timeout: 20_000 });
  const selector = page.getByLabel(/organización activa|active organization/i);
  if (await selector.isVisible().catch(() => false)) {
    const option = selector.locator("option", { hasText: DEMO_ORG });
    if (await option.count()) {
      await Promise.all([
        page.waitForNavigation({ waitUntil: "load" }).catch(() => null),
        selector.selectOption({ label: DEMO_ORG }),
      ]);
      await expect(page.getByRole("heading", { name: /visión ejecutiva|executive overview/i })).toBeVisible({ timeout: 20_000 });
    }
  }
}

test("capture product screenshots", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);

  const shots: { path: string; file: string; wait?: RegExp }[] = [
    { path: "/", file: "ui-overview.png", wait: /índice de riesgo|risk index/i },
    { path: "/soc", file: "ui-soc.png", wait: /flujo de eventos en vivo|live event feed/i },
    { path: "/incidents", file: "ui-incidents.png", wait: /incidentes|incidents/i },
    { path: "/iot-ot", file: "ui-iot-ot.png", wait: /iot|ot/i },
    { path: "/compliance", file: "ui-compliance.png", wait: /cumplimiento|compliance/i },
  ];

  for (const shot of shots) {
    await page.goto(shot.path, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible({ timeout: 20_000 });
    if (shot.wait) await expect(page.getByText(shot.wait).first()).toBeVisible({ timeout: 15_000 });
    await page.waitForTimeout(700);
    await page.screenshot({ path: `../docs/assets/${shot.file}`, fullPage: true });
  }
});
