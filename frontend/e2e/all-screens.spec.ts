import { expect, test, type Page } from "@playwright/test";

const EMAIL = process.env.HS_E2E_EMAIL ?? "admin@nova-iberia.example";
const PASSWORD = process.env.HS_E2E_PASSWORD ?? "Dev-Str0ng-Pass!2026";
const DEMO_ORG = process.env.HS_E2E_ORG ?? "Ayuntamiento de Nova Iberia (demo)";

const ROUTES: { path: string; heading: RegExp }[] = [
  { path: "/", heading: /visión ejecutiva|executive overview/i },
  { path: "/soc", heading: /centro de mando soc|soc command center/i },
  { path: "/monitoring", heading: /monitorización|threat monitoring/i },
  { path: "/incidents", heading: /incidentes|incidents/i },
  { path: "/threat-intel", heading: /inteligencia de amenazas|threat intelligence/i },
  { path: "/siem", heading: /siem/i },
  { path: "/assets", heading: /activos|assets/i },
  { path: "/attack-surface", heading: /superficie de ataque|attack surface/i },
  { path: "/vulnerabilities", heading: /vulnerabilidades|vulnerabilities/i },
  { path: "/soar", heading: /soar/i },
  { path: "/playbook-designer", heading: /playbook/i },
  { path: "/agents", heading: /agentes|agents/i },
  { path: "/iot-ot", heading: /iot|ot/i },
  { path: "/network", heading: /red|network/i },
  { path: "/cloud", heading: /cloud/i },
  { path: "/identity", heading: /identidad|identity/i },
  { path: "/forensics", heading: /forense|forensics/i },
  { path: "/compliance", heading: /cumplimiento|compliance/i },
  { path: "/integrations", heading: /integraci|integration/i },
  { path: "/models", heading: /modelo|model/i },
  { path: "/audit", heading: /auditor|audit/i },
  { path: "/organizations", heading: /organizaci|organization/i },
  { path: "/admin", heading: /administraci|administration/i },
  { path: "/profile", heading: /perfil|profile/i },
];

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel(/correo corporativo|corporate email/i).fill(EMAIL);
  await page.getByLabel(/^contraseña|^password/i).fill(PASSWORD);
  await page.getByRole("button", { name: /acceder|sign in/i }).click();
  await expect(page.getByRole("heading", { name: /visión ejecutiva|executive overview/i })).toBeVisible({ timeout: 15_000 });
  const selector = page.getByLabel(/organización activa|active organization/i);
  const selectorVisible = await selector.isVisible().catch(() => false);
  const option = selector.locator("option", { hasText: DEMO_ORG });
  if (selectorVisible && (await option.count())) {
    await Promise.all([
      page.waitForNavigation({ waitUntil: "load" }).catch(() => null),
      selector.selectOption({ label: DEMO_ORG }),
    ]);
    await page.waitForLoadState("domcontentloaded");
    await expect(page.getByRole("heading", { name: /visión ejecutiva|executive overview/i })).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(400);
  }
}

test("all SOC screens render with real data and no client errors", async ({ page }) => {
  test.setTimeout(180_000);
  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(`${page.url()} :: ${message.text()}`);
  });
  page.on("response", (response) => {
    if (response.status() >= 400) consoleErrors.push(`${page.url()} :: HTTP ${response.status()} ${response.url()}`);
  });
  page.on("pageerror", (error) => consoleErrors.push(`${page.url()} :: ${error.message}`));

  await signIn(page);
  const failures: string[] = [];

  for (const route of ROUTES) {
    const response = await page.goto(route.path, { waitUntil: "domcontentloaded" });
    if (!response || response.status() >= 400) {
      failures.push(`${route.path}: HTTP ${response?.status() ?? "no response"}`);
      continue;
    }
    try {
      await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible({ timeout: 12_000 });
      const heading = (await page.getByRole("heading", { level: 1 }).first().innerText()).trim();
      if (!route.heading.test(heading)) failures.push(`${route.path}: unexpected heading "${heading}"`);
      await page.waitForTimeout(600);
      const body = await page.locator("body").innerText();
      if (/no se pudieron cargar los datos|could not load the data/i.test(body)) {
        failures.push(`${route.path}: error banner visible`);
      }
    } catch (error) {
      failures.push(`${route.path}: ${(error as Error).message.split("\n")[0]}`);
    }
  }

  const actionableErrors = consoleErrors.filter((entry) => !/favicon|manifest|Download the React DevTools/i.test(entry));
  expect(failures, failures.join("\n")).toEqual([]);
  expect(actionableErrors, actionableErrors.join("\n")).toEqual([]);
});

test("key page interactions work", async ({ page }) => {
  test.setTimeout(90_000);
  await signIn(page);

  await page.goto("/assets");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.getByText(/servidor de copias|DC-01|ERP municipal/i).first()).toBeVisible({ timeout: 15_000 });

  await page.goto("/incidents");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.getByText(/HS-2026-/).first()).toBeVisible({ timeout: 15_000 });

  await page.goto("/compliance");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.getByText(/NIS2/i).first()).toBeVisible({ timeout: 15_000 });

  await page.goto("/audit");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
});
