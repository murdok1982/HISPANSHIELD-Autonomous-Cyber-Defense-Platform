import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { I18nProvider } from "../../lib/i18n";
import { ToastProvider } from "../../components/ui";
import { CompliancePage } from "../Compliance";

const state = vi.hoisted(() => ({ canRead: true }));

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  patch: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
  upload: vi.fn(),
}));

vi.mock("../../lib/api", () => ({
  api: apiMock,
  downloadFile: vi.fn(),
  errorMessage: (error: unknown) => (error instanceof Error ? error.message : "error"),
  isApiError: () => false,
  ApiError: class ApiError extends Error {},
}));

vi.mock("../../lib/auth", () => ({
  useAuth: () => ({
    session: {
      user: {
        id: "user-1",
        email: "analista@example.eu",
        full_name: "Analista SOC",
        status: "active",
        is_platform_admin: false,
        mfa_enabled: true,
        locale: "es",
        timezone: "Europe/Madrid",
        last_login_at: "2026-01-01T08:00:00Z",
        created_at: "2025-01-01T08:00:00Z",
      },
      organization: { id: "org-1", slug: "acme", name: "ACME", kind: "private", role: "compliance_officer" },
      role: "compliance_officer",
      permissions: ["compliance:read", "compliance:assess", "report:read"],
      organizations: [],
      csrf_token: "csrf",
      autonomy_level: "A1",
      expires_at: "2026-01-01T10:00:00Z",
    },
    status: "authenticated",
    error: null,
    can: (permission: string) => state.canRead && (permission.startsWith("compliance:") || permission.startsWith("report:")),
    login: vi.fn(),
    verifyMfa: vi.fn(),
    logout: vi.fn(),
    switchOrganization: vi.fn(),
    refresh: vi.fn(),
  }),
}));

const framework = {
  id: "fw-1",
  code: "NIS2",
  name: "Directiva NIS2",
  version: "1.0",
  jurisdiction: "EU",
  authority: "ENISA",
  effective_date: "2024-10-17",
  source_url: "https://example.eu/nis2",
  status: "published",
  is_builtin: true,
  published_at: "2024-10-17T00:00:00Z",
  controls_count: 12,
  technical_checks_count: 5,
};

function summary() {
  return {
    organization_id: "org-1",
    organization_name: "ACME",
    generated_at: "2026-01-01T09:00:00Z",
    frameworks: [
      {
        framework_id: "fw-1",
        framework_code: "NIS2",
        framework_name: "Directiva NIS2",
        framework_version: "1.0",
        assessment_id: null,
        assessment_status: null,
        score: null,
        completed_at: null,
        controls_total: 12,
        compliant: 0,
        partial: 0,
        non_compliant: 0,
        not_applicable: 0,
        not_assessed: 12,
      },
    ],
    assessed_frameworks: 0,
    average_score: null,
    disclaimer: "Technical self-assessment",
  };
}

const emptyPage = { items: [], meta: { total: 0, page: 1, page_size: 20, pages: 0, has_next: false } };

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={client}>
      <I18nProvider>
        <ToastProvider>{children}</ToastProvider>
      </I18nProvider>
    </QueryClientProvider>
  );
}

beforeEach(() => {
  window.localStorage.setItem("hs.lang", "es");
  state.canRead = true;
  apiMock.get.mockReset();
  apiMock.get.mockImplementation((path: string) => {
    if (path === "/compliance/summary") return Promise.resolve(summary());
    if (path === "/compliance/frameworks") {
      return Promise.resolve({
        items: [framework],
        meta: { total: 1, page: 1, page_size: 20, pages: 1, has_next: false },
      });
    }
    if (path === "/compliance/assessments") return Promise.resolve(emptyPage);
    if (path === "/reports") return Promise.resolve(emptyPage);
    return Promise.resolve(emptyPage);
  });
});

describe("CompliancePage", () => {
  it("renders the technical self-assessment disclaimer and real framework rows", async () => {
    render(<CompliancePage />, { wrapper });

    expect(await screen.findByTestId("compliance-disclaimer")).toHaveTextContent(/no es una certificación/i);
    expect(await screen.findByText("Directiva NIS2")).toBeInTheDocument();
    expect(screen.getByText("NIS2")).toBeInTheDocument();
    expect(apiMock.get).toHaveBeenCalledWith(
      "/compliance/frameworks",
      expect.objectContaining({ page: 1, page_size: 20 }),
    );
  });

  it("blocks the page when the role cannot read compliance", async () => {
    state.canRead = false;
    render(<CompliancePage />, { wrapper });

    expect(await screen.findByText("No tienes permiso para ver el cumplimiento.")).toBeInTheDocument();
    expect(apiMock.get).not.toHaveBeenCalled();
  });

  it("loads assessments when the assessments tab is selected", async () => {
    const user = userEvent.setup();
    render(<CompliancePage />, { wrapper });

    await screen.findByText("Directiva NIS2");
    await user.click(screen.getByRole("tab", { name: "Evaluaciones" }));

    expect(await screen.findByTestId("compliance-assessments")).toBeInTheDocument();
    await waitFor(() =>
      expect(apiMock.get).toHaveBeenCalledWith("/compliance/assessments", expect.objectContaining({ page: 1 })),
    );
  });
});
