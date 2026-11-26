import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Component, lazy, Suspense, type ErrorInfo, type ReactNode } from "react";
import { ShieldAlert } from "lucide-react";
import { useAuth } from "./lib/auth";
import { AppShell } from "./components/layout/AppShell";
import { Button, PageSkeleton } from "./components/ui";
import { LoginPage } from "./pages/Login";
const ExecutiveOverviewPage = lazy(() => import("./pages/ExecutiveOverview").then((module) => ({ default: module.ExecutiveOverviewPage })));
const SocPage = lazy(() => import("./pages/Soc").then((module) => ({ default: module.SocPage })));
const MonitoringPage = lazy(() => import("./pages/Monitoring").then((module) => ({ default: module.MonitoringPage })));
const IncidentsPage = lazy(() => import("./pages/Incidents").then((module) => ({ default: module.IncidentsPage })));
const IncidentDetailPage = lazy(() => import("./pages/IncidentDetail").then((module) => ({ default: module.IncidentDetailPage })));
const ThreatIntelPage = lazy(() => import("./pages/ThreatIntel").then((module) => ({ default: module.ThreatIntelPage })));
const AssetsPage = lazy(() => import("./pages/Assets").then((module) => ({ default: module.AssetsPage })));
const AssetDetailPage = lazy(() => import("./pages/AssetDetail").then((module) => ({ default: module.AssetDetailPage })));
const AttackSurfacePage = lazy(() => import("./pages/AttackSurface").then((module) => ({ default: module.AttackSurfacePage })));
const VulnerabilitiesPage = lazy(() => import("./pages/Vulnerabilities").then((module) => ({ default: module.VulnerabilitiesPage })));
const SiemPage = lazy(() => import("./pages/Siem").then((module) => ({ default: module.SiemPage })));
const SoarPage = lazy(() => import("./pages/Soar").then((module) => ({ default: module.SoarPage })));
const PlaybookDesignerPage = lazy(() => import("./pages/PlaybookDesigner").then((module) => ({ default: module.PlaybookDesignerPage })));
const AgentsPage = lazy(() => import("./pages/Agents").then((module) => ({ default: module.AgentsPage })));
const IotOtPage = lazy(() => import("./pages/IotOt").then((module) => ({ default: module.IotOtPage })));
const NetworkPage = lazy(() => import("./pages/Network").then((module) => ({ default: module.NetworkPage })));
const CloudPage = lazy(() => import("./pages/Cloud").then((module) => ({ default: module.CloudPage })));
const IdentityPage = lazy(() => import("./pages/Identity").then((module) => ({ default: module.IdentityPage })));
const ForensicsPage = lazy(() => import("./pages/Forensics").then((module) => ({ default: module.ForensicsPage })));
const CompliancePage = lazy(() => import("./pages/Compliance").then((module) => ({ default: module.CompliancePage })));
const IntegrationsPage = lazy(() => import("./pages/Integrations").then((module) => ({ default: module.IntegrationsPage })));
const ModelsPage = lazy(() => import("./pages/Models").then((module) => ({ default: module.ModelsPage })));
const AuditPage = lazy(() => import("./pages/Audit").then((module) => ({ default: module.AuditPage })));
const OrganizationsPage = lazy(() => import("./pages/Organizations").then((module) => ({ default: module.OrganizationsPage })));
const AdminPage = lazy(() => import("./pages/Admin").then((module) => ({ default: module.AdminPage })));
const ProfilePage = lazy(() => import("./pages/Profile").then((module) => ({ default: module.ProfilePage })));
const NotFoundPage = lazy(() => import("./pages/NotFound").then((module) => ({ default: module.NotFoundPage })));

function Splash() {
  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 14 }}>
      <div className="brand-mark" style={{ width: 46, height: 46, color: "var(--accent)" }}>
        <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
          <path d="M24 3 6 9v13c0 12.2 7.6 19.8 18 23 10.4-3.2 18-10.8 18-23V9L24 3Z" stroke="currentColor" strokeWidth="2.2" />
          <path d="m17.5 23.5 4.4 4.4 8.8-9" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
      <span className="mono" style={{ fontSize: 10, letterSpacing: "0.24em", color: "var(--dim)" }}>ESTABLECIENDO SESIÓN SEGURA</span>
    </div>
  );
}

function Protected({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();
  if (status === "loading") return <Splash />;
  if (status === "anonymous") return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled UI error", error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
          <div className="card card-pad" style={{ maxWidth: 480, textAlign: "center" }}>
            <ShieldAlert size={28} style={{ color: "var(--danger)", margin: "8px auto 12px" }} />
            <h2 style={{ fontSize: 17, marginBottom: 6 }}>Se ha producido un error en la interfaz</h2>
            <p className="muted" style={{ fontSize: 12.5, marginBottom: 16 }}>
              La sesión y la telemetría no se ven afectadas. Recarga para restablecer la vista.
            </p>
            <Button variant="primary" onClick={() => window.location.reload()}>Recargar</Button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

export function App() {
  return (
    <ErrorBoundary>
      <Suspense fallback={<PageSkeleton />}>
        <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          element={
            <Protected>
              <AppShell />
            </Protected>
          }
        >
          <Route index element={<ExecutiveOverviewPage />} />
          <Route path="soc" element={<SocPage />} />
          <Route path="monitoring" element={<MonitoringPage />} />
          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
          <Route path="threat-intel" element={<ThreatIntelPage />} />
          <Route path="siem" element={<SiemPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="assets/:assetId" element={<AssetDetailPage />} />
          <Route path="attack-surface" element={<AttackSurfacePage />} />
          <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="soar" element={<SoarPage />} />
          <Route path="playbook-designer" element={<PlaybookDesignerPage />} />
          <Route path="playbook-designer/:playbookId" element={<PlaybookDesignerPage />} />
          <Route path="agents" element={<AgentsPage />} />
          <Route path="iot-ot" element={<IotOtPage />} />
          <Route path="network" element={<NetworkPage />} />
          <Route path="cloud" element={<CloudPage />} />
          <Route path="identity" element={<IdentityPage />} />
          <Route path="forensics" element={<ForensicsPage />} />
          <Route path="compliance" element={<CompliancePage />} />
          <Route path="integrations" element={<IntegrationsPage />} />
          <Route path="models" element={<ModelsPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="organizations" element={<OrganizationsPage />} />
          <Route path="admin" element={<AdminPage />} />
          <Route path="profile" element={<ProfilePage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}
