import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Component, type ErrorInfo, type ReactNode } from "react";
import { ShieldAlert } from "lucide-react";
import { useAuth } from "./lib/auth";
import { AppShell } from "./components/layout/AppShell";
import { Button } from "./components/ui";
import { LoginPage } from "./pages/Login";
import { ExecutiveOverviewPage } from "./pages/ExecutiveOverview";
import { SocPage } from "./pages/Soc";
import { NotFoundPage } from "./pages/NotFound";

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
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </ErrorBoundary>
  );
}
