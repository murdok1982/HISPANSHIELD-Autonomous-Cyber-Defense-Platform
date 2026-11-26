import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, ApiError, errorMessage, getActiveOrg, setActiveOrg } from "./api";

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  status: string;
  is_platform_admin: boolean;
  mfa_enabled: boolean;
  locale: string;
  timezone: string;
  last_login_at: string | null;
  created_at: string;
}

export interface OrganizationSummary {
  id: string;
  slug: string;
  name: string;
  kind: string;
  is_demo?: boolean;
  role: string | null;
}

export interface Session {
  user: UserProfile;
  organization: OrganizationSummary;
  role: string;
  permissions: string[];
  organizations: OrganizationSummary[];
  csrf_token: string;
  autonomy_level: string;
  expires_at: string;
}

interface LoginResult {
  mfaRequired: boolean;
  challengeToken?: string;
}

interface AuthContextValue {
  session: Session | null;
  status: "loading" | "authenticated" | "anonymous";
  error: string | null;
  login: (email: string, password: string, orgSlug?: string) => Promise<LoginResult>;
  verifyMfa: (challengeToken: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  switchOrganization: (orgId: string, reason?: string) => Promise<void>;
  refresh: () => Promise<void>;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function storeOrg(session: Session): void {
  setActiveOrg(session.organization.id);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [status, setStatus] = useState<"loading" | "authenticated" | "anonymous">("loading");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const current = await api.get<Session>("/auth/me");
      setSession(current);
      storeOrg(current);
      setStatus("authenticated");
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setSession(null);
        setStatus("anonymous");
      } else {
        setError(errorMessage(err));
        setStatus((prev) => (prev === "authenticated" ? prev : "anonymous"));
      }
    }
  }, []);

  useEffect(() => {
    if (window.location.pathname === "/login") {
      setStatus("anonymous");
      return;
    }
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const onUnauthorized = () => {
      setSession(null);
      setStatus("anonymous");
      setActiveOrg(null);
    };
    window.addEventListener("hs:unauthorized", onUnauthorized);
    return () => window.removeEventListener("hs:unauthorized", onUnauthorized);
  }, []);

  const login = useCallback(async (email: string, password: string, orgSlug?: string): Promise<LoginResult> => {
    setError(null);
    const result = await api.post<Session | { mfa_required: true; challenge_token: string }>("/auth/login", {
      email,
      password,
      ...(orgSlug ? { org_slug: orgSlug } : {}),
    });
    if ("mfa_required" in result) {
      return { mfaRequired: true, challengeToken: result.challenge_token };
    }
    setSession(result);
    storeOrg(result);
    setStatus("authenticated");
    return { mfaRequired: false };
  }, []);

  const verifyMfa = useCallback(async (challengeToken: string, code: string) => {
    const result = await api.post<Session>("/auth/mfa/verify", { challenge_token: challengeToken, code });
    setSession(result);
    storeOrg(result);
    setStatus("authenticated");
    setError(null);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      /* the local session is cleared regardless of server reachability */
    }
    setSession(null);
    setStatus("anonymous");
    setActiveOrg(null);
  }, []);

  const switchOrganization = useCallback(async (orgId: string, reason?: string) => {
    const result = await api.post<Session>("/auth/switch-org", {
      org_id: orgId,
      ...(reason ? { reason } : {}),
    });
    setSession(result);
    storeOrg(result);
    // Reload so all cached queries are re-scoped to the new tenant.
    window.location.assign("/");
  }, []);

  const can = useCallback(
    (permission: string) => {
      if (!session) return false;
      if (session.permissions.includes("*")) return true;
      return session.permissions.some(
        (granted) =>
          granted === permission ||
          (granted.endsWith(":*") && permission.startsWith(granted.slice(0, -1))),
      );
    },
    [session],
  );

  const value = useMemo<AuthContextValue>(
    () => ({ session, status, error, login, verifyMfa, logout, switchOrganization, refresh, can }),
    [session, status, error, login, verifyMfa, logout, switchOrganization, refresh, can],
  );

  return createElement(AuthContext.Provider, { value }, children);
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}

export function usePermission(permission: string): boolean {
  return useAuth().can(permission);
}

export { getActiveOrg };
