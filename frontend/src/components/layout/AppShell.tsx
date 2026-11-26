import { useEffect, useMemo, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Bell,
  ChevronDown,
  Languages,
  LogOut,
  Menu,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  ShieldCheck,
  ShieldOff,
  Sun,
  UserRound,
} from "lucide-react";
import clsx from "clsx";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { useI18n } from "../../lib/i18n";
import { relativeTime } from "../../lib/format";
import { Badge } from "../ui";
import { CommandPalette } from "./CommandPalette";
import { ALL_NAV_ITEMS, NAV_GROUPS } from "./navigation";

interface NotificationItem {
  id: string;
  kind: string;
  title: string;
  body: string | null;
  read_at: string | null;
  created_at: string;
}

interface KillSwitchItem {
  id: string;
  scope: string;
  engaged: boolean;
  reason: string;
}

function BrandMark({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <path d="M24 3 6 9v13c0 12.2 7.6 19.8 18 23 10.4-3.2 18-10.8 18-23V9L24 3Z" stroke="currentColor" strokeWidth="2.2" />
      <path d="M24 10.5 12.5 14.4v7.4c0 8.4 4.8 13.7 11.5 16.3 6.7-2.6 11.5-7.9 11.5-16.3v-7.4L24 10.5Z" fill="currentColor" fillOpacity="0.08" stroke="currentColor" strokeWidth="1.2" />
      <path d="m17.5 23.5 4.4 4.4 8.8-9" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function AppShell() {
  const { t, lang, setLang } = useI18n();
  const { session, can, logout, switchOrganization } = useAuth();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const [theme, setTheme] = useState(() => {
    try {
      return window.localStorage.getItem("hs.theme") ?? "dark";
    } catch {
      return "dark";
    }
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem("hs.theme", theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((current) => !current);
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    setMobileOpen(false);
    setNotificationsOpen(false);
    setUserOpen(false);
  }, [location.pathname]);

  const currentItem = useMemo(() => {
    const sorted = [...ALL_NAV_ITEMS].sort((a, b) => b.path.length - a.path.length);
    return sorted.find((item) => (item.path === "/" ? location.pathname === "/" : location.pathname.startsWith(item.path)));
  }, [location.pathname]);
  const currentGroup = useMemo(
    () => NAV_GROUPS.find((group) => group.items.some((item) => item.key === currentItem?.key)),
    [currentItem],
  );

  const notificationsQuery = useQuery({
    queryKey: ["notifications"],
    queryFn: () => api.get<NotificationItem[]>("/overview/notifications"),
    enabled: Boolean(session),
    refetchInterval: 60_000,
  });
  const unread = (notificationsQuery.data ?? []).filter((item) => !item.read_at).length;

  const killSwitchQuery = useQuery({
    queryKey: ["kill-switches-shell"],
    queryFn: () => api.get<KillSwitchItem[]>("/organizations/current/kill-switches"),
    enabled: Boolean(session) && can("defence:read"),
    refetchInterval: 30_000,
  });
  const killSwitchEngaged = (killSwitchQuery.data ?? []).some((item) => item.engaged);

  return (
    <div className="app-shell" data-collapsed={collapsed} data-mobile-open={mobileOpen}>
      <a className="skip-link" href="#main-content">Saltar al contenido</a>
      <aside className="sidebar" aria-label="Navegación principal">
        <div className="sidebar-brand">
          <Link to="/" aria-label="HISPANSHIELD home" style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <BrandMark className="brand-mark" />
            <span className="brand-text">
              <strong>HISPANSHIELD</strong>
              <span>Cyber Defence Command</span>
            </span>
          </Link>
          <button
            type="button"
            className="icon-btn hide-mobile"
            onClick={() => setCollapsed((value) => !value)}
            aria-label={collapsed ? "Expandir navegación" : "Colapsar navegación"}
            style={{ marginLeft: "auto" }}
          >
            {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>
        </div>
        <nav className="sidebar-scroll">
          {NAV_GROUPS.map((group) => {
            const items = group.items.filter((item) => can(item.permission));
            if (!items.length) return null;
            return (
              <div className="nav-group" key={group.key}>
                <div className="nav-group-label">{t(group.labelKey)}</div>
                {items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <NavLink
                      key={item.key}
                      to={item.path}
                      end={item.path === "/"}
                      className={({ isActive }) => clsx("nav-item", isActive && "active")}
                      title={t(item.labelKey)}
                    >
                      <Icon size={16} />
                      <span className="nav-label">{t(item.labelKey)}</span>
                    </NavLink>
                  );
                })}
              </div>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="row-between">
            <span className="row" style={{ gap: 6 }}>
              <ShieldCheck size={13} style={{ color: "var(--success)" }} />
              <span className="footer-text mono">v0.1.0</span>
            </span>
            <span className="footer-text mono">{session?.autonomy_level ?? "A1"}</span>
          </div>
          <div className="footer-text" style={{ lineHeight: 1.5 }}>
            Zero Trust · EU hosting
            <br />
            IA local · Audit chain
          </div>
        </div>
      </aside>

      {mobileOpen ? <div className="mobile-scrim" onClick={() => setMobileOpen(false)} aria-hidden="true" /> : null}

      <div className="main-col">
        <header className="topbar">
          <button type="button" className="icon-btn hide-desktop" onClick={() => setMobileOpen(true)} aria-label="Abrir menú">
            <Menu size={18} />
          </button>
          <div className="topbar-crumbs">
            <span className="hide-mobile">{currentGroup ? t(currentGroup.labelKey) : "HISPANSHIELD"}</span>
            <span className="hide-mobile dim">/</span>
            <strong>{currentItem ? t(currentItem.labelKey) : "HISPANSHIELD"}</strong>
          </div>

          <button type="button" className="command-trigger" onClick={() => setPaletteOpen(true)} aria-label={t("common.search")}>
            <Search size={14} />
            <span className="command-label">{t("common.search")}</span>
            <kbd>⌘K</kbd>
          </button>

          <div className="topbar-spacer" />

          <div className="org-switcher hide-mobile" title={session?.organization.name}>
            <span className="org-name">{session?.organization.name}</span>
            <ChevronDown size={13} style={{ color: "var(--dim)" }} />
            <select
              aria-label="Organización activa"
              value={session?.organization.id ?? ""}
              onChange={(event) => { if (event.target.value) void switchOrganization(event.target.value); }}
            >
              {(session?.organizations ?? []).map((org) => (
                <option key={org.id} value={org.id}>{org.name}</option>
              ))}
            </select>
          </div>

          {session?.organization.is_demo ? (
            <Badge tone="amber" className="hide-mobile">DEMO</Badge>
          ) : null}
          {killSwitchEngaged ? (
            <Badge tone="danger" className="hide-mobile">
              <ShieldOff size={11} /> KILL SWITCH
            </Badge>
          ) : (
            <Badge tone="accent" className="hide-mobile">
              AUTONOMÍA {session?.autonomy_level ?? "A1"}
            </Badge>
          )}

          <button type="button" className="icon-btn" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={t("common.theme")}>
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <button
            type="button"
            className="icon-btn"
            onClick={() => setLang(lang === "es" ? "en" : "es")}
            aria-label={`${t("common.language")}: ${lang === "es" ? "English" : "Español"}`}
          >
            <Languages size={16} />
          </button>

          <div style={{ position: "relative" }}>
            <button
              type="button"
              className="icon-btn"
              onClick={() => { setNotificationsOpen((value) => !value); setUserOpen(false); }}
              aria-label={t("common.notifications")}
              aria-expanded={notificationsOpen}
            >
              <Bell size={16} />
              {unread > 0 ? <span className="dot" /> : null}
            </button>
            {notificationsOpen ? (
              <div className="card dropdown-panel" style={{ width: 340 }}>
                <div className="card-head">
                  <h3>{t("common.notifications")}</h3>
                  <span className="badge badge-neutral" style={{ marginLeft: "auto" }}>{unread}</span>
                </div>
                <div style={{ maxHeight: 360, overflowY: "auto", padding: "4px 14px" }}>
                  {(notificationsQuery.data ?? []).length === 0 ? (
                    <div style={{ padding: 20, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>{t("common.noNotifications")}</div>
                  ) : (
                    (notificationsQuery.data ?? []).map((item) => (
                      <div className="list-item" key={item.id}>
                        <div>
                          <div className="item-title">{item.title}</div>
                          {item.body ? <div className="item-sub">{item.body}</div> : null}
                          <div className="item-sub mono">{relativeTime(item.created_at, lang)}</div>
                        </div>
                        {!item.read_at ? <span className="dot-static" aria-label="Unread" /> : null}
                      </div>
                    ))
                  )}
                </div>
              </div>
            ) : null}
          </div>

          <div style={{ position: "relative" }}>
            <button
              type="button"
              className="row"
              style={{ background: "transparent", border: 0, gap: 8 }}
              onClick={() => { setUserOpen((value) => !value); setNotificationsOpen(false); }}
              aria-expanded={userOpen}
              aria-label="Menú de usuario"
            >
              <span className="avatar">{(session?.user.full_name ?? "HS").split(/\s+/).map((part) => part[0]).slice(0, 2).join("")}</span>
              <ChevronDown size={13} style={{ color: "var(--dim)" }} className="hide-mobile" />
            </button>
            {userOpen ? (
              <div className="card dropdown-panel" style={{ width: 260 }}>
                <div className="card-pad" style={{ borderBottom: "1px solid var(--border)" }}>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{session?.user.full_name}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--dim)", marginTop: 3 }}>{session?.user.email}</div>
                  <div className="row" style={{ marginTop: 8, gap: 6 }}>
                    <Badge tone="neutral">{session?.role}</Badge>
                    {session?.user.mfa_enabled ? <Badge tone="success">MFA</Badge> : <Badge tone="warning">SIN MFA</Badge>}
                  </div>
                </div>
                <div style={{ padding: 6 }}>
                  <Link to="/profile" className="palette-item" style={{ color: "var(--muted)" }}>
                    <UserRound size={14} /> {t("common.profile")}
                  </Link>
                  <button
                    type="button"
                    className="palette-item"
                    style={{ color: "var(--danger)" }}
                    onClick={() => void logout().then(() => window.location.assign("/login"))}
                  >
                    <LogOut size={14} /> {t("common.signOut")}
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </header>
        <main className="content" id="main-content">
          <Outlet />
        </main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}

export { BrandMark };
