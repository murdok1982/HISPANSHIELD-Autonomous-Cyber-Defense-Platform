import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, Command } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { useI18n } from "../../lib/i18n";
import { ALL_NAV_ITEMS } from "./navigation";
import { Badge } from "../ui";

interface SearchResult {
  type: string;
  id: string;
  title: string;
  subtitle: string | null;
  severity: string | null;
}

const TYPE_ROUTE: Record<string, string> = {
  incident: "/incidents",
  asset: "/assets",
  indicator: "/threat-intel",
  alert: "/soc",
  connector: "/integrations",
};

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n();
  const { can } = useAuth();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const navMatches = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return ALL_NAV_ITEMS.filter((item) => can(item.permission)).filter((item) => {
      if (!normalized) return true;
      return t(item.labelKey).toLowerCase().includes(normalized);
    }).slice(0, 5);
  }, [query, can, t]);

  const { data } = useQuery({
    queryKey: ["global-search", query],
    queryFn: () => api.get<{ results: SearchResult[] }>("/overview/search", { q: query }),
    enabled: open && query.trim().length >= 2 && can("org:read"),
    staleTime: 5000,
  });
  const results = data?.results ?? [];
  const options = useMemo(
    () => [
      ...navMatches.map((item) => ({ kind: "nav" as const, label: t(item.labelKey), sub: item.path, go: () => navigate(item.path) })),
      ...results.map((result) => ({
        kind: result.type as string,
        label: result.title,
        sub: result.subtitle ?? result.type,
        severity: result.severity,
        go: () => navigate(`${TYPE_ROUTE[result.type] ?? "/"}${result.type === "incident" ? `/${result.id}` : ""}`),
      })),
    ],
    [navMatches, results, navigate, t],
  );

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setActive(0);
    window.setTimeout(() => inputRef.current?.focus(), 20);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key === "ArrowDown") {
        event.preventDefault();
        setActive((current) => Math.min(options.length - 1, current + 1));
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        setActive((current) => Math.max(0, current - 1));
      }
      if (event.key === "Enter" && options[active]) {
        event.preventDefault();
        options[active].go();
        onClose();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open, options, active, onClose]);

  if (!open) return null;
  return (
    <div className="overlay" style={{ paddingTop: "10vh" }} onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <div className="palette" role="dialog" aria-modal="true" aria-label={t("common.search")}>
        <div className="row" style={{ borderBottom: "1px solid var(--border)" }}>
          <Command size={16} style={{ marginLeft: 16, color: "var(--dim)" }} />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => { setQuery(event.target.value); setActive(0); }}
            placeholder={t("common.search")}
            aria-label={t("common.search")}
          />
          <kbd style={{ marginRight: 14 }}>ESC</kbd>
        </div>
        <div className="palette-results">
          {navMatches.length > 0 ? <div className="palette-group">{t("common.searchShort")}</div> : null}
          {navMatches.map((item, index) => {
            const Icon = item.icon;
            return (
              <button
                key={item.key}
                type="button"
                className={`palette-item${active === index ? " active" : ""}`}
                onMouseEnter={() => setActive(index)}
                onClick={() => { navigate(item.path); onClose(); }}
              >
                <Icon size={14} />
                {t(item.labelKey)}
                <span className="type">{item.path}</span>
              </button>
            );
          })}
          {results.length > 0 ? <div className="palette-group">Telemetría</div> : null}
          {results.map((result, index) => {
            const optionIndex = navMatches.length + index;
            return (
              <button
                key={`${result.type}-${result.id}`}
                type="button"
                className={`palette-item${active === optionIndex ? " active" : ""}`}
                onMouseEnter={() => setActive(optionIndex)}
                onClick={() => { options[optionIndex]?.go(); onClose(); }}
              >
                <ArrowRight size={13} style={{ color: "var(--dim)" }} />
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{result.title}</span>
                {result.severity ? <Badge tone={result.severity === "critical" ? "critical" : result.severity === "high" ? "danger" : "neutral"}>{result.severity}</Badge> : null}
                <span className="type">{result.type}</span>
              </button>
            );
          })}
          {query.length >= 2 && results.length === 0 && navMatches.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>{t("common.noData")}</div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
