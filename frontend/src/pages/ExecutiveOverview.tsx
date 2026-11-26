import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertOctagon,
  ArrowUpRight,
  Crosshair,
  Gauge,
  Radar,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Siren,
  TriangleAlert,
} from "lucide-react";
import { api } from "../lib/api";
import { useI18n } from "../lib/i18n";
import { durationMinutes, formatCompact, formatDateTime, formatNumber, humanize, relativeTime, severityRank } from "../lib/format";
import {
  AreaChart,
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
  Kpi,
  LinkButton,
  PageHeader,
  PageSkeleton,
  ScoreRing,
  SeverityBadge,
  SeverityBars,
  StatusBadge,
  StatusDot,
  type Column,
} from "../components/ui";
import { useAuth } from "../lib/auth";

interface TrendPoint {
  timestamp: string;
  value: number;
}

interface IncidentSummary {
  id: string;
  ref: string;
  title: string;
  severity: string;
  status: string;
  detected_at: string;
}

interface Overview {
  generated_at: string;
  organization: { id: string; name: string; autonomy_level: string };
  risk: {
    score: number;
    level: string;
    factors: { factor: string; points: number }[];
  };
  totals: {
    assets: number;
    assets_by_kind: Record<string, number>;
    open_alerts: number;
    open_alerts_by_severity: Record<string, number>;
    open_incidents: number;
    open_incidents_by_severity: Record<string, number>;
    open_vulnerabilities: number;
    open_vulnerabilities_by_severity: Record<string, number>;
    known_exploited: number;
    events_24h: number;
    active_indicators: number;
    connectors: Record<string, number>;
    kill_switch_engaged: boolean;
  };
  mttr_minutes: number | null;
  trends: {
    events_24h: TrendPoint[];
    alerts_7d: TrendPoint[];
    incidents_7d: TrendPoint[];
  };
  recent_incidents: IncidentSummary[];
  top_vulnerable_assets: { id: string; name: string; kind: string; criticality: number; open_vulnerabilities: number }[];
  connectors: { id: string; name: string; type: string; status: string; last_health_at: string | null }[];
  data_classification: string;
}

function riskFactorLabel(factor: string, lang: string): string {
  const labels: Record<string, { es: string; en: string }> = {
    critical_incidents: { es: "Incidentes críticos", en: "Critical incidents" },
    high_incidents: { es: "Incidentes altos", en: "High incidents" },
    critical_vulnerabilities: { es: "Vulnerabilidades críticas", en: "Critical vulnerabilities" },
    known_exploited_vulnerabilities: { es: "Vulnerabilidades explotadas (KEV)", en: "Known exploited (KEV)" },
    exposed_attack_surface: { es: "Superficie expuesta", en: "Exposed attack surface" },
    degraded_connectors: { es: "Conectores degradados", en: "Degraded connectors" },
    kill_switch_engaged: { es: "Kill switch activo", en: "Kill switch engaged" },
  };
  const entry = labels[factor];
  if (!entry) return humanize(factor);
  return lang === "es" ? entry.es : entry.en;
}

const riskTone: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--danger)",
  medium: "var(--warning)",
  low: "var(--success)",
};

export function ExecutiveOverviewPage() {
  const { t, lang } = useI18n();
  const { session } = useAuth();
  const query = useQuery({
    queryKey: ["overview", "executive"],
    queryFn: () => api.get<Overview>("/overview/executive"),
    refetchInterval: 30_000,
  });

  if (query.isLoading) return <PageSkeleton />;
  if (query.isError || !query.data) {
    return (
      <div>
        <PageHeader eyebrow={t("nav.group.command")} title={t("overview.title")} subtitle={t("overview.subtitle")} />
        <ErrorBanner message={t("errors.retryHint")} onRetry={() => void query.refetch()} />
      </div>
    );
  }

  const data = query.data;
  const alertsBySeverity = Object.entries(data.totals.open_alerts_by_severity);
  const incidentsBySeverity = Object.entries(data.totals.open_incidents_by_severity);
  const vulnsBySeverity = Object.entries(data.totals.open_vulnerabilities_by_severity);
  const connectorEntries = Object.entries(data.totals.connectors);
  const healthy = data.connectors.filter((connector) => connector.status === "healthy").length;

  const columns: Column<IncidentSummary>[] = [
    {
      key: "title",
      header: "Incidente",
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div className="mono" style={{ color: "var(--accent)", fontSize: 10, marginBottom: 2 }}>{row.ref}</div>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.title}</div>
        </div>
      ),
    },
    { key: "severity", header: "Severidad", width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: "Estado", width: "128px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "detected",
      header: "Detección",
      width: "135px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11, color: "var(--muted)" }}>{relativeTime(row.detected_at, lang)}</span>,
    },
  ];

  const sortedIncidents = [...data.recent_incidents].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  return (
    <div className="animate-in" data-testid="page-overview">
      <PageHeader
        eyebrow={`${t("nav.group.command")} · ${data.organization.name}`}
        title={t("overview.title")}
        subtitle={t("overview.subtitle")}
        actions={
          <>
            <span className="live-dot" style={data.data_classification === "demo" ? { color: "var(--amber)" } : undefined}>
              {data.data_classification === "demo" ? "DEMO" : t("common.operational")}
            </span>
            <Badge tone="accent">AUTONOMÍA {data.organization.autonomy_level}</Badge>
            <Button icon={RefreshCw} onClick={() => void query.refetch()} aria-label={t("common.refresh")} />
            <LinkButton to="/soc" variant="primary" icon={Radar}>{t("overview.goToSoc")}</LinkButton>
          </>
        }
      />

      {data.data_classification === "demo" ? <div className="demo-banner" style={{ marginBottom: 12 }}>{t("common.demoData")} · seeded lab dataset</div> : null}

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi
          label={t("overview.openIncidents")}
          value={formatNumber(data.totals.open_incidents)}
          icon={Siren}
          tone={data.totals.open_incidents_by_severity.critical ? "danger" : "warning"}
          footer={
            <span>
              {formatNumber(data.totals.open_incidents_by_severity.critical ?? 0)} {t("common.critical").toLowerCase()} ·{" "}
              {formatNumber(data.totals.open_incidents_by_severity.high ?? 0)} {t("common.high").toLowerCase()}
            </span>
          }
        />
        <Kpi
          label={t("overview.openAlerts")}
          value={formatNumber(data.totals.open_alerts)}
          icon={ShieldAlert}
          tone="danger"
          footer={<span>{alertsBySeverity.length ? alertsBySeverity.map(([key, value]) => `${humanize(key)} ${value}`).join(" · ") : t("soc.noAlerts")}</span>}
        />
        <Kpi
          label={t("overview.openVulns")}
          value={formatNumber(data.totals.open_vulnerabilities)}
          icon={TriangleAlert}
          tone="warning"
          footer={<span>{formatNumber(data.totals.known_exploited)} KEV · {formatNumber(data.totals.active_indicators)} IOCs</span>}
        />
        <Kpi
          label={t("overview.events24h")}
          value={formatCompact(data.totals.events_24h)}
          icon={Activity}
          tone="accent"
          footer={<span>{formatNumber(data.totals.assets)} activos · {formatNumber(healthy)}/{formatNumber(data.connectors.length)} conectores</span>}
        />
      </div>

      <div className="split-main" style={{ marginBottom: 12 }}>
        <Card
          title={t("overview.riskScore")}
          subtitle={humanize(data.risk.level)}
          actions={<Badge tone={data.risk.level === "critical" ? "critical" : data.risk.level === "high" ? "danger" : data.risk.level === "medium" ? "warning" : "success"}>{data.risk.level}</Badge>}
        >
          <div className="row wrap" style={{ gap: 24, alignItems: "flex-start" }}>
            <ScoreRing score={data.risk.score} label={t("overview.riskScore")} tone={riskTone[data.risk.level]} />
            <div style={{ flex: 1, minWidth: 220 }}>
              <div className="section-label">{t("overview.riskFactors")}</div>
              {data.risk.factors.length === 0 ? (
                <div className="notice notice-accent">Sin factores de riesgo activos</div>
              ) : (
                <div className="metric-list">
                  {data.risk.factors.map((factor) => (
                    <div className="metric-row" key={factor.factor}>
                      <span className="metric-label">{riskFactorLabel(factor.factor, lang)}</span>
                      <span className="metric-value">+{factor.points}</span>
                    </div>
                  ))}
                </div>
              )}
              <div className="divider" />
              <div className="stat-inline">
                <div>
                  <span className="label">MTTR</span>
                  <span className="value">{durationMinutes(data.mttr_minutes)}</span>
                </div>
                <div>
                  <span className="label">{t("overview.assets")}</span>
                  <span className="value">{formatNumber(data.totals.assets)}</span>
                </div>
                <div>
                  <span className="label">{t("overview.activeIndicators")}</span>
                  <span className="value">{formatNumber(data.totals.active_indicators)}</span>
                </div>
              </div>
            </div>
          </div>
        </Card>

        <Card title={t("overview.eventVolume")} subtitle="24 h" actions={<span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{formatDateTime(data.generated_at, lang)}</span>}>
          {data.trends.events_24h.some((point) => point.value > 0) ? (
            <AreaChart data={data.trends.events_24h} height={186} />
          ) : (
            <EmptyState icon={Activity} title={t("overview.emptyEvents")} description={t("soc.noEventsHint")} action={<LinkButton to="/integrations" size="sm">Ir a integraciones</LinkButton>} />
          )}
          <div className="row-between" style={{ marginTop: 10, fontSize: 11, color: "var(--dim)" }}>
            <span>{t("overview.knownExploited")}: <b className="mono" style={{ color: data.totals.known_exploited ? "var(--danger)" : "var(--success)" }}>{data.totals.known_exploited}</b></span>
            <span>{t("overview.autonomyLevel")}: <b className="mono" style={{ color: "var(--accent)" }}>{data.organization.autonomy_level}</b></span>
          </div>
        </Card>
      </div>

      <div className="grid-3" style={{ marginBottom: 12 }}>
        <Card title={t("overview.severitySplit")} subtitle="Incidentes">
          {incidentsBySeverity.length ? (
            <SeverityBars
              data={["critical", "high", "medium", "low"].map((severity) => ({
                label: t(`common.${severity}`),
                value: data.totals.open_incidents_by_severity[severity] ?? 0,
                color: severity === "critical" ? "var(--critical)" : severity === "high" ? "var(--danger)" : severity === "medium" ? "var(--warning)" : "var(--accent)",
              }))}
            />
          ) : (
            <EmptyState icon={ShieldCheck} title={t("overview.noIncidents")} description={t("overview.noIncidentsHint")} />
          )}
        </Card>
        <Card title={t("overview.severitySplit")} subtitle="Alertas">
          {alertsBySeverity.length ? (
            <SeverityBars
              data={["critical", "high", "medium", "low"].map((severity) => ({
                label: t(`common.${severity}`),
                value: data.totals.open_alerts_by_severity[severity] ?? 0,
                color: severity === "critical" ? "var(--critical)" : severity === "high" ? "var(--danger)" : severity === "medium" ? "var(--warning)" : "var(--accent)",
              }))}
            />
          ) : (
            <EmptyState icon={ShieldCheck} title={t("soc.noAlerts")} />
          )}
        </Card>
        <Card title={t("overview.severitySplit")} subtitle="Vulnerabilidades">
          {vulnsBySeverity.length ? (
            <SeverityBars
              data={["critical", "high", "medium", "low"].map((severity) => ({
                label: t(`common.${severity}`),
                value: data.totals.open_vulnerabilities_by_severity[severity] ?? 0,
                color: severity === "critical" ? "var(--critical)" : severity === "high" ? "var(--danger)" : severity === "medium" ? "var(--warning)" : "var(--accent)",
              }))}
            />
          ) : (
            <EmptyState icon={ShieldCheck} title="Sin vulnerabilidades abiertas" />
          )}
        </Card>
      </div>

      <div className="split-main" style={{ marginBottom: 12 }}>
        <Card
          title={t("overview.recentIncidents")}
          actions={<Link to="/incidents" style={{ fontSize: 11 }}>{t("common.seeAll")} <ArrowUpRight size={11} /></Link>}
          bodyClassName=""
        >
          <DataTable
            columns={columns}
            rows={sortedIncidents}
            rowKey={(row) => row.id}
            empty={<EmptyState icon={ShieldCheck} title={t("overview.noIncidents")} description={t("overview.noIncidentsHint")} />}
          />
        </Card>

        <div className="stack">
          <Card title={t("overview.connectorHealth")} actions={<Link to="/integrations" style={{ fontSize: 11 }}>{t("common.seeAll")}</Link>}>
            {connectorEntries.length === 0 ? (
              <EmptyState icon={Crosshair} title="Sin integraciones" description="Conecta SIEM, EDR, IAM o fuentes de inteligencia." action={<LinkButton to="/integrations" size="sm">Configurar</LinkButton>} />
            ) : (
              <div className="metric-list">
                {connectorEntries.map(([status, count]) => (
                  <div className="metric-row" key={status}>
                    <span className="metric-label"><StatusDot status={status} /> {humanize(status)}</span>
                    <span className="metric-value">{count}</span>
                  </div>
                ))}
                {data.connectors.slice(0, 5).map((connector) => (
                  <div className="metric-row" key={connector.id}>
                    <span className="metric-label" style={{ color: "var(--text-secondary)" }}>
                      <StatusDot status={connector.status} /> {connector.name}
                    </span>
                    <span className="metric-value" style={{ fontSize: 10 }}>{connector.type}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title={t("overview.topAssets")}>
            {data.top_vulnerable_assets.length === 0 ? (
              <EmptyState icon={ShieldCheck} title="Sin exposición prioritaria" />
            ) : (
              <div className="metric-list">
                {data.top_vulnerable_assets.map((asset) => (
                  <Link to={`/assets/${asset.id}`} key={asset.id} className="metric-row" style={{ textDecoration: "none", color: "inherit" }}>
                    <span className="metric-label" style={{ color: "var(--text-secondary)" }}>
                      {asset.name}
                      <span className="tag">{humanize(asset.kind)}</span>
                    </span>
                    <span className="metric-value" style={{ color: asset.open_vulnerabilities > 4 ? "var(--danger)" : "var(--warning)" }}>
                      {asset.open_vulnerabilities} vulns
                    </span>
                  </Link>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      <div className="notice" style={{ fontSize: 11 }}>
        <Gauge size={14} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
        <span>
          {t("common.lastUpdated", { time: relativeTime(data.generated_at, lang) })} ·{" "}
          {t("overview.riskScore")}: {data.risk.score}/100 · {t("overview.autonomyLevel")} {session?.autonomy_level ?? data.organization.autonomy_level}
        </span>
        <AlertOctagon size={13} style={{ marginLeft: "auto", color: "var(--dim)" }} />
      </div>
    </div>
  );
}
