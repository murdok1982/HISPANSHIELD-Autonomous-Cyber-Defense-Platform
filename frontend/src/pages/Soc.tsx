import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowUpRight,
  BellRing,
  Filter,
  Pause,
  Play,
  Radar,
  RefreshCw,
  ShieldCheck,
  Siren,
  Terminal,
} from "lucide-react";
import { api } from "../lib/api";
import { useI18n } from "../lib/i18n";
import { formatDateTime, formatNumber, relativeTime } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
  Kpi,
  LinkButton,
  Modal,
  PageHeader,
  PageSkeleton,
  SeverityBadge,
  StatusBadge,
  type Column,
} from "../components/ui";

interface SecurityEvent {
  id: number;
  event_uid: string;
  occurred_at: string;
  severity_id: number;
  class_name: string;
  class_uid: number;
  message: string;
  src_ip: string | null;
  dst_ip: string | null;
  host_name: string | null;
  user_name: string | null;
  source_connector: string | null;
  mitre_techniques: string[];
  ioc_matches: { value?: string; type?: string }[];
  raw: Record<string, unknown>;
  normalized: Record<string, unknown>;
  raw_format: string;
}

interface Alert {
  id: string;
  title: string;
  severity: string;
  status: string;
  count: number;
  last_seen: string;
  mitre: string[];
  risk_score: number;
}

interface Incident {
  id: string;
  ref: string;
  title: string;
  severity: string;
  status: string;
  detected_at: string;
  assignee_id: string | null;
}

interface SocSnapshot {
  generated_at: string;
  events_last_hour: number;
  events_per_minute: number;
  recent_events: SecurityEvent[];
  new_alerts: Alert[];
  active_incidents: Incident[];
  data_classification: string;
}

const SEVERITY_BY_ID: Record<number, string> = { 5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info", 0: "info" };

export function SocPage() {
  const { t, lang } = useI18n();
  const [paused, setPaused] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const query = useQuery({
    queryKey: ["overview", "soc"],
    queryFn: () => api.get<SocSnapshot>("/overview/soc"),
    refetchInterval: paused ? false : 10_000,
  });

  if (query.isLoading) return <PageSkeleton />;
  if (query.isError || !query.data) {
    return (
      <div>
        <PageHeader eyebrow={t("nav.group.command")} title={t("soc.title")} subtitle={t("soc.subtitle")} />
        <ErrorBanner message={t("errors.retryHint")} onRetry={() => void query.refetch()} />
      </div>
    );
  }

  const data = query.data;
  const eventColumns: Column<SecurityEvent>[] = (([lang, t]: [string, (key: string) => string]) => [
      {
        key: "time",
        header: t("common.time"),
        width: "96px",
        render: (row) => <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)" }}>{formatDateTime(row.occurred_at, lang).split(", ").pop()}</span>,
      },
      {
        key: "severity",
        header: t("common.severity"),
        width: "104px",
        render: (row) => <SeverityBadge severity={SEVERITY_BY_ID[row.severity_id] ?? "info"} />,
      },
      {
        key: "event",
        header: "Evento",
        render: (row) => (
          <div style={{ minWidth: 0 }}>
            <div style={{ color: "var(--text)", fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 420 }}>{row.message}</div>
            <div className="mono" style={{ fontSize: 10, color: "var(--dim)", marginTop: 2 }}>
              {row.class_name} · {row.raw_format.toUpperCase()}
              {row.ioc_matches.length ? ` · IOC×${row.ioc_matches.length}` : ""}
            </div>
          </div>
        ),
      },
      {
        key: "host",
        header: "Origen",
        width: "180px",
        render: (row) => (
          <div className="mono" style={{ fontSize: 10.5 }}>
            <div style={{ color: "var(--text-secondary)" }}>{row.host_name ?? row.src_ip ?? "—"}</div>
            {row.src_ip && row.host_name ? <div style={{ color: "var(--dim)" }}>{row.src_ip}</div> : null}
          </div>
        ),
      },
  ])([lang, t]);

  return (
    <div className="animate-in" data-testid="page-soc">
      <PageHeader
        eyebrow={`${t("nav.group.command")} · live`}
        title={t("soc.title")}
        subtitle={t("soc.subtitle")}
        actions={
          <>
            <span className="live-dot" style={data.data_classification === "demo" ? { color: "var(--amber)" } : undefined}>
              {paused ? "PAUSED" : data.data_classification === "demo" ? "DEMO · LIVE" : "LIVE"}
            </span>
            <Button icon={paused ? Play : Pause} onClick={() => setPaused((value) => !value)}>
              {paused ? t("soc.resume") : t("soc.pause")}
            </Button>
            <Button icon={RefreshCw} onClick={() => void query.refetch()} aria-label={t("common.refresh")} />
            <LinkButton to="/monitoring" variant="primary" icon={Terminal}>{t("nav.monitoring")}</LinkButton>
          </>
        }
      />

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi label={t("soc.eventRate")} value={data.events_per_minute.toFixed(2)} suffix="/ min" icon={Activity} tone="accent" footer={<span>{formatNumber(data.events_last_hour)} {t("soc.eventsLastHour").toLowerCase()}</span>} />
        <Kpi label={t("soc.newAlerts")} value={formatNumber(data.new_alerts.length)} icon={BellRing} tone={data.new_alerts.some((alert) => alert.severity === "critical") ? "danger" : "warning"} footer={<span>{data.new_alerts.filter((alert) => alert.severity === "critical").length} críticas</span>} />
        <Kpi label={t("soc.activeIncidents")} value={formatNumber(data.active_incidents.length)} icon={Siren} tone="danger" footer={<span>{data.active_incidents.filter((incident) => incident.severity === "critical").length} críticos</span>} />
        <Kpi label={t("soc.eventsWithIoc")} value={formatNumber(data.recent_events.filter((event) => event.ioc_matches.length > 0).length)} icon={Radar} tone="warning" footer={<span>{t("soc.iocWindow")}</span>} />
      </div>

      <div className="split-main">
        <Card
          title={t("soc.liveFeed")}
          subtitle={`${data.recent_events.length} eventos`}
          actions={<Badge tone="neutral"><Filter size={10} /> últimas 24 h</Badge>}
          bodyClassName=""
          footer={
            <span className="row" style={{ gap: 6 }}>
              <ShieldCheck size={12} style={{ color: "var(--success)" }} />
              Telemetría normalizada OCSF · {formatDateTime(data.generated_at, lang)}
            </span>
          }
        >
          <DataTable
            columns={eventColumns}
            rows={data.recent_events}
            rowKey={(row) => String(row.id)}
            onRowClick={setSelectedEvent}
            empty={
              <EmptyState
                icon={Terminal}
                title={t("soc.noEvents")}
                description={t("soc.noEventsHint")}
                action={<LinkButton to="/integrations" size="sm" variant="primary">Conectar fuente</LinkButton>}
              />
            }
          />
        </Card>

        <div className="stack">
          <Card title={t("soc.newAlerts")} actions={<Link to="/siem" style={{ fontSize: 11 }}>{t("common.seeAll")}</Link>}>
            {data.new_alerts.length === 0 ? (
              <EmptyState icon={ShieldCheck} title={t("soc.noAlerts")} description={t("soc.noAlertsHint")} />
            ) : (
              <div>
                {data.new_alerts.slice(0, 7).map((alert) => (
                  <div className="list-item" key={alert.id}>
                    <div style={{ minWidth: 0 }}>
                      <div className="item-title" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{alert.title}</div>
                      <div className="item-sub">
                        {alert.count}× · {relativeTime(alert.last_seen, lang)} · riesgo {Math.round(alert.risk_score)}
                      </div>
                      <div className="chip-row" style={{ marginTop: 5 }}>
                        {alert.mitre.slice(0, 3).map((technique) => <span className="tag" key={technique}>{technique}</span>)}
                      </div>
                    </div>
                    <div className="item-side">
                      <SeverityBadge severity={alert.severity} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title={t("soc.activeIncidents")} actions={<Link to="/incidents" style={{ fontSize: 11 }}>{t("common.seeAll")} <ArrowUpRight size={11} /></Link>}>
            {data.active_incidents.length === 0 ? (
              <EmptyState icon={ShieldCheck} title={t("overview.noIncidents")} />
            ) : (
              <div>
                {data.active_incidents.slice(0, 6).map((incident) => (
                  <Link key={incident.id} to={`/incidents/${incident.id}`} className="list-item" style={{ textDecoration: "none", color: "inherit" }}>
                    <div style={{ minWidth: 0 }}>
                      <div className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{incident.ref}</div>
                      <div className="item-title" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{incident.title}</div>
                      <div className="item-sub">{relativeTime(incident.detected_at, lang)}</div>
                    </div>
                    <div className="item-side">
                      <SeverityBadge severity={incident.severity} />
                      <div style={{ marginTop: 4 }}><StatusBadge status={incident.status} /></div>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      <Modal open={selectedEvent !== null} onClose={() => setSelectedEvent(null)} title="Detalle del evento" size="lg">
        {selectedEvent ? (
          <div className="stack">
            <div className="row wrap">
              <SeverityBadge severity={SEVERITY_BY_ID[selectedEvent.severity_id] ?? "info"} />
              <Badge tone="neutral">{selectedEvent.class_name}</Badge>
              <Badge tone="neutral">{selectedEvent.raw_format.toUpperCase()}</Badge>
              <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{selectedEvent.event_uid}</span>
            </div>
            <div style={{ fontSize: 14, color: "var(--text)" }}>{selectedEvent.message}</div>
            <div className="grid-2">
              <div className="metric-list">
                <div className="metric-row"><span className="metric-label">Ocurrido</span><span className="metric-value">{formatDateTime(selectedEvent.occurred_at, lang)}</span></div>
                <div className="metric-row"><span className="metric-label">Origen</span><span className="metric-value">{selectedEvent.src_ip ?? "—"}</span></div>
                <div className="metric-row"><span className="metric-label">Destino</span><span className="metric-value">{selectedEvent.dst_ip ?? "—"}</span></div>
                <div className="metric-row"><span className="metric-label">Host</span><span className="metric-value">{selectedEvent.host_name ?? "—"}</span></div>
                <div className="metric-row"><span className="metric-label">Usuario</span><span className="metric-value">{selectedEvent.user_name ?? "—"}</span></div>
              </div>
              <div>
                <div className="section-label">MITRE ATT&CK</div>
                <div className="chip-row">{selectedEvent.mitre_techniques.length ? selectedEvent.mitre_techniques.map((technique) => <span className="tag" key={technique}>{technique}</span>) : <span className="dim" style={{ fontSize: 11 }}>Sin técnicas asociadas</span>}</div>
                <div className="section-label" style={{ marginTop: 12 }}>IOC</div>
                <div className="chip-row">{selectedEvent.ioc_matches.length ? selectedEvent.ioc_matches.map((match, index) => <span className="tag" key={index}>{match.value ?? match.type ?? "match"}</span>) : <span className="dim" style={{ fontSize: 11 }}>Sin coincidencias</span>}</div>
              </div>
            </div>
            <div>
              <div className="section-label">Evento normalizado (OCSF)</div>
              <pre className="code-block">{JSON.stringify(selectedEvent.normalized, null, 2)}</pre>
            </div>
            <div>
              <div className="section-label">Evento original</div>
              <pre className="code-block">{JSON.stringify(selectedEvent.raw, null, 2)}</pre>
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

export default SocPage;
