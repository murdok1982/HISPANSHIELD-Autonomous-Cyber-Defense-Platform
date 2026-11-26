import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Database,
  Download,
  Filter,
  Pause,
  Play,
  Radar,
  RefreshCw,
  Server,
  ShieldAlert,
  Terminal,
  Waves,
} from "lucide-react";
import { api, errorMessage, type Page } from "../lib/api";
import { useI18n, usePageCopy } from "../lib/i18n";
import { downloadCsv, formatDateTime, formatNumber, formatTime, relativeTime } from "../lib/format";
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
  Pagination,
  SearchInput,
  Select,
  SeverityBadge,
  SeverityBars,
  TableSkeleton,
  useToast,
  type Column,
} from "../components/ui";
import {
  CopyButton,
  FilterBar,
  JsonBlock,
  MetaRow,
  SEVERITY_LEVELS,
  csvStamp,
  severityFromId,
  useDebouncedValue,
  useDocumentVisible,
} from "../components/features/detect/shared";
import type { EventStats, IngestSource, SecurityEvent, SecurityEventDetail } from "../components/features/detect/types";

const COPY = {
  es: {
    "monitoring.eyebrow": "Detección · Telemetría",
    "monitoring.title": "Monitorización en vivo",
    "monitoring.subtitle": "Flujo normalizado OCSF con filtros operativos, correlación ATT&CK y detalle forense del evento.",
    "monitoring.live": "EN VIVO · 10 s",
    "monitoring.paused": "EN PAUSA",
    "monitoring.manual": "MANUAL",
    "monitoring.pause": "Pausar",
    "monitoring.resume": "Reanudar",
    "monitoring.export": "Exportar CSV",
    "monitoring.exported": "Página actual exportada a CSV",
    "monitoring.exportFail": "No se pudo exportar el CSV",
    "monitoring.exportEmpty": "No hay eventos que exportar en esta página",
    "monitoring.kpi.events": "Eventos (24 h)",
    "monitoring.kpi.critical": "Críticos",
    "monitoring.kpi.topSource": "Origen principal",
    "monitoring.kpi.topHost": "Host principal",
    "monitoring.kpi.noSource": "Sin fuente identificada",
    "monitoring.kpi.noHost": "Sin host identificado",
    "monitoring.kpi.high": "altos",
    "monitoring.kpi.ofTotal": "del total",
    "monitoring.feed": "Flujo normalizado",
    "monitoring.feedFooter": "Telemetría OCSF · la retención y el enmascaramiento se aplican en el servidor",
    "monitoring.search": "Buscar mensaje, IP, host o usuario…",
    "monitoring.filter.severity": "Severidad",
    "monitoring.filter.class": "Clase OCSF",
    "monitoring.filter.source": "Fuente de ingesta",
    "monitoring.filter.range": "Ventana temporal",
    "monitoring.filter.host": "Host",
    "monitoring.filter.hostPlaceholder": "Filtrar por host",
    "monitoring.filter.srcIp": "IP origen",
    "monitoring.filter.srcIpPlaceholder": "Filtrar por IP",
    "monitoring.filter.allClasses": "Todas las clases",
    "monitoring.filter.allSources": "Todas las fuentes",
    "monitoring.filter.allSeverities": "Todas las severidades",
    "monitoring.range.1h": "Última hora",
    "monitoring.range.24h": "Últimas 24 h",
    "monitoring.range.7d": "Últimos 7 días",
    "monitoring.auto": "Auto-actualizar (10 s)",
    "monitoring.clear": "Limpiar filtros",
    "monitoring.col.time": "Hora",
    "monitoring.col.severity": "Sev.",
    "monitoring.col.class": "Clase",
    "monitoring.col.message": "Mensaje",
    "monitoring.col.host": "Host / IP",
    "monitoring.col.mitre": "MITRE",
    "monitoring.col.ioc": "IOC",
    "monitoring.empty.title": "Esperando telemetría",
    "monitoring.empty.description": "Conecta una fuente de ingesta o envía eventos normalizados para activar el flujo en vivo.",
    "monitoring.empty.action": "Configurar fuentes en SIEM",
    "monitoring.noResults.title": "Ningún evento coincide con los filtros",
    "monitoring.noResults.description": "Amplía la ventana temporal o limpia los filtros para volver al flujo completo.",
    "monitoring.stats.severity": "Distribución por severidad",
    "monitoring.stats.sources": "Orígenes principales",
    "monitoring.stats.hosts": "Hosts principales",
    "monitoring.stats.empty": "Sin datos en la ventana",
    "monitoring.stats.window": "Ventana de 24 h",
    "monitoring.detail.title": "Detalle del evento",
    "monitoring.detail.uid": "ID de evento",
    "monitoring.detail.occurred": "Ocurrido",
    "monitoring.detail.received": "Recibido",
    "monitoring.detail.class": "Clase OCSF",
    "monitoring.detail.source": "Fuente",
    "monitoring.detail.src": "Origen",
    "monitoring.detail.dst": "Destino",
    "monitoring.detail.host": "Host",
    "monitoring.detail.user": "Usuario",
    "monitoring.detail.process": "Proceso",
    "monitoring.detail.mitre": "MITRE ATT&CK",
    "monitoring.detail.ioc": "Coincidencias IOC",
    "monitoring.detail.emptyList": "Sin coincidencias",
    "monitoring.detail.normalized": "Evento normalizado (OCSF)",
    "monitoring.detail.raw": "Evento original",
    "monitoring.detail.copyAll": "Copiar evento completo",
    "monitoring.detail.error": "No se pudo cargar el detalle del evento",
    "monitoring.mitreEmpty": "Sin técnicas asociadas",
    "monitoring.eventsCount": "eventos",
    "monitoring.statsError": "No se pudieron cargar las estadísticas",
  },
  en: {
    "monitoring.eyebrow": "Detection · Telemetry",
    "monitoring.title": "Live monitoring",
    "monitoring.subtitle": "Normalized OCSF stream with operational filters, ATT&CK correlation and forensic event detail.",
    "monitoring.live": "LIVE · 10 s",
    "monitoring.paused": "PAUSED",
    "monitoring.manual": "MANUAL",
    "monitoring.pause": "Pause",
    "monitoring.resume": "Resume",
    "monitoring.export": "Export CSV",
    "monitoring.exported": "Current page exported to CSV",
    "monitoring.exportFail": "Could not export the CSV",
    "monitoring.exportEmpty": "No events to export on this page",
    "monitoring.kpi.events": "Events (24 h)",
    "monitoring.kpi.critical": "Critical",
    "monitoring.kpi.topSource": "Top source",
    "monitoring.kpi.topHost": "Top host",
    "monitoring.kpi.noSource": "No source identified",
    "monitoring.kpi.noHost": "No host identified",
    "monitoring.kpi.high": "high",
    "monitoring.kpi.ofTotal": "of total",
    "monitoring.feed": "Normalized stream",
    "monitoring.feedFooter": "OCSF telemetry · retention and masking are enforced server-side",
    "monitoring.search": "Search message, IP, host or user…",
    "monitoring.filter.severity": "Severity",
    "monitoring.filter.class": "OCSF class",
    "monitoring.filter.source": "Ingest source",
    "monitoring.filter.range": "Time window",
    "monitoring.filter.host": "Host",
    "monitoring.filter.hostPlaceholder": "Filter by host",
    "monitoring.filter.srcIp": "Source IP",
    "monitoring.filter.srcIpPlaceholder": "Filter by IP",
    "monitoring.filter.allClasses": "All classes",
    "monitoring.filter.allSources": "All sources",
    "monitoring.filter.allSeverities": "All severities",
    "monitoring.range.1h": "Last hour",
    "monitoring.range.24h": "Last 24 h",
    "monitoring.range.7d": "Last 7 days",
    "monitoring.auto": "Auto-refresh (10 s)",
    "monitoring.clear": "Clear filters",
    "monitoring.col.time": "Time",
    "monitoring.col.severity": "Sev.",
    "monitoring.col.class": "Class",
    "monitoring.col.message": "Message",
    "monitoring.col.host": "Host / IP",
    "monitoring.col.mitre": "MITRE",
    "monitoring.col.ioc": "IOC",
    "monitoring.empty.title": "Awaiting telemetry",
    "monitoring.empty.description": "Connect an ingest source or submit normalized events to activate the live stream.",
    "monitoring.empty.action": "Configure sources in SIEM",
    "monitoring.noResults.title": "No event matches the filters",
    "monitoring.noResults.description": "Widen the time window or clear the filters to return to the full stream.",
    "monitoring.stats.severity": "Severity distribution",
    "monitoring.stats.sources": "Top sources",
    "monitoring.stats.hosts": "Top hosts",
    "monitoring.stats.empty": "No data in the window",
    "monitoring.stats.window": "24 h window",
    "monitoring.detail.title": "Event detail",
    "monitoring.detail.uid": "Event ID",
    "monitoring.detail.occurred": "Occurred",
    "monitoring.detail.received": "Received",
    "monitoring.detail.class": "OCSF class",
    "monitoring.detail.source": "Source",
    "monitoring.detail.src": "Source",
    "monitoring.detail.dst": "Destination",
    "monitoring.detail.host": "Host",
    "monitoring.detail.user": "User",
    "monitoring.detail.process": "Process",
    "monitoring.detail.mitre": "MITRE ATT&CK",
    "monitoring.detail.ioc": "IOC matches",
    "monitoring.detail.emptyList": "No matches",
    "monitoring.detail.normalized": "Normalized event (OCSF)",
    "monitoring.detail.raw": "Raw event",
    "monitoring.detail.copyAll": "Copy full event",
    "monitoring.detail.error": "Could not load the event detail",
    "monitoring.mitreEmpty": "No associated techniques",
    "monitoring.eventsCount": "events",
    "monitoring.statsError": "Could not load statistics",
  },
} as const;

type RangePreset = "1h" | "24h" | "7d";

const RANGE_MS: Record<RangePreset, number> = {
  "1h": 3_600_000,
  "24h": 86_400_000,
  "7d": 604_800_000,
};

export function MonitoringPage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const { push } = useToast();

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [classUid, setClassUid] = useState("");
  const [sourceId, setSourceId] = useState("");
  const [range, setRange] = useState<RangePreset>("24h");
  const [host, setHost] = useState("");
  const [srcIp, setSrcIp] = useState("");
  const [page, setPage] = useState(1);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [paused, setPaused] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const debouncedSearch = useDebouncedValue(search);
  const debouncedHost = useDebouncedValue(host, 450);
  const debouncedSrcIp = useDebouncedValue(srcIp, 450);

  const documentVisible = useDocumentVisible();
  const polling = autoRefresh && !paused && documentVisible;

  const sourcesQuery = useQuery({
    queryKey: ["ingest-sources", "options"],
    queryFn: () => api.get<Page<IngestSource>>("/ingest-sources", { page: 1, page_size: 100 }),
    staleTime: 60_000,
  });

  const statsQuery = useQuery({
    queryKey: ["events", "stats", 24],
    queryFn: () => api.get<EventStats>("/events/stats", { hours: 24 }),
    refetchInterval: polling ? 15_000 : false,
  });

  const eventsQuery = useQuery({
    queryKey: [
      "events",
      "stream",
      { page, search: debouncedSearch, severity, classUid, sourceId, range, host: debouncedHost, srcIp: debouncedSrcIp },
    ],
    queryFn: () => {
      const now = new Date();
      return api.get<Page<SecurityEvent>>("/events", {
        page,
        page_size: 25,
        occurred_from: new Date(now.getTime() - RANGE_MS[range]).toISOString(),
        occurred_to: now.toISOString(),
        severity_id: severity || undefined,
        class_uid: classUid || undefined,
        source_id: sourceId || undefined,
        host_name: debouncedHost || undefined,
        src_ip: debouncedSrcIp || undefined,
        q: debouncedSearch || undefined,
        sort: "occurred_at",
        order: "desc",
      });
    },
    refetchInterval: polling ? 10_000 : false,
  });

  const detailQuery = useQuery({
    queryKey: ["events", "detail", selectedId],
    queryFn: () => api.get<SecurityEventDetail>(`/events/${selectedId}`),
    enabled: selectedId !== null,
  });

  const stats = statsQuery.data;
  const rows = eventsQuery.data?.items ?? [];
  const filtersActive = Boolean(
    debouncedSearch || severity || classUid || sourceId || debouncedHost || debouncedSrcIp,
  );

  const applyFilter = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setPage(1);
  };

  const clearFilters = () => {
    setSearch("");
    setSeverity("");
    setClassUid("");
    setSourceId("");
    setHost("");
    setSrcIp("");
    setPage(1);
  };

  const exportPage = () => {
    if (!rows.length) {
      push(c("monitoring.exportEmpty"), "info");
      return;
    }
    try {
      downloadCsv(
        `hispanshield-eventos-${csvStamp()}-p${page}.csv`,
        ["occurred_at", "severity", "class_uid", "class_name", "message", "host_name", "src_ip", "user_name", "mitre", "ioc"],
        rows.map((event) => [
          event.occurred_at,
          severityFromId(event.severity_id),
          event.class_uid,
          event.class_name,
          event.message,
          event.host_name ?? "",
          event.src_ip ?? "",
          event.user_name ?? "",
          event.mitre_techniques.join(";"),
          event.ioc_matches.length,
        ]),
      );
      push(c("monitoring.exported"), "success");
    } catch (error) {
      push(`${c("monitoring.exportFail")}: ${errorMessage(error)}`, "error");
    }
  };

  const severityBreakdown = SEVERITY_LEVELS.map((level) => ({
    label: t(`common.${level.value}`),
    value: stats?.by_severity[String(level.id)] ?? 0,
    color:
      level.value === "critical"
        ? "var(--critical)"
        : level.value === "high"
          ? "var(--danger)"
          : level.value === "medium"
            ? "var(--warning)"
            : level.value === "low"
              ? "var(--accent)"
              : "var(--muted)",
  }));

  const columns: Column<SecurityEvent>[] = [
    {
      key: "time",
      header: c("monitoring.col.time"),
      width: "104px",
      render: (row) => (
        <div>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--text-secondary)" }} title={formatDateTime(row.occurred_at, lang)}>
            {formatTime(row.occurred_at, lang)}
          </div>
          <div className="mono" style={{ fontSize: 9.5, color: "var(--dim)" }}>{relativeTime(row.occurred_at, lang)}</div>
        </div>
      ),
    },
    {
      key: "severity",
      header: c("monitoring.col.severity"),
      width: "96px",
      render: (row) => <SeverityBadge severity={severityFromId(row.severity_id)} />,
    },
    {
      key: "class",
      header: c("monitoring.col.class"),
      width: "150px",
      render: (row) => (
        <div>
          <div style={{ fontSize: 11.5, color: "var(--text-secondary)" }}>{row.class_name}</div>
          <div className="mono" style={{ fontSize: 9.5, color: "var(--dim)" }}>
            {row.class_uid} · {row.raw_format.toUpperCase()}
          </div>
        </div>
      ),
    },
    {
      key: "message",
      header: c("monitoring.col.message"),
      render: (row) => (
        <div style={{ minWidth: 220, maxWidth: 520 }}>
          <div style={{ color: "var(--text)", fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {row.message}
          </div>
          <div className="mono" style={{ fontSize: 9.5, color: "var(--dim)", marginTop: 2 }}>
            {row.user_name ? `${row.user_name} · ` : ""}
            {row.process_name ?? row.domain ?? row.url ?? row.event_uid}
          </div>
        </div>
      ),
    },
    {
      key: "host",
      header: c("monitoring.col.host"),
      width: "168px",
      render: (row) => (
        <div className="mono" style={{ fontSize: 10.5 }}>
          <div style={{ color: "var(--text-secondary)" }}>{row.host_name ?? row.src_ip ?? "—"}</div>
          {row.host_name && row.src_ip ? <div style={{ color: "var(--dim)" }}>{row.src_ip}</div> : null}
        </div>
      ),
    },
    {
      key: "mitre",
      header: c("monitoring.col.mitre"),
      width: "140px",
      render: (row) =>
        row.mitre_techniques.length ? (
          <div className="chip-row">
            {row.mitre_techniques.slice(0, 2).map((technique) => (
              <span className="tag" key={technique}>
                {technique}
              </span>
            ))}
            {row.mitre_techniques.length > 2 ? <span className="tag">+{row.mitre_techniques.length - 2}</span> : null}
          </div>
        ) : (
          <span className="dim" style={{ fontSize: 11 }}>—</span>
        ),
    },
    {
      key: "ioc",
      header: c("monitoring.col.ioc"),
      width: "78px",
      render: (row) =>
        row.ioc_matches.length ? <Badge tone="danger">IOC {row.ioc_matches.length}</Badge> : <span className="dim" style={{ fontSize: 11 }}>—</span>,
    },
  ];

  if (eventsQuery.isLoading && !eventsQuery.data) {
    return <PageSkeleton />;
  }

  return (
    <div className="animate-in" data-testid="page-monitoring">
      <PageHeader
        eyebrow={c("monitoring.eyebrow")}
        title={c("monitoring.title")}
        subtitle={c("monitoring.subtitle")}
        actions={
          <>
            <span className="live-dot" style={paused || !autoRefresh ? { color: "var(--warning)" } : undefined}>
              {paused ? c("monitoring.paused") : autoRefresh ? c("monitoring.live") : c("monitoring.manual")}
            </span>
            <Button icon={paused ? Play : Pause} onClick={() => setPaused((value) => !value)} data-testid="toggle-pause">
              {paused ? c("monitoring.resume") : c("monitoring.pause")}
            </Button>
            <Button icon={RefreshCw} onClick={() => void eventsQuery.refetch()} aria-label={t("common.refresh")} />
            <LinkButton to="/siem" variant="primary" icon={Database}>
              SIEM
            </LinkButton>
          </>
        }
      />

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi
          label={c("monitoring.kpi.events")}
          value={stats ? formatNumber(stats.total) : "—"}
          icon={Activity}
          tone="accent"
          footer={
            <span>
              {statsQuery.isError
                ? c("monitoring.statsError")
                : `${formatNumber(stats?.by_class.length ?? 0)} ${lang === "es" ? "clases principales" : "top classes"}`}
            </span>
          }
        />
        <Kpi
          label={c("monitoring.kpi.critical")}
          value={stats ? formatNumber(stats.by_severity["5"] ?? 0) : "—"}
          icon={ShieldAlert}
          tone="danger"
          footer={
            <span>
              {formatNumber(stats?.by_severity["4"] ?? 0)} {c("monitoring.kpi.high")} ·{" "}
              {formatNumber(stats?.by_severity["3"] ?? 0)} {t("common.medium").toLowerCase()}
            </span>
          }
        />
        <Kpi
          label={c("monitoring.kpi.topSource")}
          value={<span style={{ fontSize: 16, overflowWrap: "anywhere" }}>{stats?.top_sources[0]?.name ?? "—"}</span>}
          icon={Waves}
          tone="neutral"
          footer={
            <span>
              {stats?.top_sources[0]
                ? `${formatNumber(stats.top_sources[0].count)} ${c("monitoring.eventsCount")} · ${formatNumber(
                    Math.round((stats.top_sources[0].count / Math.max(1, stats.total)) * 100),
                  )}% ${c("monitoring.kpi.ofTotal")}`
                : c("monitoring.kpi.noSource")}
            </span>
          }
        />
        <Kpi
          label={c("monitoring.kpi.topHost")}
          value={<span style={{ fontSize: 16, overflowWrap: "anywhere" }}>{stats?.top_hosts[0]?.host_name ?? "—"}</span>}
          icon={Server}
          tone="warning"
          footer={
            <span>
              {stats?.top_hosts[0]
                ? `${formatNumber(stats.top_hosts[0].count)} ${c("monitoring.eventsCount")}`
                : c("monitoring.kpi.noHost")}
            </span>
          }
        />
      </div>

      {statsQuery.isError ? (
        <div style={{ marginBottom: 12 }}>
          <ErrorBanner
            compact
            title={c("monitoring.statsError")}
            message={errorMessage(statsQuery.error)}
            onRetry={() => void statsQuery.refetch()}
          />
        </div>
      ) : null}

      <div className="split-main">
        <Card
          title={c("monitoring.feed")}
          actions={
            <Button size="sm" variant="ghost" icon={Download} onClick={exportPage} data-testid="export-events">
              {c("monitoring.export")}
            </Button>
          }
          bodyClassName=""
          footer={
            <span className="row wrap" style={{ gap: 6 }}>
              <Radar size={12} style={{ color: "var(--accent)" }} aria-hidden="true" />
              <span>
                {eventsQuery.data ? `${formatNumber(eventsQuery.data.meta.total)} ${c("monitoring.eventsCount")} · ` : ""}
                {c("monitoring.feedFooter")}
              </span>
            </span>
          }
        >
          <FilterBar ariaLabel={t("common.filters")}>
            <SearchInput
              value={search}
              onChange={applyFilter(setSearch)}
              placeholder={c("monitoring.search")}
              ariaLabel={c("monitoring.search")}
            />
            <Select
              value={severity}
              onChange={(event) => applyFilter(setSeverity)(event.target.value)}
              aria-label={c("monitoring.filter.severity")}
              data-testid="filter-severity"
            >
              <option value="">{c("monitoring.filter.allSeverities")}</option>
              {SEVERITY_LEVELS.map((level) => (
                <option key={level.id} value={level.id}>
                  {t(`common.${level.value}`)}
                </option>
              ))}
            </Select>
            <Select
              value={classUid}
              onChange={(event) => applyFilter(setClassUid)(event.target.value)}
              aria-label={c("monitoring.filter.class")}
              data-testid="filter-class"
            >
              <option value="">{c("monitoring.filter.allClasses")}</option>
              {(stats?.by_class ?? []).map((item) => (
                <option key={item.class_uid} value={item.class_uid}>
                  {item.class_name} ({item.class_uid})
                </option>
              ))}
            </Select>
            <Select
              value={sourceId}
              onChange={(event) => applyFilter(setSourceId)(event.target.value)}
              aria-label={c("monitoring.filter.source")}
              data-testid="filter-source"
            >
              <option value="">{c("monitoring.filter.allSources")}</option>
              {(sourcesQuery.data?.items ?? []).map((source) => (
                <option key={source.id} value={source.id}>
                  {source.name}
                </option>
              ))}
            </Select>
            <Select
              value={range}
              onChange={(event) => {
                setRange(event.target.value as RangePreset);
                setPage(1);
              }}
              aria-label={c("monitoring.filter.range")}
              data-testid="filter-range"
            >
              <option value="1h">{c("monitoring.range.1h")}</option>
              <option value="24h">{c("monitoring.range.24h")}</option>
              <option value="7d">{c("monitoring.range.7d")}</option>
            </Select>
            <input
              className="input"
              style={{ width: "auto", minWidth: 130, height: 30, paddingTop: 0, paddingBottom: 0, fontSize: 11.5 }}
              value={host}
              onChange={(event) => applyFilter(setHost)(event.target.value)}
              placeholder={c("monitoring.filter.hostPlaceholder")}
              aria-label={c("monitoring.filter.host")}
              data-testid="filter-host"
            />
            <input
              className="input"
              style={{ width: "auto", minWidth: 130, height: 30, paddingTop: 0, paddingBottom: 0, fontSize: 11.5 }}
              value={srcIp}
              onChange={(event) => applyFilter(setSrcIp)(event.target.value)}
              placeholder={c("monitoring.filter.srcIpPlaceholder")}
              aria-label={c("monitoring.filter.srcIp")}
              data-testid="filter-src-ip"
              inputMode="search"
            />
            <label className="checkbox">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(event) => setAutoRefresh(event.target.checked)}
                data-testid="toggle-auto-refresh"
              />
              {c("monitoring.auto")}
            </label>
            {filtersActive ? (
              <Button size="sm" variant="ghost" onClick={clearFilters} data-testid="clear-filters">
                {c("monitoring.clear")}
              </Button>
            ) : null}
          </FilterBar>

          <div data-testid="table-events">
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(row) => String(row.id)}
              onRowClick={(row) => setSelectedId(row.id)}
              loading={eventsQuery.isFetching && !eventsQuery.data}
              error={
                eventsQuery.isError ? (
                  <ErrorBanner message={errorMessage(eventsQuery.error)} onRetry={() => void eventsQuery.refetch()} />
                ) : undefined
              }
              empty={
                filtersActive ? (
                  <EmptyState
                    icon={Filter}
                    title={c("monitoring.noResults.title")}
                    description={c("monitoring.noResults.description")}
                    action={
                      <Button size="sm" variant="primary" onClick={clearFilters}>
                        {c("monitoring.clear")}
                      </Button>
                    }
                  />
                ) : (
                  <EmptyState
                    icon={Terminal}
                    title={c("monitoring.empty.title")}
                    description={c("monitoring.empty.description")}
                    action={
                      <LinkButton to="/siem" size="sm" variant="primary" icon={Database}>
                        {c("monitoring.empty.action")}
                      </LinkButton>
                    }
                  />
                )
              }
            />
          </div>
          <Pagination meta={eventsQuery.data?.meta} onPage={setPage} />
          {eventsQuery.isError ? null : eventsQuery.isFetching && eventsQuery.data ? (
            <div className="pagination" aria-live="polite">
              <span>{t("common.loading")}</span>
            </div>
          ) : null}
        </Card>

        <div className="stack">
          <Card
            title={c("monitoring.stats.severity")}
            actions={
              <button
                type="button"
                className="icon-btn"
                onClick={() => void statsQuery.refetch()}
                aria-label={t("common.refresh")}
              >
                <RefreshCw size={13} />
              </button>
            }
          >
            {statsQuery.isLoading ? (
              <TableSkeleton rows={4} />
            ) : stats ? (
              <SeverityBars data={severityBreakdown} />
            ) : (
              <EmptyState icon={Activity} title={c("monitoring.stats.empty")} />
            )}
          </Card>

          <Card title={c("monitoring.stats.sources")}>
            {stats && stats.top_sources.length ? (
              <div className="metric-list">
                {stats.top_sources.slice(0, 6).map((source) => (
                  <div className="metric-row" key={source.source_id ?? source.name}>
                    <span className="metric-label" style={{ color: "var(--text-secondary)" }}>{source.name}</span>
                    <span className="metric-value">{formatNumber(source.count)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={Database} title={c("monitoring.stats.empty")} />
            )}
          </Card>

          <Card title={c("monitoring.stats.hosts")}>
            {stats && stats.top_hosts.length ? (
              <div className="metric-list">
                {stats.top_hosts.slice(0, 6).map((item) => (
                  <div className="metric-row" key={item.host_name}>
                    <span className="metric-label mono" style={{ color: "var(--text-secondary)" }}>{item.host_name}</span>
                    <span className="metric-value">{formatNumber(item.count)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={Server} title={c("monitoring.stats.empty")} />
            )}
          </Card>
        </div>
      </div>

      <Modal
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        title={c("monitoring.detail.title")}
        size="lg"
        footer={
          detailQuery.data ? (
            <CopyButton
              text={JSON.stringify(detailQuery.data, null, 2)}
              label={c("monitoring.detail.copyAll")}
            />
          ) : undefined
        }
      >
        {detailQuery.isLoading ? (
          <TableSkeleton rows={6} />
        ) : detailQuery.isError ? (
          <ErrorBanner
            title={c("monitoring.detail.error")}
            message={errorMessage(detailQuery.error)}
            onRetry={() => void detailQuery.refetch()}
          />
        ) : detailQuery.data ? (
          <EventDetailView event={detailQuery.data} />
        ) : null}
      </Modal>
    </div>
  );
}

function EventDetailView({ event }: { event: SecurityEventDetail }) {
  const { t, lang } = useI18n();
  const copy = usePageCopy(COPY);
  return (
    <div className="stack">
      <div className="row wrap" style={{ gap: 6 }}>
        <SeverityBadge severity={severityFromId(event.severity_id)} />
        <Badge tone="neutral">{event.class_name}</Badge>
        <Badge tone="neutral">{event.raw_format.toUpperCase()}</Badge>
        {event.is_demo ? <Badge tone="amber">{t("common.demoData")}</Badge> : null}
        <span className="mono" style={{ fontSize: 10, color: "var(--dim)", marginLeft: "auto" }}>
          {copy("monitoring.detail.uid")}: {event.event_uid}
        </span>
      </div>
      <div style={{ fontSize: 14, color: "var(--text)" }}>{event.message}</div>

      <div className="grid-2">
        <div className="metric-list">
          <MetaRow label={copy("monitoring.detail.occurred")}>{formatDateTime(event.occurred_at, lang)}</MetaRow>
          <MetaRow label={copy("monitoring.detail.received")}>{formatDateTime(event.received_at, lang)}</MetaRow>
          <MetaRow label={copy("monitoring.detail.src")}>
            <span className="mono">{event.src_ip ?? "—"}{event.src_port ? `:${event.src_port}` : ""}</span>
          </MetaRow>
          <MetaRow label={copy("monitoring.detail.dst")}>
            <span className="mono">{event.dst_ip ?? "—"}{event.dst_port ? `:${event.dst_port}` : ""}</span>
          </MetaRow>
          <MetaRow label={copy("monitoring.detail.host")}>{event.host_name ?? "—"}</MetaRow>
          <MetaRow label={copy("monitoring.detail.user")}>{event.user_name ?? "—"}</MetaRow>
          <MetaRow label={copy("monitoring.detail.process")}>{event.process_name ?? "—"}</MetaRow>
          <MetaRow label={copy("monitoring.detail.source")}>{event.source_connector ?? event.source_id ?? "—"}</MetaRow>
        </div>
        <div>
          <div className="section-label">{copy("monitoring.detail.mitre")}</div>
          <div className="chip-row">
            {event.mitre_techniques.length ? (
              event.mitre_techniques.map((technique) => (
                <span className="tag" key={technique}>
                  {technique}
                </span>
              ))
            ) : (
              <span className="dim" style={{ fontSize: 11 }}>{copy("monitoring.mitreEmpty")}</span>
            )}
          </div>
          <div className="section-label" style={{ marginTop: 12 }}>{copy("monitoring.detail.ioc")}</div>
          <div className="chip-row">
            {event.ioc_matches.length ? (
              event.ioc_matches.map((match, index) => (
                <span className="tag" key={index}>
                  {String(match.value ?? match.type ?? "match")}
                </span>
              ))
            ) : (
              <span className="dim" style={{ fontSize: 11 }}>{copy("monitoring.detail.emptyList")}</span>
            )}
          </div>
        </div>
      </div>

      <div>
        <div className="row-between">
          <div className="section-label" style={{ marginBottom: 0 }}>{copy("monitoring.detail.normalized")}</div>
          <CopyButton text={JSON.stringify(event.normalized, null, 2)} />
        </div>
        <JsonBlock value={event.normalized} ariaLabel={copy("monitoring.detail.normalized")} />
      </div>
      <div>
        <div className="row-between">
          <div className="section-label" style={{ marginBottom: 0 }}>{copy("monitoring.detail.raw")}</div>
          <CopyButton text={JSON.stringify(event.raw, null, 2)} />
        </div>
        <JsonBlock value={event.raw} ariaLabel={copy("monitoring.detail.raw")} />
      </div>
    </div>
  );
}

export default MonitoringPage;
