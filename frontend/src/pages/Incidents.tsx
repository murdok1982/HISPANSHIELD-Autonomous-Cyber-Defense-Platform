import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Download,
  Filter,
  FolderPlus,
  Gauge,
  Pause,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Siren,
  Timer,
  TriangleAlert,
  X,
} from "lucide-react";
import { api, errorMessage, isApiError, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { downloadCsv, durationMinutes, formatDateTime, formatNumber, relativeTime } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
  Field,
  Input,
  Kpi,
  PageHeader,
  PageSkeleton,
  Pagination,
  SearchInput,
  Modal,
  Select,
  SeverityBadge,
  StatusBadge,
  Tabs,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";
import {
  INCIDENT_SEVERITIES,
  INCIDENT_STATUSES,
  incidentAgeMinutes,
  isOpenStatus,
  slaRemainingMinutes,
  slaState,
  type AssetOption,
  type Incident,
  type IncidentDetailData,
  type IncidentMetrics,
  type OrganizationMember,
} from "../components/features/respond/incidents";

const COPY = {
  es: {
    eyebrow: "Mando · Respuesta",
    title: "Gestión de incidentes",
    subtitle: "Cola operativa con ciclo de vida, SLA y trazabilidad completa por incidente.",
    totalRecords: "incidentes",
    kpiOpen: "Incidentes abiertos",
    kpiCritical: "Críticos abiertos",
    kpiSla: "SLA en riesgo",
    kpiMttr: "MTTR",
    kpiMttd: "MTTD",
    kpiOpenFoot: "{closed} cerrados de {total} históricos",
    kpiCriticalFoot: "Prioridad de contención inmediata",
    kpiSlaFoot: "Fuera de plazo o <2 h en la página actual",
    kpiMttrFoot: "Resolución media (detectado → cerrado/resuelto)",
    kpiMttdFoot: "Detección media (primera alerta → detección)",
    computed: "Calculado {time}",
    tabActive: "Activos",
    tabAll: "Todos",
    tabClosed: "Cerrados",
    filters: "Filtros de la cola",
    searchPlaceholder: "Buscar por referencia, título o descripción…",
    allSeverities: "Todas las severidades",
    allStatuses: "Todos los estados",
    allAssignees: "Cualquier responsable",
    assigneeId: "ID de responsable (UUID)",
    dateFrom: "Desde",
    dateTo: "Hasta",
    sortBy: "Orden",
    sortCreated: "Creación",
    sortDetected: "Detección",
    sortSeverity: "Severidad",
    sortPriority: "Prioridad",
    sortStatus: "Estado",
    sortRef: "Referencia",
    newestFirst: "Más recientes primero",
    oldestFirst: "Más antiguos primero",
    clearFilters: "Limpiar filtros",
    create: "Nuevo incidente",
    export: "Exportar CSV",
    refresh: "Actualizar",
    pause: "Pausar",
    resume: "Reanudar",
    live: "AUTO 30 s",
    paused: "EN PAUSA",
    colRef: "Ref.",
    colIncident: "Incidente",
    colSeverity: "Severidad",
    colStatus: "Estado",
    colPriority: "Prioridad",
    colAssets: "Activos",
    colDetected: "Detectado",
    colAge: "Antigüedad / SLA",
    colAssignee: "Responsable",
    rowOpen: "Abrir incidente",
    emptyTitle: "Todavía no hay incidentes",
    emptyDesc: "Cuando una alerta se promueva o se registre actividad adversaria, aparecerá aquí con su ciclo de vida.",
    emptyFilterTitle: "Ningún incidente coincide",
    emptyFilterDesc: "Ajusta los filtros o limpia la búsqueda para ver la cola completa.",
    errorTitle: "No se pudo cargar la cola de incidentes",
    errorHint: "Revisa la conectividad con la API y vuelve a intentarlo.",
    slaBreached: "SLA vencido",
    slaAtRisk: "SLA en riesgo",
    slaOk: "En plazo",
    slaNone: "Sin SLA",
    slaDue: "vence {time}",
    activeScopeNote: "{count} incidentes cerrados ocultos por la pestaña Activos (se conserva la paginación del servidor).",
    demo: "DEMO",
    demoBanner: "Incidentes de demostración del laboratorio",
    unassigned: "Sin asignar",
    createTitle: "Registrar incidente",
    createSubtitle: "El servidor asigna referencia, SLA y prioridad si no se indica.",
    fieldTitle: "Título",
    fieldDescription: "Descripción",
    fieldSeverity: "Severidad",
    fieldPriority: "Prioridad (1 = máxima)",
    fieldAssets: "Activos afectados",
    assetSearch: "Buscar activos por nombre, IP o clave…",
    assetHint: "Escribe al menos 2 caracteres para buscar. Los activos deben pertenecer a la organización.",
    selectedAssets: "Seleccionados ({count})",
    noAssets: "Sin activos vinculados",
    removeAsset: "Quitar",
    submitCreate: "Crear incidente",
    creating: "Creando…",
    created: "Incidente {ref} creado",
    createError: "No se pudo crear el incidente",
    titleRequired: "El título debe tener al menos 3 caracteres.",
    priorityInvalid: "La prioridad debe estar entre 1 y 5.",
    assetsCount: "{count} activos",
    assetsCountOne: "1 activo",
  },
  en: {
    eyebrow: "Command · Response",
    title: "Incident management",
    subtitle: "Operational queue with lifecycle, SLA and full per-incident traceability.",
    totalRecords: "incidents",
    kpiOpen: "Open incidents",
    kpiCritical: "Open critical",
    kpiSla: "SLA at risk",
    kpiMttr: "MTTR",
    kpiMttd: "MTTD",
    kpiOpenFoot: "{closed} closed of {total} historical",
    kpiCriticalFoot: "Immediate containment priority",
    kpiSlaFoot: "Breached or <2 h on the current page",
    kpiMttrFoot: "Mean resolution (detected → closed/resolved)",
    kpiMttdFoot: "Mean detection (first alert → detection)",
    computed: "Computed {time}",
    tabActive: "Active",
    tabAll: "All",
    tabClosed: "Closed",
    filters: "Queue filters",
    searchPlaceholder: "Search by reference, title or description…",
    allSeverities: "All severities",
    allStatuses: "All statuses",
    allAssignees: "Any assignee",
    assigneeId: "Assignee ID (UUID)",
    dateFrom: "From",
    dateTo: "To",
    sortBy: "Sort",
    sortCreated: "Created",
    sortDetected: "Detected",
    sortSeverity: "Severity",
    sortPriority: "Priority",
    sortStatus: "Status",
    sortRef: "Reference",
    newestFirst: "Newest first",
    oldestFirst: "Oldest first",
    clearFilters: "Clear filters",
    create: "New incident",
    export: "Export CSV",
    refresh: "Refresh",
    pause: "Pause",
    resume: "Resume",
    live: "AUTO 30 s",
    paused: "PAUSED",
    colRef: "Ref.",
    colIncident: "Incident",
    colSeverity: "Severity",
    colStatus: "Status",
    colPriority: "Priority",
    colAssets: "Assets",
    colDetected: "Detected",
    colAge: "Age / SLA",
    colAssignee: "Assignee",
    rowOpen: "Open incident",
    emptyTitle: "No incidents yet",
    emptyDesc: "When an alert is promoted or adversary activity is recorded it will appear here with its lifecycle.",
    emptyFilterTitle: "No incident matches",
    emptyFilterDesc: "Adjust the filters or clear the search to see the full queue.",
    errorTitle: "Could not load the incident queue",
    errorHint: "Check API connectivity and try again.",
    slaBreached: "SLA breached",
    slaAtRisk: "SLA at risk",
    slaOk: "On time",
    slaNone: "No SLA",
    slaDue: "due {time}",
    activeScopeNote: "{count} closed incidents hidden by the Active tab (server pagination is preserved).",
    demo: "DEMO",
    demoBanner: "Demonstration lab incidents",
    unassigned: "Unassigned",
    createTitle: "Register incident",
    createSubtitle: "The server assigns the reference, SLA and priority when omitted.",
    fieldTitle: "Title",
    fieldDescription: "Description",
    fieldSeverity: "Severity",
    fieldPriority: "Priority (1 = highest)",
    fieldAssets: "Affected assets",
    assetSearch: "Search assets by name, IP or key…",
    assetHint: "Type at least 2 characters to search. Assets must belong to the organization.",
    selectedAssets: "Selected ({count})",
    noAssets: "No linked assets",
    removeAsset: "Remove",
    submitCreate: "Create incident",
    creating: "Creating…",
    created: "Incident {ref} created",
    createError: "Could not create the incident",
    titleRequired: "Title must be at least 3 characters.",
    priorityInvalid: "Priority must be between 1 and 5.",
    assetsCount: "{count} assets",
    assetsCountOne: "1 asset",
  },
};

type Tab = "active" | "all" | "closed";

function slaLabel(state: string, c: (key: string) => string): string {
  if (state === "breached") return c("slaBreached");
  if (state === "at_risk") return c("slaAtRisk");
  if (state === "ok") return c("slaOk");
  return c("slaNone");
}

function slaTone(state: string): "danger" | "warning" | "success" | "neutral" {
  if (state === "breached") return "danger";
  if (state === "at_risk") return "warning";
  if (state === "ok") return "success";
  return "neutral";
}

function CreateIncidentModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (incident: IncidentDetailData) => void;
}) {
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const { can } = useAuth();
  const { push } = useToast();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [priority, setPriority] = useState("");
  const [assetQuery, setAssetQuery] = useState("");
  const [selected, setSelected] = useState<AssetOption[]>([]);
  const [formError, setFormError] = useState<string | null>(null);

  const assets = useQuery({
    queryKey: ["assets", "incident-picker", assetQuery],
    queryFn: () => api.get<Page<AssetOption>>("/assets", { q: assetQuery, page_size: 20, sort: "name", order: "asc" }),
    enabled: open && can("asset:read") && assetQuery.trim().length >= 2,
  });

  const createMutation = useMutation({
    mutationFn: () =>
      api.post<IncidentDetailData>("/incidents", {
        title: title.trim(),
        description: description.trim() || undefined,
        severity,
        priority: priority ? Number(priority) : undefined,
        affected_asset_ids: selected.map((asset) => asset.id),
      }),
    onSuccess: (incident) => {
      push(c("created").replace("{ref}", incident.ref), "success");
      setTitle("");
      setDescription("");
      setSeverity("medium");
      setPriority("");
      setSelected([]);
      setAssetQuery("");
      setFormError(null);
      onCreated(incident);
    },
    onError: (error) => {
      const message = isApiError(error)
        ? error.details.map((detail) => `${detail.field}: ${detail.message}`).join(" · ") || error.message
        : errorMessage(error);
      setFormError(message);
    },
  });

  const addAsset = (asset: AssetOption) => {
    setSelected((current) => (current.some((item) => item.id === asset.id) ? current : [...current, asset]));
    setAssetQuery("");
  };

  const removeAsset = (id: string) => {
    setSelected((current) => current.filter((item) => item.id !== id));
  };

  const submit = () => {
    setFormError(null);
    if (title.trim().length < 3) {
      setFormError(c("titleRequired"));
      return;
    }
    if (priority && (Number(priority) < 1 || Number(priority) > 5)) {
      setFormError(c("priorityInvalid"));
      return;
    }
    createMutation.mutate();
  };

  if (!open) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={c("createTitle")}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button
            variant="primary"
            icon={FolderPlus}
            loading={createMutation.isPending}
            onClick={submit}
            data-testid="submit-create-incident"
          >
            {createMutation.isPending ? c("creating") : c("submitCreate")}
          </Button>
        </>
      }
    >
      <div data-testid="create-incident-modal">
        <p className="dim" style={{ fontSize: 11.5, marginBottom: 12 }}>{c("createSubtitle")}</p>
        <div className="form-grid">
          <div className="span-2">
            <Field label={c("fieldTitle")} required htmlFor="incident-title">
              <Input
                id="incident-title"
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                maxLength={300}
                data-testid="incident-title-input"
              />
            </Field>
          </div>
          <div className="span-2">
            <Field label={c("fieldDescription")} htmlFor="incident-description">
              <Textarea
                id="incident-description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                rows={3}
                maxLength={20000}
                data-testid="incident-description-input"
              />
            </Field>
          </div>
          <Field label={c("fieldSeverity")} htmlFor="incident-severity">
            <Select
              id="incident-severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
              data-testid="incident-severity-select"
            >
              {INCIDENT_SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </Select>
          </Field>
          <Field label={c("fieldPriority")} hint="1–5" htmlFor="incident-priority">
            <Input
              id="incident-priority"
              type="number"
              min={1}
              max={5}
              value={priority}
              onChange={(event) => setPriority(event.target.value)}
              placeholder="3"
              data-testid="incident-priority-input"
            />
          </Field>
          <div className="span-2">
            <div className="section-label" style={{ marginBottom: 6 }}>{c("fieldAssets")}</div>
            <SearchInput
              value={assetQuery}
              onChange={setAssetQuery}
              placeholder={c("assetSearch")}
              ariaLabel={c("assetSearch")}
            />
            <span className="hint">{c("assetHint")}</span>
            {assets.isFetching ? <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>{t("common.loading")}</div> : null}
            {assets.data?.items.length ? (
              <div style={{ marginTop: 8, maxHeight: 180, overflowY: "auto" }} data-testid="asset-picker-results">
                {assets.data.items.map((asset) => (
                  <button
                    key={asset.id}
                    type="button"
                    className="list-item"
                    style={{ width: "100%", background: "transparent", border: 0, textAlign: "left", cursor: "pointer", padding: "8px 4px" }}
                    onClick={() => addAsset(asset)}
                  >
                    <span style={{ minWidth: 0 }}>
                      <span className="item-title" style={{ display: "block" }}>{asset.name}</span>
                      <span className="item-sub">
                        {asset.kind} · {asset.ip_addresses[0] ?? asset.id.slice(0, 8)} · {asset.environment}
                      </span>
                    </span>
                    <span className="item-side"><Badge tone="neutral">C{asset.criticality}</Badge></span>
                  </button>
                ))}
              </div>
            ) : null}
            <div className="section-label" style={{ marginTop: 12, marginBottom: 6 }}>
              {c("selectedAssets").replace("{count}", String(selected.length))}
            </div>
            {selected.length === 0 ? (
              <div className="dim" style={{ fontSize: 11 }}>{c("noAssets")}</div>
            ) : (
              <div className="chip-row" data-testid="selected-assets">
                {selected.map((asset) => (
                  <span className="tag" key={asset.id}>
                    {asset.name}
                    <button
                      type="button"
                      className="icon-btn"
                      style={{ width: 16, height: 16, marginLeft: 2 }}
                      onClick={() => removeAsset(asset.id)}
                      aria-label={`${c("removeAsset")} ${asset.name}`}
                    >
                      <X size={10} />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
        {formError ? <div style={{ marginTop: 10 }}><ErrorBanner compact message={formError} /></div> : null}
      </div>
    </Modal>
  );
}

export function IncidentsPage() {
  const c = usePageCopy(COPY);
  const { t, lang } = useI18n();
  const { can } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("active");
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [assignee, setAssignee] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [sort, setSort] = useState("created_at");
  const [order, setOrder] = useState("desc");
  const [paused, setPaused] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);

  const effectiveStatus = tab === "closed" ? "closed" : status || undefined;
  const assigneeId = assignee.trim() || undefined;

  const metrics = useQuery({
    queryKey: ["incidents", "metrics"],
    queryFn: () => api.get<IncidentMetrics>("/incidents/metrics"),
    refetchInterval: paused ? false : 30_000,
    refetchIntervalInBackground: false,
  });

  const members = useQuery({
    queryKey: ["organizations", "members", "incident-assignees"],
    queryFn: () => api.get<Page<OrganizationMember>>("/organizations/current/members", { page_size: 200 }),
    enabled: can("user:read"),
    staleTime: 120_000,
  });

  const incidents = useQuery({
    queryKey: ["incidents", { page, q, severity, effectiveStatus, assigneeId, dateFrom, dateTo, sort, order, tab }],
    queryFn: () =>
      api.get<Page<Incident>>("/incidents", {
        page,
        page_size: 25,
        q: q.trim() || undefined,
        severity: severity || undefined,
        status: effectiveStatus,
        assignee: assigneeId,
        date_from: dateFrom ? `${dateFrom}T00:00:00Z` : undefined,
        date_to: dateTo ? `${dateTo}T23:59:59Z` : undefined,
        sort,
        order,
      }),
    refetchInterval: paused ? false : 30_000,
    refetchIntervalInBackground: false,
  });

  const rows = incidents.data?.items ?? [];
  const visibleRows = useMemo(() => (tab === "active" ? rows.filter((row) => isOpenStatus(row.status)) : rows), [rows, tab]);
  const hiddenClosed = rows.length - visibleRows.length;
  const membersById = useMemo(() => {
    const map = new Map<string, OrganizationMember>();
    for (const member of members.data?.items ?? []) map.set(member.user_id, member);
    return map;
  }, [members.data]);

  const slaAtRisk = useMemo(
    () => visibleRows.filter((row) => ["at_risk", "breached"].includes(slaState(row.sla_due_at))).length,
    [visibleRows],
  );

  const hasFilters = Boolean(q || severity || status || assignee || dateFrom || dateTo || tab !== "active");

  const paginationMeta =
    incidents.data?.meta && tab === "active" && !status
      ? {
          ...incidents.data.meta,
          total: metrics.data?.open_total ?? incidents.data.meta.total,
          pages: Math.max(1, Math.ceil((metrics.data?.open_total ?? incidents.data.meta.total) / incidents.data.meta.page_size)),
        }
      : incidents.data?.meta;

  const clearFilters = () => {
    setQ("");
    setSeverity("");
    setStatus("");
    setAssignee("");
    setDateFrom("");
    setDateTo("");
    setTab("active");
    setPage(1);
  };

  const exportCsv = () => {
    downloadCsv(
      `hispanshield-incidents-${new Date().toISOString().slice(0, 10)}.csv`,
      ["ref", "title", "severity", "status", "priority", "affected_assets", "detected_at", "sla_due_at", "assignee"],
      visibleRows.map((row) => [
        row.ref,
        row.title,
        row.severity,
        row.status,
        row.priority,
        row.affected_asset_ids.length,
        row.detected_at,
        row.sla_due_at ?? "",
        row.assignee_id ?? "",
      ]),
    );
  };

  const columns: Column<Incident>[] = [
    {
      key: "ref",
      header: c("colRef"),
      width: "116px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5, color: "var(--accent)", whiteSpace: "nowrap" }}>{row.ref}</span>,
    },
    {
      key: "title",
      header: c("colIncident"),
      render: (row) => (
        <div style={{ minWidth: 210 }}>
          <div className="primary-cell" style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
            <span>{row.title}</span>
            {row.is_demo ? <Badge tone="amber">{c("demo")}</Badge> : null}
          </div>
          <div className="cell-sub">
            {row.mitre.length ? row.mitre.slice(0, 2).join(" · ") : row.description ? row.description.slice(0, 70) : "—"}
          </div>
        </div>
      ),
    },
    { key: "severity", header: c("colSeverity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: c("colStatus"), width: "124px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "priority",
      header: c("colPriority"),
      width: "86px",
      render: (row) => <span className="mono" style={{ color: row.priority <= 2 ? "var(--danger)" : "var(--text-secondary)" }}>P{row.priority}</span>,
    },
    {
      key: "assets",
      header: c("colAssets"),
      width: "84px",
      align: "right",
      render: (row) => (
        <span className="mono" title={row.affected_asset_ids.join(", ")}>
          {formatNumber(row.affected_asset_ids.length)}
        </span>
      ),
    },
    {
      key: "detected",
      header: c("colDetected"),
      width: "126px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)" }} title={formatDateTime(row.detected_at, lang)}>
          {relativeTime(row.detected_at, lang)}
        </span>
      ),
    },
    {
      key: "sla",
      header: c("colAge"),
      width: "170px",
      render: (row) => {
        const state = slaState(row.sla_due_at);
        const remaining = slaRemainingMinutes(row.sla_due_at);
        const age = incidentAgeMinutes(row.detected_at);
        return (
          <div style={{ display: "flex", flexDirection: "column", gap: 3, alignItems: "flex-start" }}>
            <span className="mono" style={{ fontSize: 10.5 }}>{durationMinutes(age)}</span>
            <Badge tone={slaTone(state)}>
              {slaLabel(state, c)}
              {remaining !== null && remaining >= 0 ? ` · ${durationMinutes(remaining)}` : ""}
            </Badge>
          </div>
        );
      },
    },
    {
      key: "assignee",
      header: c("colAssignee"),
      width: "150px",
      render: (row) => {
        const member = row.assignee_id ? membersById.get(row.assignee_id) : undefined;
        return (
          <span style={{ fontSize: 11.5, color: row.assignee_id ? "var(--text-secondary)" : "var(--dim)" }}>
            {member?.full_name ?? (row.assignee_id ? row.assignee_id.slice(0, 8) : c("unassigned"))}
          </span>
        );
      },
    },
  ];

  if (incidents.isLoading && !incidents.data) {
    return (
      <div data-testid="page-incidents">
        <PageSkeleton />
      </div>
    );
  }

  if (incidents.isError && !incidents.data) {
    return (
      <div data-testid="page-incidents">
        <PageHeader eyebrow={c("eyebrow")} title={c("title")} subtitle={c("subtitle")} />
        <ErrorBanner title={c("errorTitle")} message={errorMessage(incidents.error)} onRetry={() => void incidents.refetch()} />
      </div>
    );
  }

  return (
    <div className="animate-in" data-testid="page-incidents">
      <PageHeader
        eyebrow={`${c("eyebrow")} · ${formatNumber(metrics.data?.open_total ?? 0)} ${c("kpiOpen").toLowerCase()}`}
        title={c("title")}
        subtitle={c("subtitle")}
        actions={
          <>
            <span className={`live-dot${paused ? " paused" : ""}`} style={paused ? { color: "var(--dim)" } : undefined}>
              {paused ? c("paused") : c("live")}
            </span>
            <Button
              icon={paused ? Play : Pause}
              onClick={() => setPaused((value) => !value)}
              data-testid="toggle-incidents-autorefresh"
            >
              {paused ? c("resume") : c("pause")}
            </Button>
            <Button icon={RefreshCw} onClick={() => void incidents.refetch()} aria-label={c("refresh")} data-testid="refresh-incidents" />
            <Button icon={Download} onClick={exportCsv} disabled={!visibleRows.length} data-testid="export-incidents">
              {c("export")}
            </Button>
            {can("incident:write") ? (
              <Button variant="primary" icon={Plus} onClick={() => setCreateOpen(true)} data-testid="create-incident">
                {c("create")}
              </Button>
            ) : null}
          </>
        }
      />

      {incidents.data?.items.some((row) => row.is_demo) ? (
        <div className="demo-banner" style={{ marginBottom: 12 }}>{c("demo")} · {c("demoBanner")}</div>
      ) : null}

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi
          label={c("kpiOpen")}
          value={metrics.data ? formatNumber(metrics.data.open_total) : "—"}
          icon={Siren}
          tone={(metrics.data?.open_by_severity.critical ?? 0) > 0 ? "danger" : "warning"}
          footer={
            <span>
              {c("kpiOpenFoot")
                .replace("{closed}", formatNumber(metrics.data?.closed_total ?? 0))
                .replace("{total}", formatNumber(metrics.data?.total ?? 0))}
            </span>
          }
        />
        <Kpi
          label={c("kpiCritical")}
          value={metrics.data ? formatNumber(metrics.data.open_by_severity.critical ?? 0) : "—"}
          icon={TriangleAlert}
          tone="danger"
          footer={<span>{c("kpiCriticalFoot")}</span>}
        />
        <Kpi
          label={c("kpiSla")}
          value={formatNumber(slaAtRisk)}
          icon={Gauge}
          tone={slaAtRisk > 0 ? "warning" : "success"}
          footer={<span>{c("kpiSlaFoot")}</span>}
        />
        <Kpi
          label={`${c("kpiMttr")} / ${c("kpiMttd")}`}
          value={metrics.data?.mttr_seconds != null ? durationMinutes(metrics.data.mttr_seconds / 60) : "—"}
          suffix={metrics.data?.mttd_seconds != null ? `MTTD ${durationMinutes(metrics.data.mttd_seconds / 60)}` : undefined}
          icon={Activity}
          tone="accent"
          footer={
            <span>
              {metrics.data
                ? c("computed").replace("{time}", relativeTime(metrics.data.computed_at, lang))
                : "—"}
            </span>
          }
        />
      </div>

      {metrics.isError ? (
        <div style={{ marginBottom: 12 }}>
          <ErrorBanner compact message={errorMessage(metrics.error)} onRetry={() => void metrics.refetch()} />
        </div>
      ) : null}

      <Card
        title={c("tabActive")}
        subtitle={incidents.data?.meta ? `${formatNumber(incidents.data.meta.total)} ${c("totalRecords")}` : undefined}
        actions={
          <Tabs<Tab>
            ariaLabel={c("filters")}
            items={[
              { key: "active", label: c("tabActive"), count: metrics.data?.open_total },
              { key: "all", label: c("tabAll"), count: metrics.data?.total },
              { key: "closed", label: c("tabClosed"), count: metrics.data?.closed_total },
            ]}
            value={tab}
            onChange={(value) => {
              setTab(value);
              if (value === "active" && status === "closed") setStatus("");
              setPage(1);
            }}
          />
        }
        bodyClassName=""
        footer={
          <div className="row-between" style={{ width: "100%", flexWrap: "wrap", gap: 8 }}>
            <span className="row" style={{ gap: 6 }}>
              <ShieldCheck size={12} style={{ color: "var(--success)" }} />
              {t("common.lastUpdated", { time: relativeTime(new Date(incidents.dataUpdatedAt), lang) })}
            </span>
            {tab === "active" && hiddenClosed > 0 ? (
              <span className="dim" style={{ fontSize: 10.5 }}>{c("activeScopeNote").replace("{count}", String(hiddenClosed))}</span>
            ) : null}
            <Pagination meta={paginationMeta} onPage={setPage} />
          </div>
        }
      >
        <div className="filters-bar" data-testid="incidents-filters">
          <SearchInput
            value={q}
            onChange={(value) => {
              setQ(value);
              setPage(1);
            }}
            placeholder={c("searchPlaceholder")}
            ariaLabel={c("searchPlaceholder")}
          />
          <Select
            aria-label={c("fieldSeverity")}
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              setPage(1);
            }}
            data-testid="incidents-filter-severity"
          >
            <option value="">{c("allSeverities")}</option>
            {INCIDENT_SEVERITIES.map((value) => (
              <option key={value} value={value}>{t(`common.${value}`)}</option>
            ))}
          </Select>
          <Select
            aria-label={c("colStatus")}
            value={status}
            disabled={tab === "closed"}
            onChange={(event) => {
              setStatus(event.target.value);
              setPage(1);
            }}
            data-testid="incidents-filter-status"
          >
            <option value="">{c("allStatuses")}</option>
            {INCIDENT_STATUSES.map((value) => (
              <option key={value} value={value} disabled={tab === "active" && value === "closed"}>{value}</option>
            ))}
          </Select>
          {can("user:read") ? (
            <Select
              aria-label={c("colAssignee")}
              value={assignee}
              onChange={(event) => {
                setAssignee(event.target.value);
                setPage(1);
              }}
              data-testid="incidents-filter-assignee"
            >
              <option value="">{c("allAssignees")}</option>
              {members.data?.items.map((member) => (
                <option key={member.user_id} value={member.user_id}>{member.full_name}</option>
              ))}
            </Select>
          ) : (
            <Input
              aria-label={c("assigneeId")}
              placeholder={c("assigneeId")}
              value={assignee}
              onChange={(event) => {
                setAssignee(event.target.value);
                setPage(1);
              }}
              style={{ width: 190, height: 30, fontSize: 11.5 }}
            />
          )}
          <Input
            type="date"
            aria-label={c("dateFrom")}
            value={dateFrom}
            max={dateTo || undefined}
            onChange={(event) => {
              setDateFrom(event.target.value);
              setPage(1);
            }}
            style={{ width: 142, height: 30, fontSize: 11.5 }}
          />
          <Input
            type="date"
            aria-label={c("dateTo")}
            value={dateTo}
            min={dateFrom || undefined}
            onChange={(event) => {
              setDateTo(event.target.value);
              setPage(1);
            }}
            style={{ width: 142, height: 30, fontSize: 11.5 }}
          />
          <Select
            aria-label={c("sortBy")}
            value={`${sort}:${order}`}
            onChange={(event) => {
              const [nextSort, nextOrder] = event.target.value.split(":");
              setSort(nextSort);
              setOrder(nextOrder);
              setPage(1);
            }}
            data-testid="incidents-sort"
          >
            <option value="created_at:desc">{c("sortCreated")} · {c("newestFirst")}</option>
            <option value="created_at:asc">{c("sortCreated")} · {c("oldestFirst")}</option>
            <option value="detected_at:desc">{c("sortDetected")} · {c("newestFirst")}</option>
            <option value="severity:desc">{c("sortSeverity")}</option>
            <option value="priority:asc">{c("sortPriority")}</option>
            <option value="status:asc">{c("sortStatus")}</option>
            <option value="ref:desc">{c("sortRef")}</option>
          </Select>
          {hasFilters ? (
            <Button size="sm" variant="ghost" icon={X} onClick={clearFilters} data-testid="clear-incident-filters">
              {c("clearFilters")}
            </Button>
          ) : null}
          <Badge tone="neutral"><Filter size={10} /> {visibleRows.length}</Badge>
        </div>

        {incidents.isError ? (
          <div style={{ padding: 12 }}>
            <ErrorBanner compact message={errorMessage(incidents.error)} onRetry={() => void incidents.refetch()} />
          </div>
        ) : null}

        <div data-testid="incidents-table">
          <DataTable
            columns={columns}
            rows={visibleRows}
            rowKey={(row) => row.id}
            onRowClick={(row) => navigate(`/incidents/${row.id}`)}
            loading={incidents.isFetching && !incidents.data}
            empty={
              hasFilters ? (
                <EmptyState
                  icon={Timer}
                  title={c("emptyFilterTitle")}
                  description={c("emptyFilterDesc")}
                  action={<Button size="sm" onClick={clearFilters}>{c("clearFilters")}</Button>}
                />
              ) : (
                <EmptyState
                  icon={ShieldCheck}
                  title={c("emptyTitle")}
                  description={c("emptyDesc")}
                  action={
                    can("incident:write") ? (
                      <Button variant="primary" size="sm" icon={Plus} onClick={() => setCreateOpen(true)}>
                        {c("create")}
                      </Button>
                    ) : undefined
                  }
                />
              )
            }
          />
        </div>
      </Card>

      <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
        <ShieldCheck size={14} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
        <span>
          {c("kpiOpen")}: {formatNumber(metrics.data?.open_total ?? 0)} · {c("kpiMttr")}:{" "}
          {metrics.data?.mttr_seconds != null ? durationMinutes(metrics.data.mttr_seconds / 60) : "—"} ·{" "}
          {c("kpiMttd")}: {metrics.data?.mttd_seconds != null ? durationMinutes(metrics.data.mttd_seconds / 60) : "—"}
        </span>
      </div>

      <CreateIncidentModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(incident) => {
          setCreateOpen(false);
          void queryClient.invalidateQueries({ queryKey: ["incidents"] });
          navigate(`/incidents/${incident.id}`);
        }}
      />
    </div>
  );
}

export default IncidentsPage;
