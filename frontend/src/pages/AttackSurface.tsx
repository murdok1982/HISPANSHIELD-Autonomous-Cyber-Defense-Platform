import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Crosshair,
  Play,
  Plus,
  Radar,
  RefreshCw,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { api, apiRequest, errorMessage, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatDateTime, formatNumber, humanize, relativeTime } from "../lib/format";
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
  LinkButton,
  Modal,
  PageHeader,
  PageSkeleton,
  Pagination,
  SearchInput,
  Select,
  SeverityBadge,
  StatusBadge,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";
import {
  ConfirmModal,
  CopyButton,
  FilterBar,
  JsonBlock,
  fieldErrors,
  useDebouncedValue,
} from "../components/features/detect/shared";
import type {
  AnalyzeResult,
  Asset,
  DiscoveryJob,
  DiscoveryRunResult,
  Finding,
  FindingSummary,
} from "../components/features/detect/types";

const COPY = {
  es: {
    "as.eyebrow": "Exposición · Superficie de ataque",
    "as.title": "Superficie de ataque",
    "as.subtitle": "Hallazgos de exposición derivados del inventario, análisis acotado y trabajos de descubrimiento autorizados.",
    "as.analyze": "Analizar inventario",
    "as.analyzeHint": "Recorre el inventario y crea hallazgos deduplicados por tipo.",
    "as.analyzed": "Análisis completado",
    "as.analyzeFailed": "No se pudo ejecutar el análisis",
    "as.analyzedDetail": "activos analizados",
    "as.kpi.total": "Hallazgos",
    "as.kpi.critical": "Críticos / altos",
    "as.kpi.open": "Abiertos",
    "as.kpi.kinds": "Tipos distintos",
    "as.bySeverity": "Hallazgos por severidad",
    "as.byKind": "Hallazgos por tipo",
    "as.byStatus": "Hallazgos por estado",
    "as.noSummary": "Sin resumen disponible",
    "as.search": "Buscar por título o evidencia…",
    "as.filter.severity": "Severidad",
    "as.filter.status": "Estado",
    "as.filter.kind": "Tipo",
    "as.filter.allSeverities": "Todas las severidades",
    "as.filter.allStatuses": "Todos los estados",
    "as.filter.allKinds": "Todos los tipos",
    "as.filter.clear": "Limpiar filtros",
    "as.table.finding": "Hallazgo",
    "as.table.kind": "Tipo",
    "as.table.severity": "Severidad",
    "as.table.status": "Estado",
    "as.table.asset": "Activo",
    "as.table.firstSeen": "Primera vez",
    "as.table.lastSeen": "Última vez",
    "as.table.source": "Origen",
    "as.table.actions": "Acciones",
    "as.table.view": "Ver detalle",
    "as.count": "hallazgos",
    "as.empty.title": "Sin hallazgos de superficie",
    "as.empty.description": "Ejecuta el análisis del inventario o registra un hallazgo manual para empezar.",
    "as.empty.action": "Analizar inventario",
    "as.noResults.title": "Ningún hallazgo coincide",
    "as.noResults.description": "Ajusta los filtros o limpia la búsqueda.",
    "as.new": "Nuevo hallazgo",
    "as.loadFailed": "No se pudieron cargar los hallazgos",
    "as.detail.title": "Detalle del hallazgo",
    "as.detail.kind": "Tipo",
    "as.detail.source": "Origen",
    "as.detail.firstSeen": "Primera observación",
    "as.detail.lastSeen": "Última observación",
    "as.detail.asset": "Activo afectado",
    "as.detail.assetLink": "Abrir activo",
    "as.detail.noAsset": "Sin activo asignado",
    "as.detail.evidence": "Evidencia",
    "as.detail.noEvidence": "Sin evidencia registrada",
    "as.detail.metadata": "Metadatos",
    "as.detail.status": "Estado del hallazgo",
    "as.detail.update": "Actualizar estado",
    "as.detail.updated": "Estado del hallazgo actualizado",
    "as.detail.updateFailed": "No se pudo actualizar el estado",
    "as.detail.loadError": "No se pudo cargar el hallazgo",
    "as.form.title": "Registrar hallazgo",
    "as.form.titleLabel": "Título",
    "as.form.kind": "Tipo",
    "as.form.kindHint": "minúsculas, números y guion bajo (p. ej. exposed_service)",
    "as.form.severity": "Severidad",
    "as.form.status": "Estado",
    "as.form.source": "Origen",
    "as.form.evidence": "Evidencia",
    "as.form.asset": "Activo afectado",
    "as.form.assetSearch": "Buscar activo por nombre o clave…",
    "as.form.assetNone": "Sin activo",
    "as.form.submit": "Crear hallazgo",
    "as.form.success": "Hallazgo creado",
    "as.form.failed": "No se pudo crear el hallazgo",
    "as.form.invalidKind": "Tipo no válido",
    "as.form.required": "Obligatorio",
    "as.jobs.title": "Descubrimiento",
    "as.jobs.subtitle": "Descubrimiento pasivo por defecto; el sondeo activo exige autorización escrita y alcance acotado.",
    "as.jobs.new": "Nuevo trabajo",
    "as.jobs.safety": "Los activos OT/ICS solo se descubren en modo pasivo. El sondeo activo es un reconocimiento acotado y autorizado sobre los rangos CIDR indicados; no explota vulnerabilidades ni modifica sistemas.",
    "as.jobs.table.name": "Trabajo",
    "as.jobs.table.mode": "Modo",
    "as.jobs.table.status": "Estado",
    "as.jobs.table.scope": "Alcance",
    "as.jobs.table.auth": "Autorización",
    "as.jobs.table.lastRun": "Última ejecución",
    "as.jobs.table.actions": "Acciones",
    "as.jobs.run": "Ejecutar",
    "as.jobs.runBlocked": "Añade una referencia de autorización al trabajo antes de ejecutarlo.",
    "as.jobs.empty": "Sin trabajos de descubrimiento",
    "as.jobs.emptyHint": "Crea un trabajo pasivo para observar la red sin generar tráfico activo.",
    "as.jobs.mode.passive": "Pasivo",
    "as.jobs.mode.active": "Activo",
    "as.jobs.status.pending": "Pendiente",
    "as.jobs.status.running": "En ejecución",
    "as.jobs.status.completed": "Completado",
    "as.jobs.status.failed": "Fallido",
    "as.jobs.runTitle": "Ejecutar descubrimiento acotado",
    "as.jobs.runDescription": "Se ejecutará un reconocimiento limitado al alcance del trabajo. El servidor revalida el alcance, el modo y la autorización antes de enviar tráfico.",
    "as.jobs.runConfirm": "Ejecutar ahora",
    "as.jobs.runDone": "Descubrimiento completado",
    "as.jobs.discovered": "activos",
    "as.jobs.runFailed": "No se pudo ejecutar el descubrimiento",
    "as.jobs.form.title": "Nuevo trabajo de descubrimiento",
    "as.jobs.form.name": "Nombre",
    "as.jobs.form.mode": "Modo",
    "as.jobs.form.scope": "Alcance CIDR",
    "as.jobs.form.scopeHint": "Separado por comas, máximo 16 rangos",
    "as.jobs.form.authorizedBy": "Autorizado por",
    "as.jobs.form.authRef": "Referencia de autorización",
    "as.jobs.form.authRefHint": "Obligatoria para modo activo (ticket o documento de autorización)",
    "as.jobs.form.authRequired": "La referencia de autorización es obligatoria en modo activo",
    "as.jobs.form.scopeRequired": "El modo activo requiere al menos un rango CIDR",
    "as.jobs.form.scopeTooMany": "Máximo 16 rangos CIDR",
    "as.jobs.form.submit": "Crear trabajo",
    "as.jobs.form.success": "Trabajo creado",
    "as.jobs.form.failed": "No se pudo crear el trabajo",
    "as.jobs.loadFailed": "No se pudieron cargar los trabajos",
    "as.jobs.ports": "Puertos",
    "as.jobs.portsHint": "Lista separada por comas (opcional, máx. 32)",
    "as.findingStatus.open": "Abierto",
    "as.findingStatus.triaged": "Triado",
    "as.findingStatus.accepted": "Aceptado",
    "as.findingStatus.resolved": "Resuelto",
    "as.findingStatus.false_positive": "Falso positivo",
  },
  en: {
    "as.eyebrow": "Exposure · Attack surface",
    "as.title": "Attack surface",
    "as.subtitle": "Exposure findings derived from inventory, bounded analysis and authorized discovery jobs.",
    "as.analyze": "Analyze inventory",
    "as.analyzeHint": "Walks the inventory and creates findings deduplicated by kind.",
    "as.analyzed": "Analysis completed",
    "as.analyzeFailed": "Could not run the analysis",
    "as.analyzedDetail": "assets analysed",
    "as.kpi.total": "Findings",
    "as.kpi.critical": "Critical / high",
    "as.kpi.open": "Open",
    "as.kpi.kinds": "Distinct kinds",
    "as.bySeverity": "Findings by severity",
    "as.byKind": "Findings by kind",
    "as.byStatus": "Findings by status",
    "as.noSummary": "No summary available",
    "as.search": "Search by title or evidence…",
    "as.filter.severity": "Severity",
    "as.filter.status": "Status",
    "as.filter.kind": "Kind",
    "as.filter.allSeverities": "All severities",
    "as.filter.allStatuses": "All statuses",
    "as.filter.allKinds": "All kinds",
    "as.filter.clear": "Clear filters",
    "as.table.finding": "Finding",
    "as.table.kind": "Kind",
    "as.table.severity": "Severity",
    "as.table.status": "Status",
    "as.table.asset": "Asset",
    "as.table.firstSeen": "First seen",
    "as.table.lastSeen": "Last seen",
    "as.table.source": "Source",
    "as.table.actions": "Actions",
    "as.table.view": "View detail",
    "as.count": "findings",
    "as.empty.title": "No attack-surface findings",
    "as.empty.description": "Run the inventory analysis or register a manual finding to get started.",
    "as.empty.action": "Analyze inventory",
    "as.noResults.title": "No finding matches",
    "as.noResults.description": "Adjust the filters or clear the search.",
    "as.new": "New finding",
    "as.loadFailed": "Could not load findings",
    "as.detail.title": "Finding detail",
    "as.detail.kind": "Kind",
    "as.detail.source": "Source",
    "as.detail.firstSeen": "First seen",
    "as.detail.lastSeen": "Last seen",
    "as.detail.asset": "Affected asset",
    "as.detail.assetLink": "Open asset",
    "as.detail.noAsset": "No asset assigned",
    "as.detail.evidence": "Evidence",
    "as.detail.noEvidence": "No evidence recorded",
    "as.detail.metadata": "Metadata",
    "as.detail.status": "Finding status",
    "as.detail.update": "Update status",
    "as.detail.updated": "Finding status updated",
    "as.detail.updateFailed": "Could not update the status",
    "as.detail.loadError": "Could not load the finding",
    "as.form.title": "Register finding",
    "as.form.titleLabel": "Title",
    "as.form.kind": "Kind",
    "as.form.kindHint": "lowercase, digits and underscore (e.g. exposed_service)",
    "as.form.severity": "Severity",
    "as.form.status": "Status",
    "as.form.source": "Source",
    "as.form.evidence": "Evidence",
    "as.form.asset": "Affected asset",
    "as.form.assetSearch": "Search assets by name or key…",
    "as.form.assetNone": "No asset",
    "as.form.submit": "Create finding",
    "as.form.success": "Finding created",
    "as.form.failed": "Could not create the finding",
    "as.form.invalidKind": "Invalid kind",
    "as.form.required": "Required",
    "as.jobs.title": "Discovery",
    "as.jobs.subtitle": "Passive discovery by default; active probing requires written authorization and bounded scope.",
    "as.jobs.new": "New job",
    "as.jobs.safety": "OT/ICS assets are discovered passively only. Active discovery is bounded, authorized reconnaissance against the listed CIDR ranges; it does not exploit vulnerabilities or modify systems.",
    "as.jobs.table.name": "Job",
    "as.jobs.table.mode": "Mode",
    "as.jobs.table.status": "Status",
    "as.jobs.table.scope": "Scope",
    "as.jobs.table.auth": "Authorization",
    "as.jobs.table.lastRun": "Last run",
    "as.jobs.table.actions": "Actions",
    "as.jobs.run": "Run",
    "as.jobs.runBlocked": "Add an authorization reference to the job before running it.",
    "as.jobs.empty": "No discovery jobs",
    "as.jobs.emptyHint": "Create a passive job to observe the network without generating active traffic.",
    "as.jobs.mode.passive": "Passive",
    "as.jobs.mode.active": "Active",
    "as.jobs.status.pending": "Pending",
    "as.jobs.status.running": "Running",
    "as.jobs.status.completed": "Completed",
    "as.jobs.status.failed": "Failed",
    "as.jobs.runTitle": "Run bounded discovery",
    "as.jobs.runDescription": "A reconnaissance run limited to the job scope will start. The server re-validates scope, mode and authorization before sending traffic.",
    "as.jobs.runConfirm": "Run now",
    "as.jobs.runDone": "Discovery completed",
    "as.jobs.discovered": "assets",
    "as.jobs.runFailed": "Could not run the discovery",
    "as.jobs.form.title": "New discovery job",
    "as.jobs.form.name": "Name",
    "as.jobs.form.mode": "Mode",
    "as.jobs.form.scope": "CIDR scope",
    "as.jobs.form.scopeHint": "Comma separated, max. 16 ranges",
    "as.jobs.form.authorizedBy": "Authorized by",
    "as.jobs.form.authRef": "Authorization reference",
    "as.jobs.form.authRefHint": "Required for active mode (ticket or authorization document)",
    "as.jobs.form.authRequired": "Authorization reference is required in active mode",
    "as.jobs.form.scopeRequired": "Active mode requires at least one CIDR range",
    "as.jobs.form.scopeTooMany": "Maximum 16 CIDR ranges",
    "as.jobs.form.submit": "Create job",
    "as.jobs.form.success": "Job created",
    "as.jobs.form.failed": "Could not create the job",
    "as.jobs.loadFailed": "Could not load discovery jobs",
    "as.jobs.ports": "Ports",
    "as.jobs.portsHint": "Comma separated (optional, max. 32)",
    "as.findingStatus.open": "Open",
    "as.findingStatus.triaged": "Triaged",
    "as.findingStatus.accepted": "Accepted",
    "as.findingStatus.resolved": "Resolved",
    "as.findingStatus.false_positive": "False positive",
  },
} as const;

export const FINDING_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const FINDING_STATUSES = ["open", "triaged", "accepted", "resolved", "false_positive"] as const;
export function copyOr(copy: (key: string) => string, key: string, fallback: string): string {
  const translated = copy(key);
  return translated === key ? fallback : translated;
}

interface FindingDraft {
  title: string;
  kind: string;
  severity: string;
  status: string;
  source: string;
  evidence: string;
}

interface JobDraft {
  name: string;
  mode: "passive" | "active";
  scope: string;
  authorized_by: string;
  authorization_reference: string;
}

export function AttackSurfacePage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const canWrite = can("attack_surface:write");

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [kind, setKind] = useState("");
  const [page, setPage] = useState(1);
  const debouncedSearch = useDebouncedValue(search);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedStatus, setSelectedStatus] = useState("open");

  const [createOpen, setCreateOpen] = useState(false);
  const [draft, setDraft] = useState<FindingDraft>({ title: "", kind: "", severity: "medium", status: "open", source: "manual", evidence: "" });
  const [createErrors, setCreateErrors] = useState<Record<string, string>>({});
  const [assetSearch, setAssetSearch] = useState("");
  const [assetId, setAssetId] = useState("");
  const debouncedAssetSearch = useDebouncedValue(assetSearch, 300);

  const [jobOpen, setJobOpen] = useState(false);
  const [jobDraft, setJobDraft] = useState<JobDraft>({ name: "", mode: "passive", scope: "", authorized_by: "", authorization_reference: "" });
  const [jobErrors, setJobErrors] = useState<Record<string, string>>({});
  const [runTarget, setRunTarget] = useState<DiscoveryJob | null>(null);

  const summaryQuery = useQuery({
    queryKey: ["attack-surface", "summary"],
    queryFn: () => api.get<FindingSummary>("/attack-surface/summary"),
  });

  const findingsQuery = useQuery({
    queryKey: ["attack-surface", "findings", { page, search: debouncedSearch, severity, status, kind }],
    queryFn: () =>
      api.get<Page<Finding>>("/attack-surface/findings", {
        page,
        page_size: 25,
        q: debouncedSearch || undefined,
        severity: severity || undefined,
        status: status || undefined,
        kind: kind || undefined,
        sort: "last_seen",
        order: "desc",
      }),
  });

  const jobsQuery = useQuery({
    queryKey: ["attack-surface", "jobs"],
    queryFn: () => api.get<Page<DiscoveryJob>>("/attack-surface/discovery-jobs", { page: 1, page_size: 25 }),
  });

  const detailQuery = useQuery({
    queryKey: ["attack-surface", "finding", selectedId],
    queryFn: () => api.get<Finding>(`/attack-surface/findings/${selectedId}`),
    enabled: selectedId !== null,
  });

  const assetSearchQuery = useQuery({
    queryKey: ["assets", "finding-target", debouncedAssetSearch],
    queryFn: () => api.get<Page<Asset>>("/assets", { q: debouncedAssetSearch, page: 1, page_size: 8 }),
    enabled: createOpen && debouncedAssetSearch.trim().length >= 2,
  });

  const analyzeMutation = useMutation({
    mutationFn: () => api.post<AnalyzeResult>("/attack-surface/analyze"),
    onSuccess: (result) => {
      push(
        `${c("as.analyzed")}: ${result.scanned_assets} ${c("as.analyzedDetail")} · +${result.created} / ~${result.updated}`,
        "success",
      );
      void queryClient.invalidateQueries({ queryKey: ["attack-surface"] });
    },
    onError: (error) => push(`${c("as.analyzeFailed")}: ${errorMessage(error)}`, "error"),
  });

  const updateStatus = useMutation({
    mutationFn: ({ id, next }: { id: string; next: string }) =>
      api.patch<Finding>(`/attack-surface/findings/${id}`, { status: next }),
    onSuccess: (finding) => {
      push(c("as.detail.updated"), "success");
      setSelectedStatus(finding.status);
      void queryClient.invalidateQueries({ queryKey: ["attack-surface"] });
    },
    onError: (error) => push(`${c("as.detail.updateFailed")}: ${errorMessage(error)}`, "error"),
  });

  const createFinding = useMutation({
    mutationFn: () =>
      api.post<Finding>("/attack-surface/findings", {
        title: draft.title.trim(),
        kind: draft.kind.trim(),
        severity: draft.severity,
        status: draft.status,
        source: draft.source.trim() || "manual",
        evidence: draft.evidence.trim() ? draft.evidence.trim() : null,
        asset_id: assetId || null,
      }),
    onSuccess: () => {
      push(c("as.form.success"), "success");
      setCreateOpen(false);
      setDraft({ title: "", kind: "", severity: "medium", status: "open", source: "manual", evidence: "" });
      setAssetId("");
      setAssetSearch("");
      setCreateErrors({});
      void queryClient.invalidateQueries({ queryKey: ["attack-surface"] });
    },
    onError: (error) => {
      setCreateErrors(fieldErrors(error));
      push(`${c("as.form.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const createJob = useMutation({
    mutationFn: () =>
      api.post<DiscoveryJob>("/attack-surface/discovery-jobs", {
        name: jobDraft.name.trim(),
        mode: jobDraft.mode,
        scope_cidrs: jobDraft.scope
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean),
        authorized_by: jobDraft.authorized_by.trim() || null,
        authorization_reference: jobDraft.authorization_reference.trim() || null,
      }),
    onSuccess: () => {
      push(c("as.jobs.form.success"), "success");
      setJobOpen(false);
      setJobDraft({ name: "", mode: "passive", scope: "", authorized_by: "", authorization_reference: "" });
      setJobErrors({});
      void queryClient.invalidateQueries({ queryKey: ["attack-surface", "jobs"] });
    },
    onError: (error) => {
      setJobErrors(fieldErrors(error));
      push(`${c("as.jobs.form.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const runJob = useMutation({
    mutationFn: (jobId: string) =>
      apiRequest<DiscoveryRunResult>(`/attack-surface/discovery-jobs/${jobId}/run`, {
        method: "POST",
        body: { ports: [] },
        timeoutMs: 120_000,
      }),
    onSuccess: (result) => {
      const summary = result.summary as { discovered?: number; hosts?: number; error?: string } | null;
      push(
        `${c("as.jobs.runDone")}${summary && typeof summary.discovered === "number" ? ` · ${summary.discovered} ${c("as.jobs.discovered")}` : ""}`,
        "success",
      );
      setRunTarget(null);
      void queryClient.invalidateQueries({ queryKey: ["attack-surface", "jobs"] });
    },
    onError: (error) => push(`${c("as.jobs.runFailed")}: ${errorMessage(error)}`, "error"),
  });

  if (findingsQuery.isLoading && !findingsQuery.data) return <PageSkeleton />;

  const summary = summaryQuery.data;
  const rows = findingsQuery.data?.items ?? [];
  const jobs = jobsQuery.data?.items ?? [];
  const filtersActive = Boolean(debouncedSearch || severity || status || kind);
  const selectedFinding = detailQuery.data ?? null;

  const applyFilter = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setPage(1);
  };

  const clearFilters = () => {
    setSearch("");
    setSeverity("");
    setStatus("");
    setKind("");
    setPage(1);
  };

  const openDetail = (finding: Finding) => {
    setSelectedId(finding.id);
    setSelectedStatus(finding.status);
  };

  const kindOptions = Object.keys(summary?.by_kind ?? {}).sort();

  const columns: Column<Finding>[] = [
    {
      key: "finding",
      header: c("as.table.finding"),
      render: (row) => (
        <div style={{ minWidth: 220 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.title}</div>
          <div className="chip-row" style={{ marginTop: 4 }}>
            <span className="tag">{row.kind}</span>
            <span className="tag">{row.source}</span>
          </div>
        </div>
      ),
    },
    { key: "severity", header: c("as.table.severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "status",
      header: c("as.table.status"),
      width: "132px",
      render: (row) => <StatusBadge status={row.status} label={copyOr(c, `as.findingStatus.${row.status}`, humanize(row.status))} />,
    },
    {
      key: "asset",
      header: c("as.table.asset"),
      width: "150px",
      render: (row) =>
        row.asset_id ? (
          <Link
            to={`/assets/${row.asset_id}`}
            className="mono"
            style={{ fontSize: 10.5 }}
            onClick={(event) => event.stopPropagation()}
          >
            {row.asset_id.slice(0, 8)}…
          </Link>
        ) : (
          <span className="dim" style={{ fontSize: 11 }}>—</span>
        ),
    },
    {
      key: "first_seen",
      header: c("as.table.firstSeen"),
      width: "124px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.first_seen, lang)}</span>,
    },
    {
      key: "last_seen",
      header: c("as.table.lastSeen"),
      width: "116px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{relativeTime(row.last_seen, lang)}</span>,
    },
    {
      key: "actions",
      header: c("as.table.actions"),
      width: "68px",
      align: "right",
      render: (row) => (
        <Button
          size="sm"
          variant="ghost"
          icon={ArrowUpRight}
          aria-label={c("as.table.view")}
          onClick={(event) => {
            event.stopPropagation();
            openDetail(row);
          }}
        />
      ),
    },
  ];

  const jobColumns: Column<DiscoveryJob>[] = [
    {
      key: "name",
      header: c("as.jobs.table.name"),
      render: (row) => (
        <div>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.name}</div>
          <div className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{row.id.slice(0, 8)}…</div>
        </div>
      ),
    },
    {
      key: "mode",
      header: c("as.jobs.table.mode"),
      width: "104px",
      render: (row) => (
        <Badge tone={row.mode === "active" ? "warning" : "success"}>{copyOr(c, `as.jobs.mode.${row.mode}`, humanize(row.mode))}</Badge>
      ),
    },
    {
      key: "status",
      header: c("as.jobs.table.status"),
      width: "124px",
      render: (row) => <StatusBadge status={row.status} label={copyOr(c, `as.jobs.status.${row.status}`, humanize(row.status))} />,
    },
    {
      key: "scope",
      header: c("as.jobs.table.scope"),
      width: "180px",
      render: (row) =>
        row.scope_cidrs.length ? (
          <div className="mono" style={{ fontSize: 10.5 }}>
            <div>{row.scope_cidrs.slice(0, 2).join(", ")}</div>
            {row.scope_cidrs.length > 2 ? <div style={{ color: "var(--dim)" }}>+{row.scope_cidrs.length - 2}</div> : null}
          </div>
        ) : (
          <span className="dim" style={{ fontSize: 11 }}>—</span>
        ),
    },
    {
      key: "auth",
      header: c("as.jobs.table.auth"),
      width: "150px",
      render: (row) =>
        row.authorization_reference ? (
          <div>
            <div style={{ fontSize: 11 }}>{row.authorization_reference}</div>
            {row.authorized_by ? <div style={{ fontSize: 10, color: "var(--dim)" }}>{row.authorized_by}</div> : null}
          </div>
        ) : (
          <Badge tone={row.mode === "active" ? "danger" : "neutral"}>—</Badge>
        ),
    },
    {
      key: "last_run",
      header: c("as.jobs.table.lastRun"),
      width: "130px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5 }}>
          {row.finished_at ?? row.started_at ? relativeTime(row.finished_at ?? row.started_at ?? "", lang) : "—"}
        </span>
      ),
    },
    {
      key: "actions",
      header: c("as.jobs.table.actions"),
      width: "90px",
      align: "right",
      render: (row) => {
        const blocked = row.mode === "active" && !row.authorization_reference;
        return (
          <Button
            size="sm"
            variant="ghost"
            icon={Play}
            disabled={blocked || row.status === "running" || !canWrite}
            title={blocked ? c("as.jobs.runBlocked") : c("as.jobs.run")}
            onClick={() => setRunTarget(row)}
            data-testid={`run-job-${row.id}`}
          >
            {c("as.jobs.run")}
          </Button>
        );
      },
    },
  ];

  return (
    <div className="animate-in" data-testid="page-attack-surface">
      <PageHeader
        eyebrow={c("as.eyebrow")}
        title={c("as.title")}
        subtitle={c("as.subtitle")}
        actions={
          <>
            <Button icon={RefreshCw} onClick={() => void findingsQuery.refetch()} aria-label={t("common.refresh")} />
            {canWrite ? (
              <>
                <Button
                  icon={ScanLine}
                  loading={analyzeMutation.isPending}
                  onClick={() => analyzeMutation.mutate()}
                  title={c("as.analyzeHint")}
                  data-testid="analyze-inventory"
                >
                  {c("as.analyze")}
                </Button>
                <Button variant="primary" icon={Plus} onClick={() => { setCreateErrors({}); setCreateOpen(true); }} data-testid="open-create-finding">
                  {c("as.new")}
                </Button>
              </>
            ) : null}
          </>
        }
      />

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        {summary ? (
          <>
            <Kpi
              label={c("as.kpi.total")}
              value={formatNumber(summary.total)}
              icon={Crosshair}
              tone="accent"
              footer={<span>{formatNumber(Object.keys(summary.by_kind).length)} {c("as.kpi.kinds").toLowerCase()}</span>}
            />
            <Kpi
              label={c("as.kpi.critical")}
              value={formatNumber((summary.by_severity.critical ?? 0) + (summary.by_severity.high ?? 0))}
              icon={ShieldAlert}
              tone="danger"
              footer={
                <span>
                  {formatNumber(summary.by_severity.critical ?? 0)} {t("common.critical").toLowerCase()} ·{" "}
                  {formatNumber(summary.by_severity.high ?? 0)} {t("common.high").toLowerCase()}
                </span>
              }
            />
            <Kpi
              label={c("as.kpi.open")}
              value={formatNumber((summary.by_status.open ?? 0) + (summary.by_status.triaged ?? 0))}
              icon={Zap}
              tone="warning"
              footer={<span>{formatNumber(summary.by_status.resolved ?? 0)} {t("common.closed").toLowerCase()}</span>}
            />
            <Kpi
              label={c("as.kpi.kinds")}
              value={formatNumber(Object.keys(summary.by_kind).length)}
              icon={Radar}
              tone="success"
              footer={<span>{formatNumber(Object.keys(summary.by_status).length)} {c("as.byStatus").toLowerCase()}</span>}
            />
          </>
        ) : summaryQuery.isError ? (
          <div style={{ gridColumn: "1 / -1" }}>
            <ErrorBanner compact message={errorMessage(summaryQuery.error)} onRetry={() => void summaryQuery.refetch()} />
          </div>
        ) : null}
      </div>

      <div className="split-main" style={{ marginBottom: 12 }}>
        <Card
          title={c("as.title")}
          subtitle={findingsQuery.data ? `${formatNumber(findingsQuery.data.meta.total)} ${c("as.count")}` : undefined}
          bodyClassName=""
        >
          <FilterBar ariaLabel={t("common.filters")}>
            <SearchInput value={search} onChange={applyFilter(setSearch)} placeholder={c("as.search")} ariaLabel={c("as.search")} />
            <Select value={severity} onChange={(event) => applyFilter(setSeverity)(event.target.value)} aria-label={c("as.filter.severity")} data-testid="filter-severity">
              <option value="">{c("as.filter.allSeverities")}</option>
              {FINDING_SEVERITIES.map((value) => (
                <option key={value} value={value}>{t(`common.${value}`)}</option>
              ))}
            </Select>
            <Select value={status} onChange={(event) => applyFilter(setStatus)(event.target.value)} aria-label={c("as.filter.status")} data-testid="filter-status">
              <option value="">{c("as.filter.allStatuses")}</option>
              {FINDING_STATUSES.map((value) => (
                <option key={value} value={value}>{copyOr(c, `as.findingStatus.${value}`, humanize(value))}</option>
              ))}
            </Select>
            <Select value={kind} onChange={(event) => applyFilter(setKind)(event.target.value)} aria-label={c("as.filter.kind")} data-testid="filter-kind">
              <option value="">{c("as.filter.allKinds")}</option>
              {kindOptions.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </Select>
            {filtersActive ? (
              <Button size="sm" variant="ghost" onClick={clearFilters} data-testid="clear-filters">
                {c("as.filter.clear")}
              </Button>
            ) : null}
          </FilterBar>

          <div data-testid="table-findings">
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(row) => row.id}
              onRowClick={openDetail}
              error={
                findingsQuery.isError ? (
                  <ErrorBanner
                    title={c("as.loadFailed")}
                    message={errorMessage(findingsQuery.error)}
                    onRetry={() => void findingsQuery.refetch()}
                  />
                ) : undefined
              }
              empty={
                filtersActive ? (
                  <EmptyState
                    icon={Crosshair}
                    title={c("as.noResults.title")}
                    description={c("as.noResults.description")}
                    action={<Button size="sm" variant="primary" onClick={clearFilters}>{c("as.filter.clear")}</Button>}
                  />
                ) : (
                  <EmptyState
                    icon={ShieldCheck}
                    title={c("as.empty.title")}
                    description={c("as.empty.description")}
                    action={
                      canWrite ? (
                        <Button size="sm" variant="primary" icon={ScanLine} onClick={() => analyzeMutation.mutate()} loading={analyzeMutation.isPending}>
                          {c("as.empty.action")}
                        </Button>
                      ) : undefined
                    }
                  />
                )
              }
            />
          </div>
          <Pagination meta={findingsQuery.data?.meta} onPage={setPage} />
        </Card>

        <Card title={c("as.bySeverity")}>
          {summary ? (
            <div className="stack">
              <div className="metric-list">
                {FINDING_SEVERITIES.map((value) => (
                  <div className="metric-row" key={value}>
                    <span className="metric-label"><SeverityBadge severity={value} /></span>
                    <span className="metric-value">{formatNumber(summary.by_severity[value] ?? 0)}</span>
                  </div>
                ))}
              </div>
              <div className="divider" />
              <div className="metric-list">
                {FINDING_STATUSES.map((value) => (
                  <div className="metric-row" key={value}>
                    <span className="metric-label">{copyOr(c, `as.findingStatus.${value}`, humanize(value))}</span>
                    <span className="metric-value">{formatNumber(summary.by_status[value] ?? 0)}</span>
                  </div>
                ))}
              </div>
              <div className="divider" />
              <div>
                <div className="section-label">{c("as.byKind")}</div>
                {Object.keys(summary.by_kind).length ? (
                  <div className="metric-list">
                    {Object.entries(summary.by_kind)
                      .sort((a, b) => b[1] - a[1])
                      .slice(0, 8)
                      .map(([key, value]) => (
                        <div className="metric-row" key={key}>
                          <span className="metric-label"><span className="tag">{key}</span></span>
                          <span className="metric-value">{formatNumber(value)}</span>
                        </div>
                      ))}
                  </div>
                ) : (
                  <span className="dim" style={{ fontSize: 11.5 }}>{c("as.noSummary")}</span>
                )}
              </div>
            </div>
          ) : (
            <EmptyState icon={Radar} title={c("as.noSummary")} />
          )}
        </Card>
      </div>

      <div className="notice notice-warning" style={{ marginBottom: 12 }}>
        <ShieldAlert size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
        <span>{c("as.jobs.safety")}</span>
      </div>

      <Card
        title={c("as.jobs.title")}
        actions={
          canWrite ? (
            <Button size="sm" icon={Plus} onClick={() => { setJobErrors({}); setJobOpen(true); }} data-testid="open-create-job">
              {c("as.jobs.new")}
            </Button>
          ) : undefined
        }
        bodyClassName=""
      >
        <div style={{ padding: "10px 12px", borderBottom: "1px solid var(--border)", fontSize: 11.5, color: "var(--dim)" }}>
          {c("as.jobs.subtitle")}
        </div>
        <div data-testid="table-jobs">
          <DataTable
            columns={jobColumns}
            rows={jobs}
            rowKey={(row) => row.id}
            loading={jobsQuery.isLoading}
            error={
              jobsQuery.isError ? (
                <ErrorBanner
                  title={c("as.jobs.loadFailed")}
                  message={errorMessage(jobsQuery.error)}
                  onRetry={() => void jobsQuery.refetch()}
                />
              ) : undefined
            }
            empty={
              <EmptyState
                icon={Radar}
                title={c("as.jobs.empty")}
                description={c("as.jobs.emptyHint")}
                action={
                  canWrite ? (
                    <Button size="sm" variant="primary" icon={Plus} onClick={() => setJobOpen(true)}>
                      {c("as.jobs.new")}
                    </Button>
                  ) : undefined
                }
              />
            }
          />
        </div>
      </Card>

      <Modal
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        title={c("as.detail.title")}
        size="lg"
        footer={
          selectedFinding?.asset_id ? (
            <LinkButton to={`/assets/${selectedFinding.asset_id}`} icon={ArrowUpRight}>
              {c("as.detail.assetLink")}
            </LinkButton>
          ) : undefined
        }
      >
        {detailQuery.isLoading ? (
          <p className="muted" style={{ fontSize: 12 }}>{t("common.loading")}</p>
        ) : detailQuery.isError ? (
          <ErrorBanner
            title={c("as.detail.loadError")}
            message={errorMessage(detailQuery.error)}
            onRetry={() => void detailQuery.refetch()}
          />
        ) : selectedFinding ? (
          <div className="stack">
            <div className="row wrap" style={{ gap: 6 }}>
              <SeverityBadge severity={selectedFinding.severity} />
              <StatusBadge status={selectedFinding.status} label={copyOr(c, `as.findingStatus.${selectedFinding.status}`, humanize(selectedFinding.status))} />
              <span className="tag">{selectedFinding.kind}</span>
              <span className="tag">{selectedFinding.source}</span>
            </div>
            <h3 style={{ fontSize: 15 }}>{selectedFinding.title}</h3>
            <div className="grid-2">
              <div className="metric-list">
                <div className="metric-row"><span className="metric-label">{c("as.detail.firstSeen")}</span><span className="metric-value">{formatDateTime(selectedFinding.first_seen, lang)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("as.detail.lastSeen")}</span><span className="metric-value">{formatDateTime(selectedFinding.last_seen, lang)}</span></div>
                <div className="metric-row">
                  <span className="metric-label">{c("as.detail.asset")}</span>
                  <span className="metric-value">
                    {selectedFinding.asset_id ? (
                      <Link to={`/assets/${selectedFinding.asset_id}`} className="mono" style={{ fontSize: 10.5 }}>
                        {selectedFinding.asset_id}
                      </Link>
                    ) : (
                      c("as.detail.noAsset")
                    )}
                  </span>
                </div>
              </div>
              <div>
                <div className="section-label">{c("as.detail.status")}</div>
                {canWrite ? (
                  <div className="row wrap" style={{ gap: 8 }}>
                    <Select
                      value={selectedStatus}
                      onChange={(event) => setSelectedStatus(event.target.value)}
                      aria-label={c("as.detail.status")}
                      style={{ maxWidth: 190 }}
                      data-testid="finding-status-select"
                    >
                      {FINDING_STATUSES.map((value) => (
                        <option key={value} value={value}>{copyOr(c, `as.findingStatus.${value}`, humanize(value))}</option>
                      ))}
                    </Select>
                    <Button
                      variant="primary"
                      loading={updateStatus.isPending}
                      disabled={selectedStatus === selectedFinding.status}
                      onClick={() => updateStatus.mutate({ id: selectedFinding.id, next: selectedStatus })}
                      data-testid="submit-finding-status"
                    >
                      {c("as.detail.update")}
                    </Button>
                  </div>
                ) : (
                  <p className="muted" style={{ fontSize: 12 }}>{t("common.permissionDenied")}</p>
                )}
              </div>
            </div>
            <div>
              <div className="row-between">
                <div className="section-label" style={{ marginBottom: 0 }}>{c("as.detail.evidence")}</div>
                {selectedFinding.evidence ? <CopyButton text={selectedFinding.evidence} /> : null}
              </div>
              {selectedFinding.evidence ? (
                <pre className="code-block">{selectedFinding.evidence}</pre>
              ) : (
                <span className="dim" style={{ fontSize: 11.5 }}>{c("as.detail.noEvidence")}</span>
              )}
            </div>
            <div>
              <div className="row-between">
                <div className="section-label" style={{ marginBottom: 0 }}>{c("as.detail.metadata")}</div>
                <CopyButton text={JSON.stringify(selectedFinding.metadata, null, 2)} />
              </div>
              <JsonBlock value={selectedFinding.metadata} ariaLabel={c("as.detail.metadata")} />
            </div>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={c("as.form.title")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={createFinding.isPending}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              loading={createFinding.isPending}
              onClick={() => {
                const errors: Record<string, string> = {};
                if (!draft.title.trim()) errors.title = c("as.form.required");
                if (!/^[a-z0-9][a-z0-9_]{1,59}$/.test(draft.kind.trim())) errors.kind = c("as.form.invalidKind");
                setCreateErrors(errors);
                if (Object.keys(errors).length) return;
                createFinding.mutate();
              }}
              data-testid="submit-finding"
            >
              {c("as.form.submit")}
            </Button>
          </>
        }
      >
        <div className="form-grid">
          <div className="span-2"><Field label={c("as.form.titleLabel")} htmlFor="finding-title" required error={createErrors.title}>
            <Input
              id="finding-title"
              value={draft.title}
              maxLength={300}
              onChange={(event) => setDraft({ ...draft, title: event.target.value })}
              data-testid="input-finding-title"
            />
          </Field></div>
          <Field label={c("as.form.kind")} htmlFor="finding-kind" required hint={c("as.form.kindHint")} error={createErrors.kind}>
            <Input
              id="finding-kind"
              className="mono"
              value={draft.kind}
              maxLength={60}
              onChange={(event) => setDraft({ ...draft, kind: event.target.value })}
              data-testid="input-finding-kind"
            />
          </Field>
          <Field label={c("as.form.severity")} htmlFor="finding-severity">
            <Select id="finding-severity" value={draft.severity} onChange={(event) => setDraft({ ...draft, severity: event.target.value })}>
              {FINDING_SEVERITIES.map((value) => (
                <option key={value} value={value}>{t(`common.${value}`)}</option>
              ))}
            </Select>
          </Field>
          <Field label={c("as.form.status")} htmlFor="finding-status">
            <Select id="finding-status" value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>
              {FINDING_STATUSES.map((value) => (
                <option key={value} value={value}>{copyOr(c, `as.findingStatus.${value}`, humanize(value))}</option>
              ))}
            </Select>
          </Field>
          <Field label={c("as.form.source")} htmlFor="finding-source" error={createErrors.source}>
            <Input id="finding-source" value={draft.source} maxLength={80} onChange={(event) => setDraft({ ...draft, source: event.target.value })} />
          </Field>
          <div className="span-2"><Field label={c("as.form.asset")} error={createErrors.asset_id}>
            <div className="row wrap" style={{ gap: 8 }}>
              <div style={{ flex: 1, minWidth: 180 }}>
                <SearchInput value={assetSearch} onChange={setAssetSearch} placeholder={c("as.form.assetSearch")} ariaLabel={c("as.form.assetSearch")} />
              </div>
              <Button size="sm" variant="ghost" onClick={() => setAssetId("")} disabled={!assetId}>
                {c("as.form.assetNone")}
              </Button>
            </div>
            {assetId ? (
              <div className="notice notice-accent" style={{ marginTop: 8, fontSize: 11 }}>
                <span className="mono">{assetSearchQuery.data?.items.find((item) => item.id === assetId)?.name ?? assetId}</span>
              </div>
            ) : debouncedAssetSearch.trim().length >= 2 ? (
              <div className="metric-list" style={{ marginTop: 8, maxHeight: 170, overflowY: "auto" }}>
                {assetSearchQuery.isLoading ? (
                  <span className="dim" style={{ fontSize: 11 }}>{t("common.loading")}</span>
                ) : assetSearchQuery.isError ? (
                  <ErrorBanner compact message={errorMessage(assetSearchQuery.error)} onRetry={() => void assetSearchQuery.refetch()} />
                ) : (assetSearchQuery.data?.items ?? []).length === 0 ? (
                  <span className="dim" style={{ fontSize: 11 }}>{c("as.form.assetNone")}</span>
                ) : (
                  (assetSearchQuery.data?.items ?? []).map((asset) => (
                    <button
                      type="button"
                      key={asset.id}
                      className="list-item"
                      style={{ background: "transparent", border: "1px solid transparent", textAlign: "left", width: "100%", color: "inherit" }}
                      onClick={() => {
                        setAssetId(asset.id);
                        setAssetSearch(asset.name);
                      }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <div className="item-title">{asset.name}</div>
                        <div className="item-sub mono">{asset.asset_key} · {asset.kind}</div>
                      </div>
                    </button>
                  ))
                )}
              </div>
            ) : null}
          </Field></div>
          <div className="span-2"><Field label={c("as.form.evidence")} htmlFor="finding-evidence" error={createErrors.evidence}>
            <Textarea
              id="finding-evidence"
              className="mono"
              style={{ minHeight: 110, fontSize: 11.5 }}
              value={draft.evidence}
              maxLength={8000}
              onChange={(event) => setDraft({ ...draft, evidence: event.target.value })}
            />
          </Field></div>
        </div>
      </Modal>

      <Modal
        open={jobOpen}
        onClose={() => setJobOpen(false)}
        title={c("as.jobs.form.title")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setJobOpen(false)} disabled={createJob.isPending}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              loading={createJob.isPending}
              onClick={() => {
                const errors: Record<string, string> = {};
                if (!jobDraft.name.trim()) errors.name = c("as.form.required");
                const scopes = jobDraft.scope.split(",").map((value) => value.trim()).filter(Boolean);
                if (jobDraft.mode === "active" && scopes.length === 0) errors.scope_cidrs = c("as.jobs.form.scopeRequired");
                if (jobDraft.mode === "active" && !jobDraft.authorization_reference.trim()) {
                  errors.authorization_reference = c("as.jobs.form.authRequired");
                }
                if (scopes.length > 16) errors.scope_cidrs = c("as.jobs.form.scopeTooMany");
                setJobErrors(errors);
                if (Object.keys(errors).length) return;
                createJob.mutate();
              }}
              data-testid="submit-job"
            >
              {c("as.jobs.form.submit")}
            </Button>
          </>
        }
      >
        <div className="form-grid">
          <Field label={c("as.jobs.form.name")} htmlFor="job-name" required error={jobErrors.name}>
            <Input
              id="job-name"
              value={jobDraft.name}
              maxLength={200}
              onChange={(event) => setJobDraft({ ...jobDraft, name: event.target.value })}
              data-testid="input-job-name"
            />
          </Field>
          <Field label={c("as.jobs.form.mode")} htmlFor="job-mode">
            <Select
              id="job-mode"
              value={jobDraft.mode}
              onChange={(event) => setJobDraft({ ...jobDraft, mode: event.target.value as "passive" | "active" })}
              data-testid="input-job-mode"
            >
              <option value="passive">{c("as.jobs.mode.passive")}</option>
              <option value="active">{c("as.jobs.mode.active")}</option>
            </Select>
          </Field>
          <Field
            label={c("as.jobs.form.scope")}
            htmlFor="job-scope"
            hint={c("as.jobs.form.scopeHint")}
            error={jobErrors.scope_cidrs}
            required={jobDraft.mode === "active"}
          >
            <Input
              id="job-scope"
              className="mono"
              value={jobDraft.scope}
              placeholder="192.0.2.0/24"
              onChange={(event) => setJobDraft({ ...jobDraft, scope: event.target.value })}
              aria-invalid={Boolean(jobErrors.scope_cidrs)}
              data-testid="input-job-scope"
            />
          </Field>
          <Field label={c("as.jobs.form.authorizedBy")} htmlFor="job-authorized-by">
            <Input
              id="job-authorized-by"
              value={jobDraft.authorized_by}
              maxLength={120}
              onChange={(event) => setJobDraft({ ...jobDraft, authorized_by: event.target.value })}
            />
          </Field>
          <div className="span-2">
          <Field
            label={c("as.jobs.form.authRef")}
            htmlFor="job-auth-ref"
            hint={c("as.jobs.form.authRefHint")}
            error={jobErrors.authorization_reference}
            required={jobDraft.mode === "active"}
          >
            <Input
              id="job-auth-ref"
              value={jobDraft.authorization_reference}
              maxLength={200}
              onChange={(event) => setJobDraft({ ...jobDraft, authorization_reference: event.target.value })}
              aria-invalid={Boolean(jobErrors.authorization_reference)}
              data-testid="input-job-auth-ref"
            />
          </Field>
          </div>
        </div>
        {jobDraft.mode === "active" ? (
          <div className="notice notice-warning" style={{ marginTop: 12 }}>
            <ShieldAlert size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
            <span>{c("as.jobs.safety")}</span>
          </div>
        ) : null}
      </Modal>

      <ConfirmModal
        open={runTarget !== null}
        onClose={() => setRunTarget(null)}
        title={c("as.jobs.runTitle")}
        description={c("as.jobs.runDescription")}
        confirmLabel={c("as.jobs.runConfirm")}
        loading={runJob.isPending}
        danger={runTarget?.mode === "active"}
        onConfirm={() => {
          if (runTarget) runJob.mutate(runTarget.id);
        }}
      >
        {runTarget ? (
          <div className="metric-list">
            <div className="metric-row"><span className="metric-label">{c("as.jobs.table.name")}</span><span className="metric-value">{runTarget.name}</span></div>
            <div className="metric-row"><span className="metric-label">{c("as.jobs.table.mode")}</span><span className="metric-value">{copyOr(c, `as.jobs.mode.${runTarget.mode}`, humanize(runTarget.mode))}</span></div>
            <div className="metric-row"><span className="metric-label">{c("as.jobs.table.scope")}</span><span className="metric-value mono">{runTarget.scope_cidrs.join(", ") || "—"}</span></div>
            <div className="metric-row"><span className="metric-label">{c("as.jobs.table.auth")}</span><span className="metric-value">{runTarget.authorization_reference ?? "—"}</span></div>
          </div>
        ) : null}
      </ConfirmModal>
    </div>
  );
}

export default AttackSurfacePage;
