import { useId, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BadgeCheck,
  BookOpenCheck,
  ClipboardCheck,
  Download,
  FileText,
  Layers,
  Lock,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Upload,
  Wand2,
} from "lucide-react";
import { api, downloadFile, errorMessage, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy, type Lang } from "../lib/i18n";
import { formatDate, formatDateTime, formatNumber, humanize, relativeTime } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
  Field,
  Input,
  Modal,
  PageHeader,
  PageSkeleton,
  Pagination,
  ScoreRing,
  SearchInput,
  Select,
  StatusBadge,
  Tabs,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";
import {
  ConfirmDialog,
  MetaRows,
  daysAgoInput,
  localDateTimeInput,
  toIso,
} from "../components/features/govern/common";

/* --------------------------------------------------------------- contracts */

type TabKey = "frameworks" | "assessments" | "reports";

interface FrameworkSummary {
  id: string;
  code: string;
  name: string;
  version: string;
  jurisdiction: string;
  authority: string | null;
  effective_date: string | null;
  source_url: string | null;
  status: string;
  is_builtin: boolean;
  published_at: string | null;
  controls_count: number;
  technical_checks_count: number;
}

interface EvidenceRequirement {
  key: string;
  title: string;
  description: string;
}

interface TechnicalCheck {
  key: string;
  title: string;
  type: string;
  params: Record<string, unknown>;
  description: string;
}

interface FrameworkControl {
  id: string;
  control_id: string;
  title: string;
  description: string;
  category: string;
  weight: number;
  references: string[];
  evidence_requirements: EvidenceRequirement[];
  technical_checks: TechnicalCheck[];
  mapping: Record<string, unknown>;
}

interface FrameworkDetail extends FrameworkSummary {
  description: string | null;
  controls: FrameworkControl[];
}

interface FrameworkImportResult {
  framework: FrameworkSummary;
  created: boolean;
  checksum: string;
  format: "yaml" | "json";
  controls_imported: number;
}

interface FrameworkPosture {
  framework_id: string;
  framework_code: string;
  framework_name: string;
  framework_version: string;
  assessment_id: string | null;
  assessment_status: string | null;
  score: number | null;
  completed_at: string | null;
  controls_total: number;
  compliant: number;
  partial: number;
  non_compliant: number;
  not_applicable: number;
  not_assessed: number;
}

interface ComplianceSummary {
  organization_id: string;
  organization_name: string;
  generated_at: string;
  frameworks: FrameworkPosture[];
  assessed_frameworks: number;
  average_score: number | null;
  disclaimer: string;
}

interface AssessmentSummary {
  id: string;
  framework_id: string;
  framework_code: string;
  framework_name: string;
  framework_version: string;
  status: string;
  score: number;
  assessor: string | null;
  started_at: string;
  completed_at: string | null;
  summary: string | null;
  gaps_count: number;
  created_at: string;
}

interface ControlStatus {
  id: string;
  control_id: string;
  control_code: string;
  title: string;
  category: string;
  status: string;
  weight: number;
  notes: string | null;
  owner: string | null;
  reviewed_at: string | null;
  reviewed_by: string | null;
  evidence_ids: string[];
  technical_checks: TechnicalCheck[];
}

interface ScoreBreakdown {
  total_controls: number;
  applicable_controls: number;
  compliant: number;
  partial: number;
  non_compliant: number;
  not_applicable: number;
  not_assessed: number;
  weighted_points: number;
  weighted_total: number;
  score: number;
  formula: string;
}

interface GapItem {
  control_status_id: string;
  control_id: string;
  control_code: string;
  title: string;
  category: string;
  status: string;
  severity: "critical" | "high" | "medium" | "low";
  weight: number;
  missing_checks: TechnicalCheck[];
  recommendation: string;
}

interface AssessmentDetail extends AssessmentSummary {
  controls: ControlStatus[];
  gaps: GapItem[];
  score_breakdown: ScoreBreakdown;
  disclaimer: string;
}

interface GapAnalysis {
  assessment_id: string;
  framework_code: string;
  framework_version: string;
  status: string;
  score: number;
  gap_count: number;
  gaps_by_severity: Record<string, number>;
  gaps: GapItem[];
  generated_at: string;
  disclaimer: string;
}

interface ReportSummary {
  id: string;
  kind: string;
  title: string;
  period_start: string | null;
  period_end: string | null;
  status: string;
  format: string;
  checksum: string;
  generated_by: string | null;
  generated_at: string;
  framework_id: string | null;
  metadata: Record<string, unknown>;
}

interface ReportDetail extends ReportSummary {
  content_md: string;
  content_html: string;
  disclaimer: string;
}

const REPORT_KINDS = ["executive", "technical", "regulatory", "incident"] as const;
const CONTROL_STATUSES = ["compliant", "partial", "non_compliant", "not_applicable"] as const;

/* -------------------------------------------------------------------- copy */

const COPY: Record<Lang, Record<string, string>> = {
  es: {
    eyebrow: "Gobierno · Cumplimiento",
    title: "Cumplimiento normativo",
    subtitle: "Catálogo de marcos, autoevaluaciones técnicas, brechas y informes trazables.",
    disclaimer:
      "Autoevaluación técnica — no es una certificación. Los resultados se derivan de evidencia de la plataforma y no constituyen una opinión de auditoría ni asesoramiento legal.",
    readOnly: "Tu rol permite consultar el cumplimiento, pero no modificarlo.",
    tabFrameworks: "Marcos",
    tabAssessments: "Evaluaciones",
    tabReports: "Informes",
    assessed: "Marcos evaluados",
    averageScore: "Puntuación media",
    frameworksCatalogued: "Marcos en catálogo",
    applicableControls: "Controles aplicables",
    frameworks: "Catálogo de marcos",
    frameworkSearch: "Buscar por código, nombre o autoridad…",
    jurisdiction: "Jurisdicción",
    statusFilter: "Estado",
    allVersions: "Todas las versiones",
    selectedFramework: "Marco seleccionado",
    chooseFramework: "Selecciona un marco del catálogo para ver sus controles y evidencias.",
    controls: "controles",
    technicalChecks: "comprobaciones técnicas",
    authority: "Autoridad",
    effectiveDate: "Entrada en vigor",
    publishedAt: "Publicado",
    builtin: "Integrado",
    imported: "Importado",
    version: "Versión",
    versions: "Versiones",
    versionsTitle: "Versiones del marco",
    importFramework: "Importar marco",
    importHint: "YAML o JSON versionado. Solo administradores de plataforma; se registra en auditoría con checksum.",
    importContent: "Contenido del documento",
    importFormat: "Formato",
    importFile: "Cargar archivo",
    importResult: "Marco importado",
    importCreated: "Creado",
    importExisting: "Ya existía; no se modificó",
    checksum: "Checksum",
    controlsImported: "Controles importados",
    description: "Descripción",
    category: "Categoría",
    weight: "Peso",
    evidenceRequirements: "Evidencias requeridas",
    noEvidenceRequirements: "Sin evidencias documentales definidas.",
    technicalChecksTitle: "Comprobaciones técnicas",
    noTechnicalChecks: "Sin comprobaciones automáticas.",
    references: "Referencias",
    controlsEmpty: "Este marco no tiene controles cargados.",
    assessments: "Evaluaciones",
    assessmentsHint: "Cada evaluación deriva el estado de los controles desde la evidencia viva de la plataforma.",
    newAssessment: "Nueva evaluación",
    assessmentFramework: "Marco",
    assessor: "Evaluador",
    createAssessment: "Crear evaluación",
    noAssessments: "Todavía no hay evaluaciones",
    noAssessmentsHint: "Crea una evaluación para medir la postura frente a un marco.",
    selectAssessment: "Selecciona una evaluación para revisar controles, puntuación y brechas.",
    score: "Puntuación",
    gaps: "Brechas",
    startedAt: "Iniciada",
    completedAt: "Completada",
    status: "Estado",
    inProgress: "En curso",
    completed: "Completada",
    archived: "Archivada",
    assessmentLocked: "La evaluación está cerrada; crea una nueva para reevaluar.",
    completeAssessment: "Cerrar evaluación",
    completeWarning:
      "Al cerrar la evaluación se congela la puntuación ponderada y el snapshot de brechas. Los controles dejarán de ser editables.",
    completeConfirm: "Cerrar y congelar",
    gapAnalysis: "Análisis de brechas",
    gapAnalysisHint: "Brechas calculadas con la evidencia técnica actual.",
    gapsBySeverity: "Brechas por severidad",
    noGaps: "No hay brechas abiertas para esta evaluación.",
    recommendation: "Recomendación",
    missingChecks: "Comprobaciones pendientes",
    breakdown: "Desglose de puntuación",
    formula: "Fórmula",
    weighted: "Puntuación ponderada",
    controlsTotal: "Controles",
    notAssessed: "Sin evaluar",
    controlDetail: "Detalle del control",
    editControl: "Actualizar control",
    controlStatus: "Estado del control",
    notes: "Notas",
    owner: "Responsable",
    evidenceIds: "IDs de evidencia",
    evidenceIdsHint: "UUIDs separados por comas; deben pertenecer a la organización. Se valida en el servidor.",
    evidenceInvalid: "Todos los valores deben ser UUID válidos.",
    saveControl: "Guardar control",
    reviewedAt: "Revisado",
    reviewedBy: "Revisado por",
    evidenceLinked: "Evidencias vinculadas",
    reportList: "Informes generados",
    reportSearch: "Buscar por título…",
    reportKind: "Tipo",
    generateReport: "Generar informe",
    reportPeriod: "Periodo",
    from: "Desde",
    to: "Hasta",
    generate: "Generar",
    noReports: "Sin informes generados",
    noReportsHint: "Genera un informe ejecutivo, técnico, regulatorio o de incidente desde datos reales.",
    reportPreview: "Vista previa del informe",
    preview: "Previsualizar",
    reportMetadata: "Metadatos",
    generatedBy: "Generado por",
    generatedAt: "Generado",
    downloadHtml: "Descargar HTML",
    downloadMarkdown: "Descargar Markdown",
    deleteReport: "Eliminar informe",
    deleteReportWarning:
      "El informe y su contenido firmado se eliminan de forma permanente. El evento queda registrado en la cadena de auditoría.",
    reportCreated: "Informe generado",
    reportDeleted: "Informe eliminado",
    reportDownloaded: "Descarga iniciada",
    kindExecutive: "Ejecutivo",
    kindTechnical: "Técnico",
    kindRegulatory: "Regulatorio",
    kindIncident: "Incidente",
    periodInvalid: "La fecha final debe ser posterior al inicio y el periodo no puede superar 366 días.",
    noPermission: "No tienes permiso para ver el cumplimiento.",
    noReportPermission: "No tienes permiso para ver informes.",
    loadFailed: "No se pudo cargar la información de cumplimiento.",
    filterClear: "Limpiar filtros",
    emptyFiltered: "Ningún marco coincide con los filtros.",
    loadMore: "Ver más",
    evidenceExpiredHint:
      "Las evidencias enlazadas se validan contra la organización en el servidor; una evidencia ajena se trata como inexistente.",
    noSelection: "Sin selección",
    directControls: "Controles del marco",
    assessmentLock: "Bloqueada",
    reasonOptional: "Confirmación",
  },
  en: {
    eyebrow: "Governance · Compliance",
    title: "Regulatory compliance",
    subtitle: "Framework catalogue, technical self-assessments, gaps and traceable reports.",
    disclaimer:
      "Technical self-assessment — not a certification. Results are derived from platform evidence and are not an audit opinion or legal advice.",
    readOnly: "Your role can read compliance but cannot change it.",
    tabFrameworks: "Frameworks",
    tabAssessments: "Assessments",
    tabReports: "Reports",
    assessed: "Assessed frameworks",
    averageScore: "Average score",
    frameworksCatalogued: "Catalogued frameworks",
    applicableControls: "Applicable controls",
    frameworks: "Framework catalogue",
    frameworkSearch: "Search by code, name or authority…",
    jurisdiction: "Jurisdiction",
    statusFilter: "Status",
    allVersions: "All versions",
    selectedFramework: "Selected framework",
    chooseFramework: "Select a framework from the catalogue to inspect its controls and evidence.",
    controls: "controls",
    technicalChecks: "technical checks",
    authority: "Authority",
    effectiveDate: "Effective date",
    publishedAt: "Published",
    builtin: "Built-in",
    imported: "Imported",
    version: "Version",
    versions: "Versions",
    versionsTitle: "Framework versions",
    importFramework: "Import framework",
    importHint: "Versioned YAML or JSON. Platform administrators only; recorded in the audit chain with a checksum.",
    importContent: "Document content",
    importFormat: "Format",
    importFile: "Load file",
    importResult: "Framework imported",
    importCreated: "Created",
    importExisting: "Already existed; unchanged",
    checksum: "Checksum",
    controlsImported: "Imported controls",
    description: "Description",
    category: "Category",
    weight: "Weight",
    evidenceRequirements: "Required evidence",
    noEvidenceRequirements: "No documentary evidence defined.",
    technicalChecksTitle: "Technical checks",
    noTechnicalChecks: "No automated checks.",
    references: "References",
    controlsEmpty: "This framework has no loaded controls.",
    assessments: "Assessments",
    assessmentsHint: "Each assessment derives control status from live platform evidence.",
    newAssessment: "New assessment",
    assessmentFramework: "Framework",
    assessor: "Assessor",
    createAssessment: "Create assessment",
    noAssessments: "No assessments yet",
    noAssessmentsHint: "Create an assessment to measure posture against a framework.",
    selectAssessment: "Select an assessment to review controls, score and gaps.",
    score: "Score",
    gaps: "Gaps",
    startedAt: "Started",
    completedAt: "Completed",
    status: "Status",
    inProgress: "In progress",
    completed: "Completed",
    archived: "Archived",
    assessmentLocked: "The assessment is closed; create a new one to re-evaluate.",
    completeAssessment: "Complete assessment",
    completeWarning:
      "Completing the assessment freezes the weighted score and gap snapshot. Controls become read-only.",
    completeConfirm: "Complete and freeze",
    gapAnalysis: "Gap analysis",
    gapAnalysisHint: "Gaps computed against current technical evidence.",
    gapsBySeverity: "Gaps by severity",
    noGaps: "No open gaps for this assessment.",
    recommendation: "Recommendation",
    missingChecks: "Missing checks",
    breakdown: "Score breakdown",
    formula: "Formula",
    weighted: "Weighted score",
    controlsTotal: "Controls",
    notAssessed: "Not assessed",
    controlDetail: "Control detail",
    editControl: "Update control",
    controlStatus: "Control status",
    notes: "Notes",
    owner: "Owner",
    evidenceIds: "Evidence IDs",
    evidenceIdsHint: "Comma-separated UUIDs owned by this organization. Validated server-side.",
    evidenceInvalid: "Every value must be a valid UUID.",
    saveControl: "Save control",
    reviewedAt: "Reviewed",
    reviewedBy: "Reviewed by",
    evidenceLinked: "Linked evidence",
    reportList: "Generated reports",
    reportSearch: "Search by title…",
    reportKind: "Kind",
    generateReport: "Generate report",
    reportPeriod: "Period",
    from: "From",
    to: "To",
    generate: "Generate",
    noReports: "No reports generated",
    noReportsHint: "Generate an executive, technical, regulatory or incident report from real data.",
    reportPreview: "Report preview",
    preview: "Preview",
    reportMetadata: "Metadata",
    generatedBy: "Generated by",
    generatedAt: "Generated",
    downloadHtml: "Download HTML",
    downloadMarkdown: "Download Markdown",
    deleteReport: "Delete report",
    deleteReportWarning:
      "The report and its signed content are permanently removed. The event remains in the audit chain.",
    reportCreated: "Report generated",
    reportDeleted: "Report deleted",
    reportDownloaded: "Download started",
    kindExecutive: "Executive",
    kindTechnical: "Technical",
    kindRegulatory: "Regulatory",
    kindIncident: "Incident",
    periodInvalid: "The end date must be after the start and the period cannot exceed 366 days.",
    noPermission: "You do not have permission to view compliance.",
    noReportPermission: "You do not have permission to view reports.",
    loadFailed: "Compliance data could not be loaded.",
    filterClear: "Clear filters",
    emptyFiltered: "No framework matches the filters.",
    loadMore: "Show more",
    evidenceExpiredHint:
      "Linked evidence is validated against this organization server-side; foreign evidence is treated as missing.",
    noSelection: "No selection",
    directControls: "Framework controls",
    assessmentLock: "Locked",
    reasonOptional: "Confirmation",
  },
};

function statusLabel(status: string, t: (key: string) => string): string {
  if (status === "in_progress") return t("inProgress");
  if (status === "completed") return t("completed");
  if (status === "archived") return t("archived");
  return humanize(status);
}

function reportKindLabel(kind: string, t: (key: string) => string): string {
  if (kind === "executive") return t("kindExecutive");
  if (kind === "technical") return t("kindTechnical");
  if (kind === "regulatory") return t("kindRegulatory");
  if (kind === "incident") return t("kindIncident");
  return humanize(kind);
}

/* --------------------------------------------------------------- frameworks */

function FrameworksTab({
  canWrite,
  isPlatformAdmin,
}: {
  canWrite: boolean;
  isPlatformAdmin: boolean;
}) {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [q, setQ] = useState("");
  const [jurisdiction, setJurisdiction] = useState("");
  const [status, setStatus] = useState("");
  const [allVersions, setAllVersions] = useState(false);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<{ code: string; version?: string } | null>(null);
  const [versionsOpen, setVersionsOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importContent, setImportContent] = useState("");
  const [importFormat, setImportFormat] = useState<"auto" | "yaml" | "json">("auto");
  const [importError, setImportError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<FrameworkImportResult | null>(null);

  const pageSize = 20;

  const listQuery = useQuery({
    queryKey: ["compliance", "frameworks", { q, jurisdiction, status, allVersions, page }],
    queryFn: () =>
      api.get<Page<FrameworkSummary>>("/compliance/frameworks", {
        page,
        page_size: pageSize,
        q: q || undefined,
        jurisdiction: jurisdiction || undefined,
        status: status || undefined,
        all_versions: allVersions || undefined,
      }),
  });

  const detailQuery = useQuery({
    queryKey: ["compliance", "framework", selected?.code, selected?.version],
    queryFn: () =>
      api.get<FrameworkDetail>(`/compliance/frameworks/${encodeURIComponent(selected?.code ?? "")}`, {
        version: selected?.version,
      }),
    enabled: selected !== null,
  });

  const versionsQuery = useQuery({
    queryKey: ["compliance", "framework", selected?.code, "versions"],
    queryFn: () => api.get<FrameworkSummary[]>(`/compliance/frameworks/${encodeURIComponent(selected?.code ?? "")}/versions`),
    enabled: versionsOpen && selected !== null,
  });

  const importMutation = useMutation({
    mutationFn: () =>
      api.post<FrameworkImportResult>("/compliance/frameworks/import", {
        content: importContent,
        format: importFormat,
      }),
    onSuccess: async (result) => {
      setImportResult(result);
      setImportError(null);
      toast.push(t("importResult"), "success");
      await queryClient.invalidateQueries({ queryKey: ["compliance"] });
    },
    onError: (error) => {
      setImportError(errorMessage(error));
    },
  });

  const columns: Column<FrameworkSummary>[] = [
    {
      key: "framework",
      header: t("frameworkSearch"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div className="row" style={{ gap: 6 }}>
            <span className="mono" style={{ color: "var(--accent)", fontSize: 10 }}>{row.code}</span>
            <span className="tag">v{row.version}</span>
            {row.is_builtin ? <Badge tone="neutral">{t("builtin")}</Badge> : <Badge tone="amber">{t("imported")}</Badge>}
          </div>
          <div className="primary-cell" style={{ marginTop: 2 }}>{row.name}</div>
          {row.authority ? <div className="cell-sub">{row.authority}</div> : null}
        </div>
      ),
    },
    {
      key: "jurisdiction",
      header: t("jurisdiction"),
      width: "110px",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.jurisdiction}</span>,
    },
    {
      key: "status",
      header: t("status"),
      width: "110px",
      render: (row) => (
        <Badge tone={row.status === "published" ? "success" : row.status === "draft" ? "warning" : "neutral"}>
          {humanize(row.status)}
        </Badge>
      ),
    },
    {
      key: "effective",
      header: t("effectiveDate"),
      width: "120px",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{formatDate(row.effective_date, lang)}</span>,
    },
    {
      key: "controls",
      header: t("controls"),
      width: "130px",
      align: "right",
      render: (row) => (
        <span className="mono" style={{ fontSize: 11 }}>
          {formatNumber(row.controls_count)} · {formatNumber(row.technical_checks_count)} {t("technicalChecks").slice(0, 3)}.
        </span>
      ),
    },
  ];

  const filtersActive = Boolean(q || jurisdiction || status || allVersions);

  return (
    <div className="stack" data-testid="compliance-frameworks">
      <Card
        title={t("frameworks")}
        subtitle={listQuery.data ? `${formatNumber(listQuery.data.meta.total)}` : undefined}
        actions={
          <div className="row wrap" style={{ gap: 6 }}>
            {canWrite && isPlatformAdmin ? (
              <Button
                size="sm"
                icon={Upload}
                onClick={() => {
                  setImportOpen(true);
                  setImportError(null);
                  setImportResult(null);
                }}
                data-testid="compliance-import-open"
              >
                {t("importFramework")}
              </Button>
            ) : null}
            <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("common.refresh")} onClick={() => void listQuery.refetch()} />
          </div>
        }
        bodyClassName=""
        footer={
          filtersActive ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setQ("");
                setJurisdiction("");
                setStatus("");
                setAllVersions(false);
                setPage(1);
              }}
            >
              {t("filterClear")}
            </Button>
          ) : undefined
        }
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap" style={{ gap: 8 }}>
            <div style={{ minWidth: 220, flex: 1 }}>
              <SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder={t("frameworkSearch")} ariaLabel={t("frameworkSearch")} />
            </div>
            <Input
              value={jurisdiction}
              onChange={(event) => { setJurisdiction(event.target.value.toUpperCase().slice(0, 80)); setPage(1); }}
              placeholder={t("jurisdiction")}
              aria-label={t("jurisdiction")}
              style={{ width: 130 }}
              data-testid="compliance-framework-jurisdiction"
            />
            <Select
              value={status}
              onChange={(event) => { setStatus(event.target.value); setPage(1); }}
              aria-label={t("statusFilter")}
              style={{ width: 140 }}
              data-testid="compliance-framework-status"
            >
              <option value="">{t("common.all")}</option>
              <option value="published">published</option>
              <option value="draft">draft</option>
              <option value="retired">retired</option>
            </Select>
            <label className="checkbox">
              <input type="checkbox" checked={allVersions} onChange={(event) => { setAllVersions(event.target.checked); setPage(1); }} />
              {t("allVersions")}
            </label>
          </div>
        </div>

        {listQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(listQuery.error)} onRetry={() => void listQuery.refetch()} />
          </div>
        ) : (
          <>
            <DataTable
              columns={columns}
              rows={listQuery.data?.items}
              rowKey={(row) => row.id}
              loading={listQuery.isLoading}
              onRowClick={(row) => setSelected({ code: row.code })}
              empty={
                <EmptyState
                  icon={BookOpenCheck}
                  title={filtersActive ? t("emptyFiltered") : t("noSelection")}
                  description={filtersActive ? t("filterClear") : t("importHint")}
                  action={filtersActive ? <Button size="sm" onClick={() => { setQ(""); setJurisdiction(""); setStatus(""); setAllVersions(false); }}>{t("filterClear")}</Button> : undefined}
                />
              }
            />
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={listQuery.data?.meta} onPage={setPage} />
            </div>
          </>
        )}
      </Card>

      {selected ? (
        <Card
          title={t("selectedFramework")}
          subtitle={detailQuery.data ? `${detailQuery.data.code} · v${detailQuery.data.version}` : undefined}
          actions={
            <>
              <Button size="sm" variant="ghost" icon={Layers} onClick={() => setVersionsOpen(true)} data-testid="compliance-framework-versions">
                {t("versions")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setSelected(null)} aria-label={t("common.close")}>
                {t("common.close")}
              </Button>
            </>
          }
        >
          <div data-testid="compliance-framework-detail">
          {detailQuery.isLoading ? (
            <div className="stack">
              <div className="skeleton skeleton-row" />
              <div className="skeleton skeleton-row" />
              <div className="skeleton skeleton-chart" />
            </div>
          ) : detailQuery.isError ? (
            <ErrorBanner message={errorMessage(detailQuery.error)} onRetry={() => void detailQuery.refetch()} />
          ) : detailQuery.data ? (
            <div className="stack">
              <div className="row-between wrap" style={{ alignItems: "flex-start" }}>
                <div>
                  <h3 style={{ fontSize: 16 }}>{detailQuery.data.name}</h3>
                  <div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>
                    {detailQuery.data.authority ?? t("authority")} · {detailQuery.data.jurisdiction}
                  </div>
                </div>
                <div className="row wrap">
                  <Badge tone={detailQuery.data.is_builtin ? "neutral" : "amber"}>
                    {detailQuery.data.is_builtin ? t("builtin") : t("imported")}
                  </Badge>
                  <Badge tone="accent">{detailQuery.data.controls.length} {t("controls")}</Badge>
                </div>
              </div>
              {detailQuery.data.description ? (
                <p className="muted" style={{ fontSize: 12.5 }}>{detailQuery.data.description}</p>
              ) : null}
              <MetaRows
                items={[
                  { label: t("version"), value: <span className="mono">v{detailQuery.data.version}</span> },
                  { label: t("jurisdiction"), value: detailQuery.data.jurisdiction },
                  { label: t("authority"), value: detailQuery.data.authority ?? "—" },
                  { label: t("effectiveDate"), value: formatDate(detailQuery.data.effective_date, lang) },
                  { label: t("publishedAt"), value: formatDateTime(detailQuery.data.published_at, lang) },
                  {
                    label: "URL",
                    value: detailQuery.data.source_url ? (
                      <a href={detailQuery.data.source_url} target="_blank" rel="noreferrer noopener" style={{ fontSize: 11 }}>
                        {detailQuery.data.source_url}
                      </a>
                    ) : (
                      "—"
                    ),
                  },
                ]}
              />
              <div className="divider" />
              <div className="section-label">{t("directControls")}</div>
              {detailQuery.data.controls.length === 0 ? (
                <EmptyState icon={BookOpenCheck} title={t("controlsEmpty")} />
              ) : (
                <div className="stack">
                  {detailQuery.data.controls.map((control) => (
                    <details key={control.id} className="card card-pad" data-testid="compliance-control">
                      <summary style={{ cursor: "pointer", listStyle: "none" }}>
                        <div className="row-between wrap" style={{ gap: 8 }}>
                          <div style={{ minWidth: 0 }}>
                            <div className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{control.control_id}</div>
                            <div className="primary-cell" style={{ marginTop: 2 }}>{control.title}</div>
                          </div>
                          <div className="row wrap" style={{ gap: 4 }}>
                            <span className="tag">{control.category}</span>
                            <span className="tag">{t("weight")} {control.weight}</span>
                          </div>
                        </div>
                      </summary>
                      <div className="stack" style={{ marginTop: 10 }}>
                        <p className="muted" style={{ fontSize: 12 }}>{control.description}</p>
                        <div className="grid-2">
                          <div>
                            <div className="section-label">{t("evidenceRequirements")}</div>
                            {control.evidence_requirements.length === 0 ? (
                              <span className="dim" style={{ fontSize: 11 }}>{t("noEvidenceRequirements")}</span>
                            ) : (
                              <div className="stack" style={{ gap: 6 }}>
                                {control.evidence_requirements.map((evidence) => (
                                  <div key={evidence.key} className="list-item" style={{ padding: "6px 0" }}>
                                    <div>
                                      <div className="item-title">{evidence.title}</div>
                                      <div className="item-sub">{evidence.description}</div>
                                      <span className="tag" style={{ marginTop: 3 }}>{evidence.key}</span>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                          <div>
                            <div className="section-label">{t("technicalChecksTitle")}</div>
                            {control.technical_checks.length === 0 ? (
                              <span className="dim" style={{ fontSize: 11 }}>{t("noTechnicalChecks")}</span>
                            ) : (
                              <div className="stack" style={{ gap: 6 }}>
                                {control.technical_checks.map((check) => (
                                  <div key={check.key} className="list-item" style={{ padding: "6px 0" }}>
                                    <div style={{ minWidth: 0 }}>
                                      <div className="item-title">{check.title}</div>
                                      <div className="item-sub">{check.description || check.key}</div>
                                      <div className="chip-row" style={{ marginTop: 4 }}>
                                        <span className="tag">{check.type}</span>
                                        {Object.entries(check.params).map(([key, value]) => (
                                          <span className="tag" key={key}>{key}={String(value)}</span>
                                        ))}
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                        {control.references.length ? (
                          <div>
                            <div className="section-label">{t("references")}</div>
                            <div className="chip-row">
                              {control.references.map((reference) => <span className="tag" key={reference}>{reference}</span>)}
                            </div>
                          </div>
                        ) : null}
                      </div>
                    </details>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <EmptyState icon={BookOpenCheck} title={t("chooseFramework")} />
          )}
          </div>
        </Card>
      ) : (
        <div className="notice notice-accent">
          <BookOpenCheck size={14} style={{ flex: "0 0 auto" }} />
          <span>{t("chooseFramework")}</span>
        </div>
      )}

      <Modal
        open={versionsOpen}
        onClose={() => setVersionsOpen(false)}
        title={t("versionsTitle")}
        size="lg"
      >
        {versionsQuery.isError ? (
          <ErrorBanner message={errorMessage(versionsQuery.error)} onRetry={() => void versionsQuery.refetch()} />
        ) : versionsQuery.isLoading ? (
          <div className="skeleton skeleton-row" />
        ) : (versionsQuery.data ?? []).length === 0 ? (
          <EmptyState icon={Layers} title={t("noSelection")} />
        ) : (
          <div className="stack">
            {(versionsQuery.data ?? []).map((version) => (
              <div key={version.id} className="list-item">
                <div>
                  <div className="row" style={{ gap: 6 }}>
                    <span className="mono" style={{ color: "var(--accent)", fontSize: 11 }}>v{version.version}</span>
                    <Badge tone={version.status === "published" ? "success" : "neutral"}>{humanize(version.status)}</Badge>
                    {selected?.version === version.version ? <Badge tone="accent">{t("common.active")}</Badge> : null}
                  </div>
                  <div className="item-title" style={{ marginTop: 3 }}>{version.name}</div>
                  <div className="item-sub">
                    {formatDateTime(version.published_at, lang)} · {formatNumber(version.controls_count)} {t("controls")}
                  </div>
                </div>
                <div className="item-side">
                  <Button
                    size="sm"
                    onClick={() => {
                      setSelected({ code: version.code, version: version.version });
                      setVersionsOpen(false);
                    }}
                  >
                    {t("preview")}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Modal>

      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title={t("importFramework")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setImportOpen(false)} disabled={importMutation.isPending}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              loading={importMutation.isPending}
              disabled={importContent.trim().length < 10}
              onClick={() => {
                setImportError(null);
                setImportResult(null);
                importMutation.mutate();
              }}
              data-testid="compliance-import-submit"
            >
              {t("importFramework")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="notice">{t("importHint")}</div>
          <div className="form-grid">
            <Field label={t("importFormat")} htmlFor={`${idPrefix}-import-format`}>
              <Select
                id={`${idPrefix}-import-format`}
                value={importFormat}
                onChange={(event) => setImportFormat(event.target.value as "auto" | "yaml" | "json")}
              >
                <option value="auto">auto</option>
                <option value="yaml">YAML</option>
                <option value="json">JSON</option>
              </Select>
            </Field>
            <Field label={t("importFile")} htmlFor={`${idPrefix}-import-file`}>
              <input
                id={`${idPrefix}-import-file`}
                type="file"
                accept=".yaml,.yml,.json,text/yaml,application/json"
                className="input"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (!file) return;
                  void file.text().then((text) => {
                    setImportContent(text);
                    const lower = file.name.toLowerCase();
                    if (lower.endsWith(".json")) setImportFormat("json");
                    else if (lower.endsWith(".yaml") || lower.endsWith(".yml")) setImportFormat("yaml");
                  });
                }}
              />
            </Field>
          </div>
          <Field label={t("importContent")} htmlFor={`${idPrefix}-import-content`} required>
            <Textarea
              id={`${idPrefix}-import-content`}
              className="mono"
              rows={12}
              value={importContent}
              onChange={(event) => setImportContent(event.target.value)}
              spellCheck={false}
              placeholder={"code: NIS2\nname: ...\nversion: '1.0'\ncontrols:\n  - control_id: ..."}
              data-testid="compliance-import-content"
            />
          </Field>
          {importError ? <ErrorBanner message={importError} /> : null}
          {importResult ? (
            <div className="notice notice-accent" data-testid="compliance-import-result">
              <BadgeCheck size={14} style={{ flex: "0 0 auto" }} />
              <div className="stack" style={{ gap: 4 }}>
                <strong>{t("importResult")}</strong>
                <span>
                  {importResult.framework.code} v{importResult.framework.version} ·{" "}
                  {importResult.created ? t("importCreated") : t("importExisting")} ·{" "}
                  {formatNumber(importResult.controls_imported)} {t("controlsImported")}
                </span>
                <span className="mono" style={{ fontSize: 10 }}>
                  {t("checksum")}: {importResult.checksum.slice(0, 24)}…
                </span>
              </div>
            </div>
          ) : null}
        </div>
      </Modal>
    </div>
  );
}

/* -------------------------------------------------------------- assessments */

function AssessmentsTab({ canAssess }: { canAssess: boolean }) {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);
  const [frameworkId, setFrameworkId] = useState("");
  const [assessor, setAssessor] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState<ControlStatus | null>(null);
  const [controlStatus, setControlStatus] = useState<string>("compliant");
  const [controlNotes, setControlNotes] = useState("");
  const [controlOwner, setControlOwner] = useState("");
  const [controlEvidence, setControlEvidence] = useState("");
  const [controlError, setControlError] = useState<string | null>(null);
  const [completeOpen, setCompleteOpen] = useState(false);
  const [gapOpen, setGapOpen] = useState(false);

  const listQuery = useQuery({
    queryKey: ["compliance", "assessments", { status, q, page }],
    queryFn: () =>
      api.get<Page<AssessmentSummary>>("/compliance/assessments", {
        page,
        page_size: 20,
        status: status || undefined,
        q: q || undefined,
      }),
  });

  const frameworksQuery = useQuery({
    queryKey: ["compliance", "frameworks", { picker: true }],
    queryFn: () => api.get<Page<FrameworkSummary>>("/compliance/frameworks", { page: 1, page_size: 200 }),
    enabled: createOpen,
  });

  const detailQuery = useQuery({
    queryKey: ["compliance", "assessment", selectedId],
    queryFn: () => api.get<AssessmentDetail>(`/compliance/assessments/${selectedId}`),
    enabled: selectedId !== null,
  });

  const gapQuery = useQuery({
    queryKey: ["compliance", "assessment", selectedId, "gaps"],
    queryFn: () => api.get<GapAnalysis>(`/compliance/assessments/${selectedId}/gap-analysis`),
    enabled: gapOpen && selectedId !== null,
  });

  const createMutation = useMutation({
    mutationFn: () =>
      api.post<AssessmentDetail>("/compliance/assessments", {
        framework_id: frameworkId,
        ...(assessor.trim() ? { assessor: assessor.trim() } : {}),
      }),
    onSuccess: async (result) => {
      setCreateOpen(false);
      setCreateError(null);
      setFrameworkId("");
      setAssessor("");
      setSelectedId(result.id);
      toast.push(t("createAssessment"), "success");
      await queryClient.invalidateQueries({ queryKey: ["compliance"] });
    },
    onError: (error) => setCreateError(errorMessage(error)),
  });

  const patchMutation = useMutation({
    mutationFn: (payload: { id: string; body: Record<string, unknown> }) =>
      api.patch<ControlStatus>(`/compliance/assessments/${selectedId}/controls/${payload.id}`, payload.body),
    onSuccess: async () => {
      setEditing(null);
      setControlError(null);
      toast.push(t("saveControl"), "success");
      await queryClient.invalidateQueries({ queryKey: ["compliance", "assessment", selectedId] });
      await queryClient.invalidateQueries({ queryKey: ["compliance", "assessments"] });
    },
    onError: (error) => setControlError(errorMessage(error)),
  });

  const completeMutation = useMutation({
    mutationFn: () => api.post<AssessmentDetail>(`/compliance/assessments/${selectedId}/complete`),
    onSuccess: async () => {
      setCompleteOpen(false);
      toast.push(t("completed"), "success");
      await queryClient.invalidateQueries({ queryKey: ["compliance"] });
    },
    onError: (error) => {
      setCompleteOpen(false);
      toast.push(errorMessage(error), "error");
    },
  });

  const columns: Column<AssessmentSummary>[] = [
    {
      key: "framework",
      header: t("assessmentFramework"),
      render: (row) => (
        <div style={{ minWidth: 170 }}>
          <div className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{row.framework_code} · v{row.framework_version}</div>
          <div className="primary-cell" style={{ marginTop: 2 }}>{row.framework_name}</div>
          {row.assessor ? <div className="cell-sub">{t("assessor")}: {row.assessor}</div> : null}
        </div>
      ),
    },
    {
      key: "status",
      header: t("status"),
      width: "120px",
      render: (row) => <StatusBadge status={row.status} label={statusLabel(row.status, t)} />,
    },
    {
      key: "score",
      header: t("score"),
      width: "90px",
      align: "right",
      render: (row) => <span className="mono" style={{ color: row.score >= 75 ? "var(--success)" : row.score >= 40 ? "var(--warning)" : "var(--danger)" }}>{row.score.toFixed(1)}</span>,
    },
    {
      key: "gaps",
      header: t("gaps"),
      width: "80px",
      align: "right",
      render: (row) => <span className="mono">{formatNumber(row.gaps_count)}</span>,
    },
    {
      key: "started",
      header: t("startedAt"),
      width: "140px",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{formatDateTime(row.started_at, lang)}</span>,
    },
  ];

  const openEdit = (control: ControlStatus) => {
    setEditing(control);
    setControlStatus(control.status === "not_assessed" ? "compliant" : control.status);
    setControlNotes(control.notes ?? "");
    setControlOwner(control.owner ?? "");
    setControlEvidence(control.evidence_ids.join(", "));
    setControlError(null);
  };

  const evidenceValues = controlEvidence
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  const evidenceValid = evidenceValues.every((value) =>
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value),
  );

  const detail = detailQuery.data;
  const locked = detail ? detail.status === "completed" || detail.status === "archived" : true;

  const controlColumns: Column<ControlStatus>[] = [
    {
      key: "control",
      header: t("controls"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{row.control_code}</div>
          <div className="primary-cell" style={{ marginTop: 2 }}>{row.title}</div>
          <div className="cell-sub">{row.category} · {t("weight")} {row.weight}</div>
        </div>
      ),
    },
    {
      key: "status",
      header: t("status"),
      width: "130px",
      render: (row) => <StatusBadge status={row.status} label={humanize(row.status)} />,
    },
    {
      key: "owner",
      header: t("owner"),
      width: "140px",
      render: (row) => <span style={{ fontSize: 11.5 }}>{row.owner ?? "—"}</span>,
    },
    {
      key: "evidence",
      header: t("evidenceLinked"),
      width: "90px",
      align: "right",
      render: (row) => <span className="mono">{formatNumber(row.evidence_ids.length)}</span>,
    },
    {
      key: "reviewed",
      header: t("reviewedAt"),
      width: "140px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.reviewed_at ? formatDateTime(row.reviewed_at, lang) : "—"}</span>,
    },
    {
      key: "actions",
      header: "",
      width: "90px",
      align: "right",
      render: (row) =>
        canAssess && !locked ? (
          <Button size="sm" variant="ghost" onClick={() => openEdit(row)} data-testid="compliance-control-edit">
            {t("common.edit")}
          </Button>
        ) : (
          <span className="dim" style={{ fontSize: 10 }}>{locked ? t("assessmentLock") : "—"}</span>
        ),
    },
  ];

  return (
    <div className="stack" data-testid="compliance-assessments">
      <Card
        title={t("assessments")}
        subtitle={t("assessmentsHint")}
        actions={
          canAssess ? (
            <Button
              size="sm"
              variant="primary"
              icon={Plus}
              onClick={() => { setCreateOpen(true); setCreateError(null); }}
              data-testid="compliance-assessment-create"
            >
              {t("newAssessment")}
            </Button>
          ) : undefined
        }
        bodyClassName=""
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap" style={{ gap: 8 }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              <SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder={t("frameworkSearch")} ariaLabel={t("frameworkSearch")} />
            </div>
            <Select
              value={status}
              onChange={(event) => { setStatus(event.target.value); setPage(1); }}
              aria-label={t("statusFilter")}
              style={{ width: 160 }}
              data-testid="compliance-assessment-status"
            >
              <option value="">{t("common.all")}</option>
              <option value="in_progress">{t("inProgress")}</option>
              <option value="completed">{t("completed")}</option>
              <option value="archived">{t("archived")}</option>
            </Select>
          </div>
        </div>
        {listQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(listQuery.error)} onRetry={() => void listQuery.refetch()} />
          </div>
        ) : (
          <>
            <DataTable
              columns={columns}
              rows={listQuery.data?.items}
              rowKey={(row) => row.id}
              loading={listQuery.isLoading}
              onRowClick={(row) => setSelectedId(row.id)}
              empty={
                <EmptyState
                  icon={ClipboardCheck}
                  title={t("noAssessments")}
                  description={t("noAssessmentsHint")}
                  action={canAssess ? <Button size="sm" onClick={() => setCreateOpen(true)}>{t("newAssessment")}</Button> : undefined}
                />
              }
            />
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={listQuery.data?.meta} onPage={setPage} />
            </div>
          </>
        )}
      </Card>

      {selectedId ? (
        detailQuery.isLoading ? (
          <Card title={t("selectAssessment")}>
            <div className="skeleton skeleton-chart" />
          </Card>
        ) : detailQuery.isError ? (
          <Card title={t("selectAssessment")}>
            <ErrorBanner message={errorMessage(detailQuery.error)} onRetry={() => void detailQuery.refetch()} />
          </Card>
        ) : detail ? (
          <div className="stack" data-testid="compliance-assessment-detail">
            <Card
              title={`${detail.framework_code} · v${detail.framework_version}`}
              subtitle={detail.framework_name}
              actions={
                <>
                  <Button size="sm" icon={Wand2} onClick={() => setGapOpen(true)} data-testid="compliance-gap-analysis">
                    {t("gapAnalysis")}
                  </Button>
                  {canAssess && !locked ? (
                    <Button size="sm" variant="danger" onClick={() => setCompleteOpen(true)} data-testid="compliance-complete">
                      {t("completeAssessment")}
                    </Button>
                  ) : null}
                  <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("common.refresh")} onClick={() => void detailQuery.refetch()} />
                </>
              }
            >
              <div className="row wrap" style={{ gap: 20, alignItems: "flex-start" }}>
                <ScoreRing score={detail.score} label={t("score")} tone="var(--success)" />
                <div style={{ flex: 1, minWidth: 240 }}>
                  <div className="row wrap" style={{ gap: 8, marginBottom: 8 }}>
                    <StatusBadge status={detail.status} label={statusLabel(detail.status, t)} />
                    {detail.assessor ? <Badge tone="neutral">{detail.assessor}</Badge> : null}
                    {locked ? <Badge tone="neutral"><Lock size={10} /> {t("assessmentLock")}</Badge> : null}
                  </div>
                  <MetaRows
                    items={[
                      { label: t("startedAt"), value: formatDateTime(detail.started_at, lang) },
                      { label: t("completedAt"), value: formatDateTime(detail.completed_at, lang) },
                      { label: t("controlsTotal"), value: formatNumber(detail.score_breakdown.total_controls) },
                      { label: t("applicableControls"), value: formatNumber(detail.score_breakdown.applicable_controls) },
                      { label: t("gaps"), value: formatNumber(detail.gaps.length) },
                    ]}
                  />
                </div>
                <div style={{ flex: 1, minWidth: 240 }}>
                  <div className="section-label">{t("breakdown")}</div>
                  <div className="chip-row">
                    <Badge tone="success">compliant {detail.score_breakdown.compliant}</Badge>
                    <Badge tone="warning">partial {detail.score_breakdown.partial}</Badge>
                    <Badge tone="danger">non_compliant {detail.score_breakdown.non_compliant}</Badge>
                    <Badge tone="neutral">n/a {detail.score_breakdown.not_applicable}</Badge>
                    <Badge tone="neutral">{t("notAssessed")} {detail.score_breakdown.not_assessed}</Badge>
                  </div>
                  <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>
                    {t("weighted")}: {detail.score_breakdown.weighted_points} / {detail.score_breakdown.weighted_total}
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: "var(--dim)", marginTop: 4 }}>{detail.score_breakdown.formula}</div>
                </div>
              </div>
              {locked ? <div className="notice notice-accent" style={{ marginTop: 12 }}><ShieldCheck size={14} style={{ flex: "0 0 auto" }} />{t("assessmentLocked")}</div> : null}
              <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
                <ShieldCheck size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
                <span>{detail.disclaimer}</span>
              </div>
            </Card>

            <Card title={t("directControls")} bodyClassName="" subtitle={`${detail.controls.length}`}>
              <DataTable
                columns={controlColumns}
                rows={detail.controls}
                rowKey={(row) => row.id}
                empty={<EmptyState icon={ClipboardCheck} title={t("controlsEmpty")} />}
              />
            </Card>

            <Card title={t("gaps")} subtitle={t("gapAnalysisHint")}>
              {detail.gaps.length === 0 ? (
                <EmptyState icon={ShieldCheck} title={t("noGaps")} />
              ) : (
                <div className="table-wrap">
                  <table className="data">
                    <thead>
                      <tr>
                        <th>{t("controls")}</th>
                        <th style={{ width: 110 }}>{t("common.severity")}</th>
                        <th>{t("recommendation")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.gaps.map((gap) => (
                        <tr key={gap.control_status_id}>
                          <td>
                            <div className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{gap.control_code}</div>
                            <div className="primary-cell">{gap.title}</div>
                          </td>
                          <td><StatusBadge status={gap.status} label={humanize(gap.status)} /></td>
                          <td><span style={{ fontSize: 11.5 }}>{gap.recommendation}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </div>
        ) : (
          <Card title={t("selectAssessment")}>
            <EmptyState icon={ClipboardCheck} title={t("selectAssessment")} />
          </Card>
        )
      ) : (
        <div className="notice">
          <ClipboardCheck size={14} style={{ flex: "0 0 auto" }} />
          <span>{t("selectAssessment")}</span>
        </div>
      )}

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={t("newAssessment")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={createMutation.isPending}>{t("common.cancel")}</Button>
            <Button
              variant="primary"
              loading={createMutation.isPending}
              disabled={!frameworkId}
              onClick={() => { setCreateError(null); createMutation.mutate(); }}
              data-testid="compliance-assessment-submit"
            >
              {t("createAssessment")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="notice notice-warning">{t("disclaimer")}</div>
          <Field label={t("assessmentFramework")} htmlFor={`${idPrefix}-framework`} required>
            <Select
              id={`${idPrefix}-framework`}
              value={frameworkId}
              onChange={(event) => setFrameworkId(event.target.value)}
              data-testid="compliance-assessment-framework"
            >
              <option value="">—</option>
              {(frameworksQuery.data?.items ?? []).map((framework) => (
                <option key={framework.id} value={framework.id}>
                  {framework.code} · v{framework.version} — {framework.name}
                </option>
              ))}
            </Select>
          </Field>
          {frameworksQuery.isError ? <ErrorBanner compact message={errorMessage(frameworksQuery.error)} onRetry={() => void frameworksQuery.refetch()} /> : null}
          <Field label={t("assessor")} htmlFor={`${idPrefix}-assessor`} hint={t("common.optional")}>
            <Input id={`${idPrefix}-assessor`} value={assessor} maxLength={200} onChange={(event) => setAssessor(event.target.value)} />
          </Field>
          {createError ? <ErrorBanner message={createError} /> : null}
        </div>
      </Modal>

      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={t("editControl")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditing(null)} disabled={patchMutation.isPending}>{t("common.cancel")}</Button>
            <Button
              variant="primary"
              loading={patchMutation.isPending}
              disabled={!evidenceValid}
              onClick={() => {
                if (!editing) return;
                setControlError(null);
                patchMutation.mutate({
                  id: editing.id,
                  body: {
                    status: controlStatus,
                    notes: controlNotes,
                    owner: controlOwner,
                    evidence_ids: evidenceValues,
                  },
                });
              }}
              data-testid="compliance-control-save"
            >
              {t("saveControl")}
            </Button>
          </>
        }
      >
        {editing ? (
          <div className="stack">
            <div className="row wrap">
              <span className="mono" style={{ color: "var(--accent)", fontSize: 10 }}>{editing.control_code}</span>
              <span className="primary-cell">{editing.title}</span>
              <Badge tone="neutral">{editing.category} · {t("weight")} {editing.weight}</Badge>
            </div>
            {editing.technical_checks.length ? (
              <div>
                <div className="section-label">{t("technicalChecksTitle")}</div>
                <div className="chip-row">
                  {editing.technical_checks.map((check) => <span className="tag" key={check.key}>{check.type}</span>)}
                </div>
              </div>
            ) : null}
            <div className="form-grid">
              <Field label={t("controlStatus")} htmlFor={`${idPrefix}-control-status`} required>
                <Select id={`${idPrefix}-control-status`} value={controlStatus} onChange={(event) => setControlStatus(event.target.value)} data-testid="compliance-control-status">
                  {CONTROL_STATUSES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
                </Select>
              </Field>
              <Field label={t("owner")} htmlFor={`${idPrefix}-control-owner`}>
                <Input id={`${idPrefix}-control-owner`} maxLength={200} value={controlOwner} onChange={(event) => setControlOwner(event.target.value)} />
              </Field>
              <div className="span-2">
                <Field label={t("evidenceIds")} htmlFor={`${idPrefix}-control-evidence`} hint={t("evidenceIdsHint")} error={!evidenceValid ? t("evidenceInvalid") : undefined}>
                  <Input
                    id={`${idPrefix}-control-evidence`}
                    className="mono"
                    value={controlEvidence}
                    onChange={(event) => setControlEvidence(event.target.value)}
                    aria-invalid={!evidenceValid ? true : undefined}
                    data-testid="compliance-control-evidence"
                  />
                </Field>
              </div>
              <div className="span-2">
                <Field label={t("notes")} htmlFor={`${idPrefix}-control-notes`}>
                  <Textarea id={`${idPrefix}-control-notes`} rows={4} maxLength={4000} value={controlNotes} onChange={(event) => setControlNotes(event.target.value)} />
                </Field>
              </div>
            </div>
            <div className="dim" style={{ fontSize: 11 }}>{t("evidenceExpiredHint")}</div>
            {controlError ? <ErrorBanner message={controlError} /> : null}
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={completeOpen}
        onClose={() => setCompleteOpen(false)}
        onConfirm={() => completeMutation.mutate()}
        title={t("completeAssessment")}
        description={t("completeWarning")}
        warning={t("disclaimer")}
        confirmLabel={t("completeConfirm")}
        cancelLabel={t("common.cancel")}
        busy={completeMutation.isPending}
        testId="compliance-complete-confirm"
      />

      <Modal open={gapOpen} onClose={() => setGapOpen(false)} title={t("gapAnalysis")} size="lg">
        {gapQuery.isLoading ? (
          <div className="skeleton skeleton-chart" />
        ) : gapQuery.isError ? (
          <ErrorBanner message={errorMessage(gapQuery.error)} onRetry={() => void gapQuery.refetch()} />
        ) : gapQuery.data ? (
          <div className="stack" data-testid="compliance-gap-panel">
            <div className="row wrap">
              <Badge tone="accent">{gapQuery.data.framework_code} · v{gapQuery.data.framework_version}</Badge>
              <Badge tone="neutral">{t("score")}: {gapQuery.data.score.toFixed(1)}</Badge>
              <Badge tone={gapQuery.data.gap_count ? "warning" : "success"}>{t("gaps")}: {gapQuery.data.gap_count}</Badge>
              <span className="dim" style={{ fontSize: 11 }}>{formatDateTime(gapQuery.data.generated_at, lang)}</span>
            </div>
            <div className="section-label">{t("gapsBySeverity")}</div>
            <div className="chip-row">
              {Object.entries(gapQuery.data.gaps_by_severity).length === 0 ? (
                <span className="dim" style={{ fontSize: 11 }}>{t("noGaps")}</span>
              ) : (
                Object.entries(gapQuery.data.gaps_by_severity).map(([severity, count]) => (
                  <Badge key={severity} tone={severity === "critical" ? "critical" : severity === "high" ? "danger" : severity === "medium" ? "warning" : "accent"}>
                    {humanize(severity)} {count}
                  </Badge>
                ))
              )}
            </div>
            {gapQuery.data.gaps.length === 0 ? (
              <EmptyState icon={ShieldCheck} title={t("noGaps")} />
            ) : (
              <div className="stack">
                {gapQuery.data.gaps.map((gap) => (
                  <div className="list-item" key={gap.control_status_id}>
                    <div style={{ minWidth: 0 }}>
                      <div className="row wrap" style={{ gap: 6 }}>
                        <span className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{gap.control_code}</span>
                        <Badge tone={gap.severity === "critical" ? "critical" : gap.severity === "high" ? "danger" : gap.severity === "medium" ? "warning" : "accent"}>
                          {humanize(gap.severity)}
                        </Badge>
                      </div>
                      <div className="item-title" style={{ marginTop: 2 }}>{gap.title}</div>
                      <div className="item-sub">{gap.recommendation}</div>
                    </div>
                    <div className="item-side">
                      <StatusBadge status={gap.status} label={humanize(gap.status)} />
                    </div>
                  </div>
                ))}
              </div>
            )}
            <span className="dim" style={{ fontSize: 11 }}>{gapQuery.data.disclaimer}</span>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

/* ------------------------------------------------------------------ reports */

function ReportsTab({ canGenerate }: { canGenerate: boolean }) {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [page, setPage] = useState(1);
  const [generateOpen, setGenerateOpen] = useState(false);
  const [generateKind, setGenerateKind] = useState<(typeof REPORT_KINDS)[number]>("executive");
  const [periodStart, setPeriodStart] = useState(() => daysAgoInput(30));
  const [periodEnd, setPeriodEnd] = useState(() => localDateTimeInput(new Date()));
  const [generateFramework, setGenerateFramework] = useState("");
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [previewId, setPreviewId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ReportSummary | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  const listQuery = useQuery({
    queryKey: ["compliance", "reports", { q, kind, page }],
    queryFn: () =>
      api.get<Page<ReportSummary>>("/reports", {
        page,
        page_size: 20,
        q: q || undefined,
        kind: kind || undefined,
      }),
  });

  const frameworksQuery = useQuery({
    queryKey: ["compliance", "frameworks", { reportPicker: true }],
    queryFn: () => api.get<Page<FrameworkSummary>>("/compliance/frameworks", { page: 1, page_size: 200 }),
    enabled: generateOpen,
  });

  const detailQuery = useQuery({
    queryKey: ["compliance", "report", previewId],
    queryFn: () => api.get<ReportDetail>(`/reports/${previewId}`),
    enabled: previewId !== null,
  });

  const generateMutation = useMutation({
    mutationFn: (body: { kind: string; period_start: string; period_end: string; framework_id?: string }) =>
      api.post<ReportDetail>("/reports/generate", body),
    onSuccess: async (result) => {
      setGenerateOpen(false);
      setGenerateError(null);
      setPreviewId(result.id);
      toast.push(t("reportCreated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["compliance", "reports"] });
    },
    onError: (error) => setGenerateError(errorMessage(error)),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete<void>(`/reports/${id}`),
    onSuccess: async () => {
      setDeleteTarget(null);
      if (previewId) setPreviewId(null);
      toast.push(t("reportDeleted"), "success");
      await queryClient.invalidateQueries({ queryKey: ["compliance", "reports"] });
    },
    onError: (error) => {
      setDeleteTarget(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const download = async (report: ReportSummary, format: "html" | "md") => {
    setDownloading(`${report.id}:${format}`);
    try {
      await downloadFile(`/reports/${report.id}/download?format=${format}`, `report-${report.kind}-${report.id.slice(0, 8)}.${format}`);
      toast.push(t("reportDownloaded"), "success");
    } catch (error) {
      toast.push(errorMessage(error), "error");
    } finally {
      setDownloading(null);
    }
  };

  const startIso = toIso(periodStart);
  const endIso = toIso(periodEnd);
  const periodValid = Boolean(
    startIso &&
      endIso &&
      new Date(endIso).getTime() > new Date(startIso).getTime() &&
      (new Date(endIso).getTime() - new Date(startIso).getTime()) / 86_400_000 <= 366,
  );

  const columns: Column<ReportSummary>[] = [
    {
      key: "title",
      header: t("reportList"),
      render: (row) => (
        <div style={{ minWidth: 220 }}>
          <div className="row wrap" style={{ gap: 6 }}>
            <Badge tone="accent">{reportKindLabel(row.kind, t)}</Badge>
            <Badge tone={row.status === "generated" ? "success" : "neutral"}>{humanize(row.status)}</Badge>
          </div>
          <div className="primary-cell" style={{ marginTop: 3 }}>{row.title}</div>
          <div className="cell-sub mono">{t("checksum")}: {row.checksum.slice(0, 16)}…</div>
        </div>
      ),
    },
    {
      key: "period",
      header: t("reportPeriod"),
      width: "190px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5 }}>
          {formatDateTime(row.period_start, lang)} → {formatDateTime(row.period_end, lang)}
        </span>
      ),
    },
    {
      key: "generated",
      header: t("generatedAt"),
      width: "150px",
      render: (row) => (
        <div>
          <div className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.generated_at, lang)}</div>
          <div className="cell-sub">{row.generated_by ?? "—"}</div>
        </div>
      ),
    },
    {
      key: "actions",
      header: "",
      width: "200px",
      align: "right",
      render: (row) => (
        <div className="row" style={{ gap: 4, justifyContent: "flex-end" }}>
          <Button size="sm" variant="ghost" icon={FileText} onClick={() => setPreviewId(row.id)} data-testid="compliance-report-preview">
            {t("preview")}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={Download}
            loading={downloading === `${row.id}:html`}
            aria-label={t("downloadHtml")}
            onClick={() => void download(row, "html")}
            data-testid="compliance-download-html"
          />
          <Button
            size="sm"
            variant="ghost"
            icon={Download}
            loading={downloading === `${row.id}:md`}
            aria-label={t("downloadMarkdown")}
            onClick={() => void download(row, "md")}
            data-testid="compliance-download-md"
          />
          {canGenerate ? (
            <Button size="sm" variant="ghost" icon={Trash2} aria-label={t("deleteReport")} onClick={() => setDeleteTarget(row)} data-testid="compliance-report-delete" />
          ) : null}
        </div>
      ),
    },
  ];

  return (
    <div className="stack" data-testid="compliance-reports">
      <Card
        title={t("reportList")}
        subtitle={listQuery.data ? formatNumber(listQuery.data.meta.total) : undefined}
        actions={
          canGenerate ? (
            <Button
              size="sm"
              variant="primary"
              icon={Plus}
              onClick={() => { setGenerateOpen(true); setGenerateError(null); }}
              data-testid="compliance-report-generate"
            >
              {t("generateReport")}
            </Button>
          ) : undefined
        }
        bodyClassName=""
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap" style={{ gap: 8 }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              <SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder={t("reportSearch")} ariaLabel={t("reportSearch")} />
            </div>
            <Select value={kind} onChange={(event) => { setKind(event.target.value); setPage(1); }} aria-label={t("reportKind")} style={{ width: 160 }} data-testid="compliance-report-kind">
              <option value="">{t("common.all")}</option>
              {REPORT_KINDS.map((value) => <option key={value} value={value}>{reportKindLabel(value, t)}</option>)}
            </Select>
          </div>
        </div>
        {listQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(listQuery.error)} onRetry={() => void listQuery.refetch()} />
          </div>
        ) : (
          <>
            <DataTable
              columns={columns}
              rows={listQuery.data?.items}
              rowKey={(row) => row.id}
              loading={listQuery.isLoading}
              empty={
                <EmptyState
                  icon={FileText}
                  title={t("noReports")}
                  description={t("noReportsHint")}
                  action={canGenerate ? <Button size="sm" onClick={() => setGenerateOpen(true)}>{t("generateReport")}</Button> : undefined}
                />
              }
            />
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={listQuery.data?.meta} onPage={setPage} />
            </div>
          </>
        )}
      </Card>

      <Modal
        open={generateOpen}
        onClose={() => setGenerateOpen(false)}
        title={t("generateReport")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setGenerateOpen(false)} disabled={generateMutation.isPending}>{t("common.cancel")}</Button>
            <Button
              variant="primary"
              loading={generateMutation.isPending}
              disabled={!periodValid}
              onClick={() => {
                setGenerateError(null);
                if (!startIso || !endIso) {
                  setGenerateError(t("periodInvalid"));
                  return;
                }
                generateMutation.mutate({
                  kind: generateKind,
                  period_start: startIso,
                  period_end: endIso,
                  ...(generateFramework ? { framework_id: generateFramework } : {}),
                });
              }}
              data-testid="compliance-report-submit"
            >
              {t("generate")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="notice notice-warning">{t("disclaimer")}</div>
          <Field label={t("reportKind")} htmlFor={`${idPrefix}-report-kind`} required>
            <Select
              id={`${idPrefix}-report-kind`}
              value={generateKind}
              onChange={(event) => setGenerateKind(event.target.value as (typeof REPORT_KINDS)[number])}
            >
              {REPORT_KINDS.map((value) => <option key={value} value={value}>{reportKindLabel(value, t)}</option>)}
            </Select>
          </Field>
          <div className="form-grid">
            <Field label={t("from")} htmlFor={`${idPrefix}-report-from`} required error={!periodValid ? t("periodInvalid") : undefined}>
              <Input
                id={`${idPrefix}-report-from`}
                type="datetime-local"
                value={periodStart}
                onChange={(event) => setPeriodStart(event.target.value)}
                aria-invalid={!periodValid ? true : undefined}
              />
            </Field>
            <Field label={t("to")} htmlFor={`${idPrefix}-report-to`} required>
              <Input id={`${idPrefix}-report-to`} type="datetime-local" value={periodEnd} onChange={(event) => setPeriodEnd(event.target.value)} />
            </Field>
          </div>
          <Field label={`${t("assessmentFramework")} (${t("common.optional")})`} htmlFor={`${idPrefix}-report-framework`}>
            <Select
              id={`${idPrefix}-report-framework`}
              value={generateFramework}
              onChange={(event) => setGenerateFramework(event.target.value)}
            >
              <option value="">—</option>
              {(frameworksQuery.data?.items ?? []).map((framework) => (
                <option key={framework.id} value={framework.id}>{framework.code} · v{framework.version}</option>
              ))}
            </Select>
          </Field>
          {generateError ? <ErrorBanner message={generateError} /> : null}
        </div>
      </Modal>

      <Modal
        open={previewId !== null}
        onClose={() => setPreviewId(null)}
        title={t("reportPreview")}
        size="lg"
        footer={
          detailQuery.data ? (
            <>
              <Button variant="ghost" onClick={() => setPreviewId(null)}>{t("common.close")}</Button>
              <Button
                icon={Download}
                loading={downloading === `${detailQuery.data.id}:md`}
                onClick={() => void download(detailQuery.data, "md")}
                data-testid="compliance-preview-download-md"
              >
                Markdown
              </Button>
              <Button
                variant="primary"
                icon={Download}
                loading={downloading === `${detailQuery.data.id}:html`}
                onClick={() => void download(detailQuery.data, "html")}
                data-testid="compliance-preview-download-html"
              >
                HTML
              </Button>
            </>
          ) : undefined
        }
      >
        {detailQuery.isLoading ? (
          <div className="skeleton skeleton-chart" />
        ) : detailQuery.isError ? (
          <ErrorBanner message={errorMessage(detailQuery.error)} onRetry={() => void detailQuery.refetch()} />
        ) : detailQuery.data ? (
          <div className="stack" data-testid="compliance-report-preview">
            <div className="row wrap">
              <Badge tone="accent">{reportKindLabel(detailQuery.data.kind, t)}</Badge>
              <StatusBadge status={detailQuery.data.status} />
              <span className="dim" style={{ fontSize: 11 }}>{relativeTime(detailQuery.data.generated_at, lang)}</span>
            </div>
            <h3 style={{ fontSize: 15 }}>{detailQuery.data.title}</h3>
            <MetaRows
              items={[
                { label: t("generatedBy"), value: detailQuery.data.generated_by ?? "—" },
                { label: t("generatedAt"), value: formatDateTime(detailQuery.data.generated_at, lang) },
                { label: t("from"), value: formatDateTime(detailQuery.data.period_start, lang) },
                { label: t("to"), value: formatDateTime(detailQuery.data.period_end, lang) },
                { label: t("checksum"), value: <span className="mono" style={{ fontSize: 10 }}>{detailQuery.data.checksum}</span> },
              ]}
            />
            <div className="notice" style={{ fontSize: 11 }}>
              <ShieldCheck size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
              <span>{detailQuery.data.disclaimer}</span>
            </div>
            <div>
              <div className="section-label">Markdown</div>
              <pre className="code-block" style={{ maxHeight: 320 }}>{detailQuery.data.content_md}</pre>
            </div>
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => { if (deleteTarget) deleteMutation.mutate(deleteTarget.id); }}
        title={t("deleteReport")}
        description={deleteTarget?.title}
        warning={t("deleteReportWarning")}
        confirmLabel={t("common.delete")}
        cancelLabel={t("common.cancel")}
        busy={deleteMutation.isPending}
        testId="compliance-report-delete-confirm"
      />
    </div>
  );
}

/* --------------------------------------------------------------------- page */

export function CompliancePage() {
  const t = usePageCopy(COPY);
  const { can, session } = useAuth();
  const { lang } = useI18n();
  const [tab, setTab] = useState<TabKey>("frameworks");

  const canRead = can("compliance:read");
  const canWrite = can("compliance:write");
  const canAssess = can("compliance:assess");
  const canGenerateReports = can("report:generate");
  const canReadReports = can("report:read");
  const isPlatformAdmin = session?.user.is_platform_admin ?? false;

  const summaryQuery = useQuery({
    queryKey: ["compliance", "summary"],
    queryFn: () => api.get<ComplianceSummary>("/compliance/summary"),
    enabled: canRead,
  });

  const frameworkCountQuery = useQuery({
    queryKey: ["compliance", "frameworks", { count: true }],
    queryFn: () => api.get<Page<FrameworkSummary>>("/compliance/frameworks", { page: 1, page_size: 1 }),
    enabled: canRead,
  });

  const summary = summaryQuery.data;
  const applicableControls = useMemo(
    () => (summary?.frameworks ?? []).reduce((total, framework) => total + framework.controls_total, 0),
    [summary],
  );

  return (
    <div className="animate-in" data-testid="page-compliance">
      <PageHeader
        eyebrow={t("eyebrow")}
        title={t("title")}
        subtitle={t("subtitle")}
        actions={
          <>
            <Badge tone="warning"><ShieldCheck size={11} /> {t("disclaimer").slice(0, 34)}…</Badge>
            <Button
              variant="ghost"
              icon={RefreshCw}
              aria-label={t("common.refresh")}
              onClick={() => { void summaryQuery.refetch(); void frameworkCountQuery.refetch(); }}
            />
          </>
        }
      />

      <div className="notice notice-warning" style={{ marginBottom: 12 }} data-testid="compliance-disclaimer">
        <ShieldCheck size={14} style={{ flex: "0 0 auto" }} />
        <span>{t("disclaimer")}</span>
      </div>

      {!canRead ? (
        <Card>
          <EmptyState icon={Lock} title={t("noPermission")} description={t("readOnly")} />
        </Card>
      ) : summaryQuery.isLoading ? (
        <PageSkeleton />
      ) : summaryQuery.isError ? (
        <ErrorBanner message={errorMessage(summaryQuery.error)} onRetry={() => void summaryQuery.refetch()} />
      ) : (
        <>
          <div className="kpi-grid" style={{ marginBottom: 12 }} data-testid="compliance-summary">
            <div className="card kpi">
              <div className="kpi-label"><BadgeCheck size={13} style={{ color: "var(--success)" }} />{t("assessed")}</div>
              <div className="kpi-value kpi-success">
                {formatNumber(summary?.assessed_frameworks ?? 0)}
                <small> / {formatNumber(summary?.frameworks.length ?? 0)}</small>
              </div>
              <div className="kpi-foot">{t("frameworksCatalogued")}: {formatNumber(frameworkCountQuery.data?.meta.total ?? 0)}</div>
            </div>
            <div className="card kpi">
              <div className="kpi-label"><ClipboardCheck size={13} style={{ color: "var(--accent)" }} />{t("averageScore")}</div>
              <div className="kpi-value kpi-accent">
                {summary?.average_score !== null && summary?.average_score !== undefined ? summary.average_score.toFixed(1) : "—"}
                <small> / 100</small>
              </div>
              <div className="kpi-foot">{t("completed")} · {formatDateTime(summary?.generated_at, lang)}</div>
            </div>
            <div className="card kpi">
              <div className="kpi-label"><Layers size={13} style={{ color: "var(--warning)" }} />{t("applicableControls")}</div>
              <div className="kpi-value kpi-warning">{formatNumber(applicableControls)}</div>
              <div className="kpi-foot">{t("frameworks")}: {formatNumber(summary?.frameworks.length ?? 0)}</div>
            </div>
            <div className="card kpi">
              <div className="kpi-label"><FileText size={13} style={{ color: "var(--muted)" }} />{t("tabReports")}</div>
              <div className="kpi-value">{canReadReports ? "→" : "—"}</div>
              <div className="kpi-foot">{t("generateReport")}</div>
            </div>
          </div>

          {summary && summary.frameworks.length > 0 ? (
            <div style={{ marginBottom: 12 }}>
              <Card title={t("frameworksCatalogued")} subtitle={summary.organization_name}>
                <div className="chip-row">
                  {summary.frameworks.map((framework) => (
                    <div key={framework.framework_id} className="tag" style={{ padding: "4px 8px", gap: 6 }}>
                      <span style={{ color: "var(--text-secondary)" }}>{framework.framework_code} v{framework.framework_version}</span>
                      {framework.score !== null ? (
                        <span style={{ color: framework.score >= 75 ? "var(--success)" : framework.score >= 40 ? "var(--warning)" : "var(--danger)" }}>
                          {framework.score.toFixed(1)}
                        </span>
                      ) : (
                        <span style={{ color: "var(--dim)" }}>{t("notAssessed")}</span>
                      )}
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          ) : null}

          <div style={{ marginBottom: 12 }}>
            <Tabs<TabKey>
              ariaLabel={t("title")}
              value={tab}
              onChange={setTab}
              items={[
                { key: "frameworks", label: t("tabFrameworks") },
                { key: "assessments", label: t("tabAssessments") },
                { key: "reports", label: t("tabReports") },
              ]}
            />
          </div>

          {tab === "frameworks" ? <FrameworksTab canWrite={canWrite} isPlatformAdmin={isPlatformAdmin} /> : null}
          {tab === "assessments" ? <AssessmentsTab canAssess={canAssess} /> : null}
          {tab === "reports" ? (
            canReadReports ? <ReportsTab canGenerate={canGenerateReports} /> : <Card><EmptyState icon={Lock} title={t("noReportPermission")} /></Card>
          ) : null}
        </>
      )}
    </div>
  );
}

export default CompliancePage;
