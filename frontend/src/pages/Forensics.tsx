import { useState } from "react";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Archive,
  CheckCircle2,
  Download,
  FileCheck2,
  FileClock,
  Fingerprint,
  History,
  Lock,
  Microscope,
  RefreshCw,
  SearchX,
  ShieldCheck,
  ShieldX,
  XCircle,
} from "lucide-react";
import { api, downloadFile, errorMessage, withQuery, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatDateTime, formatNumber, humanize, relativeTime, truncate } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
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
  TableSkeleton,
  useToast,
  type Column,
} from "../components/ui";
import { formatBytes } from "../components/features/protect/common";
import { downloadPostFile } from "../components/features/protect/download";

interface CaseRow {
  id: string;
  ref: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  priority: number;
  detected_at: string;
  contained_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  mitre: string[];
  evidence_count: number;
  alert_count: number;
}

interface EvidenceRow {
  id: string;
  incident_id: string | null;
  kind: string;
  title: string;
  description: string | null;
  sha256: string;
  content_type: string;
  size_bytes: number;
  collected_by: string | null;
  collected_at: string;
  sealed: boolean;
  chain_length: number;
  has_file: boolean;
}

interface TimelineEntry {
  id: string;
  incident_id: string;
  at: string;
  kind: string;
  actor: string | null;
  summary: string;
  detail: Record<string, unknown>;
}

interface CaseAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  first_seen: string;
  last_seen: string;
  count: number;
  mitre: string[];
}

interface CaseDetail {
  case: CaseRow;
  timeline: TimelineEntry[];
  evidence: EvidenceRow[];
  alerts: CaseAlert[];
}

interface HashVerification {
  evidence_id: string;
  expected_sha256: string;
  computed_sha256: string | null;
  match: boolean;
  status: string;
  file_size: number | null;
  verified_at: string;
}

interface CustodyEntry {
  at?: string;
  action?: string;
  actor?: string;
  result?: string;
  expected_sha256?: string;
  computed_sha256?: string | null;
}

interface ChainOfCustody {
  evidence_id: string;
  incident_id: string | null;
  sha256: string;
  sealed: boolean;
  entries: CustodyEntry[];
  last_verified_at: string | null;
}

const copy = {
  es: {
    "eyebrow": "Gobernanza · Forense",
    "pageTitle": "Análisis forense",
    "subtitle":
      "Casos, evidencia inmutable, verificación de integridad SHA-256 y cadena de custodia append-only con descargas auditadas.",
    "refreshed": "Actualizado",
    "auditNote": "Toda exportación y verificación queda registrada en la cadena de auditoría inmutable.",
    "immutableNote": "La evidencia es inmutable y append-only: no se edita ni se elimina desde la interfaz.",
    "downloadNote": "Las descargas se registran con actor, recurso y checksum del paquete.",
    "cases": "Casos",
    "casesHint": "Incidentes con evidencia asociada; el recuento de evidencia proviene de la base de datos.",
    "searchCases": "Buscar por referencia, título o descripción",
    "allStatuses": "Todos los estados",
    "allSeverities": "Todas las severidades",
    "clearFilters": "Limpiar filtros",
    "noCases": "No hay casos forenses",
    "noCasesHint": "Cuando se registre evidencia sobre un incidente aparecerá aquí.",
    "noCaseResults": "Ningún caso coincide con los filtros",
    "noCaseResultsHint": "Ajusta la búsqueda o limpia los filtros para ver todos los casos.",
    "ref": "Referencia",
    "case": "Caso",
    "severity": "Severidad",
    "status": "Estado",
    "evidence": "Evidencia",
    "sealed": "Sellada",
    "alerts": "Alertas",
    "detected": "Detección",
    "open": "Abrir",
    "selected": "Caso seleccionado",
    "selectCase": "Selecciona un caso",
    "selectCaseHint": "Elige una fila de la tabla para inspeccionar su evidencia, custodia y cronología.",
    "detailTitle": "Detalle del caso",
    "description": "Descripción",
    "contained": "Contenida",
    "resolved": "Resuelta",
    "priority": "Prioridad",
    "exportZip": "Exportar caso (ZIP)",
    "exporting": "Generando ZIP…",
    "exportCsv": "Cronología CSV",
    "exportJson": "Cronología JSON",
    "exportTimelineHint": "La cronología se exporta desde el endpoint auditado del servidor.",
    "evidenceTitle": "Evidencia",
    "evidenceHint": "Lista paginada con filtros server-side. La verificación recalcula el SHA-256 real del fichero.",
    "searchEvidence": "Buscar por título, descripción o hash",
    "allKinds": "Todos los tipos",
    "kind": "Tipo",
    "sealedFilter": "Sellada",
    "anySeal": "Cualquier estado",
    "sealedYes": "Solo selladas",
    "sealedNo": "Solo sin sellar",
    "title": "Título",
    "hash": "SHA-256",
    "size": "Tamaño",
    "collected": "Recogida",
    "chain": "Cadena",
    "file": "Fichero",
    "filePresent": "Presente",
    "fileMissing": "Ausente",
    "verify": "Verificar hash",
    "verifying": "Verificando…",
    "custody": "Cadena de custodia",
    "custodyTitle": "Cadena de custodia",
    "custodyHint": "Entradas append-only; la verificación añade un registro con actor y resultado.",
    "noEvidence": "Sin evidencia para este caso",
    "noEvidenceHint": "La evidencia se registra durante la contención y el análisis del incidente.",
    "noEvidenceResults": "Ninguna evidencia coincide con los filtros",
    "noEvidenceResultsHint": "Limpia los filtros para ver toda la evidencia del caso.",
    "selectEvidence": "Selecciona evidencia para ver su cadena de custodia",
    "selectEvidenceHint": "Pulsa «Cadena de custodia» en una fila de evidencia.",
    "custodyEmpty": "La cadena de custodia está vacía para esta evidencia",
    "lastVerified": "Última verificación",
    "neverVerified": "Nunca verificada",
    "verified": "Integridad verificada",
    "mismatch": "Hash no coincide: posible alteración",
    "missingFile": "El fichero de evidencia no está disponible",
    "verificationResult": "Resultado de verificación",
    "expected": "Esperado",
    "computed": "Calculado",
    "timeline": "Cronología del caso",
    "timelineHint": "Eventos registrados por el sistema y los analistas, ordenados cronológicamente.",
    "noTimeline": "Sin eventos de cronología",
    "alertsTitle": "Alertas vinculadas",
    "alertsHint": "Alertas correlacionadas con el incidente.",
    "noAlerts": "Sin alertas vinculadas",
    "alert": "Alerta",
    "techniques": "Técnicas",
    "count": "Eventos",
    "lastSeen": "Última observación",
    "firstSeen": "Primera observación",
    "loadCasesFailed": "No se pudieron cargar los casos",
    "loadDetailFailed": "No se pudo cargar el detalle del caso",
    "loadEvidenceFailed": "No se pudo cargar la evidencia",
    "exportFailed": "No se pudo completar la exportación",
    "exportSuccess": "Exportación generada y descarga iniciada",
    "verifySuccess": "Hash verificado",
    "verifyFailed": "No se pudo verificar el hash",
    "verifyMatch": "El hash calculado coincide con el registrado",
    "verifyMismatch": "El hash calculado NO coincide con el registrado",
    "verifyMissing": "No se pudo leer el fichero de evidencia",
    "permissionDenied": "Tu rol no permite verificar hashes (incident:write).",
    "exportPerm": "La exportación requiere permiso de lectura de incidentes.",
    "audited": "Auditado",
    "caseCount": "Casos",
    "sealedCount": "Selladas",
    "evidenceCount": "Evidencia",
    "unsealed": "Sin sellar",
    "hashShort": "Hash",
    "showChain": "Ver cadena",
    "chainEntries": "{count} entradas",
    "actor": "Actor",
    "action": "Acción",
    "result": "Resultado",
    "at": "Fecha",
    "details": "Detalle",
    "noDetails": "Sin detalle adicional",
    "page": "Página",
    "caseDetailKicker": "Expediente",
    "evidenceFilters": "Filtros de evidencia",
    "clearEvidence": "Limpiar",
    "priorityLabel": "P{priority}",
    "timelineExporting": "Exportando…",
  },
  en: {
    "eyebrow": "Govern · Forensics",
    "pageTitle": "Forensics",
    "subtitle":
      "Cases, immutable evidence, SHA-256 integrity verification and an append-only chain of custody with audited downloads.",
    "refreshed": "Updated",
    "auditNote": "Every export and verification is recorded in the immutable audit chain.",
    "immutableNote": "Evidence is immutable and append-only: it cannot be edited or deleted from the UI.",
    "downloadNote": "Downloads are logged with actor, resource and bundle checksum.",
    "cases": "Cases",
    "casesHint": "Incidents with associated evidence; the evidence count comes from the database.",
    "searchCases": "Search by reference, title or description",
    "allStatuses": "All statuses",
    "allSeverities": "All severities",
    "clearFilters": "Clear filters",
    "noCases": "No forensic cases",
    "noCasesHint": "Cases appear here once evidence is recorded against an incident.",
    "noCaseResults": "No case matches the filters",
    "noCaseResultsHint": "Adjust the search or clear the filters to see every case.",
    "ref": "Reference",
    "case": "Case",
    "severity": "Severity",
    "status": "Status",
    "evidence": "Evidence",
    "sealed": "Sealed",
    "alerts": "Alerts",
    "detected": "Detected",
    "open": "Open",
    "selected": "Selected case",
    "selectCase": "Select a case",
    "selectCaseHint": "Pick a table row to inspect its evidence, custody and timeline.",
    "detailTitle": "Case detail",
    "description": "Description",
    "contained": "Contained",
    "resolved": "Resolved",
    "priority": "Priority",
    "exportZip": "Export case (ZIP)",
    "exporting": "Building ZIP…",
    "exportCsv": "Timeline CSV",
    "exportJson": "Timeline JSON",
    "exportTimelineHint": "The timeline is exported from the server's audited endpoint.",
    "evidenceTitle": "Evidence",
    "evidenceHint": "Paginated list with server-side filters. Verification recomputes the file's real SHA-256.",
    "searchEvidence": "Search by title, description or hash",
    "allKinds": "All types",
    "kind": "Type",
    "sealedFilter": "Sealed",
    "anySeal": "Any state",
    "sealedYes": "Sealed only",
    "sealedNo": "Unsealed only",
    "title": "Title",
    "hash": "SHA-256",
    "size": "Size",
    "collected": "Collected",
    "chain": "Chain",
    "file": "File",
    "filePresent": "Present",
    "fileMissing": "Missing",
    "verify": "Verify hash",
    "verifying": "Verifying…",
    "custody": "Chain of custody",
    "custodyTitle": "Chain of custody",
    "custodyHint": "Append-only entries; verification appends a record with actor and result.",
    "noEvidence": "No evidence for this case",
    "noEvidenceHint": "Evidence is recorded during incident containment and analysis.",
    "noEvidenceResults": "No evidence matches the filters",
    "noEvidenceResultsHint": "Clear the filters to see all evidence in the case.",
    "selectEvidence": "Select evidence to view its chain of custody",
    "selectEvidenceHint": "Press “View chain” on an evidence row.",
    "custodyEmpty": "The chain of custody is empty for this evidence",
    "lastVerified": "Last verification",
    "neverVerified": "Never verified",
    "verified": "Integrity verified",
    "mismatch": "Hash mismatch: possible tampering",
    "missingFile": "The evidence file is not available",
    "verificationResult": "Verification result",
    "expected": "Expected",
    "computed": "Computed",
    "timeline": "Case timeline",
    "timelineHint": "Events recorded by the system and analysts, ordered chronologically.",
    "noTimeline": "No timeline events",
    "alertsTitle": "Linked alerts",
    "alertsHint": "Alerts correlated with the incident.",
    "noAlerts": "No linked alerts",
    "alert": "Alert",
    "techniques": "Techniques",
    "count": "Events",
    "lastSeen": "Last seen",
    "firstSeen": "First seen",
    "loadCasesFailed": "Could not load cases",
    "loadDetailFailed": "Could not load case detail",
    "loadEvidenceFailed": "Could not load evidence",
    "exportFailed": "The export could not be completed",
    "exportSuccess": "Export generated and download started",
    "verifySuccess": "Hash verified",
    "verifyFailed": "Could not verify the hash",
    "verifyMatch": "The computed hash matches the recorded hash",
    "verifyMismatch": "The computed hash does NOT match the recorded hash",
    "verifyMissing": "The evidence file could not be read",
    "permissionDenied": "Your role cannot verify hashes (incident:write).",
    "exportPerm": "Export requires incident read permission.",
    "audited": "Audited",
    "caseCount": "Cases",
    "sealedCount": "Sealed",
    "evidenceCount": "Evidence",
    "unsealed": "Unsealed",
    "hashShort": "Hash",
    "showChain": "View chain",
    "chainEntries": "{count} entries",
    "actor": "Actor",
    "action": "Action",
    "result": "Result",
    "at": "Date",
    "details": "Detail",
    "noDetails": "No additional detail",
    "page": "Page",
    "caseDetailKicker": "Case file",
    "evidenceFilters": "Evidence filters",
    "clearEvidence": "Clear",
    "priorityLabel": "P{priority}",
    "timelineExporting": "Exporting…",
  },
};

function sealedBadge(sealed: boolean, labelSealed: string, labelUnsealed: string) {
  return sealed ? <Badge tone="success">{labelSealed}</Badge> : <Badge tone="neutral">{labelUnsealed}</Badge>;
}

function verificationTone(status: string): "success" | "danger" | "warning" | "neutral" {
  if (status === "match") return "success";
  if (status === "mismatch") return "danger";
  if (status === "file_missing") return "warning";
  return "neutral";
}

function safeFilename(value: string | null | undefined, fallback: string): string {
  const cleaned = (value ?? "").replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+|[._]+$/g, "").slice(0, 80);
  return cleaned || fallback;
}

export function ForensicsPage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(copy);
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();

  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [casePage, setCasePage] = useState(1);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [evidencePage, setEvidencePage] = useState(1);
  const [evidenceQ, setEvidenceQ] = useState("");
  const [evidenceKind, setEvidenceKind] = useState("");
  const [sealedFilter, setSealedFilter] = useState("");
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [verification, setVerification] = useState<HashVerification | null>(null);
  const [exportingFormat, setExportingFormat] = useState<"csv" | "json" | null>(null);
  const [confirmExport, setConfirmExport] = useState(false);

  const canVerify = can("incident:write");

  const casesQuery = useQuery({
    queryKey: ["forensics", "cases", { q, status, severity, page: casePage }],
    queryFn: () => api.get<Page<CaseRow>>("/forensics/cases", { q, status, severity, page: casePage, page_size: 10 }),
  });

  const cases = casesQuery.data?.items ?? [];
  const activeId = selectedCaseId ?? cases[0]?.id ?? null;

  const caseDetails = useQueries({
    queries: cases.map((item) => ({
      queryKey: ["forensics", "case", item.id],
      queryFn: () => api.get<CaseDetail>(`/forensics/cases/${item.id}`),
      staleTime: 30_000,
    })),
  });

  const sealedByCase = new Map<string, number>();
  caseDetails.forEach((detail, index) => {
    const row = cases[index];
    if (row && detail.data) sealedByCase.set(row.id, detail.data.evidence.filter((item) => item.sealed).length);
  });

  const detailQuery = useQuery({
    queryKey: ["forensics", "case", activeId],
    queryFn: () => api.get<CaseDetail>(`/forensics/cases/${activeId}`),
    enabled: Boolean(activeId),
  });

  const evidenceQuery = useQuery({
    queryKey: ["forensics", "evidence", { activeId, evidenceQ, evidenceKind, sealedFilter, evidencePage }],
    queryFn: () =>
      api.get<Page<EvidenceRow>>("/forensics/evidence", {
        incident_id: activeId ?? undefined,
        q: evidenceQ,
        kind: evidenceKind,
        sealed: sealedFilter === "" ? undefined : sealedFilter === "true",
        page: evidencePage,
        page_size: 10,
      }),
    enabled: Boolean(activeId),
  });

  const chainQuery = useQuery({
    queryKey: ["forensics", "custody", selectedEvidenceId],
    queryFn: () => api.get<ChainOfCustody>(`/forensics/evidence/${selectedEvidenceId}/chain-of-custody`),
    enabled: Boolean(selectedEvidenceId),
  });

  const verifyMutation = useMutation({
    mutationFn: (evidenceId: string) =>
      api.post<HashVerification>(`/forensics/evidence/${evidenceId}/verify-hash`),
    onSuccess: (result) => {
      setVerification(result);
      toast.push(
        result.status === "match"
          ? `${c("verifySuccess")}: ${c("verifyMatch")}`
          : `${c("verifySuccess")}: ${result.status === "mismatch" ? c("verifyMismatch") : c("verifyMissing")}`,
        result.status === "match" ? "success" : "error",
      );
      void queryClient.invalidateQueries({ queryKey: ["forensics", "evidence"] });
      void queryClient.invalidateQueries({ queryKey: ["forensics", "case", activeId] });
      if (selectedEvidenceId) void queryClient.invalidateQueries({ queryKey: ["forensics", "custody", selectedEvidenceId] });
    },
    onError: (error) => toast.push(errorMessage(error), "error"),
  });

  const exportMutation = useMutation({
    mutationFn: async () => {
      if (!activeId) throw new Error("No case selected");
      const ref = safeFilename(detailQuery.data?.case.ref, "case");
      await downloadPostFile(`/forensics/cases/${activeId}/export`, `case-${ref}-evidence.zip`);
    },
    onSuccess: () => {
      setConfirmExport(false);
      toast.push(c("exportSuccess"), "success");
      void queryClient.invalidateQueries({ queryKey: ["forensics", "case", activeId] });
    },
    onError: (error) => {
      setConfirmExport(false);
      toast.push(`${c("exportFailed")}: ${errorMessage(error)}`, "error");
    },
  });

  const timelineExport = async (format: "csv" | "json") => {
    if (!activeId) return;
    const ref = safeFilename(detailQuery.data?.case.ref, "case");
    setExportingFormat(format);
    try {
      await downloadFile(
        withQuery("/forensics/timeline/export", { incident_id: activeId, format }),
        `case-${ref}-timeline.${format}`,
      );
      toast.push(c("exportSuccess"), "success");
    } catch (error) {
      toast.push(`${c("exportFailed")}: ${errorMessage(error)}`, "error");
    } finally {
      setExportingFormat(null);
    }
  };

  const resetCasePaging = () => {
    setCasePage(1);
    setSelectedCaseId(null);
    setSelectedEvidenceId(null);
    setVerification(null);
    setEvidencePage(1);
  };

  const resetEvidencePaging = () => {
    setEvidencePage(1);
  };

  if (casesQuery.isLoading) return <PageSkeleton />;
  if (casesQuery.isError) {
    return (
      <div data-testid="page-forensics">
        <PageHeader eyebrow={c("eyebrow")} title={c("pageTitle")} subtitle={c("subtitle")} />
        <ErrorBanner title={c("loadCasesFailed")} message={errorMessage(casesQuery.error)} onRetry={() => void casesQuery.refetch()} />
      </div>
    );
  }

  const detail = detailQuery.data;
  const activeCase = detail?.case ?? cases.find((item) => item.id === activeId) ?? null;
  const evidenceRows = evidenceQuery.data?.items ?? [];
  const evidenceTotal = detail?.evidence.length ?? 0;
  const sealedTotal = detail?.evidence.filter((item) => item.sealed).length ?? 0;
  const hasCaseFilters = Boolean(q || status || severity);
  const hasEvidenceFilters = Boolean(evidenceQ || evidenceKind || sealedFilter);

  const caseColumns: Column<CaseRow>[] = [
    {
      key: "case",
      header: c("case"),
      render: (row) => (
        <div style={{ minWidth: 230 }}>
          <div className="mono" style={{ fontSize: 10, color: "var(--accent)", marginBottom: 2 }}>{row.ref}</div>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.title}</div>
          <div className="cell-sub">{truncate(row.description ?? "—", 72)}</div>
        </div>
      ),
    },
    { key: "severity", header: c("severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: c("status"), width: "120px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "evidence",
      header: c("evidence"),
      width: "100px",
      align: "right",
      render: (row) => <span className="mono">{formatNumber(row.evidence_count)}</span>,
    },
    {
      key: "sealed",
      header: c("sealed"),
      width: "100px",
      align: "right",
      render: (row) => {
        const sealed = sealedByCase.get(row.id);
        return sealed === undefined ? <span className="dim">—</span> : <span className="mono" style={{ color: sealed === row.evidence_count && row.evidence_count > 0 ? "var(--success)" : "var(--warning)" }}>{formatNumber(sealed)}</span>;
      },
    },
    {
      key: "alerts",
      header: c("alerts"),
      width: "88px",
      align: "right",
      render: (row) => <span className="mono">{formatNumber(row.alert_count)}</span>,
    },
    {
      key: "detected",
      header: c("detected"),
      width: "126px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)" }}>{formatDateTime(row.detected_at, lang)}</span>,
    },
  ];

  const evidenceColumns: Column<EvidenceRow>[] = [
    {
      key: "title",
      header: c("title"),
      render: (row) => (
        <div style={{ minWidth: 210 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.title}</div>
          <div className="cell-sub mono">{row.kind} · {row.content_type}</div>
          {row.description ? <div className="cell-sub">{truncate(row.description, 80)}</div> : null}
        </div>
      ),
    },
    {
      key: "hash",
      header: c("hash"),
      width: "190px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)" }} title={row.sha256}>
          {row.sha256.slice(0, 16)}…
        </span>
      ),
    },
    {
      key: "size",
      header: c("size"),
      width: "92px",
      align: "right",
      render: (row) => <span className="mono">{formatBytes(row.size_bytes)}</span>,
    },
    {
      key: "collected",
      header: c("collected"),
      width: "122px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.collected_at, lang)}</span>,
    },
    {
      key: "sealed",
      header: c("sealed"),
      width: "104px",
      render: (row) => sealedBadge(row.sealed, c("sealedYes"), c("unsealed")),
    },
    {
      key: "chain",
      header: c("chain"),
      width: "88px",
      align: "right",
      render: (row) => <span className="mono">{formatNumber(row.chain_length)}</span>,
    },
    {
      key: "file",
      header: c("file"),
      width: "100px",
      render: (row) => (
        <Badge tone={row.has_file ? "success" : "warning"}>{row.has_file ? c("filePresent") : c("fileMissing")}</Badge>
      ),
    },
    {
      key: "actions",
      header: t("common.actions"),
      width: "222px",
      render: (row) => (
        <div className="row wrap" style={{ gap: 6 }}>
          <Button
            size="sm"
            icon={FileCheck2}
            loading={verifyMutation.isPending && verifyMutation.variables === row.id}
            disabled={!canVerify}
            onClick={() => verifyMutation.mutate(row.id)}
            title={canVerify ? undefined : c("permissionDenied")}
            data-testid={`verify-${row.id}`}
          >
            {verifyMutation.isPending && verifyMutation.variables === row.id ? c("verifying") : c("verify")}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={History}
            onClick={() => {
              setSelectedEvidenceId(row.id);
              setVerification(null);
            }}
            data-testid={`custody-${row.id}`}
          >
            {c("showChain")}
          </Button>
        </div>
      ),
    },
  ];

  const alertColumns: Column<CaseAlert>[] = [
    { key: "title", header: c("alert"), render: (row) => <div style={{ minWidth: 220, color: "var(--text)" }}>{row.title}</div> },
    { key: "severity", header: c("severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: c("status"), width: "120px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "count",
      header: c("count"),
      width: "80px",
      align: "right",
      render: (row) => <span className="mono">{formatNumber(row.count)}</span>,
    },
    {
      key: "last",
      header: c("lastSeen"),
      width: "130px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{relativeTime(row.last_seen, lang)}</span>,
    },
  ];

  const caseEmpty = hasCaseFilters ? (
    <EmptyState
      icon={SearchX}
      title={c("noCaseResults")}
      description={c("noCaseResultsHint")}
      action={
        <Button
          size="sm"
          onClick={() => {
            setQ("");
            setStatus("");
            setSeverity("");
            resetCasePaging();
          }}
        >
          {c("clearFilters")}
        </Button>
      }
    />
  ) : (
    <EmptyState
      icon={Microscope}
      title={c("noCases")}
      description={c("noCasesHint")}
      action={<LinkButton to="/incidents" size="sm">{t("nav.incidents")}</LinkButton>}
    />
  );

  const evidenceEmpty = hasEvidenceFilters ? (
    <EmptyState
      icon={SearchX}
      title={c("noEvidenceResults")}
      description={c("noEvidenceResultsHint")}
      action={
        <Button
          size="sm"
          onClick={() => {
            setEvidenceQ("");
            setEvidenceKind("");
            setSealedFilter("");
            resetEvidencePaging();
          }}
        >
          {c("clearEvidence")}
        </Button>
      }
    />
  ) : (
    <EmptyState
      icon={Archive}
      title={c("noEvidence")}
      description={c("noEvidenceHint")}
      action={<LinkButton to="/incidents" size="sm">{t("nav.incidents")}</LinkButton>}
    />
  );

  return (
    <div className="animate-in" data-testid="page-forensics">
      <PageHeader
        eyebrow={c("eyebrow")}
        title={c("pageTitle")}
        subtitle={c("subtitle")}
        actions={
          <>
            <span className="mono hide-mobile" style={{ fontSize: 10, color: "var(--dim)" }}>
              {c("refreshed")}{" "}
              {casesQuery.dataUpdatedAt ? formatDateTime(new Date(casesQuery.dataUpdatedAt).toISOString(), lang) : "—"}
            </span>
            <Button
              icon={RefreshCw}
              onClick={() => {
                void casesQuery.refetch();
                if (activeId) {
                  void detailQuery.refetch();
                  void evidenceQuery.refetch();
                }
              }}
              aria-label={t("common.refresh")}
              data-testid="refresh-forensics"
            />
            <LinkButton to="/incidents" icon={Microscope}>{t("nav.incidents")}</LinkButton>
          </>
        }
      />

      <div className="notice" style={{ marginBottom: 12 }}>
        <Lock size={14} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
        <span>
          {c("immutableNote")} {c("auditNote")}
        </span>
      </div>

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi label={c("caseCount")} value={formatNumber(casesQuery.data?.meta.total ?? 0)} icon={Microscope} tone="accent" footer={<span>{c("casesHint")}</span>} />
        <Kpi
          label={c("evidenceCount")}
          value={formatNumber(evidenceTotal)}
          icon={Archive}
          tone="neutral"
          footer={<span>{c("selected")}: {activeCase?.ref ?? "—"}</span>}
        />
        <Kpi
          label={c("sealedCount")}
          value={formatNumber(sealedTotal)}
          icon={ShieldCheck}
          tone={sealedTotal === evidenceTotal && evidenceTotal > 0 ? "success" : "warning"}
          footer={<span>{formatNumber(Math.max(0, evidenceTotal - sealedTotal))} {c("unsealed").toLowerCase()}</span>}
        />
        <Kpi
          label={c("alerts")}
          value={formatNumber(detail?.alerts.length ?? 0)}
          icon={Fingerprint}
          tone={(detail?.alerts.length ?? 0) > 0 ? "warning" : "success"}
          footer={<span>{c("alertsHint")}</span>}
        />
      </div>

      <Card
        title={c("cases")}
        subtitle={c("casesHint")}
        bodyClassName=""
        actions={<Badge tone="neutral">{formatNumber(casesQuery.data?.meta.total ?? 0)}</Badge>}
        footer={<Pagination meta={casesQuery.data?.meta} onPage={(page) => { setCasePage(page); setSelectedCaseId(null); }} />}
      >
        <div className="filters-bar" data-testid="forensics-case-filters">
          <SearchInput
            value={q}
            onChange={(value) => {
              setQ(value);
              resetCasePaging();
            }}
            placeholder={c("searchCases")}
            ariaLabel={c("searchCases")}
          />
          <Select
            value={status}
            onChange={(event) => {
              setStatus(event.target.value);
              resetCasePaging();
            }}
            aria-label={c("status")}
            data-testid="filter-case-status"
          >
            <option value="">{c("allStatuses")}</option>
            <option value="new">{humanize("new")}</option>
            <option value="triaged">{humanize("triaged")}</option>
            <option value="investigating">{humanize("investigating")}</option>
            <option value="contained">{humanize("contained")}</option>
            <option value="eradicated">{humanize("eradicated")}</option>
            <option value="recovered">{humanize("recovered")}</option>
            <option value="closed">{humanize("closed")}</option>
          </Select>
          <Select
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              resetCasePaging();
            }}
            aria-label={c("severity")}
            data-testid="filter-case-severity"
          >
            <option value="">{c("allSeverities")}</option>
            <option value="critical">{t("common.critical")}</option>
            <option value="high">{t("common.high")}</option>
            <option value="medium">{t("common.medium")}</option>
            <option value="low">{t("common.low")}</option>
          </Select>
          {hasCaseFilters ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setQ("");
                setStatus("");
                setSeverity("");
                resetCasePaging();
              }}
            >
              {c("clearFilters")}
            </Button>
          ) : null}
        </div>
        <div data-testid="forensics-cases-table">
          <DataTable
            columns={caseColumns}
            rows={cases}
            rowKey={(row) => row.id}
            onRowClick={(row) => {
              setSelectedCaseId(row.id);
              setEvidencePage(1);
              setSelectedEvidenceId(null);
              setVerification(null);
            }}
            empty={caseEmpty}
          />
        </div>
      </Card>

      <div style={{ marginTop: 12 }}>
        {!activeCase ? (
          <Card title={c("detailTitle")}>
            <EmptyState icon={Microscope} title={c("selectCase")} description={c("selectCaseHint")} />
          </Card>
        ) : detailQuery.isError ? (
          <Card title={c("detailTitle")}>
            <ErrorBanner
              title={c("loadDetailFailed")}
              message={errorMessage(detailQuery.error)}
              onRetry={() => void detailQuery.refetch()}
            />
          </Card>
        ) : detailQuery.isLoading || !detail ? (
          <Card title={c("detailTitle")}>
            <TableSkeleton rows={6} />
          </Card>
        ) : (
          <div className="stack">
            <Card
              title={`${activeCase.ref} · ${activeCase.title}`}
              subtitle={`${c("caseDetailKicker")} · ${c("priorityLabel").replace("{priority}", String(activeCase.priority))}`}
              actions={
                <div className="row wrap" style={{ gap: 6 }}>
                  <SeverityBadge severity={activeCase.severity} />
                  <StatusBadge status={activeCase.status} />
                </div>
              }
              footer={
                <span className="row wrap" style={{ gap: 8 }}>
                  <Lock size={12} aria-hidden="true" />
                  <span>{c("downloadNote")}</span>
                </span>
              }
            >
              <div className="row-between wrap" style={{ gap: 12, alignItems: "flex-start" }}>
                <div style={{ flex: "1 1 320px", minWidth: 240 }}>
                  <p className="muted" style={{ fontSize: 12.5 }}>{activeCase.description ?? "—"}</p>
                  <div className="stat-inline" style={{ marginTop: 12 }}>
                    <div>
                      <span className="label">{c("detected")}</span>
                      <span className="value" style={{ fontSize: 14 }}>{formatDateTime(activeCase.detected_at, lang)}</span>
                    </div>
                    <div>
                      <span className="label">{c("contained")}</span>
                      <span className="value" style={{ fontSize: 14 }}>{formatDateTime(activeCase.contained_at, lang)}</span>
                    </div>
                    <div>
                      <span className="label">{c("resolved")}</span>
                      <span className="value" style={{ fontSize: 14 }}>{formatDateTime(activeCase.resolved_at, lang)}</span>
                    </div>
                  </div>
                  <div className="chip-row" style={{ marginTop: 10 }}>
                    {activeCase.mitre.length ? activeCase.mitre.map((technique) => <span className="tag" key={technique}>{technique}</span>) : <span className="dim">—</span>}
                  </div>
                </div>
                <div className="stack" style={{ flex: "0 1 280px", minWidth: 220 }}>
                  <Button
                    variant="primary"
                    icon={Download}
                    loading={exportMutation.isPending && !confirmExport}
                    onClick={() => setConfirmExport(true)}
                    data-testid="export-case-zip"
                  >
                    {exportMutation.isPending && !confirmExport ? c("exporting") : c("exportZip")}
                  </Button>
                  <div className="row wrap" style={{ gap: 6 }}>
                    <Button
                      size="sm"
                      icon={FileClock}
                      loading={exportingFormat === "csv"}
                      onClick={() => void timelineExport("csv")}
                      data-testid="export-timeline-csv"
                    >
                      {exportingFormat === "csv" ? c("timelineExporting") : c("exportCsv")}
                    </Button>
                    <Button
                      size="sm"
                      icon={FileClock}
                      loading={exportingFormat === "json"}
                      onClick={() => void timelineExport("json")}
                      data-testid="export-timeline-json"
                    >
                      {exportingFormat === "json" ? c("timelineExporting") : c("exportJson")}
                    </Button>
                  </div>
                  <span className="dim" style={{ fontSize: 10.5 }}>{c("exportTimelineHint")}</span>
                </div>
              </div>
            </Card>

            <div className="split-main">
              <Card
                title={c("evidenceTitle")}
                subtitle={c("evidenceHint")}
                bodyClassName=""
                actions={<Badge tone="neutral">{formatNumber(evidenceQuery.data?.meta.total ?? 0)}</Badge>}
                footer={<Pagination meta={evidenceQuery.data?.meta} onPage={setEvidencePage} />}
              >
                <div className="filters-bar" data-testid="forensics-evidence-filters">
                  <SearchInput
                    value={evidenceQ}
                    onChange={(value) => {
                      setEvidenceQ(value);
                      resetEvidencePaging();
                    }}
                    placeholder={c("searchEvidence")}
                    ariaLabel={c("searchEvidence")}
                  />
                  <Input
                    value={evidenceKind}
                    onChange={(event) => {
                      setEvidenceKind(event.target.value);
                      resetEvidencePaging();
                    }}
                    placeholder={c("kind")}
                    aria-label={c("kind")}
                    style={{ width: 130 }}
                    data-testid="filter-evidence-kind"
                  />
                  <Select
                    value={sealedFilter}
                    onChange={(event) => {
                      setSealedFilter(event.target.value);
                      resetEvidencePaging();
                    }}
                    aria-label={c("sealedFilter")}
                    data-testid="filter-evidence-sealed"
                  >
                    <option value="">{c("anySeal")}</option>
                    <option value="true">{c("sealedYes")}</option>
                    <option value="false">{c("sealedNo")}</option>
                  </Select>
                  {hasEvidenceFilters ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        setEvidenceQ("");
                        setEvidenceKind("");
                        setSealedFilter("");
                        resetEvidencePaging();
                      }}
                    >
                      {c("clearEvidence")}
                    </Button>
                  ) : null}
                </div>
                {evidenceQuery.isError ? (
                  <div style={{ padding: 12 }}>
                    <ErrorBanner
                      title={c("loadEvidenceFailed")}
                      message={errorMessage(evidenceQuery.error)}
                      onRetry={() => void evidenceQuery.refetch()}
                    />
                  </div>
                ) : (
                  <div data-testid="forensics-evidence-table">
                    <DataTable
                      columns={evidenceColumns}
                      rows={evidenceRows}
                      rowKey={(row) => row.id}
                      loading={evidenceQuery.isLoading}
                      empty={evidenceEmpty}
                    />
                  </div>
                )}
                {verification ? (
                  <div className="card-footer" style={{ borderTop: "1px solid var(--border)" }} data-testid="verification-result">
                    <Badge tone={verificationTone(verification.status)}>
                      {verification.status === "match" ? c("verified") : verification.status === "mismatch" ? c("mismatch") : c("missingFile")}
                    </Badge>
                    <span className="mono" style={{ fontSize: 10 }} title={verification.computed_sha256 ?? undefined}>
                      {c("computed")}: {verification.computed_sha256 ? `${verification.computed_sha256.slice(0, 20)}…` : "—"}
                    </span>
                    <span className="dim" style={{ fontSize: 10, marginLeft: "auto" }}>
                      {formatDateTime(verification.verified_at, lang)}
                    </span>
                  </div>
                ) : null}
              </Card>

              <div className="stack">
                <Card
                  title={c("custodyTitle")}
                  subtitle={c("custodyHint")}
                  actions={
                    chainQuery.data ? (
                      <Badge tone={chainQuery.data.sealed ? "success" : "neutral"}>
                        {chainQuery.data.sealed ? c("sealedYes") : c("unsealed")}
                      </Badge>
                    ) : null
                  }
                >
                  {!selectedEvidenceId ? (
                    <EmptyState icon={History} title={c("selectEvidence")} description={c("selectEvidenceHint")} />
                  ) : chainQuery.isLoading ? (
                    <TableSkeleton rows={4} />
                  ) : chainQuery.isError ? (
                    <ErrorBanner compact message={errorMessage(chainQuery.error)} onRetry={() => void chainQuery.refetch()} />
                  ) : !chainQuery.data || chainQuery.data.entries.length === 0 ? (
                    <EmptyState icon={History} title={c("custodyEmpty")} />
                  ) : (
                    <div data-testid="custody-timeline">
                      <div className="notice notice-accent" style={{ marginBottom: 10, fontSize: 11 }}>
                        <Fingerprint size={13} style={{ flex: "0 0 auto" }} aria-hidden="true" />
                        <span className="mono" style={{ wordBreak: "break-all" }}>{chainQuery.data.sha256}</span>
                      </div>
                      <div className="timeline">
                        {chainQuery.data.entries.map((entry, index) => (
                          <div className={`timeline-item ${entry.result === "mismatch" || entry.result === "file_missing" ? "danger" : entry.result === "match" ? "success" : ""}`} key={`${entry.at ?? index}-${index}`}>
                            <div className="row-between wrap" style={{ gap: 6 }}>
                              <strong style={{ fontSize: 12 }}>{humanize(entry.action ?? "entry")}</strong>
                              <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{entry.at ? formatDateTime(entry.at, lang) : "—"}</span>
                            </div>
                            <div className="item-sub">{c("actor")}: {entry.actor ?? "—"}</div>
                            {entry.result ? (
                              <div style={{ marginTop: 3 }}>
                                <Badge tone={entry.result === "match" ? "success" : entry.result === "mismatch" ? "danger" : "neutral"}>
                                  {entry.result}
                                </Badge>
                              </div>
                            ) : null}
                            {entry.computed_sha256 ? (
                              <div className="mono" style={{ fontSize: 9.5, color: "var(--dim)", marginTop: 4, wordBreak: "break-all" }}>
                                {c("computed")}: {entry.computed_sha256}
                              </div>
                            ) : null}
                          </div>
                        ))}
                      </div>
                      <div className="row-between" style={{ fontSize: 10.5, color: "var(--dim)", marginTop: 6 }}>
                        <span>{c("lastVerified")}</span>
                        <span className="mono">{chainQuery.data.last_verified_at ? formatDateTime(chainQuery.data.last_verified_at, lang) : c("neverVerified")}</span>
                      </div>
                    </div>
                  )}
                </Card>

                <Card title={c("alertsTitle")} subtitle={c("alertsHint")} bodyClassName="">
                  <div data-testid="forensics-alerts-table">
                    <DataTable
                      columns={alertColumns}
                      rows={detail.alerts}
                      rowKey={(row) => row.id}
                      empty={<EmptyState icon={ShieldCheck} title={c("noAlerts")} />}
                    />
                  </div>
                </Card>
              </div>
            </div>

            <div className="split-main">
              <Card title={c("timeline")} subtitle={c("timelineHint")}>
                {detail.timeline.length === 0 ? (
                  <EmptyState icon={History} title={c("noTimeline")} />
                ) : (
                  <div className="timeline" data-testid="case-timeline">
                    {detail.timeline.map((entry) => (
                      <div className="timeline-item" key={entry.id}>
                        <div className="row-between wrap" style={{ gap: 6 }}>
                          <strong style={{ fontSize: 12 }}>{entry.summary}</strong>
                          <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{formatDateTime(entry.at, lang)}</span>
                        </div>
                        <div className="item-sub">
                          {humanize(entry.kind)} · {entry.actor ?? "—"}
                        </div>
                        {Object.keys(entry.detail ?? {}).length ? (
                          <pre className="code-block" style={{ marginTop: 6, fontSize: 10 }}>{JSON.stringify(entry.detail, null, 2)}</pre>
                        ) : null}
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              <Card title={c("verificationResult")} subtitle={c("evidenceHint")}>
                {!verification ? (
                  <EmptyState icon={Fingerprint} title={c("selectEvidence")} description={c("selectEvidenceHint")} />
                ) : (
                  <div className="stack" data-testid="verification-detail">
                    <div className="row wrap" style={{ gap: 8 }}>
                      {verification.match ? (
                        <Badge tone="success"><CheckCircle2 size={12} /> {c("verified")}</Badge>
                      ) : verification.status === "file_missing" ? (
                        <Badge tone="warning"><ShieldX size={12} /> {c("missingFile")}</Badge>
                      ) : (
                        <Badge tone="danger"><XCircle size={12} /> {c("mismatch")}</Badge>
                      )}
                      <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{formatDateTime(verification.verified_at, lang)}</span>
                    </div>
                    <div className="metric-list">
                      <div className="metric-row">
                        <span className="metric-label">{c("expected")}</span>
                        <span className="metric-value" style={{ wordBreak: "break-all", textAlign: "right" }}>{verification.expected_sha256}</span>
                      </div>
                      <div className="metric-row">
                        <span className="metric-label">{c("computed")}</span>
                        <span className="metric-value" style={{ wordBreak: "break-all", textAlign: "right" }}>{verification.computed_sha256 ?? "—"}</span>
                      </div>
                      <div className="metric-row">
                        <span className="metric-label">{c("size")}</span>
                        <span className="metric-value">{formatBytes(verification.file_size)}</span>
                      </div>
                      <div className="metric-row">
                        <span className="metric-label">{c("result")}</span>
                        <span className="metric-value">{verification.status}</span>
                      </div>
                    </div>
                    {!canVerify ? <div className="notice notice-warning">{c("permissionDenied")}</div> : null}
                  </div>
                )}
              </Card>
            </div>
          </div>
        )}
      </div>

      <Modal
        open={confirmExport}
        onClose={() => setConfirmExport(false)}
        title={c("exportZip")}
        footer={
          <>
            <Button onClick={() => setConfirmExport(false)}>{t("common.cancel")}</Button>
            <Button
              variant="primary"
              loading={exportMutation.isPending}
              onClick={() => exportMutation.mutate()}
              data-testid="confirm-export-case"
            >
              {exportMutation.isPending ? c("exporting") : t("common.confirm")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <p style={{ fontSize: 12.5 }}>{c("downloadNote")}</p>
          <div className="notice notice-accent">
            <Lock size={14} style={{ flex: "0 0 auto" }} />
            <span>
              {c("auditNote")} {c("exportPerm")}
            </span>
          </div>
          <div className="metric-list">
            <div className="metric-row">
              <span className="metric-label">{c("case")}</span>
              <span className="metric-value">{activeCase?.ref ?? "—"}</span>
            </div>
            <div className="metric-row">
              <span className="metric-label">{c("evidence")}</span>
              <span className="metric-value">{formatNumber(evidenceTotal)}</span>
            </div>
            <div className="metric-row">
              <span className="metric-label">{c("sealed")}</span>
              <span className="metric-value">{formatNumber(sealedTotal)}</span>
            </div>
          </div>
        </div>
      </Modal>

      <div className="notice" style={{ fontSize: 11, marginTop: 12 }}>
        <ShieldCheck size={14} style={{ flex: "0 0 auto", color: "var(--success)" }} />
        <span>
          {c("audited")} · {c("downloadNote")} · {c("immutableNote")}
        </span>
      </div>
    </div>
  );
}

export default ForensicsPage;
