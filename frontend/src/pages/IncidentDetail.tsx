import { useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  ArrowRightLeft,
  CheckCircle2,
  Download,
  FileCheck2,
  FileLock2,
  FileSearch,
  Fingerprint,
  Gauge,
  History,
  Lock,
  Paperclip,
  PlayCircle,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Upload,
  UserRound,
} from "lucide-react";
import { api, ApiError, downloadFile, errorMessage, getActiveOrg, getCookie, isApiError, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { durationMinutes, formatDateTime, formatNumber, humanize, relativeTime } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
  Field,
  Input,
  LinkButton,
  Modal,
  PageHeader,
  PageSkeleton,
  ProgressBar,
  Select,
  SeverityBadge,
  StatusBadge,
  Tabs,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";
import {
  CLOSE_OUT_MIN_LENGTH,
  INCIDENT_SEVERITIES,
  INCIDENT_STATUSES,
  allowedTransitions,
  formatBytes,
  isTransitionAllowed,
  shortSha,
  slaRemainingMinutes,
  slaState,
  transitionNeedsCloseOut,
  transitionNeedsReason,
  type AlertLink,
  type EvidenceRecord,
  type IncidentDetailData,
  type OrganizationMember,
  type RemediationLink,
  type TimelineEntry,
} from "../components/features/respond/incidents";

const MAX_EVIDENCE_BYTES = 25 * 1024 * 1024;

interface PolicySnapshot {
  org_id: string;
  autonomy_level: string;
  approval_threshold: string;
  policy_id: string | null;
  policy_version: number | null;
  definition: Record<string, unknown>;
  evaluated_at: string;
  kill_switches: {
    global_engaged: boolean;
    organization_engaged: boolean;
    autonomy_engaged: boolean;
    autonomy_halted: boolean;
    connectors: { id: string; scope: string; target_id: string | null; target_name: string | null; reason: string; engaged_at: string }[];
    switches: { id: string; scope: string; target_id: string | null; target_name: string | null; reason: string; engaged_at: string }[];
  };
}

interface ApprovalRow {
  id: string;
  request_type: string;
  resource_type: string;
  resource_id: string | null;
  payload: Record<string, unknown>;
  status: string;
  requested_by: string | null;
  decided_at: string | null;
  reason: string | null;
  created_at: string;
}

const COPY = {
  es: {
    eyebrow: "Respuesta · Incidente",
    subtitle: "Ciclo de vida, cronología append-only, evidencias selladas y estado de respuesta.",
    back: "Volver a la cola",
    runPlaybook: "Ejecutar playbook",
    refresh: "Actualizar",
    notFoundTitle: "Incidente no encontrado",
    notFoundDesc: "La referencia no existe en esta organización o ha sido eliminada.",
    errorTitle: "No se pudo cargar el incidente",
    tabOverview: "Resumen",
    tabTimeline: "Cronología",
    tabEvidence: "Evidencias",
    tabResponse: "Respuesta",
    tabAlerts: "Alertas",
    summary: "Resumen del incidente",
    metadata: "Metadatos y SLA",
    assets: "Activos afectados",
    description: "Descripción",
    noDescription: "Sin descripción registrada.",
    rootCause: "Causa raíz",
    lessons: "Lecciones aprendidas",
    notRecorded: "No registrado",
    ref: "Referencia",
    priority: "Prioridad",
    assignee: "Responsable",
    commander: "Comandante del incidente",
    detected: "Detectado",
    contained: "Contenido",
    resolved: "Resuelto",
    closed: "Cerrado",
    sla: "SLA",
    slaDue: "Vence",
    slaBreached: "SLA vencido",
    slaAtRisk: "SLA en riesgo",
    slaOk: "En plazo",
    slaNone: "Sin SLA",
    mitre: "MITRE ATT&CK",
    noMitre: "Sin técnicas asociadas",
    noAssets: "Ningún activo vinculado",
    assetCol: "Activo",
    criticality: "Criticidad",
    environment: "Entorno",
    ip: "IP",
    lifecycle: "Ciclo de vida",
    currentStatus: "Estado actual",
    targetStatus: "Transición",
    transitionHint: "Solo se habilitan transiciones válidas según la máquina de estados del servidor.",
    applyTransition: "Aplicar transición",
    closePermission: "Cerrar requiere el permiso incident:close.",
    transitionTitle: "Confirmar cambio de estado",
    transitionReason: "Motivo del cambio",
    transitionReasonRequired: "Indica el motivo de la contención o del cierre (mín. 3 caracteres).",
    rootCauseLabel: "Causa raíz (mín. 10 caracteres)",
    lessonsLabel: "Lecciones aprendidas (mín. 10 caracteres)",
    closeOutHint: "El cierre exige causa raíz y lecciones aprendidas de al menos {min} caracteres.",
    confirmTransition: "Confirmar transición",
    transitioned: "Estado actualizado a {status}",
    transitionError: "No se pudo cambiar el estado",
    edit: "Editar incidente",
    editTitle: "Editar campos del incidente",
    save: "Guardar cambios",
    saved: "Incidente actualizado",
    editError: "No se pudo actualizar el incidente",
    titleField: "Título",
    descriptionField: "Descripción",
    severityField: "Severidad",
    priorityField: "Prioridad",
    assigneeField: "Responsable",
    commanderField: "Comandante",
    unassign: "Sin asignar",
    slaField: "Vencimiento del SLA",
    mitreField: "Técnicas MITRE",
    mitreHint: "Separadas por comas. Formato T#### o T####.###",
    timelineTitle: "Cronología inmutable",
    timelineEmpty: "Todavía no hay entradas en la cronología.",
    addNote: "Añadir nota",
    noteLabel: "Nota operativa",
    notePlaceholder: "Acción realizada, hallazgo o decisión (3–500 caracteres)…",
    noteAdded: "Nota añadida a la cronología",
    noteError: "No se pudo añadir la nota",
    noteTooShort: "La nota debe tener al menos 3 caracteres.",
    evidenceTitle: "Evidencias y cadena de custodia",
    evidenceHint: "Las descargas quedan registradas en la auditoría. El sellado es irreversible.",
    upload: "Subir evidencia",
    uploadTitle: "Título de la evidencia",
    uploadKind: "Tipo",
    uploadDescription: "Descripción",
    uploadSealed: "Sellar al subir",
    selectFile: "Archivo (máx. 25 MB)",
    maxSize: "Tamaño máximo: 25 MB.",
    uploading: "Subiendo y calculando SHA-256…",
    uploadProgress: "Progreso de subida",
    uploaded: "Evidencia almacenada y hasheada",
    uploadError: "No se pudo subir la evidencia",
    sizeTooLarge: "El archivo supera el límite de 25 MB.",
    fileRequired: "Selecciona un archivo.",
    seal: "Sellar",
    sealed: "Sellada",
    sealTitle: "Sellar evidencia",
    sealWarning:
      "El sellado fija el hash y la cadena de custodia. No se puede deshacer; cualquier verificación posterior queda auditada.",
    sealConfirm: "Sellar definitivamente",
    sealedToast: "Evidencia sellada",
    sealError: "No se pudo sellar la evidencia",
    custody: "Custodia",
    sha: "SHA-256",
    size: "Tamaño",
    collectedBy: "Recogida por",
    collectedAt: "Recogida",
    download: "Descargar",
    downloadError: "No se pudo descargar la evidencia",
    evidenceEmpty: "Sin evidencias adjuntas.",
    responseTitle: "Estado de respuesta",
    remediations: "Remediaciones vinculadas",
    remediationsEmpty: "Sin remediaciones vinculadas a este incidente.",
    policyTitle: "Política de autonomía",
    autonomyLevel: "Nivel de autonomía",
    approvalThreshold: "Aprobación requerida desde",
    policyVersion: "Versión de política",
    evaluatedAt: "Evaluada",
    killSwitch: "Kill switch",
    engaged: "Activado",
    released: "Liberado",
    approvalsTitle: "Aprobaciones",
    approvalsEmpty: "Sin aprobaciones relacionadas.",
    responseNotice:
      "Las acciones críticas no se ejecutan desde esta vista. La política se reevalúa en el servidor y la ejecución pasa por SOAR o administración.",
    goSoar: "Ir a SOAR",
    goAdmin: "Ir a administración",
    alertsTitle: "Alertas vinculadas",
    alertsEmpty: "Sin alertas vinculadas.",
    alertsHint: "La correlación y el triaje de estas alertas se gestionan en SIEM.",
    goSiem: "Ir a SIEM",
    actionType: "Acción",
    target: "Objetivo",
    risk: "Riesgo",
    rollback: "Rollback",
    executedAt: "Ejecutada",
    verifiedAt: "Verificada",
    none: "—",
    demo: "DEMO",
    timelineActor: "por {actor}",
    statusChangeTitle: "Transición de estado",
    evidenceUploaded: "Evidencia adjuntada",
    unknownKind: "Evento",
    detail: "detalle",
    actor: "Actor",
  },
  en: {
    eyebrow: "Response · Incident",
    subtitle: "Lifecycle, append-only timeline, sealed evidence and response state.",
    back: "Back to queue",
    runPlaybook: "Run playbook",
    refresh: "Refresh",
    notFoundTitle: "Incident not found",
    notFoundDesc: "The reference does not exist in this organization or has been deleted.",
    errorTitle: "Could not load the incident",
    tabOverview: "Overview",
    tabTimeline: "Timeline",
    tabEvidence: "Evidence",
    tabResponse: "Response",
    tabAlerts: "Alerts",
    summary: "Incident summary",
    metadata: "Metadata and SLA",
    assets: "Affected assets",
    description: "Description",
    noDescription: "No description recorded.",
    rootCause: "Root cause",
    lessons: "Lessons learned",
    notRecorded: "Not recorded",
    ref: "Reference",
    priority: "Priority",
    assignee: "Assignee",
    commander: "Incident commander",
    detected: "Detected",
    contained: "Contained",
    resolved: "Resolved",
    closed: "Closed",
    sla: "SLA",
    slaDue: "Due",
    slaBreached: "SLA breached",
    slaAtRisk: "SLA at risk",
    slaOk: "On time",
    slaNone: "No SLA",
    mitre: "MITRE ATT&CK",
    noMitre: "No techniques associated",
    noAssets: "No linked asset",
    assetCol: "Asset",
    criticality: "Criticality",
    environment: "Environment",
    ip: "IP",
    lifecycle: "Lifecycle",
    currentStatus: "Current status",
    targetStatus: "Transition",
    transitionHint: "Only transitions valid under the server state machine are enabled.",
    applyTransition: "Apply transition",
    closePermission: "Closing requires the incident:close permission.",
    transitionTitle: "Confirm status change",
    transitionReason: "Reason for the change",
    transitionReasonRequired: "Provide the containment or closure reason (min. 3 characters).",
    rootCauseLabel: "Root cause (min. 10 characters)",
    lessonsLabel: "Lessons learned (min. 10 characters)",
    closeOutHint: "Closure requires a root cause and lessons learned of at least {min} characters.",
    confirmTransition: "Confirm transition",
    transitioned: "Status changed to {status}",
    transitionError: "Could not change the status",
    edit: "Edit incident",
    editTitle: "Edit incident fields",
    save: "Save changes",
    saved: "Incident updated",
    editError: "Could not update the incident",
    titleField: "Title",
    descriptionField: "Description",
    severityField: "Severity",
    priorityField: "Priority",
    assigneeField: "Assignee",
    commanderField: "Commander",
    unassign: "Unassigned",
    slaField: "SLA due",
    mitreField: "MITRE techniques",
    mitreHint: "Comma separated. Format T#### or T####.###",
    timelineTitle: "Immutable timeline",
    timelineEmpty: "No timeline entries yet.",
    addNote: "Add note",
    noteLabel: "Operational note",
    notePlaceholder: "Action taken, finding or decision (3–500 characters)…",
    noteAdded: "Note added to the timeline",
    noteError: "Could not add the note",
    noteTooShort: "The note must be at least 3 characters.",
    evidenceTitle: "Evidence and chain of custody",
    evidenceHint: "Downloads are written to the audit trail. Sealing is irreversible.",
    upload: "Upload evidence",
    uploadTitle: "Evidence title",
    uploadKind: "Kind",
    uploadDescription: "Description",
    uploadSealed: "Seal on upload",
    selectFile: "File (max. 25 MB)",
    maxSize: "Maximum size: 25 MB.",
    uploading: "Uploading and computing SHA-256…",
    uploadProgress: "Upload progress",
    uploaded: "Evidence stored and hashed",
    uploadError: "Could not upload the evidence",
    sizeTooLarge: "The file exceeds the 25 MB limit.",
    fileRequired: "Select a file.",
    seal: "Seal",
    sealed: "Sealed",
    sealTitle: "Seal evidence",
    sealWarning:
      "Sealing fixes the hash and chain of custody. It cannot be undone; any later verification is audited.",
    sealConfirm: "Seal permanently",
    sealedToast: "Evidence sealed",
    sealError: "Could not seal the evidence",
    custody: "Custody",
    sha: "SHA-256",
    size: "Size",
    collectedBy: "Collected by",
    collectedAt: "Collected",
    download: "Download",
    downloadError: "Could not download the evidence",
    evidenceEmpty: "No evidence attached.",
    responseTitle: "Response state",
    remediations: "Linked remediations",
    remediationsEmpty: "No remediations linked to this incident.",
    policyTitle: "Autonomy policy",
    autonomyLevel: "Autonomy level",
    approvalThreshold: "Approval required from",
    policyVersion: "Policy version",
    evaluatedAt: "Evaluated",
    killSwitch: "Kill switch",
    engaged: "Engaged",
    released: "Released",
    approvalsTitle: "Approvals",
    approvalsEmpty: "No related approvals.",
    responseNotice:
      "Critical actions are not executed from this view. Policy is re-evaluated server-side and execution flows through SOAR or administration.",
    goSoar: "Go to SOAR",
    goAdmin: "Go to administration",
    alertsTitle: "Linked alerts",
    alertsEmpty: "No linked alerts.",
    alertsHint: "Correlation and triage of these alerts are handled in SIEM.",
    goSiem: "Go to SIEM",
    actionType: "Action",
    target: "Target",
    risk: "Risk",
    rollback: "Rollback",
    executedAt: "Executed",
    verifiedAt: "Verified",
    none: "—",
    demo: "DEMO",
    timelineActor: "by {actor}",
    statusChangeTitle: "Status transition",
    evidenceUploaded: "Evidence attached",
    unknownKind: "Event",
    detail: "detail",
    actor: "Actor",
  },
};

function slaText(dueAt: string | null, c: (key: string) => string): string {
  const state = slaState(dueAt);
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

function uploadEvidenceWithProgress(
  path: string,
  form: FormData,
  onProgress: (percent: number) => void,
): Promise<EvidenceRecord> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", `/api/v1${path}`);
    request.withCredentials = true;
    request.setRequestHeader("Accept", "application/json");
    const org = getActiveOrg();
    if (org) request.setRequestHeader("X-Organization-Id", org);
    const csrf = getCookie("hs_csrf");
    if (csrf) request.setRequestHeader("X-CSRF-Token", csrf);
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(Math.min(99, Math.round((event.loaded / event.total) * 100)));
    };
    request.onerror = () => reject(new ApiError(0, "network_error", "Unable to reach the HISPANSHIELD API"));
    request.timeout = 120_000;
    request.ontimeout = () => reject(new ApiError(0, "timeout", "The upload exceeded the client timeout"));
    request.onload = () => {
      if (request.status === 401) {
        window.dispatchEvent(new CustomEvent("hs:unauthorized"));
      }
      let body: unknown = null;
      try {
        body = JSON.parse(request.responseText);
      } catch {
        body = null;
      }
      if (request.status >= 200 && request.status < 300) {
        onProgress(100);
        resolve(body as EvidenceRecord);
        return;
      }
      const envelope = body as { error?: { code?: string; message?: string; details?: { field: string; message: string }[]; request_id?: string } } | null;
      reject(
        new ApiError(
          request.status,
          envelope?.error?.code ?? "http_error",
          envelope?.error?.message ?? `Upload failed with status ${request.status}`,
          envelope?.error?.details ?? [],
          envelope?.error?.request_id,
        ),
      );
    };
    request.send(form);
  });
}

function formatExtension(contentType: string): string {
  if (contentType.includes("json")) return ".json";
  if (contentType.includes("csv")) return ".csv";
  if (contentType.includes("pdf")) return ".pdf";
  if (contentType.includes("zip")) return ".zip";
  if (contentType.includes("text")) return ".txt";
  if (contentType.includes("png")) return ".png";
  if (contentType.includes("jpeg")) return ".jpg";
  return ".bin";
}

export function IncidentDetailPage() {
  const { incidentId } = useParams<{ incidentId: string }>();
  const c = usePageCopy(COPY);
  const { t, lang } = useI18n();
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<"overview" | "timeline" | "evidence" | "response" | "alerts">("overview");
  const [note, setNote] = useState("");
  const [transitionTarget, setTransitionTarget] = useState("");
  const [transitionOpen, setTransitionOpen] = useState(false);
  const [transitionReason, setTransitionReason] = useState("");
  const [rootCause, setRootCause] = useState("");
  const [lessons, setLessons] = useState("");
  const [sealTarget, setSealTarget] = useState<EvidenceRecord | null>(null);
  const [evidenceTitle, setEvidenceTitle] = useState("");
  const [evidenceKind, setEvidenceKind] = useState("file");
  const [evidenceDescription, setEvidenceDescription] = useState("");
  const [evidenceSealed, setEvidenceSealed] = useState(false);
  const [uploadPercent, setUploadPercent] = useState(0);
  const fileRef = useRef<HTMLInputElement>(null);
  const [editOpen, setEditOpen] = useState(false);
  const [editTitle, setEditTitle] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editSeverity, setEditSeverity] = useState("medium");
  const [editPriority, setEditPriority] = useState("3");
  const [editAssignee, setEditAssignee] = useState("");
  const [editCommander, setEditCommander] = useState("");
  const [editSla, setEditSla] = useState("");
  const [editMitre, setEditMitre] = useState("");

  const detail = useQuery({
    queryKey: ["incidents", "detail", incidentId],
    queryFn: () => api.get<IncidentDetailData>(`/incidents/${incidentId}`),
    enabled: Boolean(incidentId),
  });

  const timelineQuery = useQuery({
    queryKey: ["incidents", "timeline", incidentId],
    queryFn: () => api.get<Page<TimelineEntry>>(`/incidents/${incidentId}/timeline`, { page_size: 200 }),
    enabled: Boolean(incidentId) && tab === "timeline",
  });

  const members = useQuery({
    queryKey: ["organizations", "members", "incident-detail"],
    queryFn: () => api.get<Page<OrganizationMember>>("/organizations/current/members", { page_size: 200 }),
    enabled: can("user:read"),
    staleTime: 120_000,
  });

  const policy = useQuery({
    queryKey: ["defence", "policy", "snapshot"],
    queryFn: () => api.get<PolicySnapshot>("/defence/policy/snapshot"),
    enabled: can("defence:read"),
    staleTime: 30_000,
  });

  const approvals = useQuery({
    queryKey: ["organizations", "approvals", "incident-detail"],
    queryFn: () => api.get<Page<ApprovalRow>>("/organizations/current/approvals", { page_size: 100 }),
    enabled: can("approval:read"),
    staleTime: 30_000,
  });

  const membersById = useMemo(() => {
    const map = new Map<string, OrganizationMember>();
    for (const member of members.data?.items ?? []) map.set(member.user_id, member);
    return map;
  }, [members.data]);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["incidents"] });
  };

  const statusMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<IncidentDetailData>(`/incidents/${incidentId}/status`, body),
    onSuccess: (updated) => {
      push(c("transitioned").replace("{status}", updated.status), "success");
      setTransitionOpen(false);
      setTransitionTarget("");
      setTransitionReason("");
      setRootCause("");
      setLessons("");
      invalidate();
    },
    onError: (error) => push(`${c("transitionError")}: ${errorMessage(error)}`, "error"),
  });

  const noteMutation = useMutation({
    mutationFn: () =>
      api.post<TimelineEntry>(`/incidents/${incidentId}/timeline`, {
        kind: "note",
        summary: note.trim(),
        detail: {},
      }),
    onSuccess: () => {
      push(c("noteAdded"), "success");
      setNote("");
      invalidate();
    },
    onError: (error) => push(`${c("noteError")}: ${errorMessage(error)}`, "error"),
  });

  const sealMutation = useMutation({
    mutationFn: (evidenceId: string) => api.post<EvidenceRecord>(`/incidents/evidence/${evidenceId}/seal`),
    onSuccess: () => {
      push(c("sealedToast"), "success");
      setSealTarget(null);
      invalidate();
    },
    onError: (error) => push(`${c("sealError")}: ${errorMessage(error)}`, "error"),
  });

  const uploadMutation = useMutation({
    mutationFn: async () => {
      const file = fileRef.current?.files?.[0];
      if (!file) throw new Error(c("fileRequired"));
      if (file.size > MAX_EVIDENCE_BYTES) throw new Error(c("sizeTooLarge"));
      const form = new FormData();
      form.append("file", file);
      if (evidenceTitle.trim()) form.append("title", evidenceTitle.trim());
      form.append("kind", evidenceKind.trim() || "file");
      if (evidenceDescription.trim()) form.append("description", evidenceDescription.trim());
      if (evidenceSealed) form.append("sealed", "true");
      setUploadPercent(0);
      return uploadEvidenceWithProgress(`/incidents/${incidentId}/evidence`, form, setUploadPercent);
    },
    onSuccess: () => {
      push(c("uploaded"), "success");
      setEvidenceTitle("");
      setEvidenceDescription("");
      setEvidenceKind("file");
      setEvidenceSealed(false);
      setUploadPercent(0);
      if (fileRef.current) fileRef.current.value = "";
      invalidate();
    },
    onError: (error) => push(`${c("uploadError")}: ${errorMessage(error)}`, "error"),
  });

  const editMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.patch<IncidentDetailData>(`/incidents/${incidentId}`, body),
    onSuccess: () => {
      push(c("saved"), "success");
      setEditOpen(false);
      invalidate();
    },
    onError: (error) => push(`${c("editError")}: ${errorMessage(error)}`, "error"),
  });

  if (detail.isLoading) {
    return (
      <div data-testid="page-incident-detail">
        <PageSkeleton />
      </div>
    );
  }

  if (detail.isError || !detail.data) {
    const notFound = isApiError(detail.error) && detail.error.status === 404;
    return (
      <div data-testid="page-incident-detail">
        <PageHeader
          eyebrow={c("eyebrow")}
          title={notFound ? c("notFoundTitle") : c("errorTitle")}
          subtitle={notFound ? c("notFoundDesc") : undefined}
          actions={<LinkButton to="/incidents" icon={ArrowLeft}>{c("back")}</LinkButton>}
        />
        {notFound ? (
          <EmptyState
            icon={FileSearch}
            title={c("notFoundTitle")}
            description={c("notFoundDesc")}
            action={<LinkButton to="/incidents" variant="primary" icon={ArrowLeft}>{c("back")}</LinkButton>}
          />
        ) : (
          <ErrorBanner title={c("errorTitle")} message={errorMessage(detail.error)} onRetry={() => void detail.refetch()} />
        )}
      </div>
    );
  }

  const incident = detail.data;
  const timelineEntries = timelineQuery.data?.items ?? incident.timeline;
  const open = incident.status !== "closed";
  const transitions = allowedTransitions(incident.status).filter(
    (value) => value !== "closed" || can("incident:close"),
  );
  const sla = slaState(incident.sla_due_at);
  const remaining = slaRemainingMinutes(incident.sla_due_at);
  const policyData = policy.data;
  const killEngaged = Boolean(
    policyData &&
      (policyData.kill_switches.global_engaged ||
        policyData.kill_switches.organization_engaged ||
        policyData.kill_switches.autonomy_engaged ||
        policyData.kill_switches.autonomy_halted),
  );
  const relatedApprovals = (approvals.data?.items ?? []).filter(
    (row) => row.resource_id === incident.id || String(row.payload?.incident_id ?? "") === incident.id,
  );
  const target = transitionTarget;
  const reasonRequired = transitionNeedsReason(target);
  const closeOut = transitionNeedsCloseOut(target);
  const transitionValid = target !== "" && isTransitionAllowed(incident.status, target);

  const openTransition = (value: string) => {
    setTransitionTarget(value);
    setTransitionReason("");
    setRootCause(incident.root_cause ?? "");
    setLessons(incident.lessons_learned ?? "");
    setTransitionOpen(true);
  };

  const submitTransition = () => {
    if (!transitionValid) return;
    if (reasonRequired && transitionReason.trim().length < 3) {
      push(c("transitionReasonRequired"), "error");
      return;
    }
    if (closeOut && (rootCause.trim().length < CLOSE_OUT_MIN_LENGTH || lessons.trim().length < CLOSE_OUT_MIN_LENGTH)) {
      push(c("closeOutHint").replace("{min}", String(CLOSE_OUT_MIN_LENGTH)), "error");
      return;
    }
    statusMutation.mutate({
      status: target,
      note: transitionReason.trim() || undefined,
      root_cause: closeOut ? rootCause.trim() : undefined,
      lessons_learned: closeOut ? lessons.trim() : undefined,
    });
  };

  const openEdit = () => {
    setEditTitle(incident.title);
    setEditDescription(incident.description ?? "");
    setEditSeverity(incident.severity);
    setEditPriority(String(incident.priority));
    setEditAssignee(incident.assignee_id ?? "");
    setEditCommander(incident.commander_id ?? "");
    setEditSla(incident.sla_due_at ? incident.sla_due_at.slice(0, 16) : "");
    setEditMitre(incident.mitre.join(", "));
    setEditOpen(true);
  };

  const submitEdit = () => {
    if (editTitle.trim().length < 3) return;
    editMutation.mutate({
      title: editTitle.trim(),
      description: editDescription.trim() || null,
      severity: editSeverity,
      priority: Number(editPriority) || undefined,
      assignee_id: editAssignee || null,
      commander_id: editCommander || null,
      sla_due_at: editSla ? new Date(editSla).toISOString() : null,
      mitre: editMitre
        .split(",")
        .map((value) => value.trim().toUpperCase())
        .filter(Boolean),
    });
  };

  const downloadEvidence = async (record: EvidenceRecord) => {
    try {
      await downloadFile(
        `/incidents/evidence/${record.id}/download`,
        `${record.title.replace(/[^\w.-]+/g, "-").slice(0, 80) || "evidence"}${formatExtension(record.content_type)}`,
      );
    } catch (error) {
      push(`${c("downloadError")}: ${errorMessage(error)}`, "error");
    }
  };

  const evidenceColumns: Column<EvidenceRecord>[] = [
    {
      key: "title",
      header: c("uploadTitle"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div className="primary-cell" style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
            <span>{row.title}</span>
            {row.sealed ? <Badge tone="success"><Lock size={9} /> {c("sealed")}</Badge> : null}
          </div>
          <div className="cell-sub">{row.kind} · {row.content_type}</div>
        </div>
      ),
    },
    {
      key: "sha",
      header: c("sha"),
      width: "168px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10 }} title={row.sha256}>{shortSha(row.sha256)}</span>
      ),
    },
    { key: "size", header: c("size"), width: "88px", align: "right", render: (row) => <span className="mono">{formatBytes(row.size_bytes)}</span> },
    {
      key: "custody",
      header: c("custody"),
      width: "90px",
      align: "center",
      render: (row) => <Badge tone="neutral">{formatNumber(row.chain_of_custody.length)}</Badge>,
    },
    {
      key: "collected",
      header: c("collectedAt"),
      width: "128px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }} title={formatDateTime(row.collected_at, lang)}>{relativeTime(row.collected_at, lang)}</span>,
    },
    {
      key: "actions",
      header: t("common.actions"),
      width: "176px",
      align: "right",
      render: (row) => (
        <div className="row" style={{ gap: 4, justifyContent: "flex-end" }}>
          <Button
            size="sm"
            variant="ghost"
            icon={Download}
            onClick={(event) => {
              event.stopPropagation();
              void downloadEvidence(row);
            }}
            disabled={!can("incident:write")}
            title={can("incident:write") ? c("download") : t("common.permissionDenied")}
            data-testid={`download-evidence-${row.id}`}
          >
            {c("download")}
          </Button>
          {!row.sealed ? (
            <Button
              size="sm"
              variant="ghost"
              icon={FileLock2}
              onClick={(event) => {
                event.stopPropagation();
                setSealTarget(row);
              }}
              disabled={!can("incident:write")}
              data-testid={`seal-evidence-${row.id}`}
            >
              {c("seal")}
            </Button>
          ) : null}
        </div>
      ),
    },
  ];

  const remediationColumns: Column<RemediationLink>[] = [
    { key: "action", header: c("actionType"), width: "190px", render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.action_type}</span> },
    {
      key: "target",
      header: c("target"),
      render: (row) => (
        <div>
          <div style={{ color: "var(--text-secondary)" }}>{row.target_type}</div>
          <div className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{row.target_id}</div>
        </div>
      ),
    },
    { key: "status", header: t("common.status"), width: "118px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "risk",
      header: c("risk"),
      width: "100px",
      render: (row) => <Badge tone={row.risk_level === "critical" || row.risk_level === "high" ? "danger" : row.risk_level === "medium" ? "warning" : "neutral"}>{row.risk_level}</Badge>,
    },
    {
      key: "rollback",
      header: c("rollback"),
      width: "116px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.rollback_status ?? c("none")}</span>,
    },
    {
      key: "executed",
      header: c("executedAt"),
      width: "132px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.executed_at ? relativeTime(row.executed_at, lang) : c("none")}</span>,
    },
    {
      key: "execution",
      header: "SOAR",
      width: "110px",
      render: (row) =>
        row.execution_id ? (
          <Link to={`/soar?execution_id=${row.execution_id}`} className="mono" style={{ fontSize: 10 }}>
            {row.execution_id.slice(0, 8)}
          </Link>
        ) : (
          <span className="dim">—</span>
        ),
    },
  ];

  const alertColumns: Column<AlertLink>[] = [
    { key: "title", header: c("alertsTitle"), render: (row) => <span style={{ color: "var(--text)", fontWeight: 500 }}>{row.title}</span> },
    { key: "severity", header: t("common.severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: t("common.status"), width: "118px", render: (row) => <StatusBadge status={row.status} /> },
    { key: "count", header: "×", width: "64px", align: "right", render: (row) => <span className="mono">{formatNumber(row.count)}</span> },
    {
      key: "last_seen",
      header: c("detected"),
      width: "132px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{relativeTime(row.last_seen, lang)}</span>,
    },
    {
      key: "mitre",
      header: "MITRE",
      width: "170px",
      render: (row) => (
        <div className="chip-row">
          {row.mitre.length ? row.mitre.slice(0, 3).map((technique) => <span className="tag" key={technique}>{technique}</span>) : <span className="dim">—</span>}
        </div>
      ),
    },
  ];

  return (
    <div className="animate-in" data-testid="page-incident-detail">
      <PageHeader
        eyebrow={`${c("eyebrow")} · ${incident.ref}`}
        title={incident.title}
        subtitle={c("subtitle")}
        actions={
          <>
            {incident.is_demo ? <Badge tone="amber">{c("demo")}</Badge> : null}
            <Badge tone={slaTone(sla)}>{slaText(incident.sla_due_at, c)}{remaining !== null && remaining >= 0 ? ` · ${durationMinutes(remaining)}` : ""}</Badge>
            <Button icon={RefreshCw} onClick={() => void detail.refetch()} aria-label={c("refresh")} data-testid="refresh-incident" />
            <LinkButton to="/incidents" icon={ArrowLeft}>{c("back")}</LinkButton>
            <LinkButton to={`/soar?incident_id=${incident.id}`} variant="primary" icon={PlayCircle}>
              {c("runPlaybook")}
            </LinkButton>
          </>
        }
      />

      <div className="row wrap" style={{ gap: 6, marginBottom: 12 }}>
        <SeverityBadge severity={incident.severity} />
        <StatusBadge status={incident.status} />
        <Badge tone="neutral">P{incident.priority}</Badge>
        {incident.mitre.slice(0, 6).map((technique) => <span className="tag" key={technique}>{technique}</span>)}
        {incident.mitre.length > 6 ? <span className="tag">+{incident.mitre.length - 6}</span> : null}
        {open && can("incident:write") ? (
          <Button size="sm" variant="ghost" icon={Paperclip} onClick={openEdit} data-testid="edit-incident">
            {c("edit")}
          </Button>
        ) : null}
      </div>

      <Card bodyClassName="">
        <div style={{ padding: "0 12px" }}>
          <Tabs<"overview" | "timeline" | "evidence" | "response" | "alerts">
            ariaLabel={c("subtitle")}
            items={[
              { key: "overview", label: c("tabOverview") },
              { key: "timeline", label: c("tabTimeline"), count: timelineEntries.length },
              { key: "evidence", label: c("tabEvidence"), count: incident.evidence.length },
              { key: "response", label: c("tabResponse"), count: incident.remediations.length },
              { key: "alerts", label: c("tabAlerts"), count: incident.alerts.length },
            ]}
            value={tab}
            onChange={setTab}
          />
        </div>

        <div style={{ padding: 16 }}>
          {tab === "overview" ? (
            <div className="stack" data-testid="incident-tab-overview">
              <div className="split-main">
                <div className="stack">
                  <Card
                    title={c("summary")}
                    actions={
                      <div className="row" style={{ gap: 6 }}>
                        <StatusBadge status={incident.status} />
                        <SeverityBadge severity={incident.severity} />
                      </div>
                    }
                  >
                    <div style={{ fontSize: 13, color: "var(--text-secondary)", whiteSpace: "pre-wrap" }}>
                      {incident.description || c("noDescription")}
                    </div>
                    <div className="divider" />
                    <div className="section-label">{c("rootCause")}</div>
                    <div style={{ fontSize: 12.5, color: incident.root_cause ? "var(--text-secondary)" : "var(--dim)" }}>
                      {incident.root_cause || c("notRecorded")}
                    </div>
                    <div className="section-label" style={{ marginTop: 12 }}>{c("lessons")}</div>
                    <div style={{ fontSize: 12.5, color: incident.lessons_learned ? "var(--text-secondary)" : "var(--dim)" }}>
                      {incident.lessons_learned || c("notRecorded")}
                    </div>
                    <div className="notice" style={{ marginTop: 14, fontSize: 11 }}>
                      <History size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
                      <span>{c("transitionHint")}</span>
                    </div>
                  </Card>

                  <Card title={c("assets")} actions={<Badge tone="neutral">{incident.assets.length}</Badge>}>
                    {incident.assets.length === 0 ? (
                      <EmptyState icon={ShieldCheck} title={c("noAssets")} />
                    ) : (
                      <div className="metric-list">
                        {incident.assets.map((asset) => (
                          <Link key={asset.id} to={`/assets/${asset.id}`} className="metric-row" style={{ textDecoration: "none", color: "inherit" }}>
                            <span className="metric-label" style={{ color: "var(--text-secondary)" }}>
                              {asset.name}
                              <span className="tag">{humanize(asset.kind)}</span>
                            </span>
                            <span className="metric-value" style={{ fontSize: 10.5 }}>
                              {asset.ip_addresses[0] ?? asset.environment} · C{asset.criticality}
                            </span>
                          </Link>
                        ))}
                      </div>
                    )}
                  </Card>
                </div>

                <div className="stack">
                  <Card title={c("metadata")}>
                    <div className="metric-list">
                      <div className="metric-row"><span className="metric-label">{c("ref")}</span><span className="metric-value">{incident.ref}</span></div>
                      <div className="metric-row"><span className="metric-label">{c("priority")}</span><span className="metric-value">P{incident.priority}</span></div>
                      <div className="metric-row"><span className="metric-label">{c("assignee")}</span><span className="metric-value">{incident.assignee_id ? membersById.get(incident.assignee_id)?.full_name ?? incident.assignee_id.slice(0, 8) : c("unassign")}</span></div>
                      <div className="metric-row"><span className="metric-label">{c("commander")}</span><span className="metric-value">{incident.commander_id ? membersById.get(incident.commander_id)?.full_name ?? incident.commander_id.slice(0, 8) : c("unassign")}</span></div>
                      <div className="metric-row"><span className="metric-label">{c("detected")}</span><span className="metric-value">{formatDateTime(incident.detected_at, lang)}</span></div>
                      <div className="metric-row"><span className="metric-label">{c("contained")}</span><span className="metric-value">{incident.contained_at ? formatDateTime(incident.contained_at, lang) : c("none")}</span></div>
                      <div className="metric-row"><span className="metric-label">{c("resolved")}</span><span className="metric-value">{incident.resolved_at ? formatDateTime(incident.resolved_at, lang) : c("none")}</span></div>
                      <div className="metric-row"><span className="metric-label">{c("closed")}</span><span className="metric-value">{incident.closed_at ? formatDateTime(incident.closed_at, lang) : c("none")}</span></div>
                      <div className="metric-row">
                        <span className="metric-label">{c("slaDue")}</span>
                        <span className="metric-value">
                          {incident.sla_due_at ? formatDateTime(incident.sla_due_at, lang) : c("none")}
                          {" "}
                          <Badge tone={slaTone(sla)}>{slaText(incident.sla_due_at, c)}</Badge>
                        </span>
                      </div>
                    </div>
                  </Card>

                  <Card title={c("lifecycle")}>
                    <div className="metric-row" style={{ paddingTop: 0 }}>
                      <span className="metric-label">{c("currentStatus")}</span>
                      <span className="metric-value"><StatusBadge status={incident.status} /></span>
                    </div>
                    {transitions.length === 0 ? (
                      <div className="notice" style={{ fontSize: 11 }}>{c("transitionHint")}</div>
                    ) : (
                      <>
                        <Field label={c("targetStatus")} htmlFor="incident-transition">
                          <Select
                            id="incident-transition"
                            value={transitionTarget}
                            disabled={!open || !can("incident:write")}
                            onChange={(event) => setTransitionTarget(event.target.value)}
                            data-testid="incident-transition-select"
                          >
                            <option value="">{c("targetStatus")}</option>
                            {INCIDENT_STATUSES.map((status) => (
                              <option
                                key={status}
                                value={status}
                                disabled={!isTransitionAllowed(incident.status, status) || (status === "closed" && !can("incident:close"))}
                              >
                                {status}
                              </option>
                            ))}
                          </Select>
                        </Field>
                        <Button
                          size="sm"
                          variant="primary"
                          icon={ArrowRightLeft}
                          style={{ marginTop: 6 }}
                          disabled={!can("incident:write") || !transitionValid}
                          onClick={() => transitionTarget && openTransition(transitionTarget)}
                          data-testid="apply-transition"
                        >
                          {c("applyTransition")}
                        </Button>
                        <div className="row" style={{ marginTop: 8, gap: 6 }}>
                          {transitions.map((status) => (
                            <Button
                              key={status}
                              size="sm"
                              variant={status === "closed" ? "danger" : "default"}
                              icon={ArrowRightLeft}
                              disabled={!can("incident:write")}
                              onClick={() => openTransition(status)}
                              data-testid={`transition-${status}`}
                            >
                              {status}
                            </Button>
                          ))}
                        </div>
                        <p className="hint" style={{ marginTop: 8 }}>{c("transitionHint")}</p>
                        {!can("incident:close") ? <p className="hint">{c("closePermission")}</p> : null}
                      </>
                    )}
                  </Card>
                </div>
              </div>
            </div>
          ) : null}

          {tab === "timeline" ? (
            <div className="split-main" data-testid="incident-tab-timeline">
              <Card title={c("timelineTitle")} actions={<Badge tone="neutral">{timelineEntries.length}</Badge>}>
                {timelineQuery.isError ? (
                  <div style={{ marginBottom: 10 }}>
                    <ErrorBanner compact message={errorMessage(timelineQuery.error)} onRetry={() => void timelineQuery.refetch()} />
                  </div>
                ) : null}
                {timelineEntries.length === 0 ? (
                  <EmptyState icon={History} title={c("timelineEmpty")} />
                ) : (
                  <div className="timeline">
                    {timelineEntries.map((entry) => (
                      <div
                        key={entry.id}
                        className={`timeline-item ${entry.kind === "status_change" ? "danger" : entry.kind === "evidence" ? "success" : ""}`}
                      >
                        <div className="row-between" style={{ gap: 8, alignItems: "flex-start" }}>
                          <div style={{ minWidth: 0 }}>
                            <div style={{ fontSize: 12.5, color: "var(--text)" }}>{entry.summary}</div>
                            <div className="item-sub">
                              <span className="tag">{humanize(entry.kind)}</span>{" "}
                              {entry.actor ? c("timelineActor").replace("{actor}", entry.actor) : ""}
                            </div>
                          </div>
                          <span className="mono" style={{ fontSize: 10, color: "var(--dim)", flex: "0 0 auto" }}>
                            {formatDateTime(entry.at, lang)}
                          </span>
                        </div>
                        {Object.keys(entry.detail).length ? (
                          <details style={{ marginTop: 6 }}>
                            <summary className="dim" style={{ fontSize: 10.5, cursor: "pointer" }}>{c("detail")}</summary>
                            <pre className="code-block" style={{ marginTop: 6 }}>{JSON.stringify(entry.detail, null, 2)}</pre>
                          </details>
                        ) : null}
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              <Card title={c("addNote")}>
                <Field label={c("noteLabel")} htmlFor="timeline-note" error={note.length > 0 && note.trim().length < 3 ? c("noteTooShort") : undefined}>
                  <Textarea
                    id="timeline-note"
                    value={note}
                    onChange={(event) => setNote(event.target.value)}
                    rows={5}
                    maxLength={500}
                    placeholder={c("notePlaceholder")}
                    data-testid="timeline-note-input"
                  />
                </Field>
                <div className="row-between" style={{ marginTop: 8 }}>
                  <span className="dim" style={{ fontSize: 10.5 }}>{note.length}/500</span>
                  <Button
                    variant="primary"
                    icon={Paperclip}
                    loading={noteMutation.isPending}
                    disabled={!can("incident:write") || note.trim().length < 3}
                    onClick={() => noteMutation.mutate()}
                    data-testid="submit-timeline-note"
                  >
                    {c("addNote")}
                  </Button>
                </div>
              </Card>
            </div>
          ) : null}

          {tab === "evidence" ? (
            <div className="stack" data-testid="incident-tab-evidence">
              <div className="notice" style={{ fontSize: 11 }}>
                <Fingerprint size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
                <span>{c("evidenceHint")}</span>
              </div>

              <Card title={c("evidenceTitle")} actions={<Badge tone="neutral">{incident.evidence.length}</Badge>} bodyClassName="">
                <div data-testid="evidence-table">
                  <DataTable
                    columns={evidenceColumns}
                    rows={incident.evidence}
                    rowKey={(row) => row.id}
                    empty={<EmptyState icon={FileCheck2} title={c("evidenceEmpty")} />}
                  />
                </div>
              </Card>

              <Card title={c("upload")}>
                <div className="form-grid">
                  <Field label={c("uploadTitle")} htmlFor="evidence-title">
                    <Input
                      id="evidence-title"
                      value={evidenceTitle}
                      onChange={(event) => setEvidenceTitle(event.target.value)}
                      maxLength={300}
                      data-testid="evidence-title-input"
                    />
                  </Field>
                  <Field label={c("uploadKind")} htmlFor="evidence-kind">
                    <Input
                      id="evidence-kind"
                      value={evidenceKind}
                      onChange={(event) => setEvidenceKind(event.target.value)}
                      maxLength={40}
                      data-testid="evidence-kind-input"
                    />
                  </Field>
                  <div className="span-2">
                    <Field label={c("uploadDescription")} htmlFor="evidence-description">
                      <Textarea
                        id="evidence-description"
                        value={evidenceDescription}
                        onChange={(event) => setEvidenceDescription(event.target.value)}
                        rows={2}
                        maxLength={20000}
                      />
                    </Field>
                  </div>
                  <div className="span-2">
                    <Field label={c("selectFile")} hint={c("maxSize")} required htmlFor="evidence-file">
                      <input
                        ref={fileRef}
                        id="evidence-file"
                        className="input"
                        type="file"
                        disabled={!can("incident:write") || uploadMutation.isPending}
                        data-testid="evidence-file-input"
                      />
                    </Field>
                  </div>
                </div>
                <div className="row-between" style={{ marginTop: 10, gap: 10, flexWrap: "wrap" }}>
                  <label className="checkbox">
                    <input
                      type="checkbox"
                      checked={evidenceSealed}
                      onChange={(event) => setEvidenceSealed(event.target.checked)}
                    />
                    {c("uploadSealed")}
                  </label>
                  <Button
                    variant="primary"
                    icon={Upload}
                    loading={uploadMutation.isPending}
                    disabled={!can("incident:write") || uploadMutation.isPending}
                    onClick={() => uploadMutation.mutate()}
                    data-testid="submit-evidence-upload"
                  >
                    {uploadMutation.isPending ? c("uploading") : c("upload")}
                  </Button>
                </div>
                {uploadMutation.isPending ? (
                  <div style={{ marginTop: 10 }} aria-busy="true">
                    <div className="row-between" style={{ fontSize: 10.5, marginBottom: 4 }}>
                      <span className="dim">{c("uploadProgress")}</span>
                      <span className="mono">{uploadPercent}%</span>
                    </div>
                    <ProgressBar value={uploadPercent} />
                  </div>
                ) : null}
              </Card>
            </div>
          ) : null}

          {tab === "response" ? (
            <div className="stack" data-testid="incident-tab-response">
              <div className="notice notice-warning" style={{ fontSize: 11 }}>
                <ShieldAlert size={14} style={{ flex: "0 0 auto" }} />
                <span>{c("responseNotice")}</span>
                <span className="row" style={{ gap: 6, marginLeft: "auto", flex: "0 0 auto" }}>
                  <LinkButton to={`/soar?incident_id=${incident.id}`} size="sm">{c("goSoar")}</LinkButton>
                  <LinkButton to="/admin" size="sm" variant="ghost">{c("goAdmin")}</LinkButton>
                </span>
              </div>

              <div className="split-main">
                <Card title={c("remediations")} actions={<Badge tone="neutral">{incident.remediations.length}</Badge>} bodyClassName="">
                  <div data-testid="remediations-table">
                    <DataTable
                      columns={remediationColumns}
                      rows={incident.remediations}
                      rowKey={(row) => row.id}
                      empty={<EmptyState icon={ShieldCheck} title={c("remediationsEmpty")} />}
                    />
                  </div>
                </Card>

                <div className="stack">
                  <Card title={c("policyTitle")} actions={<Badge tone={killEngaged ? "danger" : "success"}>{killEngaged ? c("engaged") : c("released")}</Badge>}>
                    {policy.isLoading ? (
                      <div className="stack"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
                    ) : policy.isError ? (
                      <ErrorBanner compact message={errorMessage(policy.error)} onRetry={() => void policy.refetch()} />
                    ) : policyData ? (
                      <div className="metric-list">
                        <div className="metric-row"><span className="metric-label">{c("autonomyLevel")}</span><span className="metric-value">{policyData.autonomy_level}</span></div>
                        <div className="metric-row"><span className="metric-label">{c("approvalThreshold")}</span><span className="metric-value">{policyData.approval_threshold}</span></div>
                        <div className="metric-row"><span className="metric-label">{c("policyVersion")}</span><span className="metric-value">{policyData.policy_version ?? c("none")}</span></div>
                        <div className="metric-row"><span className="metric-label">{c("evaluatedAt")}</span><span className="metric-value">{relativeTime(policyData.evaluated_at, lang)}</span></div>
                        <div className="metric-row"><span className="metric-label">{c("killSwitch")}</span><span className="metric-value">{killEngaged ? c("engaged") : c("released")}</span></div>
                        {policyData.kill_switches.switches.map((entry) => (
                          <div className="metric-row" key={entry.id}>
                            <span className="metric-label"><Gauge size={11} /> {entry.scope}{entry.target_name ? ` · ${entry.target_name}` : ""}</span>
                            <span className="metric-value" style={{ fontSize: 10 }}>{entry.reason}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <EmptyState icon={Gauge} title={c("policyTitle")} />
                    )}
                  </Card>

                  <Card title={c("approvalsTitle")} actions={<Badge tone="neutral">{relatedApprovals.length}</Badge>}>
                    {!can("approval:read") ? (
                      <p className="hint">{t("common.permissionDenied")}</p>
                    ) : approvals.isLoading ? (
                      <div className="stack"><div className="skeleton skeleton-row" /></div>
                    ) : relatedApprovals.length === 0 ? (
                      <EmptyState icon={CheckCircle2} title={c("approvalsEmpty")} />
                    ) : (
                      <div className="metric-list">
                        {relatedApprovals.map((row) => (
                          <div className="metric-row" key={row.id}>
                            <span className="metric-label" style={{ color: "var(--text-secondary)" }}>
                              {row.request_type}
                              <span className="tag">{row.resource_type}</span>
                            </span>
                            <span className="metric-value"><StatusBadge status={row.status} /></span>
                          </div>
                        ))}
                      </div>
                    )}
                  </Card>
                </div>
              </div>
            </div>
          ) : null}

          {tab === "alerts" ? (
            <div className="stack" data-testid="incident-tab-alerts">
              <Card
                title={c("alertsTitle")}
                subtitle={c("alertsHint")}
                actions={<LinkButton to="/siem" size="sm">{c("goSiem")}</LinkButton>}
                bodyClassName=""
              >
                <div data-testid="linked-alerts-table">
                  <DataTable
                    columns={alertColumns}
                    rows={incident.alerts}
                    rowKey={(row) => row.id}
                    empty={<EmptyState icon={Siren} title={c("alertsEmpty")} description={c("alertsHint")} />}
                  />
                </div>
              </Card>
            </div>
          ) : null}
        </div>
      </Card>

      <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
        <UserRound size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
        <span>
          {c("detected")}: {formatDateTime(incident.detected_at, lang)} · {c("slaDue")}:{" "}
          {incident.sla_due_at ? formatDateTime(incident.sla_due_at, lang) : c("none")} · {c("custody")}: {incident.evidence.reduce((total, row) => total + row.chain_of_custody.length, 0)}
        </span>
      </div>

      <Modal
        open={transitionOpen}
        onClose={() => setTransitionOpen(false)}
        title={c("transitionTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setTransitionOpen(false)}>{t("common.cancel")}</Button>
            <Button
              variant={closeOut ? "danger" : "primary"}
              icon={ArrowRightLeft}
              loading={statusMutation.isPending}
              disabled={!transitionValid}
              onClick={submitTransition}
              data-testid="confirm-transition"
            >
              {c("confirmTransition")}
            </Button>
          </>
        }
      >
        <div data-testid="transition-modal">
          <div className="row" style={{ gap: 6, marginBottom: 12 }}>
            <StatusBadge status={incident.status} />
            <ArrowRightLeft size={13} style={{ color: "var(--dim)" }} />
            <StatusBadge status={target || incident.status} />
          </div>
          {reasonRequired ? (
            <Field label={c("transitionReason")} required htmlFor="transition-reason">
              <Textarea
                id="transition-reason"
                value={transitionReason}
                onChange={(event) => setTransitionReason(event.target.value)}
                rows={3}
                maxLength={500}
                data-testid="transition-reason-input"
              />
            </Field>
          ) : (
            <Field label={c("transitionReason")} htmlFor="transition-reason">
              <Input
                id="transition-reason"
                value={transitionReason}
                onChange={(event) => setTransitionReason(event.target.value)}
                maxLength={500}
              />
            </Field>
          )}
          {closeOut ? (
            <>
              <div className="notice notice-warning" style={{ marginTop: 10, fontSize: 11 }}>
                {c("closeOutHint").replace("{min}", String(CLOSE_OUT_MIN_LENGTH))}
              </div>
              <Field label={c("rootCauseLabel")} required htmlFor="close-root-cause">
                <Textarea
                  id="close-root-cause"
                  value={rootCause}
                  onChange={(event) => setRootCause(event.target.value)}
                  rows={3}
                  maxLength={20000}
                  data-testid="close-root-cause-input"
                />
              </Field>
              <Field label={c("lessonsLabel")} required htmlFor="close-lessons">
                <Textarea
                  id="close-lessons"
                  value={lessons}
                  onChange={(event) => setLessons(event.target.value)}
                  rows={3}
                  maxLength={20000}
                  data-testid="close-lessons-input"
                />
              </Field>
            </>
          ) : null}
          {!transitionValid ? <p className="hint">{c("transitionHint")}</p> : null}
        </div>
      </Modal>

      <Modal
        open={sealTarget !== null}
        onClose={() => setSealTarget(null)}
        title={c("sealTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setSealTarget(null)}>{t("common.cancel")}</Button>
            <Button
              variant="danger"
              icon={Lock}
              loading={sealMutation.isPending}
              disabled={!sealTarget || !can("incident:write")}
              onClick={() => sealTarget && sealMutation.mutate(sealTarget.id)}
              data-testid="confirm-seal-evidence"
            >
              {c("sealConfirm")}
            </Button>
          </>
        }
      >
        {sealTarget ? (
          <div data-testid="seal-modal">
            <div className="notice notice-warning" style={{ fontSize: 11 }}>
              <ShieldAlert size={13} style={{ flex: "0 0 auto" }} />
              <span>{c("sealWarning")}</span>
            </div>
            <div className="metric-list" style={{ marginTop: 10 }}>
              <div className="metric-row"><span className="metric-label">{c("uploadTitle")}</span><span className="metric-value">{sealTarget.title}</span></div>
              <div className="metric-row"><span className="metric-label">{c("sha")}</span><span className="metric-value" style={{ fontSize: 10 }}>{shortSha(sealTarget.sha256)}</span></div>
              <div className="metric-row"><span className="metric-label">{c("size")}</span><span className="metric-value">{formatBytes(sealTarget.size_bytes)}</span></div>
            </div>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title={c("editTitle")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditOpen(false)}>{t("common.cancel")}</Button>
            <Button
              variant="primary"
              loading={editMutation.isPending}
              disabled={!can("incident:write") || editTitle.trim().length < 3}
              onClick={submitEdit}
              data-testid="save-incident"
            >
              {c("save")}
            </Button>
          </>
        }
      >
        <div data-testid="edit-incident-modal" className="form-grid">
          <div className="span-2">
            <Field label={c("titleField")} required htmlFor="edit-title">
              <Input id="edit-title" value={editTitle} onChange={(event) => setEditTitle(event.target.value)} maxLength={300} />
            </Field>
          </div>
          <div className="span-2">
            <Field label={c("descriptionField")} htmlFor="edit-description">
              <Textarea id="edit-description" value={editDescription} onChange={(event) => setEditDescription(event.target.value)} rows={3} maxLength={20000} />
            </Field>
          </div>
          <Field label={c("severityField")} htmlFor="edit-severity">
            <Select id="edit-severity" value={editSeverity} onChange={(event) => setEditSeverity(event.target.value)}>
              {INCIDENT_SEVERITIES.map((value) => <option key={value} value={value}>{value}</option>)}
            </Select>
          </Field>
          <Field label={c("priorityField")} htmlFor="edit-priority">
            <Input id="edit-priority" type="number" min={1} max={5} value={editPriority} onChange={(event) => setEditPriority(event.target.value)} />
          </Field>
          <Field label={c("assigneeField")} htmlFor="edit-assignee">
            <Select id="edit-assignee" value={editAssignee} onChange={(event) => setEditAssignee(event.target.value)}>
              <option value="">{c("unassign")}</option>
              {members.data?.items.map((member) => <option key={member.user_id} value={member.user_id}>{member.full_name}</option>)}
            </Select>
          </Field>
          <Field label={c("commanderField")} htmlFor="edit-commander">
            <Select id="edit-commander" value={editCommander} onChange={(event) => setEditCommander(event.target.value)}>
              <option value="">{c("unassign")}</option>
              {members.data?.items.map((member) => <option key={member.user_id} value={member.user_id}>{member.full_name}</option>)}
            </Select>
          </Field>
          <Field label={c("slaField")} htmlFor="edit-sla">
            <Input id="edit-sla" type="datetime-local" value={editSla} onChange={(event) => setEditSla(event.target.value)} />
          </Field>
          <Field label={c("mitreField")} hint={c("mitreHint")} htmlFor="edit-mitre">
            <Input id="edit-mitre" value={editMitre} onChange={(event) => setEditMitre(event.target.value)} />
          </Field>
        </div>
      </Modal>
    </div>
  );
}

export default IncidentDetailPage;
