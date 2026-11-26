import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Archive,
  CheckCircle2,
  CirclePlay,
  Clock,
  FileJson2,
  FlaskConical,
  History,
  ListChecks,
  Pencil,
  PlayCircle,
  Plus,
  RefreshCw,
  Rocket,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import { api, errorMessage, isApiError, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatDateTime, formatNumber, relativeTime } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
  Field,
  LinkButton,
  Modal,
  PageHeader,
  Pagination,
  SearchInput,
  Select,
  StatusBadge,
  Tabs,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";

/* ------------------------------------------------------------------ types */

interface Playbook {
  id: string;
  org_id: string | null;
  name: string;
  description: string | null;
  version: number;
  status: string;
  trigger: Record<string, unknown>;
  definition: Record<string, unknown>;
  min_autonomy_level: string;
  created_by: string | null;
  published_at: string | null;
  created_at: string;
  updated_at: string;
}

interface Execution {
  id: string;
  org_id: string;
  playbook_id: string;
  incident_id: string | null;
  status: string;
  trigger: string;
  context: Record<string, unknown>;
  autonomy_level: string;
  dry_run: boolean;
  started_at: string;
  finished_at: string | null;
  error: string | null;
  requested_by: string | null;
  approval_id: string | null;
}

interface ExecutionStep {
  id: string;
  step_key: string;
  name: string;
  status: string;
  attempts: number;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  compensation_status: string | null;
  compensation_output: Record<string, unknown>;
}

interface ExecutionDetail extends Execution {
  steps: ExecutionStep[];
  approval_status: string | null;
}

interface ResumeResponse {
  execution: ExecutionDetail;
  resumed: boolean;
  reason: string | null;
}

interface ValidationIssue {
  field: string;
  message: string;
}

interface ValidationResult {
  valid: boolean;
  errors: ValidationIssue[];
  normalized: Record<string, unknown> | null;
}

interface SimulationStep {
  position: number;
  key: string;
  name: string;
  action: string;
  would_execute: boolean;
  condition_matched: boolean;
  reason?: string;
  approval_required?: boolean;
  decision?: Record<string, unknown>;
  params?: Record<string, unknown>;
}

interface Simulation {
  playbook_id: string;
  version: number;
  status: string;
  autonomy_level: string;
  steps: SimulationStep[];
  summary: { steps: number; would_execute: number; skipped: number };
}

interface IncidentOption {
  id: string;
  ref: string;
  title: string;
  severity: string;
  status: string;
  priority: number;
  detected_at: string;
}

type Tab = "playbooks" | "executions";

/* ------------------------------------------------------------------- copy */

const COPY = {
  es: {
    eyebrow: "Automatización · SOAR",
    title: "SOAR y automatización",
    subtitle: "Playbooks versionados, simulaciones sin efectos y ejecuciones con aprobación humana.",
    tabPlaybooks: "Playbooks",
    tabExecutions: "Ejecuciones",
    newPlaybook: "Nuevo playbook",
    refresh: "Actualizar",
    errorTitle: "No se pudieron cargar los datos de SOAR",
    playbookSearch: "Buscar playbooks por nombre o descripción…",
    statusAll: "Todos los estados",
    statusDraft: "Borrador",
    statusPublished: "Publicado",
    statusArchived: "Archivado",
    colPlaybook: "Playbook",
    colVersion: "Versión",
    colStatus: "Estado",
    colAutonomy: "Autonomía mín.",
    colTrigger: "Disparador",
    colUpdated: "Actualizado",
    colActions: "Acciones",
    validate: "Validar",
    simulate: "Simular",
    execute: "Ejecutar",
    edit: "Editar",
    publish: "Publicar",
    archive: "Archivar",
    publishTitle: "Publicar playbook",
    publishWarning: "Publicar revalida la definición en el servidor y archiva la versión publicada anterior con el mismo nombre.",
    publishConfirm: "Publicar versión",
    published: "Playbook {name} publicado",
    archiveTitle: "Archivar playbook",
    archiveWarning: "El playbook dejará de poder ejecutarse y no admitirá más ediciones.",
    archiveConfirm: "Archivar",
    archived: "Playbook archivado",
    actionError: "No se pudo completar la acción",
    validationTitle: "Validación de la definición",
    validationValid: "Definición válida",
    validationInvalid: "Definición rechazada",
    validationOkHint: "El servidor normalizó la definición y puede guardarse o publicarse.",
    validationErrorHint: "Corrige los siguientes problemas antes de guardar o publicar.",
    validateRun: "Validando…",
    playbooksEmpty: "Sin playbooks",
    playbooksEmptyDesc: "Crea un playbook y diséñalo paso a paso con acciones del catálogo defensivo.",
    playbooksFilterEmpty: "Ningún playbook coincide con los filtros.",
    clearFilters: "Limpiar filtros",
    simulateTitle: "Simular playbook",
    simulateHint:
      "La simulación evalúa condiciones y la política de autonomía sin crear ejecuciones ni ejecutar acciones. No confundir con una ejecución real.",
    contextJson: "Contexto de ejecución (JSON)",
    incidentOptional: "Incidente (opcional)",
    noIncident: "Sin incidente",
    runSimulation: "Simular",
    simulationBadge: "SIMULACIÓN · sin efectos",
    simulationSummary: "{execute} de {steps} pasos se ejecutarían · {skipped} omitidos por condición",
    wouldExecute: "Se ejecutaría",
    wouldSkip: "Omitido",
    condition: "Condición",
    policyDecision: "Decisión de política",
    approvalRequired: "Requiere aprobación",
    simulationError: "La simulación falló",
    executeTitle: "Ejecutar playbook",
    executeHint: "Solo se ejecutan playbooks publicados. La política se reevalúa en el servidor y las acciones críticas esperan aprobación.",
    executeWarning:
      "Una ejecución real puede modificar sistemas. Usa el modo de prueba (dry run) para validar primero. Las acciones A3/A4 requieren aprobación.",
    dryRun: "Modo de prueba (dry run)",
    dryRunHint: "No ejecuta acciones reales; registra la ejecución como simulada.",
    requestedLevel: "Nivel de autonomía solicitado",
    respectPolicy: "Respetar política de la organización",
    runExecution: "Ejecutar",
    executionStarted: "Ejecución {id} iniciada",
    waitingApproval: "La ejecución espera aprobación humana; revísala en Ejecuciones.",
    executionError: "No se pudo iniciar la ejecución",
    missingPublished: "Solo se pueden ejecutar playbooks publicados.",
    executionsTitle: "Ejecuciones",
    executionsSubtitle: "Historial durable con pasos, intentos, compensaciones y aprobaciones.",
    execSearchPlaybook: "Filtrar por playbook",
    execAllStatuses: "Todos los estados",
    execAllPlaybooks: "Todos los playbooks",
    execDryRun: "Solo dry run",
    execReal: "Solo ejecuciones reales",
    execAnyMode: "Todos los modos",
    colExecution: "Ejecución",
    colMode: "Modo",
    colStarted: "Inicio",
    colDuration: "Duración",
    colApproval: "Aprobación",
    realExecution: "REAL",
    dryExecution: "DRY RUN",
    execDetailTitle: "Detalle de ejecución",
    execSteps: "Pasos",
    colStep: "Paso",
    colStepStatus: "Estado",
    colAttempts: "Intentos",
    colCompensation: "Compensación",
    colError: "Error",
    approvalStatus: "Estado de aprobación",
    resume: "Reanudar tras aprobación",
    resumeHint: "La reanudación solo procede si la aprobación está aprobada y la ejecución sigue esperando.",
    resumed: "Ejecución reanudada",
    resumeBlocked: "No se reanudó: {reason}",
    resumeError: "No se pudo reanudar la ejecución",
    noSteps: "Sin pasos registrados.",
    execEmpty: "Sin ejecuciones",
    execEmptyDesc: "Lanza un playbook publicado para ver aquí su traza completa.",
    execFilterEmpty: "Ninguna ejecución coincide con los filtros.",
    execError: "No se pudieron cargar las ejecuciones",
    viewExecutions: "Ver ejecuciones",
    simulationLog: "Salida simulada",
    detailError: "No se pudo cargar la ejecución",
    demo: "DEMO",
    totalRecords: "registros",
    incidentsLoadError: "No se pudieron cargar los incidentes",
    statusWaiting: "waiting_approval",
    stepsCount: "{count} pasos",
  },
  en: {
    eyebrow: "Automation · SOAR",
    title: "SOAR and automation",
    subtitle: "Versioned playbooks, side-effect-free simulations and executions with human approval.",
    tabPlaybooks: "Playbooks",
    tabExecutions: "Executions",
    newPlaybook: "New playbook",
    refresh: "Refresh",
    errorTitle: "Could not load SOAR data",
    playbookSearch: "Search playbooks by name or description…",
    statusAll: "All statuses",
    statusDraft: "Draft",
    statusPublished: "Published",
    statusArchived: "Archived",
    colPlaybook: "Playbook",
    colVersion: "Version",
    colStatus: "Status",
    colAutonomy: "Min. autonomy",
    colTrigger: "Trigger",
    colUpdated: "Updated",
    colActions: "Actions",
    validate: "Validate",
    simulate: "Simulate",
    execute: "Execute",
    edit: "Edit",
    publish: "Publish",
    archive: "Archive",
    publishTitle: "Publish playbook",
    publishWarning: "Publishing revalidates the definition server-side and archives the previously published version with the same name.",
    publishConfirm: "Publish version",
    published: "Playbook {name} published",
    archiveTitle: "Archive playbook",
    archiveWarning: "The playbook will no longer be executable and will not accept further edits.",
    archiveConfirm: "Archive",
    archived: "Playbook archived",
    actionError: "Could not complete the action",
    validationTitle: "Definition validation",
    validationValid: "Valid definition",
    validationInvalid: "Definition rejected",
    validationOkHint: "The server normalized the definition and it can be saved or published.",
    validationErrorHint: "Fix the following issues before saving or publishing.",
    validateRun: "Validating…",
    playbooksEmpty: "No playbooks",
    playbooksEmptyDesc: "Create a playbook and design it step by step with defensive catalogue actions.",
    playbooksFilterEmpty: "No playbook matches the filters.",
    clearFilters: "Clear filters",
    simulateTitle: "Simulate playbook",
    simulateHint:
      "Simulation evaluates conditions and the autonomy policy without creating executions or running actions. Not to be confused with a real execution.",
    contextJson: "Execution context (JSON)",
    incidentOptional: "Incident (optional)",
    noIncident: "No incident",
    runSimulation: "Simulate",
    simulationBadge: "SIMULATION · no side effects",
    simulationSummary: "{execute} of {steps} steps would run · {skipped} skipped by condition",
    wouldExecute: "Would run",
    wouldSkip: "Skipped",
    condition: "Condition",
    policyDecision: "Policy decision",
    approvalRequired: "Approval required",
    simulationError: "Simulation failed",
    executeTitle: "Execute playbook",
    executeHint: "Only published playbooks run. Policy is re-evaluated server-side and critical actions wait for approval.",
    executeWarning:
      "A real execution can modify systems. Use dry run to validate first. A3/A4 actions require approval.",
    dryRun: "Dry run",
    dryRunHint: "Does not execute real actions; records the execution as simulated.",
    requestedLevel: "Requested autonomy level",
    respectPolicy: "Respect organization policy",
    runExecution: "Execute",
    executionStarted: "Execution {id} started",
    waitingApproval: "The execution is waiting for human approval; review it in Executions.",
    executionError: "Could not start the execution",
    missingPublished: "Only published playbooks can be executed.",
    executionsTitle: "Executions",
    executionsSubtitle: "Durable history with steps, attempts, compensations and approvals.",
    execSearchPlaybook: "Filter by playbook",
    execAllStatuses: "All statuses",
    execAllPlaybooks: "All playbooks",
    execDryRun: "Dry run only",
    execReal: "Real executions only",
    execAnyMode: "All modes",
    colExecution: "Execution",
    colMode: "Mode",
    colStarted: "Started",
    colDuration: "Duration",
    colApproval: "Approval",
    realExecution: "REAL",
    dryExecution: "DRY RUN",
    execDetailTitle: "Execution detail",
    execSteps: "Steps",
    colStep: "Step",
    colStepStatus: "Status",
    colAttempts: "Attempts",
    colCompensation: "Compensation",
    colError: "Error",
    approvalStatus: "Approval status",
    resume: "Resume after approval",
    resumeHint: "Resume only proceeds when the approval is granted and the execution is still waiting.",
    resumed: "Execution resumed",
    resumeBlocked: "Not resumed: {reason}",
    resumeError: "Could not resume the execution",
    noSteps: "No steps recorded.",
    execEmpty: "No executions",
    execEmptyDesc: "Launch a published playbook to see its full trace here.",
    execFilterEmpty: "No execution matches the filters.",
    execError: "Could not load executions",
    viewExecutions: "View executions",
    simulationLog: "Simulated output",
    detailError: "Could not load the execution",
    demo: "DEMO",
    totalRecords: "records",
    incidentsLoadError: "Could not load incidents",
    statusWaiting: "waiting_approval",
    stepsCount: "{count} steps",
  },
};

function errorText(error: unknown): string {
  if (isApiError(error) && error.status === 403) return "403 — insufficient permissions";
  if (isApiError(error) && error.details.length) {
    return error.details.map((detail) => `${detail.field}: ${detail.message}`).join(" · ");
  }
  return errorMessage(error);
}

function parseContext(text: string): Record<string, unknown> {
  if (!text.trim()) return {};
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Context must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

function durationBetween(start: string, end: string | null): string {
  if (!end) return "—";
  const milliseconds = new Date(end).getTime() - new Date(start).getTime();
  if (Number.isNaN(milliseconds) || milliseconds < 0) return "—";
  const seconds = Math.round(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

/* ------------------------------------------------------------- simulations */

function SimulateModal({
  playbook,
  open,
  onClose,
}: {
  playbook: Playbook | null;
  open: boolean;
  onClose: () => void;
}) {
  const c = usePageCopy(COPY);
  const { t, lang } = useI18n();
  const [context, setContext] = useState("{}");
  const [incidentId, setIncidentId] = useState("");
  const [result, setResult] = useState<Simulation | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setResult(null);
      setError(null);
    }
  }, [open, playbook]);

  const incidents = useQuery({
    queryKey: ["incidents", "soar-picker"],
    queryFn: () => api.get<Page<IncidentOption>>("/incidents", { page_size: 100, sort: "detected_at", order: "desc" }),
    enabled: open,
    staleTime: 30_000,
  });

  const mutation = useMutation({
    mutationFn: () => {
      if (!playbook) throw new Error("playbook");
      return api.post<Simulation>(`/soar/playbooks/${playbook.id}/simulate`, {
        context: parseContext(context),
        incident_id: incidentId || undefined,
      });
    },
    onSuccess: (data) => {
      setResult(data);
      setError(null);
    },
    onError: (err) => setError(errorText(err)),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={c("simulateTitle")}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
          <Button variant="primary" icon={FlaskConical} loading={mutation.isPending} onClick={() => mutation.mutate()} data-testid="run-simulation">
            {c("runSimulation")}
          </Button>
        </>
      }
    >
      <div data-testid="simulate-modal">
        <div className="notice notice-accent" style={{ fontSize: 11 }}>
          <ShieldCheck size={13} style={{ flex: "0 0 auto" }} />
          <span>{c("simulateHint")}</span>
        </div>
        <div className="form-grid" style={{ marginTop: 10 }}>
          <Field label={c("incidentOptional")} htmlFor="simulate-incident">
            <Select id="simulate-incident" value={incidentId} onChange={(event) => setIncidentId(event.target.value)}>
              <option value="">{c("noIncident")}</option>
              {incidents.data?.items.map((incident) => (
                <option key={incident.id} value={incident.id}>{incident.ref} · {incident.title}</option>
              ))}
            </Select>
          </Field>
          <div className="field">
            <span className="section-label" style={{ marginBottom: 8 }}>{playbook?.name ?? "—"}</span>
            <div className="row" style={{ gap: 6 }}>
              <Badge tone="neutral">v{playbook?.version ?? 0}</Badge>
              <StatusBadge status={playbook?.status ?? "draft"} />
            </div>
          </div>
          <div className="span-2">
            <Field label={c("contextJson")} htmlFor="simulate-context">
              <Textarea id="simulate-context" className="textarea mono" value={context} onChange={(event) => setContext(event.target.value)} rows={6} spellCheck={false} />
            </Field>
          </div>
        </div>
        {incidents.isError ? <ErrorBanner compact message={c("incidentsLoadError")} /> : null}
        {error ? <div style={{ marginTop: 10 }}><ErrorBanner compact message={error} /></div> : null}
        {result ? (
          <div style={{ marginTop: 12 }} data-testid="simulation-result">
            <div className="row wrap" style={{ gap: 6, marginBottom: 8 }}>
              <Badge tone="accent">{c("simulationBadge")}</Badge>
              <Badge tone="neutral">
                {c("simulationSummary")
                  .replace("{execute}", String(result.summary.would_execute))
                  .replace("{steps}", String(result.summary.steps))
                  .replace("{skipped}", String(result.summary.skipped))}
              </Badge>
            </div>
            <div className="stack">
              {result.steps.map((step) => (
                <div className="card card-pad" key={`${step.position}-${step.key}`}>
                  <div className="row-between" style={{ gap: 10, alignItems: "flex-start" }}>
                    <div style={{ minWidth: 0 }}>
                      <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                        <span className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{step.key}</span>
                        <strong style={{ fontSize: 12.5 }}>{step.name}</strong>
                        <Badge tone={step.would_execute ? "success" : "neutral"}>
                          {step.would_execute ? c("wouldExecute") : c("wouldSkip")}
                        </Badge>
                      </div>
                      <div className="item-sub" style={{ marginTop: 4 }}>{step.action}</div>
                      {step.reason ? <div className="hint">{c("condition")}: {step.reason}</div> : null}
                      {step.approval_required ? <Badge tone="warning">{c("approvalRequired")}</Badge> : null}
                      {step.decision ? (
                        <details style={{ marginTop: 6 }}>
                          <summary className="dim" style={{ fontSize: 10.5, cursor: "pointer" }}>{c("policyDecision")}</summary>
                          <pre className="code-block" style={{ marginTop: 6 }}>{JSON.stringify(step.decision, null, 2)}</pre>
                        </details>
                      ) : null}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <div className="section-label" style={{ marginTop: 12 }}>{c("simulationLog")}</div>
            <pre className="code-block">{JSON.stringify(result, null, 2)}</pre>
            <span className="dim" style={{ fontSize: 10.5 }}>{formatDateTime(new Date().toISOString(), lang)}</span>
          </div>
        ) : null}
      </div>
    </Modal>
  );
}

/* --------------------------------------------------------------- execution */

function ExecuteModal({
  playbook,
  open,
  onClose,
  onStarted,
}: {
  playbook: Playbook | null;
  open: boolean;
  onClose: () => void;
  onStarted: (execution: ExecutionDetail) => void;
}) {
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const { push } = useToast();
  const [params] = useSearchParams();
  const [incidentId, setIncidentId] = useState(params.get("incident_id") ?? "");
  const [context, setContext] = useState("{}");
  const [dryRun, setDryRun] = useState(false);
  const [requestedLevel, setRequestedLevel] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setIncidentId(params.get("incident_id") ?? "");
      setError(null);
    }
  }, [open, params]);

  const incidents = useQuery({
    queryKey: ["incidents", "soar-picker"],
    queryFn: () => api.get<Page<IncidentOption>>("/incidents", { page_size: 100, sort: "detected_at", order: "desc" }),
    enabled: open,
    staleTime: 30_000,
  });

  const mutation = useMutation({
    mutationFn: () => {
      if (!playbook) throw new Error("playbook");
      return api.post<ExecutionDetail>(`/soar/playbooks/${playbook.id}/execute`, {
        incident_id: incidentId || undefined,
        context: parseContext(context),
        dry_run: dryRun,
        requested_level: requestedLevel || undefined,
      });
    },
    onSuccess: (execution) => {
      push(c("executionStarted").replace("{id}", execution.id.slice(0, 8)), "success");
      if (execution.status === "waiting_approval") push(c("waitingApproval"), "info");
      onStarted(execution);
    },
    onError: (err) => setError(errorText(err)),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={c("executeTitle")}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button
            variant="primary"
            icon={CirclePlay}
            loading={mutation.isPending}
            disabled={playbook?.status !== "published"}
            onClick={() => mutation.mutate()}
            data-testid="confirm-execute"
          >
            {c("runExecution")}
          </Button>
        </>
      }
    >
      <div data-testid="execute-modal">
        <div className="notice notice-warning" style={{ fontSize: 11 }}>
          <AlertTriangle size={13} style={{ flex: "0 0 auto" }} />
          <span>{c("executeWarning")}</span>
        </div>
        <p className="hint" style={{ marginTop: 8 }}>{c("executeHint")}</p>

        <div className="form-grid" style={{ marginTop: 10 }}>
          <Field label={c("incidentOptional")} htmlFor="execute-incident">
            <Select id="execute-incident" value={incidentId} onChange={(event) => setIncidentId(event.target.value)} data-testid="execute-incident">
              <option value="">{c("noIncident")}</option>
              {incidents.data?.items.map((incident) => (
                <option key={incident.id} value={incident.id}>{incident.ref} · {incident.title}</option>
              ))}
            </Select>
          </Field>
          <Field label={c("requestedLevel")} htmlFor="execute-level">
            <Select id="execute-level" value={requestedLevel} onChange={(event) => setRequestedLevel(event.target.value)}>
              <option value="">{c("respectPolicy")}</option>
              {["A0", "A1", "A2", "A3", "A4"].map((level) => <option key={level} value={level}>{level}</option>)}
            </Select>
          </Field>
          <div className="span-2">
            <label className="checkbox">
              <input type="checkbox" checked={dryRun} onChange={(event) => setDryRun(event.target.checked)} />
              {c("dryRun")}
            </label>
            <span className="hint">{c("dryRunHint")}</span>
          </div>
          <div className="span-2">
            <Field label={c("contextJson")} htmlFor="execute-context">
              <Textarea id="execute-context" className="textarea mono" value={context} onChange={(event) => setContext(event.target.value)} rows={6} spellCheck={false} />
            </Field>
          </div>
        </div>
        {incidents.isError ? <ErrorBanner compact message={c("incidentsLoadError")} /> : null}
        {playbook?.status !== "published" ? <p className="hint">{c("missingPublished")}</p> : null}
        {error ? <div style={{ marginTop: 10 }}><ErrorBanner compact message={error} /></div> : null}
      </div>
    </Modal>
  );
}

function ExecutionDetailModal({
  executionId,
  onClose,
}: {
  executionId: string | null;
  onClose: () => void;
}) {
  const c = usePageCopy(COPY);
  const { t, lang } = useI18n();
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["soar", "executions", "detail", executionId],
    queryFn: () => api.get<ExecutionDetail>(`/soar/executions/${executionId}`),
    enabled: Boolean(executionId),
  });

  const resume = useMutation({
    mutationFn: () => api.post<ResumeResponse>(`/soar/executions/${executionId}/resume`),
    onSuccess: (result) => {
      if (result.resumed) push(c("resumed"), "success");
      else push(c("resumeBlocked").replace("{reason}", result.reason ?? "—"), "error");
      void queryClient.invalidateQueries({ queryKey: ["soar", "executions"] });
      void query.refetch();
    },
    onError: (error) => push(`${c("resumeError")}: ${errorText(error)}`, "error"),
  });

  const columns: Column<ExecutionStep>[] = [
    {
      key: "step",
      header: c("colStep"),
      render: (row) => (
        <div>
          <div className="primary-cell">{row.name}</div>
          <div className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{row.step_key}</div>
        </div>
      ),
    },
    { key: "status", header: c("colStepStatus"), width: "126px", render: (row) => <StatusBadge status={row.status} /> },
    { key: "attempts", header: c("colAttempts"), width: "84px", align: "right", render: (row) => <span className="mono">{row.attempts}</span> },
    {
      key: "compensation",
      header: c("colCompensation"),
      width: "150px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5 }}>
          {row.compensation_status ?? "—"}
          {Object.keys(row.compensation_output).length ? " ⚠" : ""}
        </span>
      ),
    },
    {
      key: "error",
      header: c("colError"),
      render: (row) => (row.error ? <span style={{ color: "var(--danger)", fontSize: 11 }}>{row.error}</span> : <span className="dim">—</span>),
    },
  ];

  return (
    <Modal
      open={executionId !== null}
      onClose={onClose}
      title={c("execDetailTitle")}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
          {query.data?.status === "waiting_approval" ? (
            <Button
              variant="primary"
              icon={Rocket}
              loading={resume.isPending}
              disabled={!can("playbook:execute")}
              onClick={() => resume.mutate()}
              data-testid="resume-execution"
            >
              {c("resume")}
            </Button>
          ) : null}
        </>
      }
    >
      <div data-testid="execution-detail-modal">
        {query.isLoading ? (
          <div className="stack"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
        ) : query.isError || !query.data ? (
          <ErrorBanner compact message={errorText(query.error)} onRetry={() => void query.refetch()} />
        ) : (
          <div className="stack">
            <div className="row wrap" style={{ gap: 6 }}>
              <span className="mono" style={{ fontSize: 10.5 }}>{query.data.id}</span>
              <StatusBadge status={query.data.status} />
              <Badge tone={query.data.dry_run ? "accent" : "danger"}>{query.data.dry_run ? c("dryExecution") : c("realExecution")}</Badge>
              <Badge tone="neutral">A{query.data.autonomy_level.replace(/^A/, "")}</Badge>
              <Badge tone="neutral">{query.data.trigger}</Badge>
            </div>
            <div className="metric-list">
              <div className="metric-row"><span className="metric-label">{c("colStarted")}</span><span className="metric-value">{formatDateTime(query.data.started_at, lang)}</span></div>
              <div className="metric-row"><span className="metric-label">{c("colDuration")}</span><span className="metric-value">{durationBetween(query.data.started_at, query.data.finished_at)}</span></div>
              <div className="metric-row"><span className="metric-label">{c("approvalStatus")}</span><span className="metric-value">{query.data.approval_status ? <StatusBadge status={query.data.approval_status} /> : "—"}</span></div>
              {query.data.incident_id ? (
                <div className="metric-row">
                  <span className="metric-label">{c("incidentOptional")}</span>
                  <span className="metric-value"><Link to={`/incidents/${query.data.incident_id}`}>{query.data.incident_id.slice(0, 8)}</Link></span>
                </div>
              ) : null}
            </div>
            {query.data.error ? <ErrorBanner compact message={query.data.error} /> : null}
            {query.data.status === "waiting_approval" ? <div className="notice notice-warning" style={{ fontSize: 11 }}>{c("resumeHint")}</div> : null}
            <div className="section-label">{c("execSteps")}</div>
            {query.data.steps.length === 0 ? (
              <EmptyState icon={ListChecks} title={c("noSteps")} />
            ) : (
              <div className="table-wrap" data-testid="execution-steps-table">
                <DataTable columns={columns} rows={query.data.steps} rowKey={(row) => row.id} />
              </div>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------- page */

export function SoarPage() {
  const c = usePageCopy(COPY);
  const { t, lang } = useI18n();
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useState<Tab>("playbooks");

  const [playbookPage, setPlaybookPage] = useState(1);
  const [playbookQuery, setPlaybookQuery] = useState("");
  const [playbookStatus, setPlaybookStatus] = useState("");

  const [executionPage, setExecutionPage] = useState(1);
  const [executionStatus, setExecutionStatus] = useState("");
  const [executionPlaybook, setExecutionPlaybook] = useState("");
  const [executionMode, setExecutionMode] = useState("");

  const [publishTarget, setPublishTarget] = useState<Playbook | null>(null);
  const [archiveTarget, setArchiveTarget] = useState<Playbook | null>(null);
  const [simulateTarget, setSimulateTarget] = useState<Playbook | null>(null);
  const [executeTarget, setExecuteTarget] = useState<Playbook | null>(null);
  const [validation, setValidation] = useState<{ playbook: Playbook; result: ValidationResult } | null>(null);
  const [executionDetailId, setExecutionDetailId] = useState<string | null>(params.get("execution_id"));

  const canWrite = can("playbook:write");
  const canExecute = can("playbook:execute");

  const playbooks = useQuery({
    queryKey: ["soar", "playbooks", { playbookPage, playbookQuery, playbookStatus }],
    queryFn: () =>
      api.get<Page<Playbook>>("/soar/playbooks", {
        page: playbookPage,
        page_size: 25,
        q: playbookQuery.trim() || undefined,
        status: playbookStatus || undefined,
        sort: "updated_at",
        order: "desc",
      }),
  });

  const executions = useQuery({
    queryKey: ["soar", "executions", { executionPage, executionStatus, executionPlaybook, executionMode }],
    queryFn: () =>
      api.get<Page<Execution>>("/soar/executions", {
        page: executionPage,
        page_size: 25,
        status: executionStatus || undefined,
        playbook_id: executionPlaybook || undefined,
        dry_run: executionMode === "" ? undefined : executionMode === "dry",
        sort: "started_at",
        order: "desc",
      }),
  });

  const allPlaybooks = useQuery({
    queryKey: ["soar", "playbooks", "options"],
    queryFn: () => api.get<Page<Playbook>>("/soar/playbooks", { page_size: 200, sort: "name", order: "asc" }),
    staleTime: 60_000,
  });

  const playbooksById = useMemo(() => {
    const map = new Map<string, Playbook>();
    for (const playbook of [...(allPlaybooks.data?.items ?? []), ...(playbooks.data?.items ?? [])]) map.set(playbook.id, playbook);
    return map;
  }, [allPlaybooks.data, playbooks.data]);

  useEffect(() => {
    const incidentId = params.get("incident_id");
    if (incidentId) {
      const published = playbooks.data?.items.find((playbook) => playbook.status === "published");
      if (published) setExecuteTarget(published);
    }
  }, [params, playbooks.data]);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["soar"] });
  };

  const publish = useMutation({
    mutationFn: (playbook: Playbook) => api.post<Playbook>(`/soar/playbooks/${playbook.id}/publish`),
    onSuccess: (playbook) => {
      push(c("published").replace("{name}", playbook.name), "success");
      setPublishTarget(null);
      invalidate();
    },
    onError: (error) => push(`${c("actionError")}: ${errorText(error)}`, "error"),
  });

  const archive = useMutation({
    mutationFn: (playbook: Playbook) => api.post<Playbook>(`/soar/playbooks/${playbook.id}/archive`),
    onSuccess: () => {
      push(c("archived"), "success");
      setArchiveTarget(null);
      invalidate();
    },
    onError: (error) => push(`${c("actionError")}: ${errorText(error)}`, "error"),
  });

  const validate = useMutation({
    mutationFn: (playbook: Playbook) => api.post<ValidationResult>(`/soar/playbooks/${playbook.id}/validate`),
    onSuccess: (result, playbook) => setValidation({ playbook, result }),
    onError: (error) => push(`${c("actionError")}: ${errorText(error)}`, "error"),
  });

  const playbookColumns: Column<Playbook>[] = [
    {
      key: "name",
      header: c("colPlaybook"),
      render: (row) => (
        <div style={{ minWidth: 230 }}>
          <div className="primary-cell">{row.name}</div>
          <div className="cell-sub">{row.description ? row.description.slice(0, 100) : "—"}</div>
        </div>
      ),
    },
    { key: "version", header: c("colVersion"), width: "80px", render: (row) => <span className="mono">v{row.version}</span> },
    { key: "status", header: c("colStatus"), width: "118px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "autonomy",
      header: c("colAutonomy"),
      width: "110px",
      render: (row) => <Badge tone={row.min_autonomy_level === "A4" ? "danger" : row.min_autonomy_level === "A3" ? "warning" : "neutral"}>{row.min_autonomy_level}</Badge>,
    },
    {
      key: "trigger",
      header: c("colTrigger"),
      width: "140px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10 }}>
          {Object.keys(row.trigger).length ? JSON.stringify(row.trigger).slice(0, 40) : "—"}
        </span>
      ),
    },
    {
      key: "updated",
      header: c("colUpdated"),
      width: "126px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{relativeTime(row.updated_at, lang)}</span>,
    },
    {
      key: "actions",
      header: c("colActions"),
      width: "340px",
      align: "right",
      render: (row) => (
        <div className="row" style={{ gap: 3, justifyContent: "flex-end", flexWrap: "wrap" }}>
          <Button size="sm" variant="ghost" icon={CheckCircle2} loading={validate.isPending && validate.variables?.id === row.id} onClick={() => validate.mutate(row)}>
            {c("validate")}
          </Button>
          <Button size="sm" variant="ghost" icon={FlaskConical} disabled={!canExecute} onClick={() => setSimulateTarget(row)}>
            {c("simulate")}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={PlayCircle}
            disabled={!canExecute || row.status !== "published"}
            onClick={() => setExecuteTarget(row)}
            data-testid={`execute-playbook-${row.id}`}
          >
            {c("execute")}
          </Button>
          <LinkButton to={`/playbook-designer/${row.id}`} size="sm" variant="ghost" icon={Pencil}>{c("edit")}</LinkButton>
          {canWrite && row.status !== "published" && row.status !== "archived" ? (
            <Button size="sm" variant="ghost" icon={Rocket} onClick={() => setPublishTarget(row)} data-testid={`publish-playbook-${row.id}`}>
              {c("publish")}
            </Button>
          ) : null}
          {canWrite && row.status !== "archived" ? (
            <Button size="sm" variant="ghost" icon={Archive} onClick={() => setArchiveTarget(row)}>
              {c("archive")}
            </Button>
          ) : null}
        </div>
      ),
    },
  ];

  const executionColumns: Column<Execution>[] = [
    {
      key: "id",
      header: c("colExecution"),
      render: (row) => (
        <div>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--accent)" }}>{row.id.slice(0, 8)}</div>
          <div className="cell-sub">{playbooksById.get(row.playbook_id)?.name ?? row.playbook_id.slice(0, 8)}</div>
        </div>
      ),
    },
    {
      key: "mode",
      header: c("colMode"),
      width: "104px",
      render: (row) => <Badge tone={row.dry_run ? "accent" : "danger"}>{row.dry_run ? c("dryExecution") : c("realExecution")}</Badge>,
    },
    { key: "status", header: c("colStatus"), width: "130px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "autonomy",
      header: c("colAutonomy"),
      width: "100px",
      render: (row) => <Badge tone="neutral">{row.autonomy_level}</Badge>,
    },
    {
      key: "started",
      header: c("colStarted"),
      width: "126px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{relativeTime(row.started_at, lang)}</span>,
    },
    {
      key: "duration",
      header: c("colDuration"),
      width: "108px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{durationBetween(row.started_at, row.finished_at)}</span>,
    },
    {
      key: "approval",
      header: c("colApproval"),
      width: "118px",
      render: (row) => row.status === "waiting_approval" ? <Badge tone="warning">{c("statusWaiting")}</Badge> : <span className="dim">—</span>,
    },
  ];

  const headerActions = (
    <>
      <Button
        icon={RefreshCw}
        onClick={() => {
          if (tab === "playbooks") void playbooks.refetch();
          else void executions.refetch();
        }}
        aria-label={c("refresh")}
        data-testid="refresh-soar"
      />
      {canWrite ? (
        <LinkButton to="/playbook-designer" variant="primary" icon={Plus}>{c("newPlaybook")}</LinkButton>
      ) : null}
    </>
  );

  const statusOptions = [
    { key: "draft", label: c("statusDraft") },
    { key: "published", label: c("statusPublished") },
    { key: "archived", label: c("statusArchived") },
  ];

  return (
    <div className="animate-in" data-testid="page-soar">
      <PageHeader eyebrow={c("eyebrow")} title={c("title")} subtitle={c("subtitle")} actions={headerActions} />

      <Card
        bodyClassName=""
        footer={
          tab === "playbooks" ? (
            <Pagination meta={playbooks.data?.meta} onPage={setPlaybookPage} />
          ) : (
            <Pagination meta={executions.data?.meta} onPage={setExecutionPage} />
          )
        }
      >
        <div style={{ padding: "0 12px" }}>
          <Tabs<Tab>
            ariaLabel={c("subtitle")}
            items={[
              { key: "playbooks", label: c("tabPlaybooks"), count: playbooks.data?.meta.total },
              { key: "executions", label: c("tabExecutions"), count: executions.data?.meta.total },
            ]}
            value={tab}
            onChange={setTab}
          />
        </div>

        {tab === "playbooks" ? (
          <div data-testid="soar-tab-playbooks">
            <div className="filters-bar" data-testid="soar-playbooks-filters">
              <SearchInput
                value={playbookQuery}
                onChange={(value) => { setPlaybookQuery(value); setPlaybookPage(1); }}
                placeholder={c("playbookSearch")}
                ariaLabel={c("playbookSearch")}
              />
              <Select
                aria-label={c("colStatus")}
                value={playbookStatus}
                onChange={(event) => { setPlaybookStatus(event.target.value); setPlaybookPage(1); }}
                data-testid="playbooks-filter-status"
              >
                <option value="">{c("statusAll")}</option>
                {statusOptions.map((option) => <option key={option.key} value={option.key}>{option.label}</option>)}
              </Select>
              {playbookQuery || playbookStatus ? (
                <Button size="sm" variant="ghost" icon={X} onClick={() => { setPlaybookQuery(""); setPlaybookStatus(""); setPlaybookPage(1); }}>
                  {c("clearFilters")}
                </Button>
              ) : null}
              <Badge tone="neutral"><Activity size={10} /> {formatNumber(playbooks.data?.meta.total ?? 0)}</Badge>
            </div>
            {playbooks.isError ? (
              <div style={{ padding: 12 }}><ErrorBanner compact message={errorText(playbooks.error)} onRetry={() => void playbooks.refetch()} /></div>
            ) : null}
            <div data-testid="soar-playbooks-table">
              <DataTable
                columns={playbookColumns}
                rows={playbooks.data?.items}
                rowKey={(row) => row.id}
                loading={playbooks.isLoading}
                empty={
                  <EmptyState
                    icon={ShieldCheck}
                    title={playbookQuery || playbookStatus ? c("playbooksFilterEmpty") : c("playbooksEmpty")}
                    description={c("playbooksEmptyDesc")}
                    action={
                      canWrite ? (
                        <LinkButton to="/playbook-designer" size="sm" variant="primary" icon={Plus}>{c("newPlaybook")}</LinkButton>
                      ) : undefined
                    }
                  />
                }
              />
            </div>
          </div>
        ) : null}

        {tab === "executions" ? (
          <div data-testid="soar-tab-executions">
            <div className="filters-bar" data-testid="soar-executions-filters">
              <Select
                aria-label={c("execSearchPlaybook")}
                value={executionPlaybook}
                onChange={(event) => { setExecutionPlaybook(event.target.value); setExecutionPage(1); }}
                style={{ minWidth: 220 }}
              >
                <option value="">{c("execAllPlaybooks")}</option>
                {allPlaybooks.data?.items.map((playbook) => (
                  <option key={playbook.id} value={playbook.id}>{playbook.name}</option>
                ))}
              </Select>
              <Select
                aria-label={c("colStatus")}
                value={executionStatus}
                onChange={(event) => { setExecutionStatus(event.target.value); setExecutionPage(1); }}
              >
                <option value="">{c("execAllStatuses")}</option>
                {["pending", "running", "waiting_approval", "completed", "failed", "canceled"].map((value) => (
                  <option key={value} value={value}>{value}</option>
                ))}
              </Select>
              <Select aria-label={c("colMode")} value={executionMode} onChange={(event) => { setExecutionMode(event.target.value); setExecutionPage(1); }}>
                <option value="">{c("execAnyMode")}</option>
                <option value="dry">{c("execDryRun")}</option>
                <option value="real">{c("execReal")}</option>
              </Select>
              <Badge tone="neutral"><History size={10} /> {formatNumber(executions.data?.meta.total ?? 0)}</Badge>
            </div>
            {executions.isError ? (
              <div style={{ padding: 12 }}><ErrorBanner compact message={c("execError")} onRetry={() => void executions.refetch()} /></div>
            ) : null}
            <div data-testid="soar-executions-table">
              <DataTable
                columns={executionColumns}
                rows={executions.data?.items}
                rowKey={(row) => row.id}
                loading={executions.isLoading}
                onRowClick={(row) => setExecutionDetailId(row.id)}
                empty={
                  <EmptyState
                    icon={FileJson2}
                    title={executionStatus || executionPlaybook || executionMode ? c("execFilterEmpty") : c("execEmpty")}
                    description={c("execEmptyDesc")}
                  />
                }
              />
            </div>
          </div>
        ) : null}
      </Card>

      <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
        <ShieldAlert size={13} style={{ flex: "0 0 auto", color: "var(--warning)" }} />
        <span>
          {c("executeWarning")} · {c("simulateBadge")}
        </span>
        <span className="row" style={{ marginLeft: "auto", gap: 6 }}>
          <Clock size={11} /> {formatDateTime(new Date().toISOString(), lang)}
        </span>
      </div>

      <Modal
        open={publishTarget !== null}
        onClose={() => setPublishTarget(null)}
        title={c("publishTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setPublishTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="primary" icon={Rocket} loading={publish.isPending} onClick={() => publishTarget && publish.mutate(publishTarget)} data-testid="confirm-publish">
              {c("publishConfirm")}
            </Button>
          </>
        }
      >
        <div data-testid="publish-modal">
          <div className="notice notice-warning" style={{ fontSize: 11 }}>
            <AlertTriangle size={13} style={{ flex: "0 0 auto" }} />
            <span>{c("publishWarning")}</span>
          </div>
          {publishTarget ? (
            <div className="metric-list" style={{ marginTop: 10 }}>
              <div className="metric-row"><span className="metric-label">{c("colPlaybook")}</span><span className="metric-value">{publishTarget.name}</span></div>
              <div className="metric-row"><span className="metric-label">{c("colVersion")}</span><span className="metric-value">v{publishTarget.version}</span></div>
              <div className="metric-row"><span className="metric-label">{c("colAutonomy")}</span><span className="metric-value">{publishTarget.min_autonomy_level}</span></div>
            </div>
          ) : null}
        </div>
      </Modal>

      <Modal
        open={archiveTarget !== null}
        onClose={() => setArchiveTarget(null)}
        title={c("archiveTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setArchiveTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" icon={Archive} loading={archive.isPending} onClick={() => archiveTarget && archive.mutate(archiveTarget)} data-testid="confirm-archive">
              {c("archiveConfirm")}
            </Button>
          </>
        }
      >
        <div data-testid="archive-modal">
          <div className="notice notice-warning" style={{ fontSize: 11 }}>
            <AlertTriangle size={13} style={{ flex: "0 0 auto" }} />
            <span>{c("archiveWarning")}</span>
          </div>
          {archiveTarget ? <div className="notice" style={{ marginTop: 10, fontSize: 11 }}>{archiveTarget.name} · v{archiveTarget.version}</div> : null}
        </div>
      </Modal>

      <Modal
        open={validation !== null}
        onClose={() => setValidation(null)}
        title={c("validationTitle")}
        size="lg"
        footer={<Button variant="ghost" onClick={() => setValidation(null)}>{t("common.close")}</Button>}
      >
        {validation ? (
          <div data-testid="validation-result">
            <div className="row" style={{ gap: 8, marginBottom: 10 }}>
              <Badge tone={validation.result.valid ? "success" : "danger"}>
                {validation.result.valid ? c("validationValid") : c("validationInvalid")}
              </Badge>
              <span className="mono" style={{ fontSize: 10.5 }}>{validation.playbook.name}</span>
            </div>
            <p className="hint">{validation.result.valid ? c("validationOkHint") : c("validationErrorHint")}</p>
            {validation.result.errors.length ? (
              <div className="metric-list" style={{ marginTop: 10 }}>
                {validation.result.errors.map((issue, index) => (
                  <div className="metric-row" key={`${issue.field}-${index}`}>
                    <span className="metric-label mono" style={{ fontSize: 10 }}>{issue.field}</span>
                    <span className="metric-value" style={{ fontSize: 10.5, color: "var(--danger)" }}>{issue.message}</span>
                  </div>
                ))}
              </div>
            ) : null}
            {validation.result.normalized ? (
              <>
                <div className="section-label" style={{ marginTop: 12 }}>normalized</div>
                <pre className="code-block">{JSON.stringify(validation.result.normalized, null, 2)}</pre>
              </>
            ) : null}
          </div>
        ) : null}
      </Modal>

      <SimulateModal playbook={simulateTarget} open={simulateTarget !== null} onClose={() => setSimulateTarget(null)} />
      <ExecuteModal
        playbook={executeTarget}
        open={executeTarget !== null}
        onClose={() => {
          setExecuteTarget(null);
          if (params.get("incident_id")) {
            params.delete("incident_id");
            setParams(params, { replace: true });
          }
        }}
        onStarted={(execution) => {
          setExecuteTarget(null);
          invalidate();
          setExecutionDetailId(execution.id);
          if (params.get("incident_id")) {
            params.delete("incident_id");
            setParams(params, { replace: true });
          }
        }}
      />
      <ExecutionDetailModal executionId={executionDetailId} onClose={() => setExecutionDetailId(null)} />
    </div>
  );
}

export default SoarPage;
