import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Bot,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  CircleSlash,
  FileSearch,
  Link2,
  MessageSquare,
  Play,
  RefreshCw,
  Send,
  ShieldAlert,
  Sparkles,
  Square,
  Terminal,
  Wrench,
  X,
} from "lucide-react";
import { Link } from "react-router-dom";
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
  Input,
  Modal,
  PageHeader,
  PageSkeleton,
  Pagination,
  Select,
  StatusBadge,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";

/* ------------------------------------------------------------------ types */

interface Agent {
  id: string;
  org_id: string | null;
  code: string;
  name: string;
  description: string | null;
  capabilities: string[];
  allowed_tools: string[];
  max_autonomy: string;
  system_prompt: string | null;
  enabled: boolean;
  catalog_available: boolean;
  is_demo?: boolean;
  created_at: string;
  updated_at: string;
}

interface AgentRun {
  id: string;
  agent_id: string;
  agent_code: string;
  incident_id: string | null;
  task: string;
  status: string;
  autonomy_level: string;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
  evidence: Record<string, unknown>[];
  model_id: string | null;
  started_at: string;
  finished_at: string | null;
  error: string | null;
  created_by: string | null;
}

interface AgentMessage {
  id: string;
  role: string;
  content: string;
  tool_name: string | null;
  tool_input: Record<string, unknown>;
  tool_output: Record<string, unknown>;
  citations: Record<string, unknown>[];
  created_at: string;
}

interface AgentRunDetail extends AgentRun {
  messages: AgentMessage[];
  tools: AgentMessage[];
  citations: Record<string, unknown>[];
  tool_calls: number;
}

interface AgentChatResponse {
  answer: string;
  citations: Record<string, unknown>[];
  analysis_mode: string;
  model: string | null;
  retrieved: number;
  generated_at: string;
}

interface ChatEntry {
  id: string;
  question: string;
  response: AgentChatResponse;
}

interface IncidentOption {
  id: string;
  ref: string;
  title: string;
}

const SECTION_KEYS = ["evidence", "source", "fact", "analysis", "inference", "hypothesis", "recommendation"] as const;

/* ------------------------------------------------------------------- copy */

const COPY = {
  es: {
    eyebrow: "IA · Control de agentes",
    title: "Control de agentes IA",
    subtitle: "Catálogo de agentes, ejecuciones acotadas y respuestas fundamentadas con citas.",
    observationTitle: "Observación únicamente — sin autoridad de ejecución",
    observationBody:
      "Los agentes A0/A1 analizan y recomiendan. No ejecutan acciones defensivas, no modifican sistemas y toda recomendación requiere aprobación humana y reevaluación de política.",
    refresh: "Actualizar",
    permissionDenied: "No tienes permiso ai:read para consultar el catálogo.",
    permissionUse: "No tienes permiso ai:use para lanzar agentes.",
    catalogue: "Catálogo de agentes",
    catalogueHint: "Selecciona un agente para revisar su alcance y lanzar una tarea.",
    selectedAgent: "Agente seleccionado",
    capabilities: "Capacidades",
    allowedTools: "Herramientas permitidas",
    maxAutonomy: "Autonomía máxima",
    catalogStatus: "Catálogo",
    catalogVerified: "Verificado",
    catalogUnverified: "No verificado",
    enabled: "Habilitado",
    disabled: "Deshabilitado",
    noCapabilities: "Sin capacidades declaradas.",
    noTools: "Sin herramientas permitidas.",
    systemPrompt: "Instrucción del sistema",
    catalogError: "No se pudo cargar el catálogo de agentes",
    agentDetailError: "No se pudo cargar el agente",
    emptyAgents: "Sin agentes disponibles",
    emptyAgentsDesc: "El catálogo de agentes todavía no se ha materializado en esta organización.",
    runLauncher: "Lanzar ejecución",
    runLauncherHint: "La tarea se ejecuta de forma síncrona y acotada. El resultado es asesor y queda auditado.",
    task: "Tarea",
    taskPlaceholder: "Describe el objetivo de análisis, el alcance y qué evidencia revisar…",
    taskTooShort: "La tarea debe tener al menos 5 caracteres.",
    incidentOptional: "Incidente (opcional)",
    noIncident: "Sin incidente",
    useLlm: "Usar síntesis LLM",
    useLlmHint: "Si no hay proveedor disponible, el agente devuelve un análisis determinista solo con evidencia.",
    launchRun: "Ejecutar agente",
    launching: "Ejecutando…",
    runStarted: "Ejecución {id} completada",
    runError: "No se pudo ejecutar el agente",
    chatTitle: "Chat fundamentado",
    chatHint: "Responde solo con evidencia recuperada de la base de conocimiento y cita cada documento.",
    chatPlaceholder: "Pregunta sobre evidencia, activos, alertas o conocimiento…",
    sendChat: "Enviar",
    sending: "Consultando…",
    chatEmpty: "Sin consultas todavía",
    chatEmptyDesc: "Formula una pregunta para recuperar evidencia citada de la base de conocimiento.",
    chatQuestion: "Pregunta",
    chatAnswer: "Respuesta",
    chatCitations: "Citas",
    chatNoEvidence: "Sin evidencia suficiente",
    chatNoEvidenceDesc: "La base de conocimiento no devolvió evidencia para esta pregunta. No se ha fabricado una respuesta.",
    chatError: "La consulta falló",
    chatModel: "Modelo",
    analysisMode: "Modo de análisis",
    model: "Modelo",
    noModel: "Sin modelo",
    aiUnavailable: "Modelo de IA no disponible",
    aiUnavailableDesc:
      "No hay proveedor/modelo saludable configurado. El agente no inventó una respuesta: muestra el modo determinista o el error real.",
    retryWithoutLlm: "Reintentar sin LLM",
    runsTitle: "Ejecuciones de agentes",
    runsSubtitle: "Historial con estado, modelo, modo de análisis y traza completa.",
    runFilterAgent: "Agente",
    allAgents: "Todos los agentes",
    runFilterStatus: "Estado",
    allStatuses: "Todos los estados",
    clearFilters: "Limpiar filtros",
    colRun: "Ejecución",
    colAgent: "Agente",
    colTask: "Tarea",
    colStatus: "Estado",
    colAutonomy: "Autonomía",
    colMode: "Modo",
    colModel: "Modelo",
    colStarted: "Inicio",
    colActions: "Acciones",
    view: "Ver",
    cancel: "Cancelar",
    cancelTitle: "Cancelar ejecución",
    cancelWarning: "Solo se pueden cancelar ejecuciones en cola. La cancelación queda auditada.",
    cancelConfirm: "Cancelar ejecución",
    canceled: "Ejecución cancelada",
    cancelError: "No se pudo cancelar la ejecución",
    colIncident: "Incidente",
    runDetailTitle: "Detalle de ejecución",
    summary: "Resumen",
    error: "Error",
    noError: "Sin error",
    toolCalls: "Llamadas a herramientas",
    citations: "Citas",
    sections: "Secciones estructuradas",
    noSection: "Sin contenido en esta sección.",
    noOutput: "La ejecución no produjo salida.",
    noCitations: "Sin citas verificadas.",
    viewKnowledge: "Abrir conocimiento",
    detailError: "No se pudo cargar la ejecución",
    emptyRuns: "Sin ejecuciones",
    emptyRunsDesc: "Lanza un agente para ver aquí su traza, herramientas y citas.",
    emptyRunsFilter: "Ninguna ejecución coincide con los filtros.",
    runsError: "No se pudieron cargar las ejecuciones",
    deterministic: "determinista",
    llmMode: "LLM",
    canceledMode: "cancelada",
    unavailableMode: "modelo no disponible",
    startedAt: "Inicio",
    finishedAt: "Fin",
    demo: "DEMO",
    unverified: "CATÁLOGO NO VERIFICADO",
    citationsCount: "{count} citas",
    toolCallsCount: "{count} herramientas",
    messages: "Mensajes",
    noMessages: "Sin mensajes registrados.",
    showTrace: "Ver traza",
    hideTrace: "Ocultar traza",
    context: "Contexto",
    evidence: "EVIDENCE",
    source: "SOURCE",
    fact: "FACT",
    analysis: "ANALYSIS",
    inference: "INFERENCE",
    hypothesis: "HYPOTHESIS",
    recommendation: "RECOMMENDATION",
    evidenceHint: "Evidencia recuperada",
    sourceHint: "Fuentes consultadas",
    factHint: "Hechos observados",
    analysisHint: "Análisis",
    inferenceHint: "Inferencias",
    hypothesisHint: "Hipótesis",
    recommendationHint: "Recomendaciones (requieren aprobación)",
    close: "Cerrar",
    totalRecords: "registros",
  },
  en: {
    eyebrow: "AI · Agent control",
    title: "AI agent control",
    subtitle: "Agent catalogue, bounded runs and grounded answers with citations.",
    observationTitle: "Observation only — no execution authority",
    observationBody:
      "A0/A1 agents analyse and recommend. They execute no defensive actions, modify no systems, and every recommendation requires human approval and policy re-evaluation.",
    refresh: "Refresh",
    permissionDenied: "You lack the ai:read permission to inspect the catalogue.",
    permissionUse: "You lack the ai:use permission to launch agents.",
    catalogue: "Agent catalogue",
    catalogueHint: "Select an agent to review its scope and launch a task.",
    selectedAgent: "Selected agent",
    capabilities: "Capabilities",
    allowedTools: "Allowed tools",
    maxAutonomy: "Maximum autonomy",
    catalogStatus: "Catalogue",
    catalogVerified: "Verified",
    catalogUnverified: "Unverified",
    enabled: "Enabled",
    disabled: "Disabled",
    noCapabilities: "No declared capabilities.",
    noTools: "No allowed tools.",
    systemPrompt: "System instruction",
    catalogError: "Could not load the agent catalogue",
    agentDetailError: "Could not load the agent",
    emptyAgents: "No agents available",
    emptyAgentsDesc: "The agent catalogue has not been materialized for this organization yet.",
    runLauncher: "Launch run",
    runLauncherHint: "The task runs synchronously and bounded. Output is advisory and audited.",
    task: "Task",
    taskPlaceholder: "Describe the analysis objective, scope and evidence to review…",
    taskTooShort: "The task must be at least 5 characters.",
    incidentOptional: "Incident (optional)",
    noIncident: "No incident",
    useLlm: "Use LLM synthesis",
    useLlmHint: "If no provider is available the agent returns a deterministic, evidence-only analysis.",
    launchRun: "Run agent",
    launching: "Running…",
    runStarted: "Run {id} completed",
    runError: "Could not run the agent",
    chatTitle: "Grounded chat",
    chatHint: "Answers only from retrieved knowledge-base evidence and cites every document.",
    chatPlaceholder: "Ask about evidence, assets, alerts or knowledge…",
    sendChat: "Send",
    sending: "Retrieving…",
    chatEmpty: "No queries yet",
    chatEmptyDesc: "Ask a question to retrieve cited evidence from the knowledge base.",
    chatQuestion: "Question",
    chatAnswer: "Answer",
    chatCitations: "Citations",
    chatNoEvidence: "Insufficient evidence",
    chatNoEvidenceDesc: "The knowledge base returned no evidence for this question. No answer was fabricated.",
    chatError: "Query failed",
    chatModel: "Model",
    analysisMode: "Analysis mode",
    model: "Model",
    noModel: "No model",
    aiUnavailable: "AI model unavailable",
    aiUnavailableDesc:
      "No healthy provider/model is configured. The agent did not invent an answer: it shows deterministic mode or the real error.",
    retryWithoutLlm: "Retry without LLM",
    runsTitle: "Agent runs",
    runsSubtitle: "History with status, model, analysis mode and full trace.",
    runFilterAgent: "Agent",
    allAgents: "All agents",
    runFilterStatus: "Status",
    allStatuses: "All statuses",
    clearFilters: "Clear filters",
    colRun: "Run",
    colAgent: "Agent",
    colTask: "Task",
    colStatus: "Status",
    colAutonomy: "Autonomy",
    colMode: "Mode",
    colModel: "Model",
    colStarted: "Started",
    colActions: "Actions",
    view: "View",
    cancel: "Cancel",
    cancelTitle: "Cancel run",
    cancelWarning: "Only queued runs can be canceled. Cancellation is audited.",
    cancelConfirm: "Cancel run",
    canceled: "Run canceled",
    cancelError: "Could not cancel the run",
    colIncident: "Incident",
    runDetailTitle: "Run detail",
    summary: "Summary",
    error: "Error",
    noError: "No error",
    toolCalls: "Tool calls",
    citations: "Citations",
    sections: "Structured sections",
    noSection: "No content in this section.",
    noOutput: "The run produced no output.",
    noCitations: "No verified citations.",
    viewKnowledge: "Open knowledge",
    detailError: "Could not load the run",
    emptyRuns: "No runs",
    emptyRunsDesc: "Launch an agent to see its trace, tools and citations here.",
    emptyRunsFilter: "No run matches the filters.",
    runsError: "Could not load runs",
    deterministic: "deterministic",
    llmMode: "LLM",
    canceledMode: "canceled",
    unavailableMode: "model unavailable",
    startedAt: "Started",
    finishedAt: "Finished",
    demo: "DEMO",
    unverified: "UNVERIFIED CATALOGUE",
    citationsCount: "{count} citations",
    toolCallsCount: "{count} tools",
    messages: "Messages",
    noMessages: "No messages recorded.",
    showTrace: "Show trace",
    hideTrace: "Hide trace",
    context: "Context",
    evidence: "EVIDENCE",
    source: "SOURCE",
    fact: "FACT",
    analysis: "ANALYSIS",
    inference: "INFERENCE",
    hypothesis: "HYPOTHESIS",
    recommendation: "RECOMMENDATION",
    evidenceHint: "Retrieved evidence",
    sourceHint: "Consulted sources",
    factHint: "Observed facts",
    analysisHint: "Analysis",
    inferenceHint: "Inferences",
    hypothesisHint: "Hypotheses",
    recommendationHint: "Recommendations (require approval)",
    close: "Close",
    totalRecords: "records",
  },
};

/* ---------------------------------------------------------------- helpers */

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function outputSections(output: Record<string, unknown>): Record<string, string[]> {
  const sections = output.sections;
  if (!sections || typeof sections !== "object" || Array.isArray(sections)) return {};
  const record = sections as Record<string, unknown>;
  const result: Record<string, string[]> = {};
  for (const key of SECTION_KEYS) result[key] = asStringArray(record[key]);
  return result;
}

function citationTitle(citation: Record<string, unknown>): string {
  const title = citation.title ?? citation.document_title ?? citation.document_id ?? "source";
  return String(title);
}

function citationDocumentId(citation: Record<string, unknown>): string | null {
  const value = citation.document_id ?? citation.documentId;
  return typeof value === "string" ? value : null;
}

function analysisModeOf(output: Record<string, unknown>, error: string | null): string {
  const mode = output.analysis_mode;
  if (typeof mode === "string") return mode;
  if (error && /ai_unavailable|No configured, healthy AI/i.test(error)) return "ai_unavailable";
  return "unknown";
}

function isAiUnavailable(error: unknown): boolean {
  return isApiError(error) && error.code === "ai_unavailable";
}

function unavailableFromRun(run: AgentRun): boolean {
  return (
    /ai_unavailable|No configured, healthy AI|providers were unavailable/i.test(run.error ?? "") ||
    analysisModeOf(run.output, run.error) === "ai_unavailable"
  );
}

/* ------------------------------------------------------------- run detail */

function RunDetailModal({ runId, onClose }: { runId: string | null; onClose: () => void }) {
  const c = usePageCopy(COPY);
  const { t, lang } = useI18n();
  const [traceOpen, setTraceOpen] = useState(false);
  const query = useQuery({
    queryKey: ["agents", "runs", "detail", runId],
    queryFn: () => api.get<AgentRunDetail>(`/agents/runs/${runId}`),
    enabled: Boolean(runId),
  });

  useEffect(() => {
    if (runId) setTraceOpen(false);
  }, [runId]);

  return (
    <Modal
      open={runId !== null}
      onClose={onClose}
      title={c("runDetailTitle")}
      size="lg"
      footer={<Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>}
    >
      <div data-testid="run-detail-modal">
        {query.isLoading ? (
          <div className="stack"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
        ) : query.isError || !query.data ? (
          <ErrorBanner compact message={`${c("detailError")}: ${errorMessage(query.error)}`} onRetry={() => void query.refetch()} />
        ) : (
          <div className="stack">
            <div className="notice notice-warning" style={{ fontSize: 11 }} data-testid="run-observation-banner">
              <ShieldAlert size={13} style={{ flex: "0 0 auto" }} />
              <span><strong>{c("observationTitle")}</strong> — {c("observationBody")}</span>
            </div>

            <div className="row wrap" style={{ gap: 6 }}>
              <span className="mono" style={{ fontSize: 10.5, color: "var(--accent)" }}>{query.data.id.slice(0, 8)}</span>
              <Badge tone="neutral">{query.data.agent_code}</Badge>
              <StatusBadge status={query.data.status} />
              <Badge tone="accent">{query.data.autonomy_level}</Badge>
              <Badge tone={analysisModeOf(query.data.output, query.data.error) === "llm" ? "accent" : "neutral"}>
                {analysisModeOf(query.data.output, query.data.error)}
              </Badge>
              {unavailableFromRun(query.data) ? <Badge tone="warning">{c("unavailableMode")}</Badge> : null}
              {query.data.output.is_demo === true ? <Badge tone="amber">{c("demo")}</Badge> : null}
            </div>

            {unavailableFromRun(query.data) ? (
              <div className="notice notice-warning" style={{ fontSize: 11 }}>
                <BrainCircuit size={13} style={{ flex: "0 0 auto" }} />
                <span><strong>{c("aiUnavailable")}</strong> — {c("aiUnavailableDesc")}</span>
              </div>
            ) : null}

            <div>
              <div className="section-label">{c("task")}</div>
              <div style={{ fontSize: 12.5, color: "var(--text-secondary)", whiteSpace: "pre-wrap" }}>{query.data.task}</div>
            </div>

            <div className="metric-list">
              <div className="metric-row"><span className="metric-label">{c("startedAt")}</span><span className="metric-value">{formatDateTime(query.data.started_at, lang)}</span></div>
              <div className="metric-row"><span className="metric-label">{c("finishedAt")}</span><span className="metric-value">{query.data.finished_at ? formatDateTime(query.data.finished_at, lang) : "—"}</span></div>
              <div className="metric-row"><span className="metric-label">{c("model")}</span><span className="metric-value">{typeof query.data.output.model === "string" ? query.data.output.model : c("noModel")}</span></div>
              <div className="metric-row"><span className="metric-label">{c("toolCalls")}</span><span className="metric-value">{formatNumber(query.data.tool_calls)}</span></div>
              <div className="metric-row"><span className="metric-label">{c("citations")}</span><span className="metric-value">{formatNumber(query.data.citations.length)}</span></div>
              {query.data.incident_id ? (
                <div className="metric-row"><span className="metric-label">{c("colIncident")}</span><span className="metric-value"><Link to={`/incidents/${query.data.incident_id}`}>{query.data.incident_id.slice(0, 8)}</Link></span></div>
              ) : null}
            </div>

            {query.data.error ? <ErrorBanner compact title={c("error")} message={query.data.error} /> : null}

            <div>
              <div className="section-label">{c("summary")}</div>
              <p style={{ fontSize: 12.5, color: "var(--text-secondary)", whiteSpace: "pre-wrap" }}>
                {typeof query.data.output.summary === "string" ? query.data.output.summary : c("noOutput")}
              </p>
            </div>

            <div>
              <div className="section-label">{c("sections")}</div>
              <div className="stack">
                {SECTION_KEYS.map((key) => {
                  const values = outputSections(query.data.output)[key] ?? [];
                  return (
                    <div key={key} className="card card-pad" data-testid={`run-section-${key}`}>
                      <div className="row-between" style={{ marginBottom: 6 }}>
                        <span className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--accent)" }}>{c(key)}</span>
                        <span className="dim" style={{ fontSize: 10 }}>{c(`${key}Hint`)}</span>
                      </div>
                      {values.length ? (
                        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, color: "var(--text-secondary)" }}>
                          {values.map((value, index) => <li key={`${key}-${index}`} style={{ marginBottom: 4 }}>{value}</li>)}
                        </ul>
                      ) : (
                        <span className="dim" style={{ fontSize: 11 }}>{c("noSection")}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="section-label">{c("citations")}</div>
              {query.data.citations.length ? (
                <div className="chip-row" data-testid="run-citations">
                  {query.data.citations.map((citation, index) => {
                    const documentId = citationDocumentId(citation);
                    const label = citationTitle(citation);
                    const chunk = typeof citation.chunk_id === "string" ? citation.chunk_id : null;
                    return documentId ? (
                      <Link key={`${documentId}-${index}`} to={`/admin?knowledge=${encodeURIComponent(documentId)}`} className="tag" style={{ textDecoration: "none" }}>
                        <Link2 size={10} /> {label}{chunk ? ` #${chunk.slice(0, 8)}` : ""}
                      </Link>
                    ) : (
                      <span className="tag" key={index}>{label}</span>
                    );
                  })}
                </div>
              ) : (
                <span className="dim" style={{ fontSize: 11 }}>{c("noCitations")}</span>
              )}
            </div>

            <div>
              <div className="row-between">
                <div className="section-label" style={{ margin: 0 }}>{c("toolCalls")} / {c("messages")}</div>
                <Button size="sm" variant="ghost" icon={Terminal} onClick={() => setTraceOpen((value) => !value)}>
                  {traceOpen ? c("hideTrace") : c("showTrace")}
                </Button>
              </div>
              {traceOpen ? (
                <div className="stack" style={{ marginTop: 8 }} data-testid="run-trace">
                  {query.data.tools.length ? (
                    query.data.tools.map((tool) => (
                      <div className="card card-pad" key={tool.id}>
                        <div className="row-between" style={{ gap: 8, marginBottom: 4 }}>
                          <span className="row" style={{ gap: 6 }}>
                            <Wrench size={12} style={{ color: "var(--accent)" }} />
                            <span className="mono" style={{ fontSize: 11 }}>{tool.tool_name ?? "tool"}</span>
                          </span>
                          <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{formatDateTime(tool.created_at, lang)}</span>
                        </div>
                        <details>
                          <summary className="dim" style={{ fontSize: 10.5, cursor: "pointer" }}>input / output</summary>
                          <div className="section-label" style={{ marginTop: 6 }}>input</div>
                          <pre className="code-block">{JSON.stringify(tool.tool_input, null, 2)}</pre>
                          <div className="section-label" style={{ marginTop: 6 }}>output</div>
                          <pre className="code-block">{JSON.stringify(tool.tool_output, null, 2)}</pre>
                        </details>
                      </div>
                    ))
                  ) : (
                    <span className="dim" style={{ fontSize: 11 }}>—</span>
                  )}
                  {query.data.messages.length ? (
                    query.data.messages.map((message) => (
                      <div className="metric-row" key={message.id} style={{ display: "block" }}>
                        <div className="row-between" style={{ marginBottom: 2 }}>
                          <Badge tone={message.role === "assistant" ? "accent" : message.role === "tool" ? "neutral" : "warning"}>{message.role}</Badge>
                          <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{formatDateTime(message.created_at, lang)}</span>
                        </div>
                        <div style={{ fontSize: 11.5, color: "var(--text-secondary)", whiteSpace: "pre-wrap", maxHeight: 180, overflow: "auto" }}>{message.content}</div>
                      </div>
                    ))
                  ) : (
                    <span className="dim" style={{ fontSize: 11 }}>{c("noMessages")}</span>
                  )}
                </div>
              ) : null}
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------- page */

export function AgentsPage() {
  const c = usePageCopy(COPY);
  const { t, lang } = useI18n();
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();

  const [selectedCode, setSelectedCode] = useState<string | null>(null);
  const [task, setTask] = useState("");
  const [incidentId, setIncidentId] = useState("");
  const [useLlm, setUseLlm] = useState(true);
  const [runsPage, setRunsPage] = useState(1);
  const [runsAgent, setRunsAgent] = useState("");
  const [runsStatus, setRunsStatus] = useState("");
  const [runDetailId, setRunDetailId] = useState<string | null>(null);
  const [cancelTarget, setCancelTarget] = useState<AgentRun | null>(null);
  const [chatInput, setChatInput] = useState("");
  const [chatHistory, setChatHistory] = useState<ChatEntry[]>([]);
  const [chatError, setChatError] = useState<string | null>(null);

  const canUse = can("ai:use");

  const catalogue = useQuery({
    queryKey: ["agents", "catalogue"],
    queryFn: () => api.get<Agent[]>("/agents"),
    enabled: can("ai:read"),
  });

  useEffect(() => {
    if (!selectedCode && catalogue.data?.length) {
      const firstEnabled = catalogue.data.find((agent) => agent.enabled) ?? catalogue.data[0];
      setSelectedCode(firstEnabled.code);
    }
  }, [catalogue.data, selectedCode]);

  const agentDetail = useQuery({
    queryKey: ["agents", "detail", selectedCode],
    queryFn: () => api.get<Agent>(`/agents/${selectedCode}`),
    enabled: Boolean(selectedCode) && can("ai:read"),
  });

  const selectedAgent = agentDetail.data ?? catalogue.data?.find((agent) => agent.code === selectedCode) ?? null;

  const incidents = useQuery({
    queryKey: ["incidents", "agents-picker"],
    queryFn: () => api.get<Page<IncidentOption>>("/incidents", { page_size: 100, sort: "detected_at", order: "desc" }),
    enabled: can("incident:read"),
    staleTime: 60_000,
  });

  const runs = useQuery({
    queryKey: ["agents", "runs", { runsPage, runsAgent, runsStatus }],
    queryFn: () =>
      api.get<Page<AgentRun>>("/agents/runs", {
        page: runsPage,
        page_size: 25,
        agent_code: runsAgent || undefined,
        status: runsStatus || undefined,
      }),
    enabled: can("ai:read"),
  });

  const runMutation = useMutation({
    mutationFn: () => {
      if (!selectedCode) throw new Error(c("selectedAgent"));
      if (task.trim().length < 5) throw new Error(c("taskTooShort"));
      return api.post<AgentRunDetail>(`/agents/${selectedCode}/runs`, {
        task: task.trim(),
        incident_id: incidentId || undefined,
        use_llm: useLlm,
        context: {},
      });
    },
    onSuccess: (run) => {
      push(c("runStarted").replace("{id}", run.id.slice(0, 8)), "success");
      setTask("");
      setRunDetailId(run.id);
      void queryClient.invalidateQueries({ queryKey: ["agents", "runs"] });
    },
    onError: (error) => push(`${c("runError")}: ${errorMessage(error)}`, "error"),
  });

  const cancelMutation = useMutation({
    mutationFn: (run: AgentRun) => api.post<AgentRun>(`/agents/runs/${run.id}/cancel`),
    onSuccess: () => {
      push(c("canceled"), "success");
      setCancelTarget(null);
      void queryClient.invalidateQueries({ queryKey: ["agents", "runs"] });
    },
    onError: (error) => push(`${c("cancelError")}: ${errorMessage(error)}`, "error"),
  });

  const chatMutation = useMutation({
    mutationFn: (variables: { message: string; useLlm: boolean }) =>
      api.post<AgentChatResponse>("/agents/chat", {
        message: variables.message,
        top_k: 5,
        use_llm: variables.useLlm,
      }),
    onSuccess: (response, variables) => {
      setChatHistory((current) => [
        ...current,
        { id: `${Date.now()}-${current.length}`, question: variables.message, response },
      ]);
      setChatInput("");
      setChatError(null);
    },
    onError: (error) => {
      if (isAiUnavailable(error)) setChatError(`${c("aiUnavailable")}: ${errorMessage(error)}`);
      else setChatError(`${c("chatError")}: ${errorMessage(error)}`);
    },
  });

  const submitChat = (forceWithoutLlm = false) => {
    const message = chatInput.trim();
    if (message.length < 2) return;
    chatMutation.mutate({ message, useLlm: forceWithoutLlm ? false : useLlm });
  };

  const agentColumns = useMemo(
    () => [
      {
        key: "run",
        header: c("colRun"),
        render: (row: AgentRun) => (
          <div>
            <span className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{row.id.slice(0, 8)}</span>
            <div className="cell-sub">{row.agent_code}</div>
          </div>
        ),
      },
      {
        key: "task",
        header: c("colTask"),
        render: (row: AgentRun) => (
          <div style={{ minWidth: 230 }}>
            <div className="primary-cell" style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 340 }}>{row.task}</span>
              {row.output.is_demo === true ? <Badge tone="amber">{c("demo")}</Badge> : null}
            </div>
            <div className="cell-sub">{row.incident_id ? `${c("colIncident")}: ${row.incident_id.slice(0, 8)}` : "—"}</div>
          </div>
        ),
      },
      { id: "status", header: c("colStatus"), width: "110px", render: (row: AgentRun) => <StatusBadge status={row.status} /> },
      { id: "autonomy", header: c("colAutonomy"), width: "100px", render: (row: AgentRun) => <Badge tone="neutral">{row.autonomy_level}</Badge> },
      {
        key: "mode",
        header: c("colMode"),
        width: "124px",
        render: (row: AgentRun) => {
          const mode = analysisModeOf(row.output, row.error);
          return <Badge tone={mode === "llm" ? "accent" : mode === "ai_unavailable" ? "warning" : "neutral"}>{mode}</Badge>;
        },
      },
      {
        key: "model",
        header: c("colModel"),
        width: "128px",
        render: (row: AgentRun) => (
          <span className="mono" style={{ fontSize: 10 }}>{typeof row.output.model === "string" ? row.output.model : c("noModel")}</span>
        ),
      },
      {
        key: "started",
        header: c("colStarted"),
        width: "124px",
        render: (row: AgentRun) => <span className="mono" style={{ fontSize: 10.5 }}>{relativeTime(row.started_at, lang)}</span>,
      },
      {
        key: "actions",
        header: c("colActions"),
        width: "150px",
        align: "right" as const,
        render: (row: AgentRun) => (
          <div className="row" style={{ gap: 4, justifyContent: "flex-end" }}>
            <Button size="sm" variant="ghost" icon={FileSearch} onClick={() => setRunDetailId(row.id)}>{c("view")}</Button>
            {canUse && row.status === "queued" ? (
              <Button size="sm" variant="ghost" icon={Square} onClick={() => setCancelTarget(row)}>{c("cancel")}</Button>
            ) : null}
          </div>
        ),
      },
    ],
    [c, canUse, lang],
  );

  const availableModes = useMemo(() => {
    const modes = new Set<string>();
    for (const run of runs.data?.items ?? []) modes.add(analysisModeOf(run.output, run.error));
    return [...modes];
  }, [runs.data]);

  if (can("ai:read") && catalogue.isLoading) {
    return (
      <div data-testid="page-agents">
        <PageSkeleton />
      </div>
    );
  }

  return (
    <div className="animate-in" data-testid="page-agents">
      <PageHeader
        eyebrow={c("eyebrow")}
        title={c("title")}
        subtitle={c("subtitle")}
        actions={
          <>
            <Button icon={RefreshCw} onClick={() => { void catalogue.refetch(); void runs.refetch(); }} aria-label={c("refresh")} data-testid="refresh-agents" />
          </>
        }
      />

      <div className="notice notice-warning" style={{ marginBottom: 12, fontSize: 11 }} data-testid="observation-banner">
        <ShieldAlert size={14} style={{ flex: "0 0 auto" }} />
        <span><strong>{c("observationTitle")}</strong> — {c("observationBody")}</span>
      </div>

      {!can("ai:read") ? (
        <Card><EmptyState icon={ShieldAlert} title={c("permissionDenied")} /></Card>
      ) : catalogue.isError ? (
        <ErrorBanner title={c("catalogError")} message={errorMessage(catalogue.error)} onRetry={() => void catalogue.refetch()} />
      ) : !catalogue.data?.length ? (
        <Card>
          <EmptyState icon={Bot} title={c("emptyAgents")} description={c("emptyAgentsDesc")} />
        </Card>
      ) : (
        <>
          <div className="split-main" style={{ alignItems: "flex-start", marginBottom: 12 }}>
            <Card title={c("catalogue")} subtitle={c("catalogueHint")} bodyClassName="">
              <div style={{ maxHeight: 560, overflowY: "auto" }} data-testid="agents-catalog">
                {catalogue.data.map((agent) => {
                  const active = agent.code === selectedCode;
                  return (
                    <button
                      key={agent.id}
                      type="button"
                      onClick={() => setSelectedCode(agent.code)}
                      className="list-item"
                      style={{
                        width: "100%",
                        border: 0,
                        borderLeft: active ? "2px solid var(--accent)" : "2px solid transparent",
                        background: active ? "var(--accent-soft)" : "transparent",
                        textAlign: "left",
                        cursor: "pointer",
                        padding: "10px 12px",
                      }}
                      data-testid={`agent-card-${agent.code}`}
                    >
                      <span style={{ minWidth: 0, flex: 1 }}>
                        <span className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                          <span className="item-title">{agent.name}</span>
                          <Badge tone="neutral">{agent.code}</Badge>
                          {agent.is_demo ? <Badge tone="amber">{c("demo")}</Badge> : null}
                          {!agent.catalog_available ? <Badge tone="warning">{c("unverified")}</Badge> : null}
                        </span>
                        <span className="item-sub" style={{ display: "block", marginTop: 2 }}>{agent.description ?? "—"}</span>
                        <span className="chip-row" style={{ marginTop: 5 }}>
                          {agent.capabilities.slice(0, 3).map((capability) => <span className="tag" key={capability}>{capability}</span>)}
                          {agent.capabilities.length > 3 ? <span className="tag">+{agent.capabilities.length - 3}</span> : null}
                        </span>
                      </span>
                      <span className="item-side">
                        <Badge tone={agent.max_autonomy === "A2" ? "warning" : "accent"}>{agent.max_autonomy}</Badge>
                        <div style={{ marginTop: 4 }}>
                          <Badge tone={agent.enabled ? "success" : "neutral"}>{agent.enabled ? c("enabled") : c("disabled")}</Badge>
                        </div>
                        <ChevronRight size={14} style={{ marginTop: 6, color: "var(--dim)" }} />
                      </span>
                    </button>
                  );
                })}
              </div>
            </Card>

            <div className="stack">
              <Card
                title={c("selectedAgent")}
                actions={selectedAgent ? <Badge tone="accent">{selectedAgent.code}</Badge> : null}
              >
                {agentDetail.isLoading && selectedAgent === null ? (
                  <div className="stack"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
                ) : agentDetail.isError ? (
                  <ErrorBanner compact message={c("agentDetailError")} onRetry={() => void agentDetail.refetch()} />
                ) : selectedAgent ? (
                  <div className="stack" data-testid="agent-detail">
                    <div>
                      <div className="row wrap" style={{ gap: 6, marginBottom: 4 }}>
                        <strong style={{ fontSize: 13 }}>{selectedAgent.name}</strong>
                        <Badge tone={selectedAgent.enabled ? "success" : "neutral"}>{selectedAgent.enabled ? c("enabled") : c("disabled")}</Badge>
                        <Badge tone={selectedAgent.catalog_available ? "success" : "warning"}>
                          {selectedAgent.catalog_available ? c("catalogVerified") : c("catalogUnverified")}
                        </Badge>
                      </div>
                      <p style={{ fontSize: 11.5, color: "var(--muted)" }}>{selectedAgent.description ?? "—"}</p>
                    </div>
                    <div>
                      <div className="section-label">{c("capabilities")}</div>
                      <div className="chip-row">
                        {selectedAgent.capabilities.length
                          ? selectedAgent.capabilities.map((capability) => <span className="tag" key={capability}>{capability}</span>)
                          : <span className="dim" style={{ fontSize: 11 }}>{c("noCapabilities")}</span>}
                      </div>
                    </div>
                    <div>
                      <div className="section-label">{c("allowedTools")}</div>
                      <div className="chip-row">
                        {selectedAgent.allowed_tools.length
                          ? selectedAgent.allowed_tools.map((tool) => <span className="tag" key={tool}><Wrench size={9} /> {tool}</span>)
                          : <span className="dim" style={{ fontSize: 11 }}>{c("noTools")}</span>}
                      </div>
                    </div>
                    <div className="metric-list">
                      <div className="metric-row"><span className="metric-label">{c("maxAutonomy")}</span><span className="metric-value">{selectedAgent.max_autonomy}</span></div>
                      <div className="metric-row"><span className="metric-label">{c("catalogStatus")}</span><span className="metric-value">{selectedAgent.catalog_available ? c("catalogVerified") : c("catalogUnverified")}</span></div>
                    </div>
                    {selectedAgent.system_prompt ? (
                      <details>
                        <summary className="dim" style={{ fontSize: 10.5, cursor: "pointer" }}>{c("systemPrompt")}</summary>
                        <pre className="code-block" style={{ marginTop: 6, maxHeight: 160 }}>{selectedAgent.system_prompt}</pre>
                      </details>
                    ) : null}
                  </div>
                ) : null}
              </Card>

              <Card title={c("runLauncher")} subtitle={c("runLauncherHint")}>
                <Field label={c("task")} required htmlFor="agent-task">
                  <Textarea
                    id="agent-task"
                    value={task}
                    onChange={(event) => setTask(event.target.value)}
                    rows={4}
                    maxLength={4000}
                    placeholder={c("taskPlaceholder")}
                    data-testid="agent-task-input"
                  />
                </Field>
                <div className="form-grid" style={{ marginTop: 8 }}>
                  <Field label={c("incidentOptional")} htmlFor="agent-incident">
                    <Select id="agent-incident" value={incidentId} onChange={(event) => setIncidentId(event.target.value)}>
                      <option value="">{c("noIncident")}</option>
                      {incidents.data?.items.map((incident) => (
                        <option key={incident.id} value={incident.id}>{incident.ref} · {incident.title}</option>
                      ))}
                    </Select>
                  </Field>
                  <div className="field">
                    <label className="checkbox" style={{ marginTop: 24 }}>
                      <input type="checkbox" checked={useLlm} onChange={(event) => setUseLlm(event.target.checked)} />
                      {c("useLlm")}
                    </label>
                    <span className="hint">{c("useLlmHint")}</span>
                  </div>
                </div>
                {incidents.isError ? <ErrorBanner compact message={errorMessage(incidents.error)} /> : null}
                <div className="row-between" style={{ marginTop: 8 }}>
                  <span className="dim" style={{ fontSize: 10.5 }}>{task.length}/4000</span>
                  <Button
                    variant="primary"
                    icon={Play}
                    loading={runMutation.isPending}
                    disabled={!canUse || task.trim().length < 5 || !selectedCode}
                    onClick={() => runMutation.mutate()}
                    data-testid="submit-agent-run"
                  >
                    {runMutation.isPending ? c("launching") : c("launchRun")}
                  </Button>
                </div>
                {!canUse ? <p className="hint">{c("permissionUse")}</p> : null}
              </Card>
            </div>
          </div>

          <Card title={c("chatTitle")} subtitle={c("chatHint")} bodyClassName="">
            <div style={{ padding: 14 }} data-testid="chat-panel">
              <div className="stack" style={{ maxHeight: 420, overflowY: "auto", marginBottom: 10 }}>
                {chatHistory.length === 0 ? (
                  <EmptyState icon={MessageSquare} title={c("chatEmpty")} description={c("chatEmptyDesc")} />
                ) : (
                  chatHistory.map((entry) => (
                    <div className="card card-pad" key={entry.id}>
                      <div className="section-label">{c("chatQuestion")}</div>
                      <p style={{ fontSize: 12.5, color: "var(--text)" }}>{entry.question}</p>
                      <div className="divider" />
                      {entry.response.analysis_mode === "no_evidence" ? (
                        <div className="notice notice-warning" style={{ fontSize: 11 }} data-testid="chat-no-evidence">
                          <CircleSlash size={13} style={{ flex: "0 0 auto" }} />
                          <span><strong>{c("chatNoEvidence")}</strong> — {c("chatNoEvidenceDesc")}</span>
                        </div>
                      ) : (
                        <p style={{ fontSize: 12.5, color: "var(--text-secondary)", whiteSpace: "pre-wrap" }}>{entry.response.answer}</p>
                      )}
                      <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
                        <Badge tone={entry.response.analysis_mode === "llm" ? "accent" : "neutral"}>
                          {entry.response.analysis_mode}
                        </Badge>
                        <Badge tone="neutral">{entry.response.model ?? c("noModel")}</Badge>
                        <Badge tone="neutral">{c("chatCitations")}: {entry.response.citations.length}</Badge>
                      </div>
                      {entry.response.citations.length ? (
                        <div className="chip-row" style={{ marginTop: 8 }}>
                          {entry.response.citations.map((citation, index) => {
                            const documentId = citationDocumentId(citation);
                            const label = citationTitle(citation);
                            return documentId ? (
                              <Link key={`${documentId}-${index}`} to={`/admin?knowledge=${encodeURIComponent(documentId)}`} className="tag" style={{ textDecoration: "none" }}>
                                <Link2 size={10} /> {label}
                              </Link>
                            ) : (
                              <span className="tag" key={index}>{label}</span>
                            );
                          })}
                        </div>
                      ) : null}
                    </div>
                  ))
                )}
              </div>
              {chatError ? (
                <div style={{ marginBottom: 8 }}>
                  <ErrorBanner compact message={chatError} />
                  {chatMutation.isError && isAiUnavailable(chatMutation.error) ? (
                    <div style={{ marginTop: 6 }}>
                      <Button size="sm" icon={BrainCircuit} onClick={() => submitChat(true)} disabled={chatInput.trim().length < 2}>
                        {c("retryWithoutLlm")}
                      </Button>
                    </div>
                  ) : null}
                </div>
              ) : null}
              <div className="row" style={{ gap: 8, alignItems: "flex-end" }}>
                <div style={{ flex: 1 }}>
                  <Field label={c("chatPlaceholder")} htmlFor="chat-input">
                    <Input
                      id="chat-input"
                      value={chatInput}
                      onChange={(event) => setChatInput(event.target.value)}
                      placeholder={c("chatPlaceholder")}
                      maxLength={4000}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" && !event.shiftKey) {
                          event.preventDefault();
                          submitChat();
                        }
                      }}
                      data-testid="chat-input"
                    />
                  </Field>
                </div>
                <Button
                  variant="primary"
                  icon={Send}
                  loading={chatMutation.isPending}
                  disabled={!canUse || chatInput.trim().length < 2}
                  onClick={() => submitChat()}
                  data-testid="send-chat"
                >
                  {chatMutation.isPending ? c("sending") : c("sendChat")}
                </Button>
              </div>
              <label className="checkbox" style={{ marginTop: 8 }}>
                <input type="checkbox" checked={useLlm} onChange={(event) => setUseLlm(event.target.checked)} />
                {c("useLlm")}
              </label>
            </div>
          </Card>

          <Card
            title={c("runsTitle")}
            subtitle={c("runsSubtitle")}
            bodyClassName=""
            footer={<Pagination meta={runs.data?.meta} onPage={setRunsPage} />}
          >
            <div className="filters-bar" data-testid="agents-runs-filters">
              <Select aria-label={c("runFilterAgent")} value={runsAgent} onChange={(event) => { setRunsAgent(event.target.value); setRunsPage(1); }}>
                <option value="">{c("allAgents")}</option>
                {catalogue.data?.map((agent) => <option key={agent.code} value={agent.code}>{agent.code}</option>)}
              </Select>
              <Select aria-label={c("runFilterStatus")} value={runsStatus} onChange={(event) => { setRunsStatus(event.target.value); setRunsPage(1); }}>
                <option value="">{c("allStatuses")}</option>
                {["queued", "running", "completed", "failed", "canceled"].map((value) => <option key={value} value={value}>{value}</option>)}
              </Select>
              {runsAgent || runsStatus ? (
                <Button size="sm" variant="ghost" icon={X} onClick={() => { setRunsAgent(""); setRunsStatus(""); setRunsPage(1); }}>
                  {c("clearFilters")}
                </Button>
              ) : null}
              <Badge tone="neutral">{formatNumber(runs.data?.meta.total ?? 0)} {c("totalRecords")}</Badge>
              {availableModes.length ? (
                <span className="chip-row" style={{ marginLeft: "auto" }}>
                  {availableModes.map((mode) => <span className="tag" key={mode}>{mode}</span>)}
                </span>
              ) : null}
            </div>
            {runs.isError ? (
              <div style={{ padding: 12 }}><ErrorBanner compact message={c("runsError")} onRetry={() => void runs.refetch()} /></div>
            ) : null}
            <div data-testid="agents-runs-table">
              <DataTable
                columns={agentColumns as Column<AgentRun>[]}
                rows={runs.data?.items}
                rowKey={(row) => row.id}
                loading={runs.isLoading}
                empty={
                  <EmptyState
                    icon={Bot}
                    title={runsAgent || runsStatus ? c("emptyRunsFilter") : c("emptyRuns")}
                    description={c("emptyRunsDesc")}
                    action={
                      runsAgent || runsStatus ? (
                        <Button size="sm" onClick={() => { setRunsAgent(""); setRunsStatus(""); }}>{c("clearFilters")}</Button>
                      ) : undefined
                    }
                  />
                }
              />
            </div>
          </Card>
        </>
      )}

      <RunDetailModal runId={runDetailId} onClose={() => setRunDetailId(null)} />

      <Modal
        open={cancelTarget !== null}
        onClose={() => setCancelTarget(null)}
        title={c("cancelTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCancelTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" icon={Square} loading={cancelMutation.isPending} onClick={() => cancelTarget && cancelMutation.mutate(cancelTarget)} data-testid="confirm-cancel-run">
              {c("cancelConfirm")}
            </Button>
          </>
        }
      >
        <div data-testid="cancel-run-modal">
          <div className="notice notice-warning" style={{ fontSize: 11 }}>
            <AlertTriangle size={13} style={{ flex: "0 0 auto" }} />
            <span>{c("cancelWarning")}</span>
          </div>
          {cancelTarget ? (
            <div className="metric-list" style={{ marginTop: 10 }}>
              <div className="metric-row"><span className="metric-label">{c("colRun")}</span><span className="metric-value">{cancelTarget.id.slice(0, 8)}</span></div>
              <div className="metric-row"><span className="metric-label">{c("colAgent")}</span><span className="metric-value">{cancelTarget.agent_code}</span></div>
              <div className="metric-row"><span className="metric-label">{c("colTask")}</span><span className="metric-value" style={{ fontSize: 10 }}>{cancelTarget.task.slice(0, 80)}</span></div>
            </div>
          ) : null}
        </div>
      </Modal>

      <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
        <Sparkles size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
        <span>
          {c("observationTitle")} · {c("chatTitle")} · {formatDateTime(new Date().toISOString(), lang)}
        </span>
        <span className="row" style={{ marginLeft: "auto", gap: 6 }}>
          <CheckCircle2 size={11} style={{ color: "var(--success)" }} /> {c("catalogue")}: {formatNumber(catalogue.data?.length ?? 0)}
        </span>
      </div>
    </div>
  );
}

export default AgentsPage;
