import { useId, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Beaker,
  BookText,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  Download,
  FlaskConical,
  Gauge,
  HardDrive,
  KeyRound,
  Layers,
  Lock,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Trash2,
  XCircle,
} from "lucide-react";
import { api, errorMessage, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy, type Lang } from "../lib/i18n";
import { formatDateTime, formatNumber, formatPercent, humanize, relativeTime } from "../lib/format";
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
  SearchInput,
  Select,
  StatusBadge,
  StatusDot,
  Tabs,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";
import {
  ConfirmDialog,
  JsonEditor,
  MetaRows,
  PreBlock,
  apiFieldErrors,
  parseJsonRecord,
  splitTags,
} from "../components/features/govern/common";

/* --------------------------------------------------------------- contracts */

type TabKey = "providers" | "models" | "knowledge" | "usage";
type ProviderKind = "ollama" | "vllm" | "llamacpp" | "openai_compatible";
type ModelStatus = "available" | "disabled" | "deprecated";
type KnowledgeKind = "runbook" | "playbook" | "policy" | "sop" | "reference" | "other";

interface AIProvider {
  id: string;
  org_id: string | null;
  name: string;
  kind: string;
  base_url: string;
  default_model: string | null;
  is_local: boolean;
  enabled: boolean;
  health_status: string;
  last_health_at: string | null;
  last_health_error: string | null;
  config: Record<string, unknown>;
  has_api_key: boolean;
  created_at: string;
  updated_at: string;
}

interface ProviderHealthResult {
  provider_id: string;
  healthy: boolean;
  health_status: string;
  error: string | null;
  detail: Record<string, unknown>;
  checked_at: string;
}

interface AIModel {
  id: string;
  provider_id: string;
  provider_name: string | null;
  name: string;
  display_name: string | null;
  task_tags: string[];
  context_window: number;
  max_output_tokens: number;
  status: string;
  evaluation: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface ModelDiscoverResult {
  provider_id: string;
  provider_name: string;
  discovered: number;
  created: number;
  updated: number;
  models: AIModel[];
}

interface HealthProviderEntry {
  id: string;
  name: string;
  kind: string;
  enabled: boolean;
  health_status: string;
  last_health_at: string | null;
  last_health_error: string | null;
}

interface AIHealth {
  status: string;
  ai_available: boolean;
  generated_at: string;
  providers_total: number;
  providers_enabled: number;
  providers_healthy: number;
  available: boolean;
  providers: HealthProviderEntry[];
  models: Record<string, number>;
  knowledge: { documents: number; chunks: number };
  invocations_24h: { total: number; by_status: Record<string, number>; error_rate: number };
}

interface EvaluationCaseResult {
  name: string;
  passed: boolean;
  status: string;
  checks?: Record<string, boolean>;
  error?: string;
  model?: string;
  latency_ms?: number;
  parse_error?: string | null;
  output_excerpt?: string;
}

interface EvaluationSummary {
  model_id: string;
  model: string;
  provider_id: string;
  provider: string;
  evaluated_at: string;
  total: number;
  passed: number;
  failed: number;
  score: number;
  rubric: string[];
  results: EvaluationCaseResult[];
}

interface KnowledgeDocument {
  id: string;
  org_id: string;
  title: string;
  source: string;
  kind: string;
  version: string;
  checksum: string;
  metadata: Record<string, unknown>;
  chunk_count: number;
  created_at: string;
  updated_at: string;
}

interface KnowledgeChunk {
  id: string;
  ordinal: number;
  text: string;
  tokens: number;
  embedding_model: string;
  embedding_dimension: number;
}

interface KnowledgeDocumentDetail extends KnowledgeDocument {
  text: string;
  chunks: KnowledgeChunk[];
}

interface KnowledgeCitation {
  document_id: string;
  title: string;
  source: string;
  chunk_id: string;
  snippet: string;
  score: number;
}

interface KnowledgeSearchResult extends KnowledgeCitation {
  kind: string;
  ordinal: number;
  checksum: string;
  version: string;
  updated_at: string | null;
}

interface KnowledgeSearchResponse {
  query: string;
  results: KnowledgeSearchResult[];
  citations: KnowledgeCitation[];
  count: number;
  embedding_models: string[];
  scanned_chunks: number;
}

interface UsageBucket {
  count: number;
  success: number;
  error: number;
  prompt_tokens: number;
  completion_tokens: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
}

interface UsageResponse {
  window_days: number;
  since: string;
  totals: UsageBucket;
  by_task: Record<string, UsageBucket>;
  by_model: Record<string, UsageBucket>;
  by_status: Record<string, number>;
  invocations: number;
}

const PROVIDER_KINDS: ProviderKind[] = ["ollama", "vllm", "llamacpp", "openai_compatible"];
const KNOWLEDGE_KINDS: KnowledgeKind[] = ["runbook", "playbook", "policy", "sop", "reference", "other"];

const KIND_URLS: Record<ProviderKind, string> = {
  ollama: "http://127.0.0.1:11434",
  vllm: "http://127.0.0.1:8000/v1",
  llamacpp: "http://127.0.0.1:8080/v1",
  openai_compatible: "https://gateway.internal/v1",
};

function latestEvaluationScore(evaluation: Record<string, unknown>): number | null {
  const latest = evaluation.latest;
  if (!latest || typeof latest !== "object" || Array.isArray(latest)) return null;
  const score = (latest as Record<string, unknown>).score;
  return typeof score === "number" ? score : null;
}

function statusTone(status: string): "success" | "warning" | "danger" | "neutral" {
  if (status === "available" || status === "healthy" || status === "ok") return "success";
  if (status === "degraded" || status === "unknown") return "warning";
  if (status === "disabled") return "neutral";
  return "danger";
}

/* -------------------------------------------------------------------- copy */

const COPY: Record<Lang, Record<string, string>> = {
  es: {
    eyebrow: "Gobierno · IA",
    title: "Gestión de modelos",
    subtitle: "Proveedores local-first, registro de modelos, conocimiento con citas y consumo real del gateway.",
    tabProviders: "Proveedores",
    tabModels: "Modelos",
    tabKnowledge: "Conocimiento",
    tabUsage: "Consumo",
    gatewayStatus: "Estado del gateway",
    available: "IA disponible",
    unavailable: "IA no disponible",
    unavailableHint: "No hay ningún proveedor habilitado y saludable. No se generará salida de modelo hasta que uno responda.",
    providersTotal: "Proveedores",
    providersHealthy: "Saludables",
    modelsAvailable: "Modelos registrados",
    knowledgeDocs: "Documentos",
    errorRate: "Tasa de error 24 h",
    localFirst: "Local-first",
    localFirstHint: "Los proveedores locales (Ollama, vLLM, llama.cpp) se prefieren. Un proveedor externo es opt-in y debe declararse explícitamente.",
    local: "Local",
    external: "Externo",
    platformScope: "Plataforma",
    orgScope: "Organización",
    providersTitle: "Proveedores de IA",
    providersSub: "Credenciales cifradas y comprobación de salud real; nunca se muestran claves.",
    registerProvider: "Registrar proveedor",
    editProvider: "Editar proveedor",
    providerName: "Nombre",
    kind: "Tipo",
    baseUrl: "URL base",
    defaultModel: "Modelo por defecto",
    apiKey: "API key",
    apiKeyHint: "Se cifra en el servidor y no se vuelve a mostrar. Déjalo vacío para conservar la actual.",
    apiKeySet: "API key configurada",
    clearApiKey: "Borrar API key",
    isLocal: "Proveedor local",
    enabled: "Habilitado",
    scope: "Ámbito",
    config: "Configuración JSON",
    health: "Salud",
    lastHealth: "Último health",
    lastError: "Último error",
    testHealth: "Probar salud",
    discoverModels: "Descubrir modelos",
    noProviders: "Sin proveedores",
    noProvidersHint: "Registra Ollama, vLLM, llama.cpp o un endpoint compatible con OpenAI.",
    providerCreated: "Proveedor registrado",
    providerUpdated: "Proveedor actualizado",
    providerDeleted: "Proveedor eliminado",
    deleteProvider: "Eliminar proveedor",
    deleteProviderWarning:
      "Se eliminan el proveedor, su credencial cifrada y todos los modelos registrados. Las invocaciones históricas permanecen auditadas.",
    testResult: "Resultado del health check",
    healthy: "Saludable",
    unhealthy: "No saludable",
    discoverResult: "Descubrimiento de modelos",
    discovered: "Descubiertos",
    created: "Creados",
    updated: "Actualizados",
    modelsForProvider: "Modelos conocidos",
    guidance: "Guía de conexión",
    guidanceOllama: "Ollama: URL raíz del runtime (por defecto :11434), sin API key en red interna.",
    guidanceVllm: "vLLM: endpoint compatible OpenAI con sufijo /v1 y modelo servido declarado.",
    guidanceLlamacpp: "llama.cpp: servidor compatible OpenAI (/v1) para GGUF en CPU o GPU.",
    guidanceOpenai: "OpenAI-compatible: solo si la política lo permite; declara el proveedor como externo.",
    modelsTitle: "Registro de modelos",
    modelsSub: "Metadatos deterministas y etiquetas de tarea; sin metadatos inventados.",
    registerModel: "Registrar modelo",
    editModel: "Editar modelo",
    provider: "Proveedor",
    modelName: "Nombre del modelo",
    displayName: "Nombre visible",
    taskTags: "Etiquetas de tarea",
    taskTagsHint: "Separadas por comas; minúsculas, formato task.subtask.",
    contextWindow: "Ventana de contexto",
    maxOutput: "Máx. tokens de salida",
    status: "Estado",
    evaluation: "Evaluación",
    evaluate: "Evaluar",
    evaluateTitle: "Evaluar modelo con rúbrica",
    evaluateSub: "Las pruebas se ejecutan contra el modelo real; si el proveedor no responde, el caso falla y no se simula.",
    defaultCases: "Casos por defecto (rúbrica del servidor)",
    customCases: "Casos personalizados (JSON)",
    casesJson: "Array JSON de casos",
    casesHint: "Cada caso requiere name y prompt; opcional expect_json, required_keys, require_citation.",
    invalidCases: "El JSON debe ser un array de objetos con name y prompt.",
    runEvaluation: "Ejecutar evaluación",
    evaluationResult: "Resultado de la evaluación",
    score: "Puntuación",
    passed: "Aprobados",
    failed: "Fallidos",
    checks: "Comprobaciones",
    rubric: "Rúbrica",
    outputExcerpt: "Extracto de salida",
    notRun: "No ejecutado",
    noModels: "Sin modelos",
    noModelsHint: "Descubre modelos desde un proveedor saludable o registra sus metadatos.",
    noModelMatches: "Ningún modelo coincide con los filtros.",
    modelCreated: "Modelo registrado",
    modelUpdated: "Modelo actualizado",
    modelDeleted: "Modelo eliminado",
    deleteModel: "Eliminar modelo",
    deleteModelWarning: "Se elimina el modelo del registro operativo. Las evaluaciones e invocaciones previas permanecen auditadas.",
    latestEval: "Última evaluación",
    noEvaluation: "Sin evaluar",
    knowledgeTitle: "Base de conocimiento",
    knowledgeSub: "Documentos versionados con checksum, chunking y búsqueda híbrida con citas verificables.",
    newDocument: "Nuevo documento",
    editDocument: "Editar documento",
    title: "Título",
    source: "Origen",
    version: "Versión",
    text: "Texto",
    metadata: "Metadatos JSON",
    chunks: "Chunks",
    checksum: "Checksum",
    updatedAt: "Actualizado",
    docCreated: "Documento creado",
    docUpdated: "Documento actualizado",
    docDeleted: "Documento eliminado",
    deleteDocument: "Eliminar documento",
    deleteDocumentWarning: "Se eliminan el documento, sus chunks y sus embeddings. La búsqueda dejará de citarlo.",
    noDocuments: "Sin documentos",
    noDocumentsHint: "Ingesta runbooks, políticas o SOP para que el RAG cite evidencia real.",
    docDetail: "Detalle del documento",
    searchKnowledge: "Probar búsqueda",
    searchHint: "Consulta híbrida limitada a la organización. Devuelve fragmentos con cita y puntuación.",
    query: "Consulta",
    topK: "Resultados",
    results: "Resultados",
    citations: "Citas",
    noResults: "Sin resultados",
    noResultsHint: "Ajusta la consulta o amplía los tipos de documento.",
    scannedChunks: "Chunks analizados",
    embeddingModels: "Modelos de embedding",
    relevance: "Relevancia",
    document: "Documento",
    searchError: "La búsqueda falló",
    usageTitle: "Consumo del gateway",
    usageSub: "Invocaciones reales por tarea, modelo y estado, con latencia media y p95.",
    window: "Ventana",
    days7: "7 días",
    days30: "30 días",
    days90: "90 días",
    invocations: "Invocaciones",
    successRate: "Tasa de éxito",
    tokens: "Tokens",
    promptTokens: "Prompt",
    completionTokens: "Completado",
    avgLatency: "Latencia media",
    p95Latency: "p95",
    byTask: "Por tarea",
    byModel: "Por modelo",
    byStatus: "Por estado",
    since: "Desde",
    noUsage: "Sin invocaciones en la ventana",
    noUsageHint: "El gateway registrará consumo cuando los agentes o flujos invoquen un modelo.",
    providerHealth: "Salud por proveedor",
    loadFailed: "No se pudo cargar la información de IA.",
    noPermission: "No tienes permiso para consultar la gestión de modelos.",
    noAdmin: "Tu rol no puede modificar proveedores, modelos ni conocimiento.",
    noUse: "Tu rol no puede ejecutar evaluaciones ni búsquedas.",
    save: "Guardar",
    cancel: "Cancelar",
    close: "Cerrar",
    refresh: "Actualizar",
    all: "Todos",
    filtersClear: "Limpiar filtros",
    searchModels: "Buscar modelos…",
    searchDocs: "Buscar documentos…",
    kindFilter: "Tipo",
    providerFilter: "Proveedor",
    taskFilter: "Etiqueta de tarea",
    healthCheckDone: "Health check completado",
    providerUnavailable: "Proveedor no disponible",
    providerUnavailableHint: "El servidor devolvió un error real; revisa URL, red y credencial.",
    detail: "Detalle",
    localOnlyWarning: "Si el proveedor no es local, la política de datos debe permitirlo explícitamente.",
    optional: "Opcional",
    requiresName: "El nombre es obligatorio.",
    requiresUrl: "La URL base debe tener al menos 8 caracteres.",
    invalidTags: "Etiquetas inválidas. Usa minúsculas y el formato task.subtask.",
    outputTooLarge: "Los tokens de salida no pueden superar la ventana de contexto.",
    knowledgeTextMin: "El texto debe tener al menos 10 caracteres.",
    noChunks: "Este documento aún no tiene chunks.",
    chunkText: "Fragmento",
    chunkTokens: "tokens",
    evaluatedAt: "Evaluado",
    caseName: "Caso",
    caseStatus: "Estado",
    result: "Resultado",
    apiKeyNeverShown: "La clave nunca se devuelve desde el servidor.",
    delete: "Eliminar",
    statusDisabled: "Deshabilitado",
  },
  en: {
    eyebrow: "Governance · AI",
    title: "Model management",
    subtitle: "Local-first providers, model registry, cited knowledge and real gateway usage.",
    tabProviders: "Providers",
    tabModels: "Models",
    tabKnowledge: "Knowledge",
    tabUsage: "Usage",
    gatewayStatus: "Gateway status",
    available: "AI available",
    unavailable: "AI unavailable",
    unavailableHint: "No provider is enabled and healthy. No model output will be generated until one responds.",
    providersTotal: "Providers",
    providersHealthy: "Healthy",
    modelsAvailable: "Registered models",
    knowledgeDocs: "Documents",
    errorRate: "24 h error rate",
    localFirst: "Local-first",
    localFirstHint: "Local providers (Ollama, vLLM, llama.cpp) are preferred. An external provider is opt-in and must be declared explicitly.",
    local: "Local",
    external: "External",
    platformScope: "Platform",
    orgScope: "Organization",
    providersTitle: "AI providers",
    providersSub: "Encrypted credentials and real health checks; keys are never displayed.",
    registerProvider: "Register provider",
    editProvider: "Edit provider",
    providerName: "Name",
    kind: "Type",
    baseUrl: "Base URL",
    defaultModel: "Default model",
    apiKey: "API key",
    apiKeyHint: "Encrypted server-side and never shown again. Leave blank to keep the current one.",
    apiKeySet: "API key configured",
    clearApiKey: "Clear API key",
    isLocal: "Local provider",
    enabled: "Enabled",
    scope: "Scope",
    config: "JSON configuration",
    health: "Health",
    lastHealth: "Last health",
    lastError: "Last error",
    testHealth: "Test health",
    discoverModels: "Discover models",
    noProviders: "No providers",
    noProvidersHint: "Register Ollama, vLLM, llama.cpp or an OpenAI-compatible endpoint.",
    providerCreated: "Provider registered",
    providerUpdated: "Provider updated",
    providerDeleted: "Provider deleted",
    deleteProvider: "Delete provider",
    deleteProviderWarning:
      "The provider, its encrypted credential and all registered models are removed. Historical invocations remain audited.",
    testResult: "Health check result",
    healthy: "Healthy",
    unhealthy: "Unhealthy",
    discoverResult: "Model discovery",
    discovered: "Discovered",
    created: "Created",
    updated: "Updated",
    modelsForProvider: "Known models",
    guidance: "Connection guidance",
    guidanceOllama: "Ollama: runtime root URL (default :11434), no API key on an internal network.",
    guidanceVllm: "vLLM: OpenAI-compatible endpoint with /v1 suffix and a declared served model.",
    guidanceLlamacpp: "llama.cpp: OpenAI-compatible server (/v1) for GGUF on CPU or GPU.",
    guidanceOpenai: "OpenAI-compatible: only if policy allows it; declare the provider as external.",
    modelsTitle: "Model registry",
    modelsSub: "Deterministic metadata and task tags; no invented metadata.",
    registerModel: "Register model",
    editModel: "Edit model",
    provider: "Provider",
    modelName: "Model name",
    displayName: "Display name",
    taskTags: "Task tags",
    taskTagsHint: "Comma-separated; lowercase, task.subtask format.",
    contextWindow: "Context window",
    maxOutput: "Max output tokens",
    status: "Status",
    evaluation: "Evaluation",
    evaluate: "Evaluate",
    evaluateTitle: "Evaluate model with rubric",
    evaluateSub: "Cases run against the real model; if the provider does not respond the case fails and is never simulated.",
    defaultCases: "Default cases (server rubric)",
    customCases: "Custom cases (JSON)",
    casesJson: "JSON array of cases",
    casesHint: "Each case requires name and prompt; optional expect_json, required_keys, require_citation.",
    invalidCases: "The JSON must be an array of objects with name and prompt.",
    runEvaluation: "Run evaluation",
    evaluationResult: "Evaluation result",
    score: "Score",
    passed: "Passed",
    failed: "Failed",
    checks: "Checks",
    rubric: "Rubric",
    outputExcerpt: "Output excerpt",
    notRun: "Not run",
    noModels: "No models",
    noModelsHint: "Discover models from a healthy provider or register their metadata.",
    noModelMatches: "No model matches the filters.",
    modelCreated: "Model registered",
    modelUpdated: "Model updated",
    modelDeleted: "Model deleted",
    deleteModel: "Delete model",
    deleteModelWarning: "The model is removed from the operational registry. Previous evaluations and invocations remain audited.",
    latestEval: "Latest evaluation",
    noEvaluation: "Not evaluated",
    knowledgeTitle: "Knowledge base",
    knowledgeSub: "Versioned documents with checksum, chunking and hybrid search with verifiable citations.",
    newDocument: "New document",
    editDocument: "Edit document",
    title: "Title",
    source: "Source",
    version: "Version",
    text: "Text",
    metadata: "Metadata JSON",
    chunks: "Chunks",
    checksum: "Checksum",
    updatedAt: "Updated",
    docCreated: "Document created",
    docUpdated: "Document updated",
    docDeleted: "Document deleted",
    deleteDocument: "Delete document",
    deleteDocumentWarning: "The document, its chunks and embeddings are removed. Search will stop citing it.",
    noDocuments: "No documents",
    noDocumentsHint: "Ingest runbooks, policies or SOPs so RAG cites real evidence.",
    docDetail: "Document detail",
    searchKnowledge: "Test search",
    searchHint: "Organization-scoped hybrid query. Returns snippets with citation and score.",
    query: "Query",
    topK: "Results",
    results: "Results",
    citations: "Citations",
    noResults: "No results",
    noResultsHint: "Adjust the query or broaden the document kinds.",
    scannedChunks: "Scanned chunks",
    embeddingModels: "Embedding models",
    relevance: "Relevance",
    document: "Document",
    searchError: "Search failed",
    usageTitle: "Gateway usage",
    usageSub: "Real invocations by task, model and status, with average and p95 latency.",
    window: "Window",
    days7: "7 days",
    days30: "30 days",
    days90: "90 days",
    invocations: "Invocations",
    successRate: "Success rate",
    tokens: "Tokens",
    promptTokens: "Prompt",
    completionTokens: "Completion",
    avgLatency: "Average latency",
    p95Latency: "p95",
    byTask: "By task",
    byModel: "By model",
    byStatus: "By status",
    since: "Since",
    noUsage: "No invocations in the window",
    noUsageHint: "The gateway records usage when agents or flows invoke a model.",
    providerHealth: "Health by provider",
    loadFailed: "AI information could not be loaded.",
    noPermission: "You do not have permission to view model management.",
    noAdmin: "Your role cannot modify providers, models or knowledge.",
    noUse: "Your role cannot run evaluations or searches.",
    save: "Save",
    cancel: "Cancel",
    close: "Close",
    refresh: "Refresh",
    all: "All",
    filtersClear: "Clear filters",
    searchModels: "Search models…",
    searchDocs: "Search documents…",
    kindFilter: "Type",
    providerFilter: "Provider",
    taskFilter: "Task tag",
    healthCheckDone: "Health check completed",
    providerUnavailable: "Provider unavailable",
    providerUnavailableHint: "The server returned a real error; check URL, network and credential.",
    detail: "Detail",
    localOnlyWarning: "If the provider is not local, the data policy must explicitly allow it.",
    optional: "Optional",
    requiresName: "Name is required.",
    requiresUrl: "Base URL must be at least 8 characters.",
    invalidTags: "Invalid tags. Use lowercase task.subtask format.",
    outputTooLarge: "Output tokens cannot exceed the context window.",
    knowledgeTextMin: "Text must be at least 10 characters.",
    noChunks: "This document has no chunks yet.",
    chunkText: "Snippet",
    chunkTokens: "tokens",
    evaluatedAt: "Evaluated",
    caseName: "Case",
    caseStatus: "Status",
    result: "Result",
    apiKeyNeverShown: "The key is never returned by the server.",
    delete: "Delete",
    statusDisabled: "Disabled",
  },
};

/* --------------------------------------------------------------- providers */

interface ProviderFormState {
  name: string;
  kind: ProviderKind;
  baseUrl: string;
  defaultModel: string;
  apiKey: string;
  clearApiKey: boolean;
  isLocal: boolean;
  enabled: boolean;
  scope: "organization" | "platform";
  configText: string;
}

const EMPTY_PROVIDER_FORM: ProviderFormState = {
  name: "",
  kind: "ollama",
  baseUrl: "http://127.0.0.1:11434",
  defaultModel: "",
  apiKey: "",
  clearApiKey: false,
  isLocal: true,
  enabled: true,
  scope: "organization",
  configText: "{}",
};

function ProvidersTab({ canAdmin, isPlatformAdmin, aiAvailable }: { canAdmin: boolean; isPlatformAdmin: boolean; aiAvailable: boolean }) {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [scope, setScope] = useState("all");
  const [page, setPage] = useState(1);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<AIProvider | null>(null);
  const [form, setForm] = useState<ProviderFormState>(EMPTY_PROVIDER_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [healthResult, setHealthResult] = useState<{ name: string; result: ProviderHealthResult } | null>(null);
  const [discoverResult, setDiscoverResult] = useState<ModelDiscoverResult | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AIProvider | null>(null);

  const providersQuery = useQuery({
    queryKey: ["models", "providers", { scope, page }],
    queryFn: () => api.get<Page<AIProvider>>("/ai/providers", { page, page_size: 25, scope }),
  });

  const openCreate = () => {
    setEditing(null);
    setForm({ ...EMPTY_PROVIDER_FORM });
    setFormError(null);
    setFieldErrors({});
    setFormOpen(true);
  };

  const openEdit = (provider: AIProvider) => {
    setEditing(provider);
    setForm({
      name: provider.name,
      kind: provider.kind as ProviderKind,
      baseUrl: provider.base_url,
      defaultModel: provider.default_model ?? "",
      apiKey: "",
      clearApiKey: false,
      isLocal: provider.is_local,
      enabled: provider.enabled,
      scope: provider.org_id === null ? "platform" : "organization",
      configText: JSON.stringify(provider.config ?? {}, null, 2),
    });
    setFormError(null);
    setFieldErrors({});
    setFormOpen(true);
  };

  const configParsed = parseJsonRecord(form.configText);

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<AIProvider>("/ai/providers", body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(t("providerCreated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const updateMutation = useMutation({
    mutationFn: (payload: { id: string; body: Record<string, unknown> }) => api.patch<AIProvider>(`/ai/providers/${payload.id}`, payload.body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(t("providerUpdated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (provider: AIProvider) => api.delete<void>(`/ai/providers/${provider.id}`),
    onSuccess: async () => {
      setDeleteTarget(null);
      toast.push(t("providerDeleted"), "success");
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
    onError: (error) => {
      setDeleteTarget(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const healthMutation = useMutation({
    mutationFn: (provider: AIProvider) => api.post<ProviderHealthResult>(`/ai/providers/${provider.id}/test`),
    onSuccess: async (result, provider) => {
      setHealthResult({ name: provider.name, result });
      toast.push(result.healthy ? t("healthy") : t("unhealthy"), result.healthy ? "success" : "error");
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
    onError: (error, provider) => {
      setHealthResult({
        name: provider.name,
        result: {
          provider_id: provider.id,
          healthy: false,
          health_status: "unhealthy",
          error: errorMessage(error),
          detail: {},
          checked_at: new Date().toISOString(),
        },
      });
    },
  });

  const discoverMutation = useMutation({
    mutationFn: (provider: AIProvider) => api.post<ModelDiscoverResult>(`/ai/providers/${provider.id}/discover`),
    onSuccess: async (result) => {
      setDiscoverResult(result);
      toast.push(`${t("discoverResult")}: ${result.discovered}`, "success");
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
    onError: (error) => toast.push(errorMessage(error), "error"),
  });

  const submit = () => {
    setFormError(null);
    if (form.name.trim().length === 0) {
      setFormError(t("requiresName"));
      return;
    }
    if (form.baseUrl.trim().length < 8) {
      setFormError(t("requiresUrl"));
      return;
    }
    if (!configParsed.ok) {
      setFormError(configParsed.error);
      return;
    }
    const base: Record<string, unknown> = {
      name: form.name.trim(),
      kind: form.kind,
      base_url: form.baseUrl.trim(),
      is_local: form.isLocal,
      enabled: form.enabled,
      config: configParsed.value,
    };
    if (form.defaultModel.trim()) base.default_model = form.defaultModel.trim();
    if (form.apiKey) base.api_key = form.apiKey;
    if (editing) {
      if (form.clearApiKey) base.clear_api_key = true;
      updateMutation.mutate({ id: editing.id, body: base });
    } else {
      base.scope = form.scope;
      createMutation.mutate(base);
    }
  };

  const columns: Column<AIProvider>[] = [
    {
      key: "name",
      header: t("providerName"),
      render: (row) => (
        <div style={{ minWidth: 210 }}>
          <div className="row wrap" style={{ gap: 5 }}>
            <StatusDot status={row.health_status} />
            <span className="primary-cell">{row.name}</span>
            <Badge tone={row.is_local ? "success" : "warning"}>{row.is_local ? t("local") : t("external")}</Badge>
            {row.has_api_key ? <Badge tone="neutral"><KeyRound size={10} /> {t("apiKeySet")}</Badge> : null}
          </div>
          <div className="cell-sub mono">{row.kind} · {row.org_id === null ? t("platformScope") : t("orgScope")}</div>
          <div className="cell-sub mono" style={{ wordBreak: "break-all" }}>{row.base_url}</div>
        </div>
      ),
    },
    {
      key: "status",
      header: t("health"),
      width: "140px",
      render: (row) => (
        <div className="stack" style={{ gap: 3 }}>
          <Badge tone={statusTone(row.health_status)}>{humanize(row.health_status)}</Badge>
          <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{relativeTime(row.last_health_at, lang)}</span>
        </div>
      ),
    },
    {
      key: "default",
      header: t("defaultModel"),
      width: "150px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.default_model ?? "—"}</span>,
    },
    {
      key: "lastError",
      header: t("lastError"),
      width: "190px",
      render: (row) => (
        <span style={{ fontSize: 10.5, color: row.last_health_error ? "var(--danger)" : "var(--dim)", display: "block", maxWidth: 190, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {row.last_health_error ?? "—"}
        </span>
      ),
    },
    {
      key: "enabled",
      header: t("enabled"),
      width: "90px",
      render: (row) => <Badge tone={row.enabled ? "success" : "neutral"}>{row.enabled ? t("enabled") : t("statusDisabled")}</Badge>,
    },
    {
      key: "actions",
      header: t("common.actions"),
      width: "250px",
      align: "right",
      render: (row) => (
        <div className="row wrap" style={{ gap: 3, justifyContent: "flex-end" }}>
          {canAdmin ? (
            <>
              <Button size="sm" variant="ghost" icon={Activity} aria-label={t("testHealth")} loading={healthMutation.isPending} onClick={() => healthMutation.mutate(row)} data-testid="provider-test" />
              <Button size="sm" variant="ghost" icon={Download} aria-label={t("discoverModels")} loading={discoverMutation.isPending} onClick={() => discoverMutation.mutate(row)} data-testid="provider-discover" />
              <Button size="sm" variant="ghost" onClick={() => openEdit(row)} data-testid="provider-edit">{t("common.edit")}</Button>
              <Button size="sm" variant="ghost" icon={Trash2} aria-label={t("deleteProvider")} onClick={() => setDeleteTarget(row)} data-testid="provider-delete" />
            </>
          ) : (
            <span className="dim" style={{ fontSize: 10 }}>{t("noAdmin")}</span>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="stack" data-testid="models-providers">
      {!aiAvailable ? <div className="notice notice-warning"><AlertTriangle size={14} style={{ flex: "0 0 auto" }} />{t("unavailableHint")}</div> : null}

      <div className="grid-3">
        {PROVIDER_KINDS.map((kind) => (
          <div className="card card-pad stack" key={kind} style={{ gap: 4 }}>
            <div className="row" style={{ gap: 6 }}>
              <Cpu size={14} style={{ color: "var(--accent)" }} />
              <span className="primary-cell">{kind}</span>
            </div>
            <div className="mono" style={{ fontSize: 10, color: "var(--dim)", wordBreak: "break-all" }}>{KIND_URLS[kind]}</div>
            <div style={{ fontSize: 11, color: "var(--muted)" }}>
              {kind === "ollama" ? t("guidanceOllama") : kind === "vllm" ? t("guidanceVllm") : kind === "llamacpp" ? t("guidanceLlamacpp") : t("guidanceOpenai")}
            </div>
          </div>
        ))}
      </div>

      <Card
        title={t("providersTitle")}
        subtitle={t("providersSub")}
        actions={
          canAdmin ? (
            <Button size="sm" variant="primary" icon={Plus} onClick={openCreate} data-testid="provider-create-open">{t("registerProvider")}</Button>
          ) : <span className="dim" style={{ fontSize: 11 }}>{t("noAdmin")}</span>
        }
        bodyClassName=""
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap">
            <Select value={scope} onChange={(event) => { setScope(event.target.value); setPage(1); }} aria-label={t("scope")} style={{ width: 180 }} data-testid="provider-scope-filter">
              <option value="all">{t("all")}</option>
              <option value="organization">{t("orgScope")}</option>
              <option value="platform">{t("platformScope")}</option>
            </Select>
            <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("refresh")} onClick={() => void providersQuery.refetch()} />
          </div>
        </div>
        {providersQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(providersQuery.error)} onRetry={() => void providersQuery.refetch()} />
          </div>
        ) : (
          <>
            <DataTable
              columns={columns}
              rows={providersQuery.data?.items}
              rowKey={(row) => row.id}
              loading={providersQuery.isLoading}
              empty={
                <EmptyState
                  icon={Server}
                  title={t("noProviders")}
                  description={t("noProvidersHint")}
                  action={canAdmin ? <Button size="sm" onClick={openCreate}>{t("registerProvider")}</Button> : undefined}
                />
              }
            />
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={providersQuery.data?.meta} onPage={setPage} />
            </div>
          </>
        )}
      </Card>

      <div className="notice" style={{ fontSize: 11 }}>
        <HardDrive size={13} style={{ flex: "0 0 auto", color: "var(--success)" }} />
        <span>{t("localFirstHint")} {t("localOnlyWarning")}</span>
      </div>

      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={editing ? t("editProvider") : t("registerProvider")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setFormOpen(false)} disabled={createMutation.isPending || updateMutation.isPending}>{t("cancel")}</Button>
            <Button variant="primary" loading={createMutation.isPending || updateMutation.isPending} onClick={submit} data-testid="provider-submit">
              {editing ? t("save") : t("registerProvider")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="notice">{t("localFirstHint")}</div>
          <div className="form-grid">
            <Field label={t("providerName")} htmlFor={`${idPrefix}-name`} error={fieldErrors.name} required>
              <Input id={`${idPrefix}-name`} value={form.name} maxLength={120} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} />
            </Field>
            <Field label={t("kind")} htmlFor={`${idPrefix}-kind`} error={fieldErrors.kind} required>
              <Select id={`${idPrefix}-kind`} value={form.kind} onChange={(event) => setForm((current) => ({ ...current, kind: event.target.value as ProviderKind }))} data-testid="provider-kind">
                {PROVIDER_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
              </Select>
            </Field>
            <div className="span-2">
              <Field label={t("baseUrl")} htmlFor={`${idPrefix}-url`} error={fieldErrors.base_url} hint={KIND_URLS[form.kind]} required>
                <Input id={`${idPrefix}-url`} value={form.baseUrl} maxLength={500} onChange={(event) => setForm((current) => ({ ...current, baseUrl: event.target.value }))} />
              </Field>
            </div>
            <Field label={t("defaultModel")} htmlFor={`${idPrefix}-default`} error={fieldErrors.default_model} hint={t("optional")}>
              <Input id={`${idPrefix}-default`} value={form.defaultModel} maxLength={160} onChange={(event) => setForm((current) => ({ ...current, defaultModel: event.target.value }))} />
            </Field>
            <Field label={t("scope")} htmlFor={`${idPrefix}-scope`} hint={editing ? t("scope") : undefined}>
              <Select
                id={`${idPrefix}-scope`}
                value={form.scope}
                disabled={editing !== null || !isPlatformAdmin}
                onChange={(event) => setForm((current) => ({ ...current, scope: event.target.value as "organization" | "platform" }))}
              >
                <option value="organization">{t("orgScope")}</option>
                {isPlatformAdmin ? <option value="platform">{t("platformScope")}</option> : null}
              </Select>
            </Field>
            <div className="span-2">
              <Field label={t("apiKey")} htmlFor={`${idPrefix}-key`} hint={`${t("apiKeyHint")} ${t("apiKeyNeverShown")}`} error={fieldErrors.api_key}>
                <Input id={`${idPrefix}-key`} type="password" autoComplete="new-password" value={form.apiKey} onChange={(event) => setForm((current) => ({ ...current, apiKey: event.target.value }))} placeholder={editing?.has_api_key ? "••••••••" : ""} data-testid="provider-api-key" />
              </Field>
            </div>
            <div className="span-2">
              <JsonEditor
                id={`${idPrefix}-config`}
                label={t("config")}
                value={form.configText}
                onChange={(value) => setForm((current) => ({ ...current, configText: value }))}
                error={!configParsed.ok ? configParsed.error : fieldErrors.config}
                testId="provider-config"
              />
            </div>
            <label className="checkbox">
              <input type="checkbox" checked={form.isLocal} onChange={(event) => setForm((current) => ({ ...current, isLocal: event.target.checked }))} />
              {t("isLocal")}
            </label>
            <label className="checkbox">
              <input type="checkbox" checked={form.enabled} onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))} />
              {t("enabled")}
            </label>
            {editing ? (
              <label className="checkbox">
                <input type="checkbox" checked={form.clearApiKey} onChange={(event) => setForm((current) => ({ ...current, clearApiKey: event.target.checked }))} />
                {t("clearApiKey")}
              </label>
            ) : null}
          </div>
          {formError ? <ErrorBanner message={formError} /> : null}
        </div>
      </Modal>

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => { if (deleteTarget) deleteMutation.mutate(deleteTarget); }}
        title={t("deleteProvider")}
        description={deleteTarget ? `${deleteTarget.name} · ${deleteTarget.kind}` : undefined}
        warning={t("deleteProviderWarning")}
        confirmLabel={t("delete") ?? "Delete"}
        cancelLabel={t("cancel")}
        busy={deleteMutation.isPending}
        testId="provider-delete-confirm"
      />

      <Modal open={healthResult !== null} onClose={() => setHealthResult(null)} title={t("testResult")} footer={<Button onClick={() => setHealthResult(null)}>{t("close")}</Button>}>
        {healthResult ? (
          <div className="stack">
            <div className="row wrap">
              <Badge tone={healthResult.result.healthy ? "success" : "danger"}>
                {healthResult.result.healthy ? t("healthy") : t("unhealthy")}
              </Badge>
              <Badge tone="neutral">{humanize(healthResult.result.health_status)}</Badge>
              <span className="dim" style={{ fontSize: 11 }}>{healthResult.name}</span>
            </div>
            {healthResult.result.error ? <div className="notice notice-danger">{healthResult.result.error}</div> : null}
            <MetaRows
              items={[
                { label: t("lastHealth"), value: formatDateTime(healthResult.result.checked_at, lang) },
                { label: t("providerUnavailable"), value: healthResult.result.healthy ? "—" : t("providerUnavailableHint") },
              ]}
            />
            <PreBlock value={healthResult.result.detail} label={t("detail")} />
          </div>
        ) : null}
      </Modal>

      <Modal open={discoverResult !== null} onClose={() => setDiscoverResult(null)} title={t("discoverResult")} footer={<Button onClick={() => setDiscoverResult(null)}>{t("close")}</Button>}>
        {discoverResult ? (
          <div className="stack">
            <MetaRows
              items={[
                { label: t("provider"), value: discoverResult.provider_name },
                { label: t("discovered"), value: formatNumber(discoverResult.discovered) },
                { label: t("created"), value: formatNumber(discoverResult.created) },
                { label: t("updated"), value: formatNumber(discoverResult.updated) },
              ]}
            />
            {discoverResult.models.length ? (
              <div className="chip-row">{discoverResult.models.map((model) => <span className="tag" key={model.id}>{model.name}</span>)}</div>
            ) : null}
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

/* ------------------------------------------------------------------ models */

interface ModelFormState {
  providerId: string;
  name: string;
  displayName: string;
  taskTags: string;
  contextWindow: string;
  maxOutput: string;
  status: ModelStatus;
}

const EMPTY_MODEL_FORM: ModelFormState = {
  providerId: "",
  name: "",
  displayName: "",
  taskTags: "",
  contextWindow: "8192",
  maxOutput: "2048",
  status: "available",
};

function ModelsTab({ canAdmin, canUse, aiAvailable }: { canAdmin: boolean; canUse: boolean; aiAvailable: boolean }) {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [providerId, setProviderId] = useState("");
  const [page, setPage] = useState(1);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<AIModel | null>(null);
  const [form, setForm] = useState<ModelFormState>(EMPTY_MODEL_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [deleteTarget, setDeleteTarget] = useState<AIModel | null>(null);
  const [evalFor, setEvalFor] = useState<AIModel | null>(null);
  const [evalMode, setEvalMode] = useState<"default" | "custom">("default");
  const [evalCases, setEvalCases] = useState("");
  const [evalError, setEvalError] = useState<string | null>(null);
  const [evalResult, setEvalResult] = useState<EvaluationSummary | null>(null);

  const providersQuery = useQuery({
    queryKey: ["models", "providers", { picker: true }],
    queryFn: () => api.get<Page<AIProvider>>("/ai/providers", { page: 1, page_size: 200 }),
  });

  const modelsQuery = useQuery({
    queryKey: ["models", "registry", { q, status, providerId, page }],
    queryFn: () =>
      api.get<Page<AIModel>>("/ai/models", {
        page,
        page_size: 25,
        q: q || undefined,
        status: status || undefined,
        provider_id: providerId || undefined,
      }),
  });

  const openCreate = () => {
    setEditing(null);
    setForm({ ...EMPTY_MODEL_FORM, providerId: providersQuery.data?.items[0]?.id ?? "" });
    setFormError(null);
    setFieldErrors({});
    setFormOpen(true);
  };

  const openEdit = (model: AIModel) => {
    setEditing(model);
    setForm({
      providerId: model.provider_id,
      name: model.name,
      displayName: model.display_name ?? "",
      taskTags: model.task_tags.join(", "),
      contextWindow: String(model.context_window),
      maxOutput: String(model.max_output_tokens),
      status: model.status as ModelStatus,
    });
    setFormError(null);
    setFieldErrors({});
    setFormOpen(true);
  };

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<AIModel>("/ai/models", body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(t("modelCreated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const updateMutation = useMutation({
    mutationFn: (payload: { id: string; body: Record<string, unknown> }) => api.patch<AIModel>(`/ai/models/${payload.id}`, payload.body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(t("modelUpdated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (model: AIModel) => api.delete<void>(`/ai/models/${model.id}`),
    onSuccess: async () => {
      setDeleteTarget(null);
      toast.push(t("modelDeleted"), "success");
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
    onError: (error) => {
      setDeleteTarget(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const evaluateMutation = useMutation({
    mutationFn: (payload: { model: AIModel; cases: unknown[] | undefined }) =>
      api.post<EvaluationSummary>(`/ai/models/${payload.model.id}/evaluate`, payload.cases ? { cases: payload.cases } : {}),
    onSuccess: async (result) => {
      setEvalResult(result);
      setEvalError(null);
      toast.push(`${t("evaluationResult")}: ${result.passed}/${result.total}`, result.failed === 0 ? "success" : "warning");
      await queryClient.invalidateQueries({ queryKey: ["models"] });
    },
    onError: (error) => {
      setEvalResult(null);
      setEvalError(errorMessage(error));
    },
  });

  const tags = splitTags(form.taskTags);
  const tagsValid = tags.every((tag) => /^[a-z][a-z0-9_.-]{1,59}$/.test(tag));
  const contextValue = Number(form.contextWindow);
  const outputValue = Number(form.maxOutput);
  const windowValid = Number.isFinite(contextValue) && contextValue >= 256 && contextValue <= 2_000_000;
  const outputValid = Number.isFinite(outputValue) && outputValue >= 1 && outputValue <= contextValue;

  const submit = () => {
    setFormError(null);
    if (!form.providerId) {
      setFormError(t("provider"));
      return;
    }
    if (form.name.trim().length === 0) {
      setFormError(t("requiresName"));
      return;
    }
    if (!tagsValid) {
      setFormError(t("invalidTags"));
      return;
    }
    if (!windowValid) {
      setFormError(t("contextWindow"));
      return;
    }
    if (!outputValid) {
      setFormError(t("outputTooLarge"));
      return;
    }
    if (editing) {
      updateMutation.mutate({
        id: editing.id,
        body: {
          display_name: form.displayName.trim() || null,
          task_tags: tags,
          context_window: Math.round(contextValue),
          max_output_tokens: Math.round(outputValue),
          status: form.status,
        },
      });
    } else {
      createMutation.mutate({
        provider_id: form.providerId,
        name: form.name.trim(),
        display_name: form.displayName.trim() || null,
        task_tags: tags,
        context_window: Math.round(contextValue),
        max_output_tokens: Math.round(outputValue),
        status: form.status,
      });
    }
  };

  const customCasesParsed = (): { ok: true; value: unknown[] } | { ok: false; error: string } => {
    const trimmed = evalCases.trim();
    if (!trimmed) return { ok: false, error: t("invalidCases") };
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (!Array.isArray(parsed) || parsed.length === 0) return { ok: false, error: t("invalidCases") };
      for (const item of parsed) {
        if (!item || typeof item !== "object" || Array.isArray(item)) return { ok: false, error: t("invalidCases") };
        const record = item as Record<string, unknown>;
        if (typeof record.name !== "string" || record.name.length === 0) return { ok: false, error: t("invalidCases") };
        if (typeof record.prompt !== "string" || record.prompt.length < 5) return { ok: false, error: t("invalidCases") };
      }
      return { ok: true, value: parsed };
    } catch {
      return { ok: false, error: t("invalidCases") };
    }
  };

  const columns: Column<AIModel>[] = [
    {
      key: "model",
      header: t("modelName"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div className="primary-cell mono" style={{ fontSize: 11.5 }}>{row.name}</div>
          <div className="cell-sub">{row.display_name ?? "—"}</div>
          <div className="cell-sub">{t("provider")}: {row.provider_name ?? row.provider_id.slice(0, 8)}</div>
        </div>
      ),
    },
    {
      key: "tags",
      header: t("taskTags"),
      width: "190px",
      render: (row) => (
        <div className="chip-row">
          {row.task_tags.length === 0 ? <span className="dim" style={{ fontSize: 10 }}>—</span> : row.task_tags.slice(0, 3).map((tag) => <span className="tag" key={tag}>{tag}</span>)}
          {row.task_tags.length > 3 ? <span className="tag">+{row.task_tags.length - 3}</span> : null}
        </div>
      ),
    },
    {
      key: "context",
      header: t("contextWindow"),
      width: "130px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatNumber(row.context_window)} / {formatNumber(row.max_output_tokens)}</span>,
    },
    {
      key: "status",
      header: t("status"),
      width: "110px",
      render: (row) => <Badge tone={statusTone(row.status)}>{humanize(row.status)}</Badge>,
    },
    {
      key: "eval",
      header: t("latestEval"),
      width: "120px",
      render: (row) => {
        const score = latestEvaluationScore(row.evaluation);
        return score === null ? (
          <span className="dim" style={{ fontSize: 10.5 }}>{t("noEvaluation")}</span>
        ) : (
          <span className="mono" style={{ color: score >= 0.8 ? "var(--success)" : score >= 0.5 ? "var(--warning)" : "var(--danger)" }}>
            {formatPercent(score * 100, 0)}
          </span>
        );
      },
    },
    {
      key: "actions",
      header: t("common.actions"),
      width: "220px",
      align: "right",
      render: (row) => (
        <div className="row wrap" style={{ gap: 3, justifyContent: "flex-end" }}>
          {canUse ? (
            <Button
              size="sm"
              variant="ghost"
              icon={Beaker}
              disabled={!aiAvailable}
              title={!aiAvailable ? t("unavailableHint") : undefined}
              onClick={() => {
                setEvalFor(row);
                setEvalMode("default");
                setEvalCases("");
                setEvalResult(null);
                setEvalError(null);
              }}
              data-testid="model-evaluate"
            >
              {t("evaluate")}
            </Button>
          ) : null}
          {canAdmin ? (
            <>
              <Button size="sm" variant="ghost" onClick={() => openEdit(row)} data-testid="model-edit">{t("common.edit")}</Button>
              <Button size="sm" variant="ghost" icon={Trash2} aria-label={t("deleteModel")} onClick={() => setDeleteTarget(row)} data-testid="model-delete" />
            </>
          ) : null}
        </div>
      ),
    },
  ];

  return (
    <div className="stack" data-testid="models-models">
      {!aiAvailable ? <div className="notice notice-warning"><AlertTriangle size={14} style={{ flex: "0 0 auto" }} />{t("unavailableHint")}</div> : null}
      <Card
        title={t("modelsTitle")}
        subtitle={t("modelsSub")}
        actions={canAdmin ? <Button size="sm" variant="primary" icon={Plus} onClick={openCreate} data-testid="model-create-open">{t("registerModel")}</Button> : undefined}
        bodyClassName=""
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap" style={{ gap: 8 }}>
            <div style={{ flex: 1, minWidth: 190 }}>
              <SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder={t("searchModels")} ariaLabel={t("searchModels")} />
            </div>
            <Select value={providerId} onChange={(event) => { setProviderId(event.target.value); setPage(1); }} aria-label={t("providerFilter")} style={{ width: 190 }} data-testid="model-provider-filter">
              <option value="">{t("all")} · {t("providerFilter")}</option>
              {(providersQuery.data?.items ?? []).map((provider) => <option key={provider.id} value={provider.id}>{provider.name}</option>)}
            </Select>
            <Select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1); }} aria-label={t("status")} style={{ width: 140 }} data-testid="model-status-filter">
              <option value="">{t("all")}</option>
              <option value="available">available</option>
              <option value="disabled">disabled</option>
              <option value="deprecated">deprecated</option>
            </Select>
            <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("refresh")} onClick={() => void modelsQuery.refetch()} />
          </div>
        </div>
        {modelsQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(modelsQuery.error)} onRetry={() => void modelsQuery.refetch()} />
          </div>
        ) : (
          <>
            <DataTable
              columns={columns}
              rows={modelsQuery.data?.items}
              rowKey={(row) => row.id}
              loading={modelsQuery.isLoading}
              empty={
                <EmptyState
                  icon={BrainCircuit}
                  title={q || status || providerId ? t("noModelMatches") : t("noModels")}
                  description={t("noModelsHint")}
                  action={canAdmin ? <Button size="sm" onClick={openCreate}>{t("registerModel")}</Button> : undefined}
                />
              }
            />
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={modelsQuery.data?.meta} onPage={setPage} />
            </div>
          </>
        )}
      </Card>

      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={editing ? t("editModel") : t("registerModel")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setFormOpen(false)} disabled={createMutation.isPending || updateMutation.isPending}>{t("cancel")}</Button>
            <Button variant="primary" loading={createMutation.isPending || updateMutation.isPending} onClick={submit} data-testid="model-submit">
              {editing ? t("save") : t("registerModel")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <Field label={t("provider")} htmlFor={`${idPrefix}-model-provider`} error={fieldErrors.provider_id} required>
            <Select id={`${idPrefix}-model-provider`} value={form.providerId} disabled={editing !== null} onChange={(event) => setForm((current) => ({ ...current, providerId: event.target.value }))} data-testid="model-provider">
              <option value="">—</option>
              {(providersQuery.data?.items ?? []).map((provider) => <option key={provider.id} value={provider.id}>{provider.name} ({provider.kind})</option>)}
            </Select>
          </Field>
          <div className="form-grid">
            <Field label={t("modelName")} htmlFor={`${idPrefix}-model-name`} error={fieldErrors.name} required>
              <Input id={`${idPrefix}-model-name`} value={form.name} maxLength={160} disabled={editing !== null} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} />
            </Field>
            <Field label={t("displayName")} htmlFor={`${idPrefix}-model-display`} error={fieldErrors.display_name}>
              <Input id={`${idPrefix}-model-display`} value={form.displayName} maxLength={160} onChange={(event) => setForm((current) => ({ ...current, displayName: event.target.value }))} />
            </Field>
            <div className="span-2">
              <Field label={t("taskTags")} htmlFor={`${idPrefix}-model-tags`} hint={t("taskTagsHint")} error={!tagsValid ? t("invalidTags") : fieldErrors.task_tags}>
                <Input id={`${idPrefix}-model-tags`} value={form.taskTags} onChange={(event) => setForm((current) => ({ ...current, taskTags: event.target.value }))} aria-invalid={!tagsValid ? true : undefined} />
              </Field>
            </div>
            <Field label={t("contextWindow")} htmlFor={`${idPrefix}-model-context`} error={!windowValid ? t("contextWindow") : fieldErrors.context_window}>
              <Input id={`${idPrefix}-model-context`} inputMode="numeric" value={form.contextWindow} onChange={(event) => setForm((current) => ({ ...current, contextWindow: event.target.value.replace(/\D/g, "").slice(0, 7) }))} />
            </Field>
            <Field label={t("maxOutput")} htmlFor={`${idPrefix}-model-output`} error={!outputValid ? t("outputTooLarge") : fieldErrors.max_output_tokens}>
              <Input id={`${idPrefix}-model-output`} inputMode="numeric" value={form.maxOutput} onChange={(event) => setForm((current) => ({ ...current, maxOutput: event.target.value.replace(/\D/g, "").slice(0, 6) }))} />
            </Field>
            <Field label={t("status")} htmlFor={`${idPrefix}-model-status`}>
              <Select id={`${idPrefix}-model-status`} value={form.status} onChange={(event) => setForm((current) => ({ ...current, status: event.target.value as ModelStatus }))}>
                <option value="available">available</option>
                <option value="disabled">disabled</option>
                <option value="deprecated">deprecated</option>
              </Select>
            </Field>
          </div>
          {formError ? <ErrorBanner message={formError} /> : null}
        </div>
      </Modal>

      <Modal
        open={evalFor !== null}
        onClose={() => { setEvalFor(null); setEvalResult(null); }}
        title={t("evaluateTitle")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => { setEvalFor(null); setEvalResult(null); }}>{t("close")}</Button>
            <Button
              variant="primary"
              icon={FlaskConical}
              loading={evaluateMutation.isPending}
              disabled={!aiAvailable || (evalMode === "custom" && !customCasesParsed().ok)}
              onClick={() => {
                if (!evalFor) return;
                setEvalError(null);
                if (evalMode === "default") {
                  evaluateMutation.mutate({ model: evalFor, cases: undefined });
                  return;
                }
                const parsed = customCasesParsed();
                if (!parsed.ok) {
                  setEvalError(parsed.error);
                  return;
                }
                evaluateMutation.mutate({ model: evalFor, cases: parsed.value });
              }}
              data-testid="model-evaluate-submit"
            >
              {t("runEvaluation")}
            </Button>
          </>
        }
      >
        {evalFor ? (
          <div className="stack">
            <div className="notice notice-warning">{t("evaluateSub")}</div>
            <div className="row wrap">
              <span className="mono" style={{ fontSize: 11 }}>{evalFor.name}</span>
              <Badge tone="neutral">{evalFor.provider_name ?? "—"}</Badge>
              {!aiAvailable ? <Badge tone="danger">{t("unavailable")}</Badge> : null}
            </div>
            <Field label={t("evaluation")} htmlFor={`${idPrefix}-eval-mode`}>
              <Select id={`${idPrefix}-eval-mode`} value={evalMode} onChange={(event) => { setEvalMode(event.target.value as "default" | "custom"); setEvalResult(null); }}>
                <option value="default">{t("defaultCases")}</option>
                <option value="custom">{t("customCases")}</option>
              </Select>
            </Field>
            {evalMode === "custom" ? (
              <Field
                label={t("casesJson")}
                htmlFor={`${idPrefix}-eval-cases`}
                hint={t("casesHint")}
                error={!customCasesParsed().ok ? customCasesParsed().error : undefined}
              >
                <Textarea
                  id={`${idPrefix}-eval-cases`}
                  className="mono"
                  rows={8}
                  value={evalCases}
                  onChange={(event) => setEvalCases(event.target.value)}
                  placeholder={'[{"name":"json_triage","prompt":"...","expect_json":true,"required_keys":["severity"]}]'}
                  spellCheck={false}
                  data-testid="model-eval-cases"
                />
              </Field>
            ) : null}
            {evalError ? <ErrorBanner message={evalError} /> : null}
            {evalResult ? (
              <div className="stack" data-testid="model-evaluation-result">
                <div className="row wrap">
                  <Badge tone={evalResult.failed === 0 ? "success" : "warning"}>{t("score")}: {formatPercent(evalResult.score * 100, 0)}</Badge>
                  <Badge tone="success">{t("passed")}: {evalResult.passed}</Badge>
                  <Badge tone="danger">{t("failed")}: {evalResult.failed}</Badge>
                  <span className="dim" style={{ fontSize: 11 }}>{formatDateTime(evalResult.evaluated_at, lang)}</span>
                </div>
                <div className="progress" style={{ height: 5 }}>
                  <span style={{ width: `${evalResult.total ? (evalResult.passed / evalResult.total) * 100 : 0}%`, background: "var(--success)" }} />
                </div>
                <div className="table-wrap">
                  <table className="data">
                    <thead>
                      <tr><th>{t("caseName")}</th><th style={{ width: 110 }}>{t("caseStatus")}</th><th>{t("result")}</th></tr>
                    </thead>
                    <tbody>
                      {evalResult.results.map((result) => (
                        <tr key={result.name}>
                          <td><span className="mono" style={{ fontSize: 10.5 }}>{result.name}</span></td>
                          <td><Badge tone={result.passed ? "success" : "danger"}>{result.passed ? t("passed") : result.status === "not_run" ? t("notRun") : t("failed")}</Badge></td>
                          <td>
                            {result.error ? <span style={{ color: "var(--danger)", fontSize: 11 }}>{result.error}</span> : (
                              <div className="chip-row">
                                {Object.entries(result.checks ?? {}).map(([check, ok]) => (
                                  <span className="tag" key={check} style={{ color: ok ? "var(--success)" : "var(--danger)" }}>{check}</span>
                                ))}
                                {result.output_excerpt ? <span style={{ fontSize: 10.5, color: "var(--dim)", display: "block", marginTop: 4 }}>{result.output_excerpt.slice(0, 140)}</span> : null}
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="chip-row">{evalResult.rubric.map((item) => <span className="tag" key={item}>{item}</span>)}</div>
              </div>
            ) : null}
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => { if (deleteTarget) deleteMutation.mutate(deleteTarget); }}
        title={t("deleteModel")}
        description={deleteTarget?.name}
        warning={t("deleteModelWarning")}
        confirmLabel={t("delete") ?? "Delete"}
        cancelLabel={t("cancel")}
        busy={deleteMutation.isPending}
        testId="model-delete-confirm"
      />
    </div>
  );
}

/* --------------------------------------------------------------- knowledge */

function KnowledgeTab({ canAdmin, canUse }: { canAdmin: boolean; canUse: boolean }) {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [page, setPage] = useState(1);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<KnowledgeDocument | null>(null);
  const [title, setTitle] = useState("");
  const [source, setSource] = useState("");
  const [docKind, setDocKind] = useState<KnowledgeKind>("runbook");
  const [version, setVersion] = useState("1");
  const [text, setText] = useState("");
  const [metadata, setMetadata] = useState("{}");
  const [formError, setFormError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [detailId, setDetailId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<KnowledgeDocument | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [topK, setTopK] = useState("5");
  const [searchKinds, setSearchKinds] = useState<KnowledgeKind[]>([]);
  const [searchResult, setSearchResult] = useState<KnowledgeSearchResponse | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);

  const listQuery = useQuery({
    queryKey: ["models", "knowledge", { q, kind, page }],
    queryFn: () =>
      api.get<Page<KnowledgeDocument>>("/ai/knowledge", {
        page,
        page_size: 25,
        q: q || undefined,
        kind: kind || undefined,
      }),
  });

  const detailQuery = useQuery({
    queryKey: ["models", "knowledge", "detail", detailId],
    queryFn: () => api.get<KnowledgeDocumentDetail>(`/ai/knowledge/${detailId}`),
    enabled: detailId !== null,
  });

  const metadataParsed = parseJsonRecord(metadata);

  const openCreate = () => {
    setEditing(null);
    setTitle("");
    setSource("");
    setDocKind("runbook");
    setVersion("1");
    setText("");
    setMetadata("{}");
    setFormError(null);
    setFieldErrors({});
    setFormOpen(true);
  };

  const openEdit = (document: KnowledgeDocument) => {
    setEditing(document);
    setTitle(document.title);
    setSource(document.source);
    setDocKind(document.kind as KnowledgeKind);
    setVersion(document.version);
    setText("");
    setMetadata(JSON.stringify(document.metadata ?? {}, null, 2));
    setFormError(null);
    setFieldErrors({});
    setDetailId(null);
    setFormOpen(true);
  };

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<KnowledgeDocument>("/ai/knowledge", body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(t("docCreated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["models", "knowledge"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const updateMutation = useMutation({
    mutationFn: (payload: { id: string; body: Record<string, unknown> }) => api.patch<KnowledgeDocument>(`/ai/knowledge/${payload.id}`, payload.body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(t("docUpdated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["models", "knowledge"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (document: KnowledgeDocument) => api.delete<void>(`/ai/knowledge/${document.id}`),
    onSuccess: async () => {
      setDeleteTarget(null);
      setDetailId(null);
      toast.push(t("docDeleted"), "success");
      await queryClient.invalidateQueries({ queryKey: ["models", "knowledge"] });
    },
    onError: (error) => {
      setDeleteTarget(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const searchMutation = useMutation({
    mutationFn: () =>
      api.post<KnowledgeSearchResponse>("/ai/knowledge/search", {
        query: searchQuery.trim(),
        top_k: Math.min(10, Math.max(1, Number(topK) || 5)),
        ...(searchKinds.length ? { kinds: searchKinds } : {}),
      }),
    onSuccess: (result) => {
      setSearchResult(result);
      setSearchError(null);
    },
    onError: (error) => {
      setSearchResult(null);
      setSearchError(errorMessage(error));
    },
  });

  const submit = () => {
    setFormError(null);
    if (title.trim().length === 0) {
      setFormError(t("title"));
      return;
    }
    if (source.trim().length === 0) {
      setFormError(t("source"));
      return;
    }
    if (!metadataParsed.ok) {
      setFormError(metadataParsed.error);
      return;
    }
    if (!editing && text.trim().length < 10) {
      setFormError(t("knowledgeTextMin"));
      return;
    }
    if (editing) {
      updateMutation.mutate({
        id: editing.id,
        body: {
          title: title.trim(),
          source: source.trim(),
          kind: docKind,
          version: version.trim() || "1",
          ...(text.trim() ? { text } : {}),
          metadata: metadataParsed.value,
        },
      });
    } else {
      createMutation.mutate({
        title: title.trim(),
        source: source.trim(),
        kind: docKind,
        version: version.trim() || "1",
        text,
        metadata: metadataParsed.value,
      });
    }
  };

  const columns: Column<KnowledgeDocument>[] = [
    {
      key: "title",
      header: t("title"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div className="primary-cell">{row.title}</div>
          <div className="cell-sub">{row.source} · v{row.version}</div>
          <div className="cell-sub mono" style={{ fontSize: 9.5 }}>{t("checksum")}: {row.checksum.slice(0, 12)}…</div>
        </div>
      ),
    },
    { key: "kind", header: t("kind"), width: "110px", render: (row) => <Badge tone="neutral">{humanize(row.kind)}</Badge> },
    {
      key: "chunks",
      header: t("chunks"),
      width: "90px",
      align: "right",
      render: (row) => <span className="mono">{formatNumber(row.chunk_count)}</span>,
    },
    {
      key: "updated",
      header: t("updatedAt"),
      width: "150px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.updated_at, lang)}</span>,
    },
    {
      key: "actions",
      header: t("common.actions"),
      width: "200px",
      align: "right",
      render: (row) => (
        <div className="row wrap" style={{ gap: 3, justifyContent: "flex-end" }}>
          <Button size="sm" variant="ghost" onClick={() => setDetailId(row.id)} data-testid="knowledge-detail">{t("detail")}</Button>
          {canAdmin ? (
            <>
              <Button size="sm" variant="ghost" onClick={() => openEdit(row)} data-testid="knowledge-edit">{t("common.edit")}</Button>
              <Button size="sm" variant="ghost" icon={Trash2} aria-label={t("deleteDocument")} onClick={() => setDeleteTarget(row)} data-testid="knowledge-delete" />
            </>
          ) : null}
        </div>
      ),
    },
  ];

  return (
    <div className="stack" data-testid="models-knowledge">
      <Card
        title={t("knowledgeTitle")}
        subtitle={t("knowledgeSub")}
        actions={canAdmin ? <Button size="sm" variant="primary" icon={Plus} onClick={openCreate} data-testid="knowledge-create-open">{t("newDocument")}</Button> : undefined}
        bodyClassName=""
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap" style={{ gap: 8 }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              <SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder={t("searchDocs")} ariaLabel={t("searchDocs")} />
            </div>
            <Select value={kind} onChange={(event) => { setKind(event.target.value); setPage(1); }} aria-label={t("kindFilter")} style={{ width: 160 }} data-testid="knowledge-kind-filter">
              <option value="">{t("all")}</option>
              {KNOWLEDGE_KINDS.map((value) => <option key={value} value={value}>{value}</option>)}
            </Select>
            <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("refresh")} onClick={() => void listQuery.refetch()} />
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
                  icon={BookText}
                  title={t("noDocuments")}
                  description={t("noDocumentsHint")}
                  action={canAdmin ? <Button size="sm" onClick={openCreate}>{t("newDocument")}</Button> : undefined}
                />
              }
            />
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={listQuery.data?.meta} onPage={setPage} />
            </div>
          </>
        )}
      </Card>

      <Card title={t("searchKnowledge")} subtitle={t("searchHint")}>
        <div className="stack">
          {!canUse ? <div className="notice">{t("noUse")}</div> : null}
          <div className="row wrap" style={{ gap: 8, alignItems: "flex-end" }}>
            <div style={{ flex: 1, minWidth: 220 }}>
              <Field label={t("query")} htmlFor={`${idPrefix}-search`} required>
                <Input id={`${idPrefix}-search`} value={searchQuery} maxLength={1000} onChange={(event) => setSearchQuery(event.target.value)} placeholder={t("searchHint")} />
              </Field>
            </div>
            <Field label={t("topK")} htmlFor={`${idPrefix}-topk`}>
              <Select id={`${idPrefix}-topk`} value={topK} onChange={(event) => setTopK(event.target.value)} style={{ width: 90 }}>
                {[1, 3, 5, 10].map((value) => <option key={value} value={String(value)}>{value}</option>)}
              </Select>
            </Field>
            <Button
              variant="primary"
              icon={Search}
              loading={searchMutation.isPending}
              disabled={!canUse || searchQuery.trim().length < 2}
              onClick={() => {
                setSearchError(null);
                searchMutation.mutate();
              }}
              data-testid="knowledge-search-submit"
            >
              {t("searchKnowledge")}
            </Button>
          </div>
          <div className="chip-row">
            {KNOWLEDGE_KINDS.map((value) => {
              const checked = searchKinds.includes(value);
              return (
                <label className="checkbox" key={value}>
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() =>
                      setSearchKinds((current) => (checked ? current.filter((item) => item !== value) : [...current, value]))
                    }
                  />
                  {value}
                </label>
              );
            })}
          </div>
          {searchError ? <ErrorBanner message={searchError} /> : null}
          {searchResult ? (
            <div className="stack" data-testid="knowledge-search-result">
              <div className="row wrap">
                <Badge tone="accent">{t("results")}: {formatNumber(searchResult.count)}</Badge>
                <Badge tone="neutral">{t("scannedChunks")}: {formatNumber(searchResult.scanned_chunks)}</Badge>
                {searchResult.embedding_models.map((model) => <span className="tag" key={model}>{model}</span>)}
              </div>
              {searchResult.results.length === 0 ? (
                <EmptyState icon={Search} title={t("noResults")} description={t("noResultsHint")} />
              ) : (
                <div className="stack">
                  {searchResult.results.map((result) => (
                    <div className="list-item" key={result.chunk_id}>
                      <div style={{ minWidth: 0 }}>
                        <div className="row wrap" style={{ gap: 5 }}>
                          <span className="item-title">{result.title}</span>
                          <Badge tone="neutral">{humanize(result.kind)}</Badge>
                          <span className="tag">{t("relevance")} {(result.score * 100).toFixed(1)}%</span>
                        </div>
                        <div className="item-sub">{result.source} · chunk {result.ordinal}</div>
                        <p style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 4 }}>{result.snippet}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {searchResult.citations.length ? (
                <div>
                  <div className="section-label">{t("citations")}</div>
                  <div className="stack" style={{ gap: 4 }}>
                    {searchResult.citations.map((citation) => (
                      <div className="tag" key={citation.chunk_id} style={{ whiteSpace: "normal", justifyContent: "flex-start" }}>
                        {citation.title} · {citation.source} · {citation.chunk_id.slice(0, 8)} · {(citation.score * 100).toFixed(1)}%
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </Card>

      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={editing ? t("editDocument") : t("newDocument")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setFormOpen(false)} disabled={createMutation.isPending || updateMutation.isPending}>{t("cancel")}</Button>
            <Button variant="primary" loading={createMutation.isPending || updateMutation.isPending} onClick={submit} data-testid="knowledge-submit">
              {editing ? t("save") : t("newDocument")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="form-grid">
            <Field label={t("title")} htmlFor={`${idPrefix}-doc-title`} error={fieldErrors.title} required>
              <Input id={`${idPrefix}-doc-title`} value={title} maxLength={300} onChange={(event) => setTitle(event.target.value)} />
            </Field>
            <Field label={t("source")} htmlFor={`${idPrefix}-doc-source`} error={fieldErrors.source} required>
              <Input id={`${idPrefix}-doc-source`} value={source} maxLength={500} onChange={(event) => setSource(event.target.value)} placeholder="runbook://soc/..." />
            </Field>
            <Field label={t("kind")} htmlFor={`${idPrefix}-doc-kind`}>
              <Select id={`${idPrefix}-doc-kind`} value={docKind} onChange={(event) => setDocKind(event.target.value as KnowledgeKind)}>
                {KNOWLEDGE_KINDS.map((value) => <option key={value} value={value}>{value}</option>)}
              </Select>
            </Field>
            <Field label={t("version")} htmlFor={`${idPrefix}-doc-version`}>
              <Input id={`${idPrefix}-doc-version`} value={version} maxLength={40} onChange={(event) => setVersion(event.target.value)} />
            </Field>
            <div className="span-2">
              <Field
                label={t("text")}
                htmlFor={`${idPrefix}-doc-text`}
                hint={editing ? t("optional") : t("knowledgeTextMin")}
                error={fieldErrors.text}
                required={!editing}
              >
                <Textarea
                  id={`${idPrefix}-doc-text`}
                  rows={8}
                  value={text}
                  maxLength={200_000}
                  onChange={(event) => setText(event.target.value)}
                  data-testid="knowledge-text"
                />
              </Field>
            </div>
            <div className="span-2">
              <JsonEditor
                id={`${idPrefix}-doc-meta`}
                label={t("metadata")}
                value={metadata}
                onChange={setMetadata}
                error={!metadataParsed.ok ? metadataParsed.error : fieldErrors.metadata}
              />
            </div>
          </div>
          {formError ? <ErrorBanner message={formError} /> : null}
        </div>
      </Modal>

      <Modal
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        title={t("docDetail")}
        size="lg"
        footer={<Button onClick={() => setDetailId(null)}>{t("close")}</Button>}
      >
        {detailQuery.isLoading ? (
          <div className="skeleton skeleton-chart" />
        ) : detailQuery.isError ? (
          <ErrorBanner message={errorMessage(detailQuery.error)} onRetry={() => void detailQuery.refetch()} />
        ) : detailQuery.data ? (
          <div className="stack" data-testid="knowledge-detail-panel">
            <h3 style={{ fontSize: 15 }}>{detailQuery.data.title}</h3>
            <MetaRows
              items={[
                { label: t("source"), value: detailQuery.data.source },
                { label: t("kindFilter"), value: humanize(detailQuery.data.kind) },
                { label: t("version"), value: detailQuery.data.version },
                { label: t("chunks"), value: formatNumber(detailQuery.data.chunk_count) },
                { label: t("checksum"), value: <span className="mono" style={{ fontSize: 10 }}>{detailQuery.data.checksum}</span> },
                { label: t("updatedAt"), value: formatDateTime(detailQuery.data.updated_at, lang) },
              ]}
            />
            <div>
              <div className="section-label">{t("chunks")}</div>
              {detailQuery.data.chunks.length === 0 ? (
                <span className="dim" style={{ fontSize: 11 }}>{t("noChunks")}</span>
              ) : (
                <div className="stack" style={{ maxHeight: 320, overflowY: "auto" }}>
                  {detailQuery.data.chunks.map((chunk) => (
                    <div className="list-item" key={chunk.id}>
                      <div style={{ minWidth: 0 }}>
                        <div className="row wrap" style={{ gap: 5 }}>
                          <span className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>#{chunk.ordinal}</span>
                          <span className="tag">{chunk.tokens} {t("chunkTokens")}</span>
                          <span className="tag">{chunk.embedding_model} · {chunk.embedding_dimension}d</span>
                        </div>
                        <p style={{ fontSize: 11.5, color: "var(--text-secondary)", marginTop: 4 }}>{chunk.text.slice(0, 400)}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => { if (deleteTarget) deleteMutation.mutate(deleteTarget); }}
        title={t("deleteDocument")}
        description={deleteTarget?.title}
        warning={t("deleteDocumentWarning")}
        confirmLabel={t("delete") ?? "Delete"}
        cancelLabel={t("cancel")}
        busy={deleteMutation.isPending}
        testId="knowledge-delete-confirm"
      />
    </div>
  );
}

/* ------------------------------------------------------------------- usage */

function UsageTab() {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const [days, setDays] = useState("7");

  const usageQuery = useQuery({
    queryKey: ["models", "usage", days],
    queryFn: () => api.get<UsageResponse>("/ai/usage", { days: Number(days) }),
  });

  const healthQuery = useQuery({
    queryKey: ["models", "health"],
    queryFn: () => api.get<AIHealth>("/ai/health"),
  });

  const usage = usageQuery.data;
  const successRate = usage && usage.totals.count > 0 ? (usage.totals.success / usage.totals.count) * 100 : null;

  const bucketColumns = (label: string): Column<{ name: string; bucket: UsageBucket }>[] => [
    { key: "name", header: label, render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.name}</span> },
    { key: "count", header: t("invocations"), width: "100px", align: "right", render: (row) => <span className="mono">{formatNumber(row.bucket.count)}</span> },
    { key: "success", header: t("passed"), width: "90px", align: "right", render: (row) => <span className="mono" style={{ color: "var(--success)" }}>{formatNumber(row.bucket.success)}</span> },
    { key: "error", header: t("failed"), width: "90px", align: "right", render: (row) => <span className="mono" style={{ color: row.bucket.error ? "var(--danger)" : "var(--dim)" }}>{formatNumber(row.bucket.error)}</span> },
    {
      key: "tokens",
      header: t("tokens"),
      width: "150px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatNumber(row.bucket.prompt_tokens)} / {formatNumber(row.bucket.completion_tokens)}</span>,
    },
    {
      key: "latency",
      header: `${t("avgLatency")} / ${t("p95Latency")}`,
      width: "140px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{Math.round(row.bucket.avg_latency_ms)} / {Math.round(row.bucket.p95_latency_ms)} ms</span>,
    },
  ];

  const taskRows = Object.entries(usage?.by_task ?? {}).map(([name, bucket]) => ({ name, bucket }));
  const modelRows = Object.entries(usage?.by_model ?? {}).map(([name, bucket]) => ({ name, bucket }));
  const statusEntries = Object.entries(usage?.by_status ?? {});

  return (
    <div className="stack" data-testid="models-usage">
      <Card
        title={t("usageTitle")}
        subtitle={t("usageSub")}
        actions={
          <div className="row" style={{ gap: 6 }}>
            <Select value={days} onChange={(event) => setDays(event.target.value)} aria-label={t("window")} style={{ width: 130 }} data-testid="usage-days">
              <option value="7">{t("days7")}</option>
              <option value="30">{t("days30")}</option>
              <option value="90">{t("days90")}</option>
            </Select>
            <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("refresh")} onClick={() => { void usageQuery.refetch(); void healthQuery.refetch(); }} />
          </div>
        }
      >
        {usageQuery.isError ? (
          <ErrorBanner message={errorMessage(usageQuery.error)} onRetry={() => void usageQuery.refetch()} />
        ) : usageQuery.isLoading ? (
          <div className="skeleton skeleton-chart" />
        ) : usage && usage.invocations === 0 ? (
          <EmptyState icon={Gauge} title={t("noUsage")} description={t("noUsageHint")} />
        ) : usage ? (
          <div className="stack">
            <div className="kpi-grid">
              <div className="card kpi">
                <div className="kpi-label"><Activity size={13} style={{ color: "var(--accent)" }} />{t("invocations")}</div>
                <div className="kpi-value">{formatNumber(usage.totals.count)}</div>
                <div className="kpi-foot">{t("since")}: {formatDateTime(usage.since, lang)}</div>
              </div>
              <div className="card kpi">
                <div className="kpi-label"><CheckCircle2 size={13} style={{ color: "var(--success)" }} />{t("successRate")}</div>
                <div className="kpi-value kpi-success">{successRate === null ? "—" : formatPercent(successRate, 1)}</div>
                <div className="kpi-foot">{t("failed")}: {formatNumber(usage.totals.error)}</div>
              </div>
              <div className="card kpi">
                <div className="kpi-label"><Layers size={13} style={{ color: "var(--warning)" }} />{t("tokens")}</div>
                <div className="kpi-value kpi-warning">{formatNumber(usage.totals.prompt_tokens + usage.totals.completion_tokens)}</div>
                <div className="kpi-foot">{t("promptTokens")}: {formatNumber(usage.totals.prompt_tokens)} · {t("completionTokens")}: {formatNumber(usage.totals.completion_tokens)}</div>
              </div>
              <div className="card kpi">
                <div className="kpi-label"><Gauge size={13} style={{ color: "var(--muted)" }} />{t("avgLatency")}</div>
                <div className="kpi-value">{Math.round(usage.totals.avg_latency_ms)}<small> ms</small></div>
                <div className="kpi-foot">p95 {Math.round(usage.totals.p95_latency_ms)} ms</div>
              </div>
            </div>
            <div>
              <div className="section-label">{t("byStatus")}</div>
              <div className="chip-row">
                {statusEntries.length === 0 ? <span className="dim" style={{ fontSize: 11 }}>—</span> : statusEntries.map(([name, count]) => (
                  <Badge key={name} tone={name === "success" ? "success" : name === "error" ? "danger" : "neutral"}>{name} {formatNumber(count)}</Badge>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </Card>

      {usage && usage.invocations > 0 ? (
        <div className="grid-2">
          <Card title={t("byTask")} bodyClassName="">
            <DataTable columns={bucketColumns(t("byTask"))} rows={taskRows} rowKey={(row) => row.name} empty={<EmptyState title={t("noUsage")} />} />
          </Card>
          <Card title={t("byModel")} bodyClassName="">
            <DataTable columns={bucketColumns(t("byModel"))} rows={modelRows} rowKey={(row) => row.name} empty={<EmptyState title={t("noUsage")} />} />
          </Card>
        </div>
      ) : null}

      <Card title={t("providerHealth")} subtitle={t("gatewayStatus")}>
        {healthQuery.isError ? (
          <ErrorBanner message={errorMessage(healthQuery.error)} onRetry={() => void healthQuery.refetch()} />
        ) : healthQuery.isLoading ? (
          <div className="skeleton skeleton-row" />
        ) : healthQuery.data ? (
          <div className="stack">
            <div className="row wrap">
              <Badge tone={healthQuery.data.ai_available ? "success" : "danger"}>{healthQuery.data.ai_available ? t("available") : t("unavailable")}</Badge>
              <Badge tone="neutral">{t("providersTotal")}: {healthQuery.data.providers_total}</Badge>
              <Badge tone="neutral">{t("providersHealthy")}: {healthQuery.data.providers_healthy}</Badge>
              <Badge tone="neutral">{t("knowledgeDocs")}: {healthQuery.data.knowledge.documents}</Badge>
              <Badge tone="neutral">{t("errorRate")}: {formatPercent(healthQuery.data.invocations_24h.error_rate * 100, 2)}</Badge>
            </div>
            {healthQuery.data.providers.length === 0 ? (
              <span className="dim" style={{ fontSize: 11 }}>{t("unavailableHint")}</span>
            ) : (
              <div className="stack" style={{ gap: 4 }}>
                {healthQuery.data.providers.map((provider) => (
                  <div className="list-item" key={provider.id}>
                    <div>
                      <div className="row" style={{ gap: 6 }}>
                        <StatusDot status={provider.health_status} />
                        <span className="item-title">{provider.name}</span>
                        <span className="tag">{provider.kind}</span>
                        <Badge tone={provider.enabled ? "neutral" : "neutral"}>{provider.enabled ? t("enabled") : t("statusDisabled")}</Badge>
                      </div>
                      <div className="item-sub">
                        {humanize(provider.health_status)} · {relativeTime(provider.last_health_at, lang)}
                        {provider.last_health_error ? ` · ${provider.last_health_error}` : ""}
                      </div>
                    </div>
                    <div className="item-side">
                      <Badge tone={statusTone(provider.health_status)}>{humanize(provider.health_status)}</Badge>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : null}
      </Card>
    </div>
  );
}

/* -------------------------------------------------------------------- page */

export function ModelsPage() {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const { can, session } = useAuth();
  const [tab, setTab] = useState<TabKey>("providers");

  const canRead = can("ai:read");
  const canAdmin = can("ai:admin");
  const canUse = can("ai:use");
  const isPlatformAdmin = session?.user.is_platform_admin ?? false;

  const healthQuery = useQuery({
    queryKey: ["models", "health"],
    queryFn: () => api.get<AIHealth>("/ai/health"),
    enabled: canRead,
  });

  const health = healthQuery.data;
  const available = health?.ai_available ?? false;

  const tabs = useMemo(
    () => [
      { key: "providers" as TabKey, label: t("tabProviders"), count: health?.providers_total },
      { key: "models" as TabKey, label: t("tabModels") },
      { key: "knowledge" as TabKey, label: t("tabKnowledge"), count: health?.knowledge.documents },
      { key: "usage" as TabKey, label: t("tabUsage"), count: health?.invocations_24h.total },
    ],
    [health, t],
  );

  if (!canRead) {
    return (
      <div className="animate-in" data-testid="page-models">
        <PageHeader eyebrow={t("eyebrow")} title={t("title")} subtitle={t("subtitle")} />
        <Card><EmptyState icon={Lock} title={t("noPermission")} /></Card>
      </div>
    );
  }

  if (healthQuery.isLoading) return <PageSkeleton />;

  return (
    <div className="animate-in" data-testid="page-models">
      <PageHeader
        eyebrow={t("eyebrow")}
        title={t("title")}
        subtitle={t("subtitle")}
        actions={
          <>
            <Badge tone={available ? "success" : "danger"}>
              {available ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
              {available ? t("available") : t("unavailable")}
            </Badge>
            <Badge tone="accent"><HardDrive size={11} /> {t("localFirst")}</Badge>
            <Button variant="ghost" icon={RefreshCw} aria-label={t("refresh")} onClick={() => void healthQuery.refetch()} />
          </>
        }
      />

      {healthQuery.isError ? (
        <ErrorBanner message={errorMessage(healthQuery.error)} onRetry={() => void healthQuery.refetch()} />
      ) : !available ? (
        <div className="notice notice-warning" style={{ marginBottom: 12 }} data-testid="models-unavailable">
          <AlertTriangle size={14} style={{ flex: "0 0 auto" }} />
          <span>{t("unavailableHint")}</span>
        </div>
      ) : null}

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <div className="card kpi">
          <div className="kpi-label"><Server size={13} style={{ color: "var(--accent)" }} />{t("providersHealthy")}</div>
          <div className="kpi-value kpi-accent">{formatNumber(health?.providers_healthy ?? 0)}<small> / {formatNumber(health?.providers_total ?? 0)}</small></div>
          <div className="kpi-foot">{t("providersTotal")}: {formatNumber(health?.providers_total ?? 0)}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label"><Cpu size={13} style={{ color: "var(--muted)" }} />{t("modelsAvailable")}</div>
          <div className="kpi-value">{formatNumber(Object.values(health?.models ?? {}).reduce((total, value) => total + value, 0))}</div>
          <div className="kpi-foot">
            {Object.entries(health?.models ?? {}).map(([key, value]) => `${humanize(key)} ${value}`).join(" · ") || "—"}
          </div>
        </div>
        <div className="card kpi">
          <div className="kpi-label"><BookText size={13} style={{ color: "var(--warning)" }} />{t("knowledgeDocs")}</div>
          <div className="kpi-value kpi-warning">{formatNumber(health?.knowledge.documents ?? 0)}</div>
          <div className="kpi-foot">{t("chunks")}: {formatNumber(health?.knowledge.chunks ?? 0)}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label"><Gauge size={13} style={{ color: "var(--danger)" }} />{t("errorRate")}</div>
          <div className="kpi-value">
            {formatPercent((health?.invocations_24h.error_rate ?? 0) * 100, 2)}
          </div>
          <div className="kpi-foot">
            {t("invocations")}: {formatNumber(health?.invocations_24h.total ?? 0)} · {healthQuery.data ? formatDateTime(healthQuery.data.generated_at, lang) : "—"}
          </div>
        </div>
      </div>

      <div style={{ marginBottom: 12 }}>
        <Tabs<TabKey> ariaLabel={t("title")} items={tabs} value={tab} onChange={setTab} />
      </div>

      {tab === "providers" ? <ProvidersTab canAdmin={canAdmin} isPlatformAdmin={isPlatformAdmin} aiAvailable={available} /> : null}
      {tab === "models" ? <ModelsTab canAdmin={canAdmin} canUse={canUse} aiAvailable={available} /> : null}
      {tab === "knowledge" ? <KnowledgeTab canAdmin={canAdmin} canUse={canUse} /> : null}
      {tab === "usage" ? <UsageTab /> : null}

      <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
        <ShieldCheck size={13} style={{ flex: "0 0 auto", color: "var(--success)" }} />
        <span>{t("localFirstHint")} {t("apiKeyNeverShown")}</span>
      </div>
    </div>
  );
}

export default ModelsPage;
