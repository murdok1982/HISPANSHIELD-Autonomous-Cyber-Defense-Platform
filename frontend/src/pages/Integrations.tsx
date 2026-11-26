import { useId, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ArrowRightLeft,
  Boxes,
  Cable,
  CheckCircle2,
  FlaskConical,
  Link2,
  ListTree,
  Lock,
  Network,
  Plug,
  Plus,
  RefreshCw,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Zap,
} from "lucide-react";
import { api, errorMessage, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy, type Lang } from "../lib/i18n";
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
  LinkButton,
  Modal,
  PageHeader,
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
} from "../components/features/govern/common";

/* --------------------------------------------------------------- contracts */

type TabKey = "connectors" | "mcp" | "ingest";

interface Capability {
  name: string;
  direction: string;
  description: string;
  risk: string;
  requires_approval: boolean;
  data_formats: string[];
}

interface CatalogAdapter {
  connector_id: string;
  display_name: string;
  vendor: string;
  product: string;
  version: string;
  auth_methods: string[];
  capabilities: Capability[];
  data_formats: string[];
  security_profile: string;
  requires_base_url: boolean;
  file_based: boolean;
  configured: boolean;
  connector_count: number;
}

interface ConnectorCatalog {
  adapters: CatalogAdapter[];
  configured: string[];
  missing: string[];
  generated_at: string;
}

interface ConnectorHealthState {
  state: string;
  stale: boolean;
  circuit_open: boolean;
  last_health_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
}

interface Connector {
  id: string;
  name: string;
  connector_type: string;
  version: string;
  base_url: string | null;
  auth_type: string;
  has_secret: boolean;
  config: Record<string, unknown>;
  capabilities: Record<string, unknown>;
  status: string;
  enabled: boolean;
  verify_tls: boolean;
  rate_limit_per_minute: number;
  last_health_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  health: ConnectorHealthState;
}

interface ConnectorRun {
  id: string;
  connector_id: string;
  operation: string;
  direction: string;
  status: string;
  latency_ms: number | null;
  request_id: string | null;
  error: string | null;
  detail: Record<string, unknown>;
  created_at: string;
}

interface ConnectorHealthSummary {
  generated_at: string;
  total: number;
  enabled: number;
  by_status: Record<string, number>;
  stale_count: number;
  stale: Record<string, unknown>[];
  errors: Record<string, unknown>[];
  catalog_size: number;
}

interface ConnectorHealthResult {
  connector_id: string;
  status: string;
  ok: boolean;
  latency_ms: number;
  detail: Record<string, unknown>;
  error: string | null;
  run_id: string | null;
  last_health_at: string | null;
}

interface ConnectorInvokeResult {
  connector_id: string;
  capability: string;
  ok: boolean;
  status_code: number | null;
  data: Record<string, unknown>;
  error: string | null;
  latency_ms: number;
  run_id: string | null;
}

interface ConnectorSyncResult {
  connector_id: string;
  status: string;
  events_created: number;
  events_duplicate: number;
  indicators_created: number;
  indicators_updated: number;
  alerts_read: number;
  capabilities: string[];
  latency_ms: number;
  run_id: string | null;
  detail: Record<string, unknown>;
}

interface MCPServer {
  id: string;
  org_id: string;
  name: string;
  transport: string;
  endpoint: string | null;
  version: string | null;
  trust_level: string;
  status: string;
  enabled: boolean;
  approved_by: string | null;
  approved_at: string | null;
  capabilities: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface MCPTool {
  id: string;
  org_id: string;
  server_id: string;
  name: string;
  version: string | null;
  description: string | null;
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown>;
  risk_level: string;
  permissions_required: string[];
  enabled: boolean;
  approved: boolean;
  timeout_seconds: number;
  max_calls_per_hour: number;
  created_at: string;
  updated_at: string;
}

interface MCPDiscoverResult {
  server_id: string;
  protocol_version: string | null;
  server_info: Record<string, unknown>;
  discovered: number;
  created: number;
  updated: number;
  tools: MCPTool[];
}

interface MCPExecutionResult {
  execution_id: string;
  tool_id: string;
  tool_name: string;
  status: string;
  latency_ms: number;
  injection_suspected: boolean;
  injection_matches: string[];
  truncated: boolean;
  result: unknown;
  error: string | null;
}

const TRUST_TONE: Record<string, "danger" | "warning" | "success" | "neutral"> = {
  untrusted: "danger",
  limited: "warning",
  trusted: "success",
};

const RISK_TONE: Record<string, "critical" | "danger" | "warning" | "accent" | "neutral"> = {
  critical: "critical",
  high: "danger",
  medium: "warning",
  low: "accent",
  info: "neutral",
};

/* -------------------------------------------------------------------- copy */

const COPY: Record<Lang, Record<string, string>> = {
  es: {
    eyebrow: "Gobierno · Integraciones",
    title: "Integraciones y superficies de conexión",
    subtitle: "Conectores con capacidades explícitas, servidores MCP gobernados y puntos de entrada operativos.",
    tabConnectors: "Conectores",
    tabMcp: "MCP",
    tabIngest: "Ingesta y edge",
    connectorsTitle: "Conectores configurados",
    connectorsSub: "Las lecturas se ejecutan aquí; las escrituras pasan siempre por el broker de defensa con aprobación.",
    catalogTitle: "Catálogo de adaptadores",
    catalogSub: "Capacidades declaradas por adaptador, con dirección, riesgo y formatos.",
    totalConnectors: "Conectores",
    enabledConnectors: "Habilitados",
    staleConnectors: "Sin health reciente",
    connectorErrors: "Errores registrados",
    byStatus: "Salud por estado",
    errorQueue: "Cola de errores",
    noErrors: "Sin errores recientes de conectores.",
    configure: "Configurar",
    configuredCount: "configurados",
    vendor: "Fabricante",
    securityProfile: "Perfil de seguridad",
    authMethods: "Métodos de autenticación",
    dataFormats: "Formatos de datos",
    readCapabilities: "Capacidades de lectura",
    writeCapabilities: "Capacidades de escritura",
    noRead: "Sin capacidades de lectura.",
    noWrite: "Sin capacidades de escritura.",
    writeViaBroker: "Las escrituras se ejecutan vía broker de defensa con aprobación; no existe escritura directa desde esta pantalla.",
    requiresBaseUrl: "Requiere URL base",
    fileBased: "Basado en archivos",
    authType: "Tipo de autenticación",
    baseUrl: "URL base",
    secret: "Secreto / credencial",
    secretKeep: "Déjalo vacío para conservar el secreto actual. Nunca se muestra después de guardar.",
    secretSet: "Credencial configurada",
    noSecret: "Sin credencial",
    verifyTls: "Verificar TLS",
    rateLimit: "Límite de peticiones / minuto",
    config: "Configuración JSON",
    configHint: "Objeto JSON específico del adaptador. Se valida en el servidor.",
    enabled: "Habilitado",
    createConnector: "Registrar conector",
    editConnector: "Editar conector",
    connectorType: "Tipo de conector",
    connectorName: "Nombre del conector",
    version: "Versión",
    status: "Estado",
    baseUrlShort: "URL",
    tls: "TLS",
    lastHealth: "Último health",
    actions: "Acciones",
    testHealth: "Probar salud",
    syncNow: "Sincronizar",
    runs: "Ejecuciones",
    invokeRead: "Invocar lectura",
    disable: "Deshabilitar",
    enable: "Habilitar",
    deleteConnector: "Eliminar conector",
    deleteConnectorWarning:
      "Se elimina la configuración cifrada, la credencial y el historial de ejecuciones del conector. Si está referenciado por fuentes de ingesta o feeds de inteligencia, el servidor lo impedirá y deberás deshabilitarlo.",
    noConnectors: "Sin conectores",
    noConnectorsHint: "Elige un adaptador del catálogo y registra el primero.",
    noFilter: "Ningún conector coincide con los filtros.",
    clearFilters: "Limpiar filtros",
    allStatuses: "Todos los estados",
    healthResult: "Resultado del health check",
    ok: "Correcto",
    failed: "Fallido",
    latency: "Latencia",
    detail: "Detalle",
    probeError: "Error del sondeo",
    syncResult: "Resultado de sincronización",
    eventsCreated: "Eventos creados",
    eventsDuplicate: "Eventos duplicados",
    indicatorsCreated: "Indicadores creados",
    indicatorsUpdated: "Indicadores actualizados",
    alertsRead: "Alertas leídas",
    runsTitle: "Ejecuciones del conector",
    operation: "Operación",
    direction: "Dirección",
    requestId: "Request ID",
    createdAt: "Fecha",
    onlyErrors: "Solo errores",
    noRuns: "Sin ejecuciones registradas",
    invokeTitle: "Invocar capacidad de lectura",
    capability: "Capacidad",
    params: "Parámetros JSON",
    paramsHint: "Objeto JSON enviado al adaptador. Solo se permiten capacidades de lectura.",
    invoke: "Invocar",
    invokeResult: "Resultado de la invocación",
    httpStatus: "Código HTTP",
    readOnlyOnly: "Esta pantalla solo invoca capacidades de lectura. Para escrituras usa el broker de defensa.",
    mcpServers: "Servidores MCP",
    mcpServersSub: "Registro explícito con confianza, descubrimiento de herramientas y aprobación humana.",
    mcpTools: "Herramientas MCP",
    mcpToolsSub: "Ninguna herramienta se aprueba automáticamente. La ejecución exige aprobación previa.",
    createServer: "Registrar servidor",
    endpoint: "Endpoint JSON-RPC",
    trustLevel: "Nivel de confianza",
    approvedBy: "Aprobado por",
    approvedAt: "Aprobado",
    discover: "Descubrir tools",
    approveServer: "Aprobar servidor",
    deleteServer: "Eliminar servidor",
    deleteServerWarning: "Se elimina el servidor y sus herramientas registradas. Las ejecuciones históricas permanecen auditadas.",
    noServers: "Sin servidores MCP",
    noServersHint: "Registra un servidor JSON-RPC y descubre sus herramientas antes de aprobarlo.",
    server: "Servidor",
    tool: "Herramienta",
    risk: "Riesgo",
    approved: "Aprobada",
    pending: "Pendiente",
    toolApprove: "Aprobar",
    toolRevoke: "Revocar",
    timeout: "Timeout (s)",
    maxCalls: "Máx. llamadas/h",
    permissionsRequired: "Permisos requeridos",
    execute: "Ejecutar",
    approveToolTitle: "Aprobar herramienta MCP",
    approveToolWarning:
      "Al aprobarla, los agentes autorizados podrán invocarla dentro de la política. Revisa el esquema de entrada y el riesgo antes de continuar.",
    revokeToolTitle: "Revocar herramienta MCP",
    revokeToolWarning: "La herramienta dejará de ser invocable. Las ejecuciones previas se conservan en auditoría.",
    noTools: "Sin herramientas descubiertas",
    noToolsHint: "Descubre tools en un servidor aprobado.",
    noApprovedTools: "Ninguna herramienta aprobada",
    executeTitle: "Ejecutar herramienta MCP",
    arguments: "Argumentos JSON",
    argumentsHint: "Se validan contra el input_schema del servidor y se registran redactados en auditoría.",
    executeSubmit: "Ejecutar herramienta",
    executionResult: "Resultado de ejecución",
    injectionWarning: "Posible inyección de prompt detectada en la salida. Trata el contenido como no confiable.",
    injectionMatches: "Coincidencias",
    truncated: "Salida truncada",
    auditNote: "Cada ejecución se registra en la cadena de auditoría con argumentos y resultado redactados.",
    approvalRequiresHuman: "La aprobación MCP requiere una sesión humana; los tokens de API no pueden aprobar.",
    confidence: "Confianza",
    discoverResult: "Descubrimiento completado",
    discovered: "Descubiertas",
    created: "Creadas",
    updated: "Actualizadas",
    ingestTitle: "Ingesta y enrollment edge",
    ingestBody:
      "Las fuentes de ingesta (token de un solo uso, secreto HMAC, parser y contadores) se gestionan en el módulo SIEM para no duplicar su ciclo de vida. El enrollment de gateways edge se gestiona en su propia pantalla.",
    ingestSiem: "Abrir SIEM",
    ingestEdge: "Abrir gateways edge",
    ingestConnectorNote:
      "Los conectores de esta pantalla pueden asociarse a fuentes de ingesta desde SIEM; el token y el secreto HMAC solo se muestran una vez al crearlos.",
    ingestChecklist: "Lista de verificación operativa",
    checklist1: "Registrar el conector con TLS verificado y credencial de mínimo privilegio.",
    checklist2: "Ejecutar health check y sincronizar lecturas antes de asociarlo a una fuente.",
    checklist3: "Crear la fuente de ingesta en SIEM y guardar el token/HMAC en el gestor de secretos.",
    checklist4: "Enrolar el gateway edge con su clave y verificar la telemetría firmada.",
    noPermission: "No tienes permiso para consultar integraciones.",
    noConnectorWrite: "Tu rol no puede modificar conectores.",
    noConnectorExecute: "Tu rol no puede ejecutar sondeos ni sincronizaciones.",
    noMcpWrite: "Tu rol no puede registrar ni aprobar MCP.",
    noMcpExecute: "Tu rol no puede ejecutar herramientas MCP.",
    loadingFailed: "No se pudieron cargar las integraciones.",
    filterSearch: "Buscar conectores…",
    mcpSearch: "Buscar servidores o herramientas…",
    approvedTools: "Aprobadas",
    allTools: "Todas",
    allServers: "Todos los servidores",
    catalogEmpty: "El catálogo no expone adaptadores.",
    healthSummary: "Resumen de salud",
    stale: "Obsoleto",
    circuitOpen: "Circuito abierto",
    lastError: "Último error",
    configureFromCatalog: "Configurar este adaptador",
    connectorsHint: "Los conectores de escritura no se invocan aquí; se proponen al broker con aprobación y auditoría.",
    baseUrlRequired: "Este adaptador requiere una URL base válida.",
    nameRequired: "Indica un nombre de al menos 2 caracteres.",
    createdConnector: "Conector registrado",
    updatedConnector: "Conector actualizado",
    deletedConnector: "Conector eliminado",
    healthOk: "Conector saludable",
    healthFail: "El conector no respondió correctamente",
    syncDone: "Sincronización completada",
    invocationDone: "Invocación completada",
    invocationFailed: "La invocación devolvió un error",
    delete: "Eliminar",
    close: "Cerrar",
    fullDetails: "Detalle completo",
    noSelection: "Sin selección",
    serverCreated: "Servidor MCP registrado",
    serverApproved: "Servidor MCP aprobado",
    serverDeleted: "Servidor MCP eliminado",
    toolApproved: "Herramienta aprobada",
    toolRevoked: "Herramienta revocada",
    executionDone: "Ejecución completada",
    trustUntrusted: "No confiable",
    trustLimited: "Limitado",
    trustTrusted: "Confiable",
    inputSchema: "Esquema de entrada",
    outputSchema: "Esquema de salida",
    statusDisabled: "Deshabilitado",
    requiresApproval: "Requiere aprobación",
    directWriteBlocked: "Escritura directa bloqueada",
    readOnlyBadge: "Lectura",
    writeBadge: "Escritura",
    enabledCount: "habilitados",
    connectorRunCount: "ejecuciones",
  },
  en: {
    eyebrow: "Governance · Integrations",
    title: "Integrations and connection surfaces",
    subtitle: "Connectors with explicit capabilities, governed MCP servers and operational entry points.",
    tabConnectors: "Connectors",
    tabMcp: "MCP",
    tabIngest: "Ingest & edge",
    connectorsTitle: "Configured connectors",
    connectorsSub: "Reads run here; writes always pass through the defence broker with approval.",
    catalogTitle: "Adapter catalogue",
    catalogSub: "Capabilities declared per adapter, with direction, risk and formats.",
    totalConnectors: "Connectors",
    enabledConnectors: "Enabled",
    staleConnectors: "Without recent health",
    connectorErrors: "Recorded errors",
    byStatus: "Health by state",
    errorQueue: "Error queue",
    noErrors: "No recent connector errors.",
    configure: "Configure",
    configuredCount: "configured",
    vendor: "Vendor",
    securityProfile: "Security profile",
    authMethods: "Authentication methods",
    dataFormats: "Data formats",
    readCapabilities: "Read capabilities",
    writeCapabilities: "Write capabilities",
    noRead: "No read capabilities.",
    noWrite: "No write capabilities.",
    writeViaBroker: "Writes execute via the defence broker with approval; there is no direct write from this screen.",
    requiresBaseUrl: "Requires base URL",
    fileBased: "File based",
    authType: "Authentication type",
    baseUrl: "Base URL",
    secret: "Secret / credential",
    secretKeep: "Leave blank to keep the current secret. It is never shown after saving.",
    secretSet: "Credential configured",
    noSecret: "No credential",
    verifyTls: "Verify TLS",
    rateLimit: "Requests per minute",
    config: "JSON configuration",
    configHint: "Adapter-specific JSON object. Validated server-side.",
    enabled: "Enabled",
    createConnector: "Register connector",
    editConnector: "Edit connector",
    connectorType: "Connector type",
    connectorName: "Connector name",
    version: "Version",
    status: "Status",
    baseUrlShort: "URL",
    tls: "TLS",
    lastHealth: "Last health",
    actions: "Actions",
    testHealth: "Test health",
    syncNow: "Sync",
    runs: "Runs",
    invokeRead: "Invoke read",
    disable: "Disable",
    enable: "Enable",
    deleteConnector: "Delete connector",
    deleteConnectorWarning:
      "Encrypted configuration, the credential and the run history are removed. If referenced by ingest sources or intelligence feeds the server will refuse; disable it instead.",
    noConnectors: "No connectors",
    noConnectorsHint: "Pick an adapter from the catalogue and register the first one.",
    noFilter: "No connector matches the filters.",
    clearFilters: "Clear filters",
    allStatuses: "All states",
    healthResult: "Health check result",
    ok: "OK",
    failed: "Failed",
    latency: "Latency",
    detail: "Detail",
    probeError: "Probe error",
    syncResult: "Sync result",
    eventsCreated: "Events created",
    eventsDuplicate: "Duplicate events",
    indicatorsCreated: "Indicators created",
    indicatorsUpdated: "Indicators updated",
    alertsRead: "Alerts read",
    runsTitle: "Connector runs",
    operation: "Operation",
    direction: "Direction",
    requestId: "Request ID",
    createdAt: "Date",
    onlyErrors: "Errors only",
    noRuns: "No runs recorded",
    invokeTitle: "Invoke read capability",
    capability: "Capability",
    params: "JSON parameters",
    paramsHint: "JSON object sent to the adapter. Only read capabilities are allowed.",
    invoke: "Invoke",
    invokeResult: "Invocation result",
    httpStatus: "HTTP status",
    readOnlyOnly: "This screen only invokes read capabilities. Use the defence broker for writes.",
    mcpServers: "MCP servers",
    mcpServersSub: "Explicit registry with trust, tool discovery and human approval.",
    mcpTools: "MCP tools",
    mcpToolsSub: "No tool is auto-approved. Execution requires prior approval.",
    createServer: "Register server",
    endpoint: "JSON-RPC endpoint",
    trustLevel: "Trust level",
    approvedBy: "Approved by",
    approvedAt: "Approved",
    discover: "Discover tools",
    approveServer: "Approve server",
    deleteServer: "Delete server",
    deleteServerWarning: "The server and its registered tools are removed. Historical executions remain audited.",
    noServers: "No MCP servers",
    noServersHint: "Register a JSON-RPC server and discover its tools before approval.",
    server: "Server",
    tool: "Tool",
    risk: "Risk",
    approved: "Approved",
    pending: "Pending",
    toolApprove: "Approve",
    toolRevoke: "Revoke",
    timeout: "Timeout (s)",
    maxCalls: "Max calls/h",
    permissionsRequired: "Required permissions",
    execute: "Execute",
    approveToolTitle: "Approve MCP tool",
    approveToolWarning:
      "Once approved, authorized agents may invoke it within policy. Review the input schema and risk first.",
    revokeToolTitle: "Revoke MCP tool",
    revokeToolWarning: "The tool becomes non-invocable. Previous executions remain in the audit trail.",
    noTools: "No discovered tools",
    noToolsHint: "Discover tools on an approved server.",
    noApprovedTools: "No approved tools",
    executeTitle: "Execute MCP tool",
    arguments: "JSON arguments",
    argumentsHint: "Validated against the server input_schema and recorded redacted in the audit trail.",
    executeSubmit: "Execute tool",
    executionResult: "Execution result",
    injectionWarning: "Possible prompt injection detected in the output. Treat the content as untrusted.",
    injectionMatches: "Matches",
    truncated: "Output truncated",
    auditNote: "Every execution is recorded in the audit chain with redacted arguments and results.",
    approvalRequiresHuman: "MCP approval requires a human session; API tokens cannot approve.",
    confidence: "Trust",
    discoverResult: "Discovery completed",
    discovered: "Discovered",
    created: "Created",
    updated: "Updated",
    ingestTitle: "Ingest and edge enrollment",
    ingestBody:
      "Ingest sources (one-time token, HMAC secret, parser and counters) are managed in the SIEM module to avoid duplicating their lifecycle. Edge gateway enrollment lives on its own screen.",
    ingestSiem: "Open SIEM",
    ingestEdge: "Open edge gateways",
    ingestConnectorNote:
      "Connectors on this screen can be linked to ingest sources from SIEM; the token and HMAC secret are shown exactly once on creation.",
    ingestChecklist: "Operational checklist",
    checklist1: "Register the connector with verified TLS and a least-privilege credential.",
    checklist2: "Run a health check and sync reads before linking it to a source.",
    checklist3: "Create the ingest source in SIEM and store the token/HMAC in the secret manager.",
    checklist4: "Enroll the edge gateway with its key and verify signed telemetry.",
    noPermission: "You do not have permission to view integrations.",
    noConnectorWrite: "Your role cannot modify connectors.",
    noConnectorExecute: "Your role cannot run probes or syncs.",
    noMcpWrite: "Your role cannot register or approve MCP.",
    noMcpExecute: "Your role cannot execute MCP tools.",
    loadingFailed: "Integrations could not be loaded.",
    filterSearch: "Search connectors…",
    mcpSearch: "Search servers or tools…",
    approvedTools: "Approved",
    allTools: "All",
    allServers: "All servers",
    catalogEmpty: "The catalogue exposes no adapters.",
    healthSummary: "Health summary",
    stale: "Stale",
    circuitOpen: "Circuit open",
    lastError: "Last error",
    configureFromCatalog: "Configure this adapter",
    connectorsHint: "Write connectors are not invoked here; they are proposed to the broker with approval and audit.",
    baseUrlRequired: "This adapter requires a valid base URL.",
    nameRequired: "Provide a name of at least 2 characters.",
    createdConnector: "Connector registered",
    updatedConnector: "Connector updated",
    deletedConnector: "Connector deleted",
    healthOk: "Connector healthy",
    healthFail: "Connector did not respond correctly",
    syncDone: "Sync completed",
    invocationDone: "Invocation completed",
    invocationFailed: "Invocation returned an error",
    delete: "Delete",
    close: "Close",
    fullDetails: "Full detail",
    noSelection: "No selection",
    serverCreated: "MCP server registered",
    serverApproved: "MCP server approved",
    serverDeleted: "MCP server deleted",
    toolApproved: "Tool approved",
    toolRevoked: "Tool revoked",
    executionDone: "Execution completed",
    trustUntrusted: "Untrusted",
    trustLimited: "Limited",
    trustTrusted: "Trusted",
    inputSchema: "Input schema",
    outputSchema: "Output schema",
    statusDisabled: "Disabled",
    requiresApproval: "Requires approval",
    directWriteBlocked: "Direct write blocked",
    readOnlyBadge: "Read",
    writeBadge: "Write",
    enabledCount: "enabled",
    connectorRunCount: "runs",
  },
};

function trustLabel(level: string, t: (key: string) => string): string {
  if (level === "untrusted") return t("trustUntrusted");
  if (level === "limited") return t("trustLimited");
  if (level === "trusted") return t("trustTrusted");
  return humanize(level);
}

function summaryCell(entry: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = entry[key];
    if (typeof value === "string" && value.length > 0) return value;
    if (typeof value === "number") return String(value);
  }
  return "—";
}

/* --------------------------------------------------------------- connectors */

interface ConnectorFormState {
  name: string;
  connectorType: string;
  version: string;
  baseUrl: string;
  authType: string;
  secret: string;
  verifyTls: boolean;
  rateLimit: string;
  enabled: boolean;
  configText: string;
}

const EMPTY_CONNECTOR_FORM: ConnectorFormState = {
  name: "",
  connectorType: "",
  version: "1.0.0",
  baseUrl: "",
  authType: "none",
  secret: "",
  verifyTls: true,
  rateLimit: "60",
  enabled: true,
  configText: "{}",
};

function ConnectorsTab({
  canWrite,
  canExecute,
}: {
  canWrite: boolean;
  canExecute: boolean;
}) {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Connector | null>(null);
  const [form, setForm] = useState<ConnectorFormState>(EMPTY_CONNECTOR_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [probe, setProbe] = useState<{ name: string; result: ConnectorHealthResult } | null>(null);
  const [sync, setSync] = useState<{ name: string; result: ConnectorSyncResult } | null>(null);
  const [runsFor, setRunsFor] = useState<Connector | null>(null);
  const [runsPage, setRunsPage] = useState(1);
  const [runsErrorsOnly, setRunsErrorsOnly] = useState(false);
  const [invokeFor, setInvokeFor] = useState<Connector | null>(null);
  const [invokeCapability, setInvokeCapability] = useState("");
  const [invokeParams, setInvokeParams] = useState("{}");
  const [invokeError, setInvokeError] = useState<string | null>(null);
  const [invokeResult, setInvokeResult] = useState<ConnectorInvokeResult | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Connector | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const catalogQuery = useQuery({
    queryKey: ["integrations", "catalog"],
    queryFn: () => api.get<ConnectorCatalog>("/connectors/catalog"),
  });

  const listQuery = useQuery({
    queryKey: ["integrations", "connectors", { q, status, page }],
    queryFn: () =>
      api.get<Page<Connector>>("/connectors", {
        page,
        page_size: 25,
        q: q || undefined,
        status: status || undefined,
        sort: "name",
      }),
  });

  const healthQuery = useQuery({
    queryKey: ["integrations", "connectors", "health"],
    queryFn: () => api.get<ConnectorHealthSummary>("/connectors/health/summary"),
  });

  const runsQuery = useQuery({
    queryKey: ["integrations", "connector", runsFor?.id, "runs", { page: runsPage, errorsOnly: runsErrorsOnly }],
    queryFn: () =>
      api.get<Page<ConnectorRun>>(`/connectors/${runsFor?.id}/runs`, {
        page: runsPage,
        page_size: 25,
        status: runsErrorsOnly ? "failed" : undefined,
      }),
    enabled: runsFor !== null,
  });

  const adapters = catalogQuery.data?.adapters ?? [];
  const adapterByType = useMemo(() => {
    const map = new Map<string, CatalogAdapter>();
    for (const adapter of adapters) map.set(adapter.connector_id, adapter);
    return map;
  }, [adapters]);

  const openCreate = (adapter?: CatalogAdapter) => {
    setEditing(null);
    setForm({
      ...EMPTY_CONNECTOR_FORM,
      connectorType: adapter?.connector_id ?? "",
      name: adapter ? adapter.display_name.slice(0, 160) : "",
      authType: adapter?.auth_methods[0] ?? "none",
    });
    setFieldErrors({});
    setFormError(null);
    setFormOpen(true);
  };

  const openEdit = (connector: Connector) => {
    setEditing(connector);
    setForm({
      name: connector.name,
      connectorType: connector.connector_type,
      version: connector.version,
      baseUrl: connector.base_url ?? "",
      authType: connector.auth_type,
      secret: "",
      verifyTls: connector.verify_tls,
      rateLimit: String(connector.rate_limit_per_minute),
      enabled: connector.enabled,
      configText: JSON.stringify(connector.config ?? {}, null, 2),
    });
    setFieldErrors({});
    setFormError(null);
    setFormOpen(true);
  };

  const configParsed = parseJsonRecord(form.configText);

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<Connector>("/connectors", body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(editing ? t("updatedConnector") : t("createdConnector"), "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const updateMutation = useMutation({
    mutationFn: (payload: { id: string; body: Record<string, unknown> }) => api.patch<Connector>(`/connectors/${payload.id}`, payload.body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(t("updatedConnector"), "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const toggleMutation = useMutation({
    mutationFn: (connector: Connector) => api.patch<Connector>(`/connectors/${connector.id}`, { enabled: !connector.enabled }),
    onSuccess: async () => {
      toast.push(t("updatedConnector"), "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (error) => toast.push(errorMessage(error), "error"),
  });

  const deleteMutation = useMutation({
    mutationFn: (connector: Connector) => api.delete<void>(`/connectors/${connector.id}`),
    onSuccess: async () => {
      setDeleteTarget(null);
      toast.push(t("deletedConnector"), "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (error) => {
      setDeleteTarget(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const healthMutation = useMutation({
    mutationFn: (connector: Connector) => api.post<ConnectorHealthResult>(`/connectors/${connector.id}/health`),
    onSuccess: async (result, connector) => {
      setProbe({ name: connector.name, result });
      toast.push(result.ok ? t("healthOk") : t("healthFail"), result.ok ? "success" : "error");
      await queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (error, connector) => {
      toast.push(errorMessage(error), "error");
      setProbe({
        name: connector.name,
        result: {
          connector_id: connector.id,
          status: "error",
          ok: false,
          latency_ms: 0,
          detail: {},
          error: errorMessage(error),
          run_id: null,
          last_health_at: connector.last_health_at,
        },
      });
    },
  });

  const syncMutation = useMutation({
    mutationFn: (connector: Connector) => api.post<ConnectorSyncResult>(`/connectors/${connector.id}/sync`, { limit: 100 }),
    onSuccess: async (result, connector) => {
      setSync({ name: connector.name, result });
      toast.push(t("syncDone"), "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (error) => toast.push(errorMessage(error), "error"),
  });

  const invokeMutation = useMutation({
    mutationFn: (payload: { connector: Connector; capability: string; params: Record<string, unknown> }) =>
      api.post<ConnectorInvokeResult>(`/connectors/${payload.connector.id}/invoke/${payload.capability}`, {
        params: payload.params,
      }),
    onSuccess: (result) => {
      setInvokeResult(result);
      setInvokeError(null);
      toast.push(result.ok ? t("invocationDone") : t("invocationFailed"), result.ok ? "success" : "error");
    },
    onError: (error) => {
      setInvokeResult(null);
      setInvokeError(errorMessage(error));
    },
  });

  const submitForm = () => {
    setFormError(null);
    if (form.name.trim().length < 2) {
      setFormError(t("nameRequired"));
      return;
    }
    const adapter = adapterByType.get(form.connectorType);
    if (!editing && !adapter) {
      setFormError(t("connectorType"));
      return;
    }
    if ((adapter?.requires_base_url ?? false) && editing === null && form.baseUrl.trim().length === 0) {
      setFormError(t("baseUrlRequired"));
      return;
    }
    if (!configParsed.ok) {
      setFormError(configParsed.error);
      return;
    }
    const rate = Number(form.rateLimit);
    if (!Number.isFinite(rate) || rate < 1 || rate > 6000) {
      setFormError(t("rateLimit"));
      return;
    }
    const base: Record<string, unknown> = {
      name: form.name.trim(),
      version: form.version.trim() || "1.0.0",
      base_url: form.baseUrl.trim() || null,
      auth_type: form.authType,
      config: configParsed.value,
      verify_tls: form.verifyTls,
      rate_limit_per_minute: Math.round(rate),
      enabled: form.enabled,
    };
    if (form.secret) base.secret = form.secret;
    if (editing) {
      updateMutation.mutate({ id: editing.id, body: base });
    } else {
      createMutation.mutate({ ...base, connector_type: form.connectorType });
    }
  };

  const columns: Column<Connector>[] = [
    {
      key: "name",
      header: t("connectorName"),
      render: (row) => (
        <div style={{ minWidth: 190 }}>
          <div className="row" style={{ gap: 6 }}>
            <StatusDot status={row.health.state} />
            <span className="primary-cell">{row.name}</span>
            {row.has_secret ? <Badge tone="neutral">{t("secretSet")}</Badge> : null}
          </div>
          <div className="cell-sub mono">{row.connector_type} · v{row.version}</div>
          {row.base_url ? <div className="cell-sub mono" style={{ wordBreak: "break-all" }}>{row.base_url}</div> : null}
        </div>
      ),
    },
    {
      key: "status",
      header: t("status"),
      width: "150px",
      render: (row) => (
        <div className="stack" style={{ gap: 3 }}>
          <StatusBadge status={row.enabled ? row.status : "disabled"} label={row.enabled ? humanize(row.status) : t("statusDisabled")} />
          <span className="mono" style={{ fontSize: 10, color: row.verify_tls ? "var(--success)" : "var(--danger)" }}>
            {t("tls")}: {row.verify_tls ? "on" : "off"}
          </span>
        </div>
      ),
    },
    {
      key: "health",
      header: t("lastHealth"),
      width: "150px",
      render: (row) => (
        <div>
          <span className="mono" style={{ fontSize: 10.5 }}>{relativeTime(row.health.last_health_at, lang)}</span>
          {row.health.stale ? <div className="cell-sub" style={{ color: "var(--warning)" }}>{t("stale")}</div> : null}
          {row.health.circuit_open ? <div className="cell-sub" style={{ color: "var(--danger)" }}>{t("circuitOpen")}</div> : null}
          {row.last_error ? <div className="cell-sub" style={{ color: "var(--danger)", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.last_error}</div> : null}
        </div>
      ),
    },
    {
      key: "rate",
      header: t("rateLimit"),
      width: "90px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.rate_limit_per_minute}/min</span>,
    },
    {
      key: "actions",
      header: t("actions"),
      width: "250px",
      align: "right",
      render: (row) => (
        <div className="row wrap" style={{ gap: 3, justifyContent: "flex-end" }}>
          {canExecute ? (
            <Button
              size="sm"
              variant="ghost"
              icon={Activity}
              aria-label={t("testHealth")}
              loading={healthMutation.isPending && busyId === row.id}
              onClick={() => { setBusyId(row.id); healthMutation.mutate(row); }}
              data-testid="connector-health"
            />
          ) : null}
          {canExecute && row.enabled ? (
            <Button
              size="sm"
              variant="ghost"
              icon={ArrowRightLeft}
              aria-label={t("syncNow")}
              loading={syncMutation.isPending && busyId === row.id}
              onClick={() => { setBusyId(row.id); syncMutation.mutate(row); }}
              data-testid="connector-sync"
            />
          ) : null}
          <Button size="sm" variant="ghost" icon={ListTree} aria-label={t("runs")} onClick={() => { setRunsFor(row); setRunsPage(1); setRunsErrorsOnly(false); }} data-testid="connector-runs" />
          {canExecute && row.enabled ? (
            <Button
              size="sm"
              variant="ghost"
              icon={FlaskConical}
              aria-label={t("invokeRead")}
              onClick={() => {
                const adapter = adapterByType.get(row.connector_type);
                const firstRead = adapter?.capabilities.find((capability) => capability.direction === "read");
                setInvokeFor(row);
                setInvokeCapability(firstRead?.name ?? "");
                setInvokeParams("{}");
                setInvokeResult(null);
                setInvokeError(null);
              }}
              data-testid="connector-invoke"
            />
          ) : null}
          {canWrite ? (
            <Button size="sm" variant="ghost" aria-label={t("common.edit")} onClick={() => openEdit(row)} data-testid="connector-edit">
              {t("common.edit")}
            </Button>
          ) : null}
          {canWrite ? (
            <Button
              size="sm"
              variant="ghost"
              aria-label={row.enabled ? t("disable") : t("enable")}
              loading={toggleMutation.isPending && busyId === row.id}
              onClick={() => { setBusyId(row.id); toggleMutation.mutate(row); }}
            >
              {row.enabled ? t("disable") : t("enable")}
            </Button>
          ) : null}
          {canWrite ? (
            <Button size="sm" variant="ghost" icon={Trash2} aria-label={t("deleteConnector")} onClick={() => setDeleteTarget(row)} data-testid="connector-delete" />
          ) : null}
        </div>
      ),
    },
  ];

  const runColumns: Column<ConnectorRun>[] = [
    {
      key: "operation",
      header: t("operation"),
      render: (row) => (
        <div>
          <div className="mono" style={{ fontSize: 11 }}>{row.operation}</div>
          <div className="cell-sub">{row.direction}</div>
        </div>
      ),
    },
    { key: "status", header: t("status"), width: "100px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "latency",
      header: t("latency"),
      width: "90px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.latency_ms !== null ? `${row.latency_ms} ms` : "—"}</span>,
    },
    {
      key: "created",
      header: t("createdAt"),
      width: "150px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.created_at, lang)}</span>,
    },
    {
      key: "error",
      header: t("lastError"),
      render: (row) => (
        <span style={{ fontSize: 11, color: row.error ? "var(--danger)" : "var(--dim)" }}>{row.error ?? "—"}</span>
      ),
    },
  ];

  const invokeOptions = invokeFor ? adapterByType.get(invokeFor.connector_type)?.capabilities.filter((capability) => capability.direction === "read") ?? [] : [];
  const filtersActive = Boolean(q || status);

  return (
    <div className="stack" data-testid="integrations-connectors">
      <div className="kpi-grid">
        <div className="card kpi">
          <div className="kpi-label"><Plug size={13} style={{ color: "var(--accent)" }} />{t("totalConnectors")}</div>
          <div className="kpi-value">{formatNumber(healthQuery.data?.total ?? listQuery.data?.meta.total ?? 0)}</div>
          <div className="kpi-foot">{t("enabledCount")}: {formatNumber(healthQuery.data?.enabled ?? 0)}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label"><ShieldCheck size={13} style={{ color: "var(--success)" }} />{t("healthSummary")}</div>
          <div className="kpi-value kpi-success">{formatNumber(healthQuery.data?.by_status.healthy ?? 0)}</div>
          <div className="kpi-foot">{t("byStatus")}: {Object.entries(healthQuery.data?.by_status ?? {}).map(([key, value]) => `${humanize(key)} ${value}`).join(" · ") || "—"}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label"><RefreshCw size={13} style={{ color: "var(--warning)" }} />{t("staleConnectors")}</div>
          <div className="kpi-value kpi-warning">{formatNumber(healthQuery.data?.stale_count ?? 0)}</div>
          <div className="kpi-foot">{formatDateTime(healthQuery.data?.generated_at, lang)}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label"><ShieldAlert size={13} style={{ color: "var(--danger)" }} />{t("connectorErrors")}</div>
          <div className="kpi-value kpi-danger">{formatNumber(healthQuery.data?.errors.length ?? 0)}</div>
          <div className="kpi-foot">{t("catalogTitle")}: {formatNumber(healthQuery.data?.catalog_size ?? 0)}</div>
        </div>
      </div>

      <Card
        title={t("catalogTitle")}
        subtitle={t("catalogSub")}
        actions={canWrite ? <Button size="sm" variant="primary" icon={Plus} onClick={() => openCreate()} data-testid="connector-create-open">{t("createConnector")}</Button> : undefined}
      >
        {catalogQuery.isError ? (
          <ErrorBanner message={errorMessage(catalogQuery.error)} onRetry={() => void catalogQuery.refetch()} />
        ) : catalogQuery.isLoading ? (
          <div className="grid-2">
            <div className="skeleton skeleton-card" />
            <div className="skeleton skeleton-card" />
          </div>
        ) : adapters.length === 0 ? (
          <EmptyState icon={Boxes} title={t("catalogEmpty")} />
        ) : (
          <div className="grid-2" data-testid="connector-catalog">
            {adapters.map((adapter) => {
              const readCapabilities = adapter.capabilities.filter((capability) => capability.direction === "read");
              const writeCapabilities = adapter.capabilities.filter((capability) => capability.direction !== "read");
              return (
                <div className="card card-pad stack" key={adapter.connector_id} data-testid="connector-card" style={{ gap: 10 }}>
                  <div className="row-between wrap" style={{ alignItems: "flex-start" }}>
                    <div>
                      <div className="primary-cell">{adapter.display_name}</div>
                      <div className="cell-sub">{adapter.vendor} · {adapter.product} · v{adapter.version}</div>
                    </div>
                    <div className="row wrap" style={{ gap: 4 }}>
                      {adapter.configured ? <Badge tone="success">{formatNumber(adapter.connector_count)} {t("configuredCount")}</Badge> : <Badge tone="neutral">{t("configuredCount")} 0</Badge>}
                      {adapter.file_based ? <Badge tone="neutral">{t("fileBased")}</Badge> : null}
                      {adapter.requires_base_url ? <Badge tone="warning">{t("requiresBaseUrl")}</Badge> : null}
                    </div>
                  </div>
                  <div>
                    <div className="section-label">{t("authMethods")}</div>
                    <div className="chip-row">{adapter.auth_methods.map((method) => <span className="tag" key={method}>{method}</span>)}</div>
                  </div>
                  <div className="grid-2" style={{ gap: 8 }}>
                    <div>
                      <div className="section-label">{t("readCapabilities")}</div>
                      {readCapabilities.length === 0 ? <span className="dim" style={{ fontSize: 11 }}>{t("noRead")}</span> : (
                        <div className="stack" style={{ gap: 3 }}>
                          {readCapabilities.map((capability) => (
                            <div key={capability.name} className="row" style={{ gap: 5, alignItems: "flex-start" }}>
                              <Badge tone="accent">{t("readOnlyBadge")}</Badge>
                              <div style={{ minWidth: 0 }}>
                                <div className="mono" style={{ fontSize: 10.5, color: "var(--text-secondary)" }}>{capability.name}</div>
                                <div style={{ fontSize: 10.5, color: "var(--dim)" }}>{capability.description}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div>
                      <div className="section-label">{t("writeCapabilities")}</div>
                      {writeCapabilities.length === 0 ? <span className="dim" style={{ fontSize: 11 }}>{t("noWrite")}</span> : (
                        <div className="stack" style={{ gap: 3 }}>
                          {writeCapabilities.map((capability) => (
                            <div key={capability.name} className="row" style={{ gap: 5, alignItems: "flex-start" }}>
                              <Badge tone={capability.requires_approval ? "danger" : "warning"}>{t("writeBadge")}</Badge>
                              <div style={{ minWidth: 0 }}>
                                <div className="mono" style={{ fontSize: 10.5, color: "var(--text-secondary)" }}>{capability.name}</div>
                                <div style={{ fontSize: 10.5, color: "var(--dim)" }}>{capability.description}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                  {writeCapabilities.length ? <div className="notice notice-warning" style={{ fontSize: 10.5 }}>{t("writeViaBroker")}</div> : null}
                  <div className="row-between wrap">
                    <div className="chip-row">
                      {adapter.data_formats.map((format) => <span className="tag" key={format}>{format}</span>)}
                      <span className="tag">{adapter.security_profile}</span>
                    </div>
                    {canWrite ? (
                      <Button size="sm" onClick={() => openCreate(adapter)} data-testid="connector-configure">
                        {t("configure")}
                      </Button>
                    ) : null}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {healthQuery.data && healthQuery.data.errors.length > 0 ? (
        <Card title={t("errorQueue")} subtitle={t("connectorErrors")}>
          <div className="stack">
            {healthQuery.data.errors.map((entry, index) => (
              <div className="list-item" key={index}>
                <ShieldAlert size={14} style={{ color: "var(--danger)", flex: "0 0 auto", marginTop: 2 }} />
                <div>
                  <div className="item-title">{summaryCell(entry, ["name", "connector_name", "connector_id"])}</div>
                  <div className="item-sub mono">{summaryCell(entry, ["error", "last_error", "status"])}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      ) : null}

      <Card
        title={t("connectorsTitle")}
        subtitle={t("connectorsSub")}
        actions={
          <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("common.refresh")} onClick={() => { void listQuery.refetch(); void healthQuery.refetch(); }} />
        }
        bodyClassName=""
        footer={<span>{t("connectorsHint")}</span>}
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap" style={{ gap: 8 }}>
            <div style={{ flex: 1, minWidth: 220 }}>
              <SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder={t("filterSearch")} ariaLabel={t("filterSearch")} />
            </div>
            <Select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1); }} aria-label={t("status")} style={{ width: 170 }} data-testid="connector-status-filter">
              <option value="">{t("allStatuses")}</option>
              <option value="healthy">healthy</option>
              <option value="degraded">degraded</option>
              <option value="unhealthy">unhealthy</option>
              <option value="disabled">{t("statusDisabled")}</option>
            </Select>
            {filtersActive ? <Button size="sm" variant="ghost" onClick={() => { setQ(""); setStatus(""); }}>{t("clearFilters")}</Button> : null}
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
                  icon={Plug}
                  title={filtersActive ? t("noFilter") : t("noConnectors")}
                  description={filtersActive ? t("clearFilters") : t("noConnectorsHint")}
                  action={!filtersActive && canWrite ? <Button size="sm" onClick={() => openCreate()}>{t("createConnector")}</Button> : undefined}
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
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={editing ? t("editConnector") : t("createConnector")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setFormOpen(false)} disabled={createMutation.isPending || updateMutation.isPending}>{t("common.cancel")}</Button>
            <Button
              variant="primary"
              loading={createMutation.isPending || updateMutation.isPending}
              onClick={submitForm}
              data-testid="connector-submit"
            >
              {editing ? t("common.save") : t("createConnector")}
            </Button>
          </>
        }
      >
        <div className="stack" data-testid="connector-form">
          <div className="form-grid">
            <Field label={t("connectorName")} htmlFor={`${idPrefix}-name`} error={fieldErrors.name} required>
              <Input id={`${idPrefix}-name`} value={form.name} maxLength={160} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} />
            </Field>
            <Field label={t("connectorType")} htmlFor={`${idPrefix}-type`} error={fieldErrors.connector_type} required>
              <Select
                id={`${idPrefix}-type`}
                value={form.connectorType}
                disabled={editing !== null}
                onChange={(event) => {
                  const adapter = adapterByType.get(event.target.value);
                  setForm((current) => ({
                    ...current,
                    connectorType: event.target.value,
                    authType: adapter?.auth_methods[0] ?? current.authType,
                  }));
                }}
                data-testid="connector-type"
              >
                <option value="">—</option>
                {adapters.map((adapter) => (
                  <option key={adapter.connector_id} value={adapter.connector_id}>{adapter.display_name} ({adapter.connector_id})</option>
                ))}
              </Select>
            </Field>
            <Field label={t("baseUrl")} htmlFor={`${idPrefix}-base`} error={fieldErrors.base_url} hint={adapterByType.get(form.connectorType)?.requires_base_url ? t("baseUrlRequired") : undefined}>
              <Input id={`${idPrefix}-base`} value={form.baseUrl} maxLength={500} onChange={(event) => setForm((current) => ({ ...current, baseUrl: event.target.value }))} placeholder="https://" />
            </Field>
            <Field label={t("authType")} htmlFor={`${idPrefix}-auth`} error={fieldErrors.auth_type}>
              <Select id={`${idPrefix}-auth`} value={form.authType} onChange={(event) => setForm((current) => ({ ...current, authType: event.target.value }))}>
                {(adapterByType.get(form.connectorType)?.auth_methods ?? ["none"]).map((method) => (
                  <option key={method} value={method}>{method}</option>
                ))}
                <option value="none">none</option>
              </Select>
            </Field>
            <div className="span-2">
              <Field label={t("secret")} htmlFor={`${idPrefix}-secret`} hint={t("secretKeep")} error={fieldErrors.secret}>
                <Input
                  id={`${idPrefix}-secret`}
                  type="password"
                  autoComplete="new-password"
                  value={form.secret}
                  onChange={(event) => setForm((current) => ({ ...current, secret: event.target.value }))}
                  placeholder={editing?.has_secret ? "••••••••" : ""}
                  data-testid="connector-secret"
                />
              </Field>
              {editing ? (
                <div className="dim" style={{ fontSize: 11 }}>
                  {editing.has_secret ? t("secretSet") : t("noSecret")} · {t("secretKeep")}
                </div>
              ) : null}
            </div>
            <Field label={t("rateLimit")} htmlFor={`${idPrefix}-rate`} error={fieldErrors.rate_limit_per_minute}>
              <Input
                id={`${idPrefix}-rate`}
                inputMode="numeric"
                value={form.rateLimit}
                onChange={(event) => setForm((current) => ({ ...current, rateLimit: event.target.value.replace(/\D/g, "").slice(0, 4) }))}
              />
            </Field>
            <Field label={t("version")} htmlFor={`${idPrefix}-version`}>
              <Input id={`${idPrefix}-version`} value={form.version} maxLength={20} onChange={(event) => setForm((current) => ({ ...current, version: event.target.value }))} />
            </Field>
            <div className="span-2">
              <JsonEditor
                id={`${idPrefix}-config`}
                label={t("config")}
                value={form.configText}
                onChange={(value) => setForm((current) => ({ ...current, configText: value }))}
                hint={t("configHint")}
                error={!configParsed.ok ? configParsed.error : fieldErrors.config}
                testId="connector-config"
              />
            </div>
            <label className="checkbox">
              <input type="checkbox" checked={form.verifyTls} onChange={(event) => setForm((current) => ({ ...current, verifyTls: event.target.checked }))} />
              {t("verifyTls")}
            </label>
            <label className="checkbox">
              <input type="checkbox" checked={form.enabled} onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))} />
              {t("enabled")}
            </label>
          </div>
          {formError ? <ErrorBanner message={formError} /> : null}
        </div>
      </Modal>

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => { if (deleteTarget) deleteMutation.mutate(deleteTarget); }}
        title={t("deleteConnector")}
        description={deleteTarget ? `${deleteTarget.name} · ${deleteTarget.connector_type}` : undefined}
        warning={t("deleteConnectorWarning")}
        confirmLabel={t("delete")}
        cancelLabel={t("common.cancel")}
        busy={deleteMutation.isPending}
        testId="connector-delete-confirm"
      />

      <Modal open={probe !== null} onClose={() => setProbe(null)} title={t("healthResult")} footer={<Button onClick={() => setProbe(null)}>{t("close")}</Button>}>
        {probe ? (
          <div className="stack">
            <div className="row wrap">
              <Badge tone={probe.result.ok ? "success" : "danger"}>{probe.result.ok ? t("ok") : t("failed")}</Badge>
              <Badge tone="neutral">{humanize(probe.result.status)}</Badge>
              <span className="dim" style={{ fontSize: 11 }}>{probe.name}</span>
            </div>
            <MetaRows
              items={[
                { label: t("latency"), value: `${probe.result.latency_ms} ms` },
                { label: t("lastHealth"), value: formatDateTime(probe.result.last_health_at, lang) },
                { label: t("probeError"), value: probe.result.error ?? "—" },
              ]}
            />
            <PreBlock value={probe.result.detail} label={t("detail")} />
          </div>
        ) : null}
      </Modal>

      <Modal open={sync !== null} onClose={() => setSync(null)} title={t("syncResult")} footer={<Button onClick={() => setSync(null)}>{t("close")}</Button>}>
        {sync ? (
          <div className="stack">
            <div className="row wrap">
              <StatusBadge status={sync.result.status} />
              <span className="dim" style={{ fontSize: 11 }}>{sync.name}</span>
            </div>
            <MetaRows
              items={[
                { label: t("eventsCreated"), value: formatNumber(sync.result.events_created) },
                { label: t("eventsDuplicate"), value: formatNumber(sync.result.events_duplicate) },
                { label: t("indicatorsCreated"), value: formatNumber(sync.result.indicators_created) },
                { label: t("indicatorsUpdated"), value: formatNumber(sync.result.indicators_updated) },
                { label: t("alertsRead"), value: formatNumber(sync.result.alerts_read) },
                { label: t("latency"), value: `${sync.result.latency_ms} ms` },
              ]}
            />
            <div className="chip-row">{sync.result.capabilities.map((capability) => <span className="tag" key={capability}>{capability}</span>)}</div>
            <PreBlock value={sync.result.detail} label={t("detail")} />
          </div>
        ) : null}
      </Modal>

      <Modal
        open={runsFor !== null}
        onClose={() => setRunsFor(null)}
        title={`${t("runsTitle")}${runsFor ? ` · ${runsFor.name}` : ""}`}
        size="lg"
        footer={<Button onClick={() => setRunsFor(null)}>{t("close")}</Button>}
      >
        <div className="stack">
          <div className="row-between wrap">
            <label className="checkbox">
              <input type="checkbox" checked={runsErrorsOnly} onChange={(event) => { setRunsErrorsOnly(event.target.checked); setRunsPage(1); }} />
              {t("onlyErrors")}
            </label>
            <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => void runsQuery.refetch()} aria-label={t("common.refresh")} />
          </div>
          {runsQuery.isError ? (
            <ErrorBanner message={errorMessage(runsQuery.error)} onRetry={() => void runsQuery.refetch()} />
          ) : (
            <>
              <DataTable
                columns={runColumns}
                rows={runsQuery.data?.items}
                rowKey={(row) => row.id}
                loading={runsQuery.isLoading}
                empty={<EmptyState icon={ListTree} title={t("noRuns")} />}
              />
              <Pagination meta={runsQuery.data?.meta} onPage={setRunsPage} />
            </>
          )}
        </div>
      </Modal>

      <Modal
        open={invokeFor !== null}
        onClose={() => setInvokeFor(null)}
        title={`${t("invokeTitle")}${invokeFor ? ` · ${invokeFor.name}` : ""}`}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setInvokeFor(null)}>{t("close")}</Button>
            <Button
              variant="primary"
              loading={invokeMutation.isPending}
              disabled={!invokeCapability || !parseJsonRecord(invokeParams).ok}
              onClick={() => {
                if (!invokeFor) return;
                const parsed = parseJsonRecord(invokeParams);
                if (!parsed.ok) {
                  setInvokeError(parsed.error);
                  return;
                }
                setInvokeError(null);
                invokeMutation.mutate({ connector: invokeFor, capability: invokeCapability, params: parsed.value });
              }}
              data-testid="connector-invoke-submit"
            >
              {t("invoke")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="notice notice-warning">{t("readOnlyOnly")}</div>
          {invokeOptions.length === 0 ? (
            <EmptyState icon={Lock} title={t("noRead")} description={t("writeViaBroker")} />
          ) : (
            <>
              <Field label={t("capability")} htmlFor={`${idPrefix}-capability`} required>
                <Select id={`${idPrefix}-capability`} value={invokeCapability} onChange={(event) => setInvokeCapability(event.target.value)} data-testid="connector-invoke-capability">
                  {invokeOptions.map((capability) => (
                    <option key={capability.name} value={capability.name}>{capability.name} — {capability.description}</option>
                  ))}
                </Select>
              </Field>
              <JsonEditor
                id={`${idPrefix}-params`}
                label={t("params")}
                value={invokeParams}
                onChange={setInvokeParams}
                hint={t("paramsHint")}
                error={!parseJsonRecord(invokeParams).ok ? parseJsonRecord(invokeParams).error : undefined}
                testId="connector-invoke-params"
              />
            </>
          )}
          {invokeError ? <ErrorBanner message={invokeError} /> : null}
          {invokeResult ? (
            <div className="stack" data-testid="connector-invoke-result">
              <div className="row wrap">
                <Badge tone={invokeResult.ok ? "success" : "danger"}>{invokeResult.ok ? t("ok") : t("failed")}</Badge>
                <Badge tone="neutral">{invokeResult.capability}</Badge>
                <span className="dim" style={{ fontSize: 11 }}>
                  {t("httpStatus")}: {invokeResult.status_code ?? "—"} · {invokeResult.latency_ms} ms
                </span>
              </div>
              {invokeResult.error ? <div className="notice notice-danger">{invokeResult.error}</div> : null}
              <PreBlock value={invokeResult.data} label={t("invokeResult")} />
            </div>
          ) : null}
        </div>
      </Modal>
    </div>
  );
}

/* ---------------------------------------------------------------------- MCP */

function McpTab({ canWrite, canExecute }: { canWrite: boolean; canExecute: boolean }) {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [serverPage, setServerPage] = useState(1);
  const [serverStatus, setServerStatus] = useState("");
  const [serverFormOpen, setServerFormOpen] = useState(false);
  const [serverName, setServerName] = useState("");
  const [serverEndpoint, setServerEndpoint] = useState("");
  const [serverVersion, setServerVersion] = useState("");
  const [serverTrust, setServerTrust] = useState("untrusted");
  const [serverError, setServerError] = useState<string | null>(null);
  const [serverFieldErrors, setServerFieldErrors] = useState<Record<string, string>>({});
  const [approveServer, setApproveServer] = useState<MCPServer | null>(null);
  const [deleteServer, setDeleteServer] = useState<MCPServer | null>(null);
  const [toolsPage, setToolsPage] = useState(1);
  const [toolsQ, setToolsQ] = useState("");
  const [toolsServer, setToolsServer] = useState("");
  const [toolsApproved, setToolsApproved] = useState("approved");
  const [approvingTool, setApprovingTool] = useState<MCPTool | null>(null);
  const [toolTimeout, setToolTimeout] = useState("30");
  const [toolMaxCalls, setToolMaxCalls] = useState("60");
  const [revokingTool, setRevokingTool] = useState<MCPTool | null>(null);
  const [executingTool, setExecutingTool] = useState<MCPTool | null>(null);
  const [toolArguments, setToolArguments] = useState("{}");
  const [executionResult, setExecutionResult] = useState<MCPExecutionResult | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);

  const serversQuery = useQuery({
    queryKey: ["integrations", "mcp", "servers", { page: serverPage, status: serverStatus }],
    queryFn: () =>
      api.get<Page<MCPServer>>("/mcp/servers", {
        page: serverPage,
        page_size: 25,
        status: serverStatus || undefined,
      }),
  });

  const allServersQuery = useQuery({
    queryKey: ["integrations", "mcp", "servers", { picker: true }],
    queryFn: () => api.get<Page<MCPServer>>("/mcp/servers", { page: 1, page_size: 200 }),
  });

  const toolsQuery = useQuery({
    queryKey: ["integrations", "mcp", "tools", { page: toolsPage, q: toolsQ, server: toolsServer, approved: toolsApproved }],
    queryFn: () =>
      api.get<Page<MCPTool>>("/mcp/tools", {
        page: toolsPage,
        page_size: 50,
        q: toolsQ || undefined,
        server_id: toolsServer || undefined,
        approved: toolsApproved === "" ? undefined : toolsApproved === "approved",
      }),
  });

  const serverMap = useMemo(() => {
    const map = new Map<string, MCPServer>();
    for (const server of allServersQuery.data?.items ?? []) map.set(server.id, server);
    for (const server of serversQuery.data?.items ?? []) map.set(server.id, server);
    return map;
  }, [allServersQuery.data, serversQuery.data]);

  const createServerMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<MCPServer>("/mcp/servers", body),
    onSuccess: async () => {
      setServerFormOpen(false);
      toast.push(t("serverCreated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations", "mcp"] });
    },
    onError: (error) => {
      setServerError(errorMessage(error));
      setServerFieldErrors(apiFieldErrors(error));
    },
  });

  const discoverMutation = useMutation({
    mutationFn: (server: MCPServer) => api.post<MCPDiscoverResult>(`/mcp/servers/${server.id}/discover`),
    onSuccess: async (result) => {
      toast.push(`${t("discoverResult")}: ${result.discovered} · ${t("created")} ${result.created} · ${t("updated")} ${result.updated}`, "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations", "mcp"] });
    },
    onError: (error) => toast.push(errorMessage(error), "error"),
  });

  const approveServerMutation = useMutation({
    mutationFn: (server: MCPServer) => api.post<MCPServer>(`/mcp/servers/${server.id}/approve`),
    onSuccess: async () => {
      setApproveServer(null);
      toast.push(t("serverApproved"), "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations", "mcp"] });
    },
    onError: (error) => {
      setApproveServer(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const deleteServerMutation = useMutation({
    mutationFn: (server: MCPServer) => api.delete<void>(`/mcp/servers/${server.id}`),
    onSuccess: async () => {
      setDeleteServer(null);
      toast.push(t("serverDeleted"), "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations", "mcp"] });
    },
    onError: (error) => {
      setDeleteServer(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const toolDecisionMutation = useMutation({
    mutationFn: (payload: { tool: MCPTool; approved: boolean; timeout?: number; maxCalls?: number }) =>
      api.post<MCPTool>(`/mcp/tools/${payload.tool.id}/approve`, {
        approved: payload.approved,
        ...(payload.timeout !== undefined ? { timeout_seconds: payload.timeout } : {}),
        ...(payload.maxCalls !== undefined ? { max_calls_per_hour: payload.maxCalls } : {}),
      }),
    onSuccess: async (_result, payload) => {
      setApprovingTool(null);
      setRevokingTool(null);
      toast.push(payload.approved ? t("toolApproved") : t("toolRevoked"), "success");
      await queryClient.invalidateQueries({ queryKey: ["integrations", "mcp"] });
    },
    onError: (error) => {
      setApprovingTool(null);
      setRevokingTool(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const executeMutation = useMutation({
    mutationFn: (payload: { tool: MCPTool; args: Record<string, unknown> }) =>
      api.post<MCPExecutionResult>(`/mcp/tools/${payload.tool.id}/execute`, { arguments: payload.args }),
    onSuccess: (result) => {
      setExecutionResult(result);
      setExecutionError(null);
      toast.push(t("executionDone"), result.status === "success" ? "success" : "error");
    },
    onError: (error) => {
      setExecutionResult(null);
      setExecutionError(errorMessage(error));
    },
  });

  const serverColumns: Column<MCPServer>[] = [
    {
      key: "name",
      header: t("server"),
      render: (row) => (
        <div style={{ minWidth: 180 }}>
          <div className="row" style={{ gap: 6 }}>
            <ServerCog size={13} style={{ color: "var(--accent)" }} />
            <span className="primary-cell">{row.name}</span>
          </div>
          <div className="cell-sub mono" style={{ wordBreak: "break-all" }}>{row.endpoint ?? "—"}</div>
          {row.version ? <div className="cell-sub">v{row.version} · {row.transport}</div> : <div className="cell-sub">{row.transport}</div>}
        </div>
      ),
    },
    {
      key: "trust",
      header: t("trustLevel"),
      width: "130px",
      render: (row) => <Badge tone={TRUST_TONE[row.trust_level] ?? "neutral"}>{trustLabel(row.trust_level, t)}</Badge>,
    },
    {
      key: "status",
      header: t("status"),
      width: "130px",
      render: (row) => (
        <div className="stack" style={{ gap: 3 }}>
          <StatusBadge status={row.enabled ? row.status : "disabled"} label={row.enabled ? humanize(row.status) : t("statusDisabled")} />
          {row.approved_by ? <span className="cell-sub">{t("approvedBy")}: {row.approved_by}</span> : <span className="cell-sub">{t("pending")}</span>}
        </div>
      ),
    },
    {
      key: "approvedAt",
      header: t("approvedAt"),
      width: "130px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.approved_at, lang)}</span>,
    },
    {
      key: "actions",
      header: t("actions"),
      width: "230px",
      align: "right",
      render: (row) => (
        <div className="row wrap" style={{ gap: 3, justifyContent: "flex-end" }}>
          {canWrite ? (
            <Button size="sm" variant="ghost" icon={Network} aria-label={t("discover")} loading={discoverMutation.isPending} onClick={() => discoverMutation.mutate(row)} data-testid="mcp-discover">
              {t("discover")}
            </Button>
          ) : null}
          {canWrite && !row.approved_at ? (
            <Button size="sm" variant="primary" icon={ShieldCheck} onClick={() => setApproveServer(row)} data-testid="mcp-approve">
              {t("approveServer")}
            </Button>
          ) : null}
          {canWrite ? (
            <Button size="sm" variant="ghost" icon={Trash2} aria-label={t("deleteServer")} onClick={() => setDeleteServer(row)} data-testid="mcp-server-delete" />
          ) : null}
        </div>
      ),
    },
  ];

  const toolColumns: Column<MCPTool>[] = [
    {
      key: "name",
      header: t("tool"),
      render: (row) => (
        <div style={{ minWidth: 190 }}>
          <div className="primary-cell mono" style={{ fontSize: 11.5 }}>{row.name}</div>
          <div className="cell-sub">{row.description ?? "—"}</div>
          <div className="cell-sub">{t("server")}: {serverMap.get(row.server_id)?.name ?? row.server_id.slice(0, 8)}</div>
        </div>
      ),
    },
    {
      key: "risk",
      header: t("risk"),
      width: "100px",
      render: (row) => <Badge tone={RISK_TONE[row.risk_level] ?? "neutral"}>{humanize(row.risk_level)}</Badge>,
    },
    {
      key: "approved",
      header: t("approved"),
      width: "110px",
      render: (row) => <Badge tone={row.approved && row.enabled ? "success" : "warning"}>{row.approved && row.enabled ? t("approved") : t("pending")}</Badge>,
    },
    {
      key: "limits",
      header: `${t("timeout")} / ${t("maxCalls")}`,
      width: "120px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.timeout_seconds}s · {row.max_calls_per_hour}/h</span>,
    },
    {
      key: "permissions",
      header: t("permissionsRequired"),
      width: "170px",
      render: (row) => (
        <div className="chip-row">
          {row.permissions_required.length === 0 ? <span className="dim" style={{ fontSize: 10 }}>—</span> : row.permissions_required.slice(0, 2).map((permission) => <span className="tag" key={permission}>{permission}</span>)}
          {row.permissions_required.length > 2 ? <span className="tag">+{row.permissions_required.length - 2}</span> : null}
        </div>
      ),
    },
    {
      key: "actions",
      header: t("actions"),
      width: "210px",
      align: "right",
      render: (row) => (
        <div className="row wrap" style={{ gap: 3, justifyContent: "flex-end" }}>
          {canExecute && row.approved && row.enabled ? (
            <Button
              size="sm"
              variant="ghost"
              icon={Zap}
              onClick={() => {
                setExecutingTool(row);
                setToolArguments("{}");
                setExecutionResult(null);
                setExecutionError(null);
              }}
              data-testid="mcp-tool-execute"
            >
              {t("execute")}
            </Button>
          ) : null}
          {canWrite ? (
            row.approved ? (
              <Button size="sm" variant="ghost" onClick={() => setRevokingTool(row)} data-testid="mcp-tool-revoke">{t("toolRevoke")}</Button>
            ) : (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setApprovingTool(row);
                  setToolTimeout(String(row.timeout_seconds));
                  setToolMaxCalls(String(row.max_calls_per_hour));
                }}
                data-testid="mcp-tool-approve"
              >
                {t("toolApprove")}
              </Button>
            )
          ) : null}
        </div>
      ),
    },
  ];

  return (
    <div className="stack" data-testid="integrations-mcp">
      <div className="notice notice-accent">
        <ShieldAlert size={14} style={{ flex: "0 0 auto" }} />
        <span>{t("approvalRequiresHuman")} {t("auditNote")}</span>
      </div>

      {!canWrite ? <div className="notice">{t("noMcpWrite")}</div> : null}

      <Card
        title={t("mcpServers")}
        subtitle={t("mcpServersSub")}
        actions={
          canWrite ? (
            <Button
              size="sm"
              variant="primary"
              icon={Plus}
              onClick={() => {
                setServerFormOpen(true);
                setServerName("");
                setServerEndpoint("");
                setServerVersion("");
                setServerTrust("untrusted");
                setServerError(null);
                setServerFieldErrors({});
              }}
              data-testid="mcp-server-create"
            >
              {t("createServer")}
            </Button>
          ) : undefined
        }
        bodyClassName=""
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap">
            <Select value={serverStatus} onChange={(event) => { setServerStatus(event.target.value); setServerPage(1); }} aria-label={t("status")} style={{ width: 170 }} data-testid="mcp-server-status">
              <option value="">{t("allStatuses")}</option>
              <option value="discovered">discovered</option>
              <option value="approved">approved</option>
              <option value="error">error</option>
              <option value="disabled">{t("statusDisabled")}</option>
            </Select>
            <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("common.refresh")} onClick={() => void serversQuery.refetch()} />
          </div>
        </div>
        {serversQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(serversQuery.error)} onRetry={() => void serversQuery.refetch()} />
          </div>
        ) : (
          <>
            <DataTable
              columns={serverColumns}
              rows={serversQuery.data?.items}
              rowKey={(row) => row.id}
              loading={serversQuery.isLoading}
              empty={
                <EmptyState
                  icon={ServerCog}
                  title={t("noServers")}
                  description={t("noServersHint")}
                  action={canWrite ? <Button size="sm" onClick={() => setServerFormOpen(true)}>{t("createServer")}</Button> : undefined}
                />
              }
            />
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={serversQuery.data?.meta} onPage={setServerPage} />
            </div>
          </>
        )}
      </Card>

      <Card
        title={t("mcpTools")}
        subtitle={t("mcpToolsSub")}
        actions={<Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("common.refresh")} onClick={() => void toolsQuery.refetch()} />}
        bodyClassName=""
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap" style={{ gap: 8 }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              <SearchInput value={toolsQ} onChange={(value) => { setToolsQ(value); setToolsPage(1); }} placeholder={t("mcpSearch")} ariaLabel={t("mcpSearch")} />
            </div>
            <Select value={toolsServer} onChange={(event) => { setToolsServer(event.target.value); setToolsPage(1); }} aria-label={t("server")} style={{ width: 200 }} data-testid="mcp-tool-server-filter">
              <option value="">{t("allServers")}</option>
              {(allServersQuery.data?.items ?? []).map((server) => <option key={server.id} value={server.id}>{server.name}</option>)}
            </Select>
            <Select value={toolsApproved} onChange={(event) => { setToolsApproved(event.target.value); setToolsPage(1); }} aria-label={t("approvedTools")} style={{ width: 150 }} data-testid="mcp-tool-approved-filter">
              <option value="approved">{t("approvedTools")}</option>
              <option value="pending">{t("pending")}</option>
              <option value="">{t("allTools")}</option>
            </Select>
          </div>
        </div>
        {toolsQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(toolsQuery.error)} onRetry={() => void toolsQuery.refetch()} />
          </div>
        ) : (
          <>
            <DataTable
              columns={toolColumns}
              rows={toolsQuery.data?.items}
              rowKey={(row) => row.id}
              loading={toolsQuery.isLoading}
              empty={<EmptyState icon={Cable} title={t("noTools")} description={t("noToolsHint")} />}
            />
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={toolsQuery.data?.meta} onPage={setToolsPage} />
            </div>
          </>
        )}
      </Card>

      <Modal
        open={serverFormOpen}
        onClose={() => setServerFormOpen(false)}
        title={t("createServer")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setServerFormOpen(false)} disabled={createServerMutation.isPending}>{t("common.cancel")}</Button>
            <Button
              variant="primary"
              loading={createServerMutation.isPending}
              disabled={serverName.trim().length === 0 || serverEndpoint.trim().length < 8}
              onClick={() => {
                setServerError(null);
                createServerMutation.mutate({
                  name: serverName.trim(),
                  transport: "http",
                  endpoint: serverEndpoint.trim(),
                  trust_level: serverTrust,
                  ...(serverVersion.trim() ? { version: serverVersion.trim() } : {}),
                });
              }}
              data-testid="mcp-server-submit"
            >
              {t("createServer")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <Field label={t("connectorName")} htmlFor={`${idPrefix}-mcp-name`} error={serverFieldErrors.name} required>
            <Input id={`${idPrefix}-mcp-name`} value={serverName} maxLength={120} onChange={(event) => setServerName(event.target.value)} />
          </Field>
          <Field label={t("endpoint")} htmlFor={`${idPrefix}-mcp-endpoint`} error={serverFieldErrors.endpoint} required hint="https://host/mcp">
            <Input id={`${idPrefix}-mcp-endpoint`} value={serverEndpoint} maxLength={500} onChange={(event) => setServerEndpoint(event.target.value)} placeholder="https://" />
          </Field>
          <Field label={t("trustLevel")} htmlFor={`${idPrefix}-mcp-trust`}>
            <Select id={`${idPrefix}-mcp-trust`} value={serverTrust} onChange={(event) => setServerTrust(event.target.value)}>
              <option value="untrusted">{t("trustUntrusted")}</option>
              <option value="limited">{t("trustLimited")}</option>
              <option value="trusted">{t("trustTrusted")}</option>
            </Select>
          </Field>
          <Field label={t("version")} htmlFor={`${idPrefix}-mcp-version`} hint={t("common.optional")}>
            <Input id={`${idPrefix}-mcp-version`} value={serverVersion} maxLength={40} onChange={(event) => setServerVersion(event.target.value)} />
          </Field>
          {serverError ? <ErrorBanner message={serverError} /> : null}
        </div>
      </Modal>

      <ConfirmDialog
        open={approveServer !== null}
        onClose={() => setApproveServer(null)}
        onConfirm={() => { if (approveServer) approveServerMutation.mutate(approveServer); }}
        title={t("approveServer")}
        description={approveServer ? `${approveServer.name} · ${approveServer.endpoint ?? ""}` : undefined}
        warning={`${t("approveToolWarning")} ${t("auditNote")}`}
        confirmLabel={t("approveServer")}
        cancelLabel={t("common.cancel")}
        tone="primary"
        busy={approveServerMutation.isPending}
        testId="mcp-approve-confirm"
      />

      <ConfirmDialog
        open={deleteServer !== null}
        onClose={() => setDeleteServer(null)}
        onConfirm={() => { if (deleteServer) deleteServerMutation.mutate(deleteServer); }}
        title={t("deleteServer")}
        description={deleteServer?.name}
        warning={t("deleteServerWarning")}
        confirmLabel={t("delete")}
        cancelLabel={t("common.cancel")}
        busy={deleteServerMutation.isPending}
        testId="mcp-server-delete-confirm"
      />

      <Modal
        open={approvingTool !== null}
        onClose={() => setApprovingTool(null)}
        title={t("approveToolTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setApprovingTool(null)} disabled={toolDecisionMutation.isPending}>{t("common.cancel")}</Button>
            <Button
              variant="primary"
              loading={toolDecisionMutation.isPending}
              disabled={Number(toolTimeout) < 1 || Number(toolTimeout) > 120 || Number(toolMaxCalls) < 1}
              onClick={() => {
                if (!approvingTool) return;
                toolDecisionMutation.mutate({
                  tool: approvingTool,
                  approved: true,
                  timeout: Number(toolTimeout),
                  maxCalls: Number(toolMaxCalls),
                });
              }}
              data-testid="mcp-tool-approve-submit"
            >
              {t("toolApprove")}
            </Button>
          </>
        }
      >
        {approvingTool ? (
          <div className="stack">
            <div className="notice notice-warning">{t("approveToolWarning")}</div>
            <div className="row wrap">
              <Badge tone={RISK_TONE[approvingTool.risk_level] ?? "neutral"}>{humanize(approvingTool.risk_level)}</Badge>
              <span className="mono" style={{ fontSize: 11 }}>{approvingTool.name}</span>
              <span className="dim" style={{ fontSize: 11 }}>{t("server")}: {serverMap.get(approvingTool.server_id)?.name ?? "—"}</span>
            </div>
            <div className="form-grid">
              <Field label={t("timeout")} htmlFor={`${idPrefix}-tool-timeout`}>
                <Input id={`${idPrefix}-tool-timeout`} inputMode="numeric" value={toolTimeout} onChange={(event) => setToolTimeout(event.target.value.replace(/\D/g, "").slice(0, 3))} />
              </Field>
              <Field label={t("maxCalls")} htmlFor={`${idPrefix}-tool-calls`}>
                <Input id={`${idPrefix}-tool-calls`} inputMode="numeric" value={toolMaxCalls} onChange={(event) => setToolMaxCalls(event.target.value.replace(/\D/g, "").slice(0, 5))} />
              </Field>
            </div>
            <PreBlock value={approvingTool.input_schema} label={t("inputSchema")} />
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={revokingTool !== null}
        onClose={() => setRevokingTool(null)}
        onConfirm={() => { if (revokingTool) toolDecisionMutation.mutate({ tool: revokingTool, approved: false }); }}
        title={t("revokeToolTitle")}
        description={revokingTool?.name}
        warning={t("revokeToolWarning")}
        confirmLabel={t("toolRevoke")}
        cancelLabel={t("common.cancel")}
        busy={toolDecisionMutation.isPending}
        testId="mcp-tool-revoke-confirm"
      />

      <Modal
        open={executingTool !== null}
        onClose={() => setExecutingTool(null)}
        title={t("executeTitle")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setExecutingTool(null)}>{t("close")}</Button>
            <Button
              variant="primary"
              loading={executeMutation.isPending}
              disabled={!parseJsonRecord(toolArguments).ok}
              onClick={() => {
                if (!executingTool) return;
                const parsed = parseJsonRecord(toolArguments);
                if (!parsed.ok) {
                  setExecutionError(parsed.error);
                  return;
                }
                setExecutionError(null);
                executeMutation.mutate({ tool: executingTool, args: parsed.value });
              }}
              data-testid="mcp-execute-submit"
            >
              {t("executeSubmit")}
            </Button>
          </>
        }
      >
        {executingTool ? (
          <div className="stack">
            <div className="row wrap">
              <Badge tone={RISK_TONE[executingTool.risk_level] ?? "neutral"}>{humanize(executingTool.risk_level)}</Badge>
              <span className="mono" style={{ fontSize: 11 }}>{executingTool.name}</span>
              <span className="dim" style={{ fontSize: 11 }}>{t("server")}: {serverMap.get(executingTool.server_id)?.name ?? "—"}</span>
            </div>
            <div className="notice">{t("argumentsHint")} {t("auditNote")}</div>
            <PreBlock value={executingTool.input_schema} label={t("inputSchema")} />
            <JsonEditor
              id={`${idPrefix}-tool-args`}
              label={t("arguments")}
              value={toolArguments}
              onChange={setToolArguments}
              error={!parseJsonRecord(toolArguments).ok ? parseJsonRecord(toolArguments).error : undefined}
              testId="mcp-execute-args"
            />
            {executionError ? <ErrorBanner message={executionError} /> : null}
            {executionResult ? (
              <div className="stack" data-testid="mcp-execution-result">
                <div className="row wrap">
                  <StatusBadge status={executionResult.status} />
                  <span className="dim" style={{ fontSize: 11 }}>{executionResult.latency_ms} ms · {executionResult.execution_id.slice(0, 8)}</span>
                  {executionResult.truncated ? <Badge tone="warning">{t("truncated")}</Badge> : null}
                </div>
                {executionResult.injection_suspected ? (
                  <div className="notice notice-danger">
                    <ShieldAlert size={14} style={{ flex: "0 0 auto" }} />
                    <div>
                      <strong>{t("injectionWarning")}</strong>
                      {executionResult.injection_matches.length ? (
                        <div className="chip-row" style={{ marginTop: 4 }}>
                          {executionResult.injection_matches.map((match) => <span className="tag" key={match}>{match}</span>)}
                        </div>
                      ) : null}
                    </div>
                  </div>
                ) : null}
                {executionResult.error ? <ErrorBanner message={executionResult.error} /> : null}
                <PreBlock value={executionResult.result} label={t("executionResult")} />
              </div>
            ) : null}
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

/* ----------------------------------------------------------------- ingest */

function IngestPointerTab() {
  const t = usePageCopy(COPY);
  return (
    <div className="stack" data-testid="integrations-ingest">
      <Card title={t("ingestTitle")} subtitle={t("ingestBody")}>
        <div className="stack">
          <div className="notice notice-accent">
            <Link2 size={14} style={{ flex: "0 0 auto" }} />
            <span>{t("ingestConnectorNote")}</span>
          </div>
          <div className="row wrap" style={{ gap: 8 }}>
            <LinkButton to="/siem" variant="primary" icon={Activity}>{t("ingestSiem")}</LinkButton>
            <LinkButton to="/edge" icon={Network}>{t("ingestEdge")}</LinkButton>
          </div>
          <div className="divider" />
          <div className="section-label">{t("ingestChecklist")}</div>
          <div className="stack" style={{ gap: 8 }}>
            {[t("checklist1"), t("checklist2"), t("checklist3"), t("checklist4")].map((item, index) => (
              <div className="row" style={{ gap: 8, alignItems: "flex-start" }} key={item}>
                <span className="mono" style={{ fontSize: 10, color: "var(--accent)", flex: "0 0 auto", marginTop: 2 }}>0{index + 1}</span>
                <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{item}</span>
              </div>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}

/* -------------------------------------------------------------------- page */

export function IntegrationsPage() {
  const t = usePageCopy(COPY);
  const { can } = useAuth();
  const [tab, setTab] = useState<TabKey>("connectors");

  const canReadConnectors = can("connector:read");
  const canWriteConnectors = can("connector:write");
  const canExecuteConnectors = can("connector:execute");
  const canReadMcp = can("mcp:read");
  const canWriteMcp = can("mcp:write");
  const canExecuteMcp = can("mcp:execute");

  const visibleTabs = useMemo(() => {
    const items: { key: TabKey; label: string }[] = [];
    if (canReadConnectors) items.push({ key: "connectors", label: t("tabConnectors") });
    if (canReadMcp) items.push({ key: "mcp", label: t("tabMcp") });
    items.push({ key: "ingest", label: t("tabIngest") });
    return items;
  }, [canReadConnectors, canReadMcp, t]);

  const active = visibleTabs.some((item) => item.key === tab) ? tab : visibleTabs[0]?.key ?? "ingest";

  if (!canReadConnectors && !canReadMcp) {
    return (
      <div className="animate-in" data-testid="page-integrations">
        <PageHeader eyebrow={t("eyebrow")} title={t("title")} subtitle={t("subtitle")} />
        <Card>
          <EmptyState icon={Lock} title={t("noPermission")} />
        </Card>
      </div>
    );
  }

  return (
    <div className="animate-in" data-testid="page-integrations">
      <PageHeader
        eyebrow={t("eyebrow")}
        title={t("title")}
        subtitle={t("subtitle")}
        actions={
          <>
            {canWriteConnectors ? <Badge tone="accent"><Plug size={11} /> {t("tabConnectors")}</Badge> : null}
            {canWriteMcp ? <Badge tone="warning"><ServerCog size={11} /> {t("tabMcp")}</Badge> : null}
            <LinkButton to="/defence" icon={ShieldCheck}>{t("writeViaBroker").split(";")[0]}</LinkButton>
          </>
        }
      />

      <div style={{ marginBottom: 12 }}>
        <Tabs<TabKey> ariaLabel={t("title")} items={visibleTabs} value={active} onChange={setTab} />
      </div>

      {active === "connectors" && canReadConnectors ? (
        <ConnectorsTab canWrite={canWriteConnectors} canExecute={canExecuteConnectors} />
      ) : null}
      {active === "mcp" && canReadMcp ? <McpTab canWrite={canWriteMcp} canExecute={canExecuteMcp} /> : null}
      {active === "ingest" ? <IngestPointerTab /> : null}

      <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
        <CheckCircle2 size={13} style={{ flex: "0 0 auto", color: "var(--success)" }} />
        <span>{t("connectorsHint")}</span>
      </div>
    </div>
  );
}

export default IntegrationsPage;
