import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Archive,
  BellRing,
  Check,
  Copy,
  Database,
  FileCode2,
  Filter,
  FlaskConical,
  KeyRound,
  Layers,
  Pencil,
  Plus,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Siren,
  Trash2,
  UploadCloud,
  X,
} from "lucide-react";
import { api, errorMessage, isApiError, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatCompact, formatDateTime, formatNumber, relativeTime } from "../lib/format";
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
  Modal,
  PageHeader,
  Pagination,
  SearchInput,
  Select,
  SeverityBadge,
  StatusBadge,
  Tabs,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";

/* ------------------------------------------------------------------ types */

interface DetectionRule {
  id: string;
  org_id: string | null;
  name: string;
  description: string | null;
  severity: string;
  status: string;
  enabled: boolean;
  version: number;
  logsource: Record<string, unknown>;
  definition: Record<string, unknown>;
  mitre: string[];
  tags: string[];
  false_positive_count: number;
  true_positive_count: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  scope: "global" | "organization";
}

interface RuleTemplate {
  key?: string;
  name: string;
  description?: string;
  severity?: string;
  logsource?: Record<string, unknown>;
  definition?: Record<string, unknown>;
  mitre?: string[];
  tags?: string[];
}

interface RuleTestResult {
  rule_id: string;
  rule_name: string;
  version: number;
  matched_count?: number;
  would_alert?: boolean;
  [key: string]: unknown;
}

interface SigmaImportResponse {
  imported: DetectionRule[];
  skipped: { title: string; reason: string }[];
}

interface AlertSummary {
  id: string;
  org_id: string;
  rule_id: string | null;
  rule_name: string | null;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  dedupe_key: string | null;
  event_ids: number[];
  first_seen: string;
  last_seen: string;
  count: number;
  assignee_id: string | null;
  incident_id: string | null;
  mitre: string[];
  risk_score: number;
  is_demo: boolean;
  created_at: string;
  updated_at: string;
}

interface AlertDetail extends AlertSummary {
  evidence: Record<string, unknown>;
}

interface AlertStats {
  generated_at: string;
  window_hours: number;
  total: number;
  open: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  top_rules: { rule_id: string | null; name: string; count: number }[];
  timeline: { timestamp: string; count: number }[];
}

interface BulkResult {
  updated: number;
  skipped: number;
  ids: string[];
}

interface PromoteResult {
  incident: { id: string; ref: string; title: string };
  alert_id: string;
  incident_id: string;
}

interface OrganizationMember {
  user_id: string;
  full_name: string;
  email: string;
}

interface IngestSource {
  id: string;
  org_id: string;
  name: string;
  kind: string;
  parser: string;
  enabled: boolean;
  connector_id: string | null;
  config: Record<string, unknown>;
  last_event_at: string | null;
  event_count: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  has_token: boolean;
  has_hmac_secret: boolean;
}

interface IngestSourceCreated extends IngestSource {
  token: string;
  hmac_secret: string | null;
}

interface RetentionPolicy {
  policy_id: string | null;
  name: string;
  kind: string;
  version: number;
  enabled: boolean;
  definition: {
    hot_days?: number;
    cold_days?: number;
    batch_size?: number;
    purge_enabled?: boolean;
  };
  effective_cutoff: string;
  source: "default" | "policy";
  updated_at: string | null;
}

interface PurgeResult {
  deleted: number;
  cutoff: string;
  batches: number;
  truncated: boolean;
}

interface SecretReveal {
  title: string;
  token: string | null;
  hmacSecret: string | null;
  sourceName: string;
}

type Tab = "rules" | "alerts" | "sources" | "retention";

/* ------------------------------------------------------------------- copy */

const COPY = {
  es: {
    eyebrow: "Detección · SIEM",
    title: "SIEM y detección",
    subtitle: "Reglas versionadas, triaje de alertas, fuentes de ingesta y retención de eventos.",
    tabRules: "Reglas",
    tabAlerts: "Alertas",
    tabSources: "Fuentes",
    tabRetention: "Retención",
    refresh: "Actualizar",
    errorTitle: "No se pudieron cargar los datos del SIEM",
    forbidden: "Permisos insuficientes para este recurso.",
    rulesTitle: "Catálogo de reglas",
    rulesSubtitle: "Reglas globales y de la organización con versionado y pruebas sobre eventos reales.",
    newRule: "Nueva regla",
    templates: "Plantillas",
    importSigma: "Importar Sigma",
    coverage: "Cobertura MITRE",
    ruleSearch: "Buscar reglas por nombre…",
    scopeAll: "Todos los ámbitos",
    scopeOrg: "Organización",
    scopeGlobal: "Globales",
    enabledAll: "Habilitadas y deshabilitadas",
    enabledOnly: "Solo habilitadas",
    disabledOnly: "Solo deshabilitadas",
    colRule: "Regla",
    colSeverity: "Severidad",
    colStatus: "Estado",
    colScope: "Ámbito",
    colVersion: "Versión",
    colEnabled: "Activa",
    colUpdated: "Actualizada",
    colActions: "Acciones",
    edit: "Editar",
    test: "Probar",
    enable: "Habilitar",
    disable: "Deshabilitar",
    delete: "Eliminar",
    deleteRuleTitle: "Eliminar regla de detección",
    deleteRuleWarning: "La regla dejará de evaluarse. Las alertas históricas se conservan y la acción queda auditada.",
    deleteRuleConfirm: "Eliminar regla",
    ruleDeleted: "Regla eliminada",
    ruleEnabled: "Regla habilitada",
    ruleDisabled: "Regla deshabilitada",
    ruleToggleError: "No se pudo cambiar el estado de la regla",
    ruleSaved: "Regla guardada",
    ruleSaveError: "No se pudo guardar la regla",
    ruleEditorNew: "Nueva regla de detección",
    ruleEditorEdit: "Editar regla",
    ruleName: "Nombre",
    ruleDescription: "Descripción",
    ruleSeverity: "Severidad",
    ruleStatus: "Ciclo de vida",
    ruleLogsource: "Logsource (JSON)",
    ruleDefinition: "Definición ejecutable (JSON)",
    ruleMitre: "Técnicas MITRE",
    ruleTags: "Etiquetas",
    ruleEnabledField: "Regla habilitada",
    saveRule: "Guardar regla",
    invalidJson: "JSON inválido en {field}: {error}",
    ruleTestTitle: "Probar regla contra eventos",
    ruleTestHint: "Pega un evento JSON o una lista de eventos. El servidor evalúa la definición y los umbrales.",
    sampleEvent: "Evento(s) de muestra (JSON)",
    runTest: "Ejecutar prueba",
    testResult: "Resultado de la prueba",
    matched: "Coincidencias",
    wouldAlert: "Generaría alerta",
    testError: "La prueba de la regla falló",
    sigmaTitle: "Importar reglas Sigma",
    sigmaHint: "Pega una regla Sigma o una lista. El servidor convierte el subconjunto soportado y rechaza el resto con motivo.",
    sigmaInput: "Regla(s) Sigma (JSON)",
    import: "Importar",
    sigmaResult: "Resultado de la importación",
    imported: "Importadas",
    skipped: "Omitidas",
    importError: "No se pudo importar el Sigma",
    templatesTitle: "Plantillas de detección",
    templatesHint: "Reglas integradas listas para clonar y ajustar en la organización.",
    useTemplate: "Usar plantilla",
    templatesEmpty: "No hay plantillas disponibles.",
    coverageTitle: "Cobertura MITRE ATT&CK",
    coverageHint: "Técnicas observadas en eventos y alertas de la organización.",
    coverageEmpty: "Sin técnicas observadas todavía.",
    technique: "Técnica",
    techniqueName: "Nombre",
    events: "Eventos",
    alerts: "Alertas",
    totalTechniques: "{count} técnicas",
    alertsTitle: "Cola de alertas",
    alertsSubtitle: "Triaje, asignación y promoción a incidente.",
    kpiTotalAlerts: "Alertas totales",
    kpiOpenAlerts: "Abiertas",
    kpiCriticalAlerts: "Críticas",
    kpiVolume: "Volumen 24 h",
    alertsOpenFoot: "new · triaged · investigating",
    alertsCriticalFoot: "Severidad crítica en la ventana",
    alertsVolumeFoot: "Eventos de alerta agregados por hora",
    alertSearch: "Buscar alertas por título…",
    alertAllStatuses: "Todos los estados",
    alertAllSeverities: "Todas las severidades",
    alertSort: "Orden",
    sortCreated: "Creación",
    sortLastSeen: "Última observación",
    sortSeverity: "Severidad",
    sortRisk: "Riesgo",
    sortCount: "Recurrencia",
    bulkAction: "Acción masiva ({count})",
    bulkTitle: "Triaje masivo de alertas",
    bulkHint: "Se aplicará el mismo cambio a {count} alertas seleccionadas.",
    bulkStatus: "Nuevo estado",
    bulkNote: "Nota de triaje",
    applyBulk: "Aplicar a seleccionadas",
    bulkDone: "{updated} alertas actualizadas · {skipped} omitidas",
    bulkError: "No se pudo aplicar el triaje masivo",
    selectAll: "Seleccionar página",
    colAlert: "Alerta",
    colCount: "Veces",
    colRisk: "Riesgo",
    colLastSeen: "Última vez",
    colIncident: "Incidente",
    openIncident: "Abrir incidente",
    alertDetailTitle: "Detalle de alerta",
    alertTriage: "Triaje",
    alertTriageStatus: "Estado",
    alertTriageNote: "Nota",
    alertAssignee: "Responsable",
    keepAssignee: "Mantener responsable actual",
    saveTriage: "Guardar triaje",
    triageSaved: "Alerta actualizada",
    triageError: "No se pudo actualizar la alerta",
    promote: "Promover a incidente",
    promoteTitle: "Promover alerta a incidente",
    promoteHint: "Se creará un incidente con la severidad y los activos correlacionados. La operación queda auditada.",
    promoteIncidentTitle: "Título del incidente (opcional)",
    promoteDescription: "Descripción (opcional)",
    promoteConfirm: "Crear incidente",
    promoted: "Incidente {ref} creado",
    promoteError: "No se pudo promover la alerta",
    alertEvidence: "Evidencia correlacionada",
    alertEvents: "IDs de eventos",
    alertMitre: "MITRE",
    noEvidence: "Sin evidencia almacenada.",
    emptyAlertsTitle: "Sin alertas",
    emptyAlertsDesc: "Las reglas de detección no han generado alertas con estos filtros.",
    emptyAlertsFilter: "Ninguna alerta coincide con los filtros.",
    clearFilters: "Limpiar filtros",
    sourcesTitle: "Fuentes de ingesta",
    sourcesSubtitle: "Tokens de ingesta, firma HMAC y actividad por fuente.",
    newSource: "Nueva fuente",
    sourceSearch: "Buscar fuentes por nombre…",
    colSource: "Fuente",
    colKind: "Tipo",
    colParser: "Parser",
    colLastEvent: "Último evento",
    colEvents: "Eventos",
    colToken: "Credenciales",
    rotate: "Rotar token",
    rotateTitle: "Rotar token de ingesta",
    rotateWarning: "El token anterior se invalida inmediatamente. Los emisores deben actualizarse.",
    rotateConfirm: "Rotar token",
    deleteSourceTitle: "Eliminar fuente de ingesta",
    deleteSourceWarning: "Los emisores que usen esta fuente dejarán de poder ingerir. La acción queda auditada.",
    deleteSourceConfirm: "Eliminar fuente",
    sourceCreated: "Fuente creada",
    sourceUpdated: "Fuente actualizada",
    sourceDeleted: "Fuente eliminada",
    sourceError: "No se pudo guardar la fuente",
    sourceToggleError: "No se pudo cambiar el estado de la fuente",
    createSource: "Crear fuente de ingesta",
    createSourceHint: "El token se muestra una única vez al crear la fuente o al rotarlo.",
    sourceName: "Nombre",
    sourceKind: "Tipo",
    sourceParser: "Parser",
    generateSecret: "Generar secreto HMAC",
    customSecret: "Secreto HMAC personalizado (opcional, mín. 16)",
    submitSource: "Crear fuente",
    tokenOnceTitle: "Credenciales de ingesta",
    tokenOnceWarning: "Copia estos valores ahora. No volverán a mostrarse completos.",
    tokenLabel: "Token de ingesta",
    secretLabel: "Secreto HMAC",
    copy: "Copiar",
    copied: "Copiado al portapapeles",
    curlTitle: "Ejemplo de envío",
    curlHint: "Sustituye <TOKEN> por el token de la fuente. La firma HMAC es opcional pero recomendada.",
    curlShow: "Ver ejemplo cURL",
    hasToken: "Token",
    hasSecret: "HMAC",
    yes: "Sí",
    no: "No",
    enabled: "Activa",
    disabled: "Inactiva",
    lastEventNever: "Nunca",
    sourcesEmpty: "Sin fuentes de ingesta",
    sourcesEmptyDesc: "Crea una fuente para empezar a recibir telemetría normalizada.",
    retentionTitle: "Política de retención",
    retentionSubtitle: "Ventana caliente, tamaño de lote y purga inmutable auditada.",
    retentionSourceDefault: "Valores por defecto de la plataforma",
    retentionSourcePolicy: "Política de la organización",
    hotDays: "Días en caliente",
    coldDays: "Días en frío",
    batchSize: "Tamaño de lote",
    purgeEnabled: "Purga habilitada",
    saveRetention: "Guardar política",
    retentionSaved: "Política de retención guardada",
    retentionError: "No se pudo guardar la política",
    effectiveCutoff: "Corte efectivo",
    policyVersion: "Versión",
    policySource: "Origen",
    updatedAt: "Actualizada",
    purgeTitle: "Purgar eventos antiguos",
    purgeWarning:
      "La purga elimina de forma permanente los eventos anteriores al corte. Es irreversible y queda registrada en la auditoría.",
    purgeNow: "Purgar ahora",
    purgeConfirm: "Confirmar purga",
    purgeDone: "Purgados {deleted} eventos en {batches} lotes",
    purgeTruncated: "La purga alcanzó el límite de lotes; ejecútala de nuevo para continuar.",
    purgeError: "La purga falló",
    purgeDisabled: "La purga está deshabilitada en esta política.",
    hotHint: "1–3650 días.",
    coldHint: "Debe ser ≥ días en caliente.",
    batchHint: "100–50000 registros por lote.",
    demo: "DEMO",
    totalRecords: "registros",
    rulesEmpty: "Sin reglas de detección",
    rulesEmptyDesc: "Crea una regla, importa Sigma o clona una plantilla integrada.",
  },
  en: {
    eyebrow: "Detection · SIEM",
    title: "SIEM and detection",
    subtitle: "Versioned rules, alert triage, ingestion sources and event retention.",
    tabRules: "Rules",
    tabAlerts: "Alerts",
    tabSources: "Sources",
    tabRetention: "Retention",
    refresh: "Refresh",
    errorTitle: "Could not load SIEM data",
    forbidden: "Insufficient permissions for this resource.",
    rulesTitle: "Detection rule catalogue",
    rulesSubtitle: "Global and organization rules with versioning and tests against real events.",
    newRule: "New rule",
    templates: "Templates",
    importSigma: "Import Sigma",
    coverage: "MITRE coverage",
    ruleSearch: "Search rules by name…",
    scopeAll: "All scopes",
    scopeOrg: "Organization",
    scopeGlobal: "Global",
    enabledAll: "Enabled and disabled",
    enabledOnly: "Enabled only",
    disabledOnly: "Disabled only",
    colRule: "Rule",
    colSeverity: "Severity",
    colStatus: "Status",
    colScope: "Scope",
    colVersion: "Version",
    colEnabled: "Enabled",
    colUpdated: "Updated",
    colActions: "Actions",
    edit: "Edit",
    test: "Test",
    enable: "Enable",
    disable: "Disable",
    delete: "Delete",
    deleteRuleTitle: "Delete detection rule",
    deleteRuleWarning: "The rule will stop being evaluated. Historical alerts are retained and the action is audited.",
    deleteRuleConfirm: "Delete rule",
    ruleDeleted: "Rule deleted",
    ruleEnabled: "Rule enabled",
    ruleDisabled: "Rule disabled",
    ruleToggleError: "Could not change the rule state",
    ruleSaved: "Rule saved",
    ruleSaveError: "Could not save the rule",
    ruleEditorNew: "New detection rule",
    ruleEditorEdit: "Edit rule",
    ruleName: "Name",
    ruleDescription: "Description",
    ruleSeverity: "Severity",
    ruleStatus: "Lifecycle",
    ruleLogsource: "Logsource (JSON)",
    ruleDefinition: "Executable definition (JSON)",
    ruleMitre: "MITRE techniques",
    ruleTags: "Tags",
    ruleEnabledField: "Rule enabled",
    saveRule: "Save rule",
    invalidJson: "Invalid JSON in {field}: {error}",
    ruleTestTitle: "Test rule against events",
    ruleTestHint: "Paste one JSON event or a list. The server evaluates the definition and thresholds.",
    sampleEvent: "Sample event(s) (JSON)",
    runTest: "Run test",
    testResult: "Test result",
    matched: "Matches",
    wouldAlert: "Would alert",
    testError: "Rule test failed",
    sigmaTitle: "Import Sigma rules",
    sigmaHint: "Paste one Sigma rule or a list. The server converts the supported subset and rejects the rest with a reason.",
    sigmaInput: "Sigma rule(s) (JSON)",
    import: "Import",
    sigmaResult: "Import result",
    imported: "Imported",
    skipped: "Skipped",
    importError: "Could not import Sigma",
    templatesTitle: "Detection templates",
    templatesHint: "Built-in rules ready to clone and tune for the organization.",
    useTemplate: "Use template",
    templatesEmpty: "No templates available.",
    coverageTitle: "MITRE ATT&CK coverage",
    coverageHint: "Techniques observed across organization events and alerts.",
    coverageEmpty: "No techniques observed yet.",
    technique: "Technique",
    techniqueName: "Name",
    events: "Events",
    alerts: "Alerts",
    totalTechniques: "{count} techniques",
    alertsTitle: "Alert queue",
    alertsSubtitle: "Triage, assignment and promotion to incident.",
    kpiTotalAlerts: "Total alerts",
    kpiOpenAlerts: "Open",
    kpiCriticalAlerts: "Critical",
    kpiVolume: "24 h volume",
    alertsOpenFoot: "new · triaged · investigating",
    alertsCriticalFoot: "Critical severity in the window",
    alertsVolumeFoot: "Alert events aggregated hourly",
    alertSearch: "Search alerts by title…",
    alertAllStatuses: "All statuses",
    alertAllSeverities: "All severities",
    alertSort: "Sort",
    sortCreated: "Created",
    sortLastSeen: "Last seen",
    sortSeverity: "Severity",
    sortRisk: "Risk",
    sortCount: "Recurrence",
    bulkAction: "Bulk action ({count})",
    bulkTitle: "Bulk alert triage",
    bulkHint: "The same change will be applied to {count} selected alerts.",
    bulkStatus: "New status",
    bulkNote: "Triage note",
    applyBulk: "Apply to selected",
    bulkDone: "{updated} alerts updated · {skipped} skipped",
    bulkError: "Could not apply bulk triage",
    selectAll: "Select page",
    colAlert: "Alert",
    colCount: "Count",
    colRisk: "Risk",
    colLastSeen: "Last seen",
    colIncident: "Incident",
    openIncident: "Open incident",
    alertDetailTitle: "Alert detail",
    alertTriage: "Triage",
    alertTriageStatus: "Status",
    alertTriageNote: "Note",
    alertAssignee: "Assignee",
    keepAssignee: "Keep current assignee",
    saveTriage: "Save triage",
    triageSaved: "Alert updated",
    triageError: "Could not update the alert",
    promote: "Promote to incident",
    promoteTitle: "Promote alert to incident",
    promoteHint: "An incident will be created with the correlated severity and assets. The operation is audited.",
    promoteIncidentTitle: "Incident title (optional)",
    promoteDescription: "Description (optional)",
    promoteConfirm: "Create incident",
    promoted: "Incident {ref} created",
    promoteError: "Could not promote the alert",
    alertEvidence: "Correlated evidence",
    alertEvents: "Event IDs",
    alertMitre: "MITRE",
    noEvidence: "No stored evidence.",
    emptyAlertsTitle: "No alerts",
    emptyAlertsDesc: "Detection rules have not produced alerts for these filters.",
    emptyAlertsFilter: "No alert matches the filters.",
    clearFilters: "Clear filters",
    sourcesTitle: "Ingestion sources",
    sourcesSubtitle: "Ingestion tokens, HMAC signatures and per-source activity.",
    newSource: "New source",
    sourceSearch: "Search sources by name…",
    colSource: "Source",
    colKind: "Kind",
    colParser: "Parser",
    colLastEvent: "Last event",
    colEvents: "Events",
    colToken: "Credentials",
    rotate: "Rotate token",
    rotateTitle: "Rotate ingestion token",
    rotateWarning: "The previous token is invalidated immediately. Emitters must be updated.",
    rotateConfirm: "Rotate token",
    deleteSourceTitle: "Delete ingestion source",
    deleteSourceWarning: "Emitters using this source will no longer be able to ingest. The action is audited.",
    deleteSourceConfirm: "Delete source",
    sourceCreated: "Source created",
    sourceUpdated: "Source updated",
    sourceDeleted: "Source deleted",
    sourceError: "Could not save the source",
    sourceToggleError: "Could not change the source state",
    createSource: "Create ingestion source",
    createSourceHint: "The token is shown once when the source is created or rotated.",
    sourceName: "Name",
    sourceKind: "Kind",
    sourceParser: "Parser",
    generateSecret: "Generate HMAC secret",
    customSecret: "Custom HMAC secret (optional, min. 16)",
    submitSource: "Create source",
    tokenOnceTitle: "Ingestion credentials",
    tokenOnceWarning: "Copy these values now. They will never be shown in full again.",
    tokenLabel: "Ingestion token",
    secretLabel: "HMAC secret",
    copy: "Copy",
    copied: "Copied to clipboard",
    curlTitle: "Submission example",
    curlHint: "Replace <TOKEN> with the source token. The HMAC signature is optional but recommended.",
    curlShow: "Show cURL example",
    hasToken: "Token",
    hasSecret: "HMAC",
    yes: "Yes",
    no: "No",
    enabled: "Enabled",
    disabled: "Disabled",
    lastEventNever: "Never",
    sourcesEmpty: "No ingestion sources",
    sourcesEmptyDesc: "Create a source to start receiving normalized telemetry.",
    retentionTitle: "Retention policy",
    retentionSubtitle: "Hot window, batch size and audited immutable purge.",
    retentionSourceDefault: "Platform defaults",
    retentionSourcePolicy: "Organization policy",
    hotDays: "Hot days",
    coldDays: "Cold days",
    batchSize: "Batch size",
    purgeEnabled: "Purge enabled",
    saveRetention: "Save policy",
    retentionSaved: "Retention policy saved",
    retentionError: "Could not save the policy",
    effectiveCutoff: "Effective cutoff",
    policyVersion: "Version",
    policySource: "Source",
    updatedAt: "Updated",
    purgeTitle: "Purge old events",
    purgeWarning:
      "Purge permanently deletes events older than the cutoff. It is irreversible and recorded in the audit trail.",
    purgeNow: "Purge now",
    purgeConfirm: "Confirm purge",
    purgeDone: "Purged {deleted} events in {batches} batches",
    purgeTruncated: "Purge hit the batch limit; run it again to continue.",
    purgeError: "Purge failed",
    purgeDisabled: "Purge is disabled in this policy.",
    hotHint: "1–3650 days.",
    coldHint: "Must be ≥ hot days.",
    batchHint: "100–50000 records per batch.",
    demo: "DEMO",
    totalRecords: "records",
    rulesEmpty: "No detection rules",
    rulesEmptyDesc: "Create a rule, import Sigma or clone a built-in template.",
  },
};

/* ---------------------------------------------------------------- helpers */

function parseObject(text: string, field: string, c: (key: string) => string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(c("invalidJson").replace("{field}", field).replace("{error}", "object expected"));
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    throw new Error(
      c("invalidJson")
        .replace("{field}", field)
        .replace("{error}", error instanceof Error ? error.message : "invalid JSON"),
    );
  }
}

function errorText(error: unknown, c: (key: string) => string): string {
  if (isApiError(error) && error.status === 403) return c("forbidden");
  if (isApiError(error) && error.details.length) {
    return error.details.map((detail) => `${detail.field}: ${detail.message}`).join(" · ");
  }
  return errorMessage(error);
}

/* ------------------------------------------------------------ rule editor */

function RuleEditorModal({
  open,
  rule,
  template,
  onClose,
  onSaved,
}: {
  open: boolean;
  rule: DetectionRule | null;
  template: RuleTemplate | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const { push } = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [status, setStatus] = useState("production");
  const [enabled, setEnabled] = useState(true);
  const [logsource, setLogsource] = useState("{}");
  const [definition, setDefinition] = useState('{\n  "selection": {},\n  "condition": "and"\n}');
  const [mitre, setMitre] = useState("");
  const [tags, setTags] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const reset = (nextRule: DetectionRule | null, nextTemplate: RuleTemplate | null) => {
    setName(nextRule?.name ?? nextTemplate?.name ?? "");
    setDescription(nextRule?.description ?? nextTemplate?.description ?? "");
    setSeverity(nextRule?.severity ?? nextTemplate?.severity ?? "medium");
    setStatus(nextRule?.status ?? "production");
    setEnabled(nextRule?.enabled ?? true);
    setLogsource(JSON.stringify(nextRule?.logsource ?? nextTemplate?.logsource ?? {}, null, 2));
    setDefinition(
      JSON.stringify(
        nextRule?.definition ?? nextTemplate?.definition ?? { selection: {}, condition: "and" },
        null,
        2,
      ),
    );
    setMitre((nextRule?.mitre ?? nextTemplate?.mitre ?? []).join(", "));
    setTags((nextRule?.tags ?? nextTemplate?.tags ?? []).join(", "));
    setFormError(null);
  };

  useEffect(() => {
    if (open) reset(rule, template);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, rule, template]);

  const mutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      rule
        ? api.patch<DetectionRule>(`/siem/rules/${rule.id}`, body)
        : api.post<DetectionRule>("/siem/rules", body),
    onSuccess: () => {
      push(c("ruleSaved"), "success");
      onSaved();
    },
    onError: (error) => setFormError(errorText(error, c)),
  });

  const submit = () => {
    setFormError(null);
    if (name.trim().length < 3) {
      setFormError(c("ruleName"));
      return;
    }
    try {
      const parsedLogsource = parseObject(logsource, c("ruleLogsource"), c);
      const parsedDefinition = parseObject(definition, c("ruleDefinition"), c);
      mutation.mutate({
        name: name.trim(),
        description: description.trim() || null,
        severity,
        status,
        enabled,
        logsource: parsedLogsource,
        definition: parsedDefinition,
        mitre: mitre
          .split(",")
          .map((value) => value.trim().toUpperCase())
          .filter(Boolean),
        tags: tags
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean),
      });
    } catch (error) {
      setFormError(error instanceof Error ? error.message : String(error));
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={rule ? c("ruleEditorEdit") : c("ruleEditorNew")}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button variant="primary" loading={mutation.isPending} onClick={submit} data-testid="submit-rule">
            {c("saveRule")}
          </Button>
        </>
      }
    >
      <div className="form-grid" data-testid="rule-editor">
        <div className="span-2">
          <Field label={c("ruleName")} required htmlFor="rule-name">
            <Input id="rule-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={200} data-testid="rule-name-input" />
          </Field>
        </div>
        <div className="span-2">
          <Field label={c("ruleDescription")} htmlFor="rule-description">
            <Textarea id="rule-description" value={description} onChange={(event) => setDescription(event.target.value)} rows={2} maxLength={2000} />
          </Field>
        </div>
        <Field label={c("ruleSeverity")} htmlFor="rule-severity">
          <Select id="rule-severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
            {["informational", "low", "medium", "high", "critical"].map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </Select>
        </Field>
        <Field label={c("ruleStatus")} htmlFor="rule-status">
          <Select id="rule-status" value={status} onChange={(event) => setStatus(event.target.value)}>
            {["production", "experimental", "draft", "deprecated"].map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </Select>
        </Field>
        <Field label={c("ruleMitre")} hint="T####, T####.###" htmlFor="rule-mitre">
          <Input id="rule-mitre" value={mitre} onChange={(event) => setMitre(event.target.value)} />
        </Field>
        <Field label={c("ruleTags")} hint="comma separated" htmlFor="rule-tags">
          <Input id="rule-tags" value={tags} onChange={(event) => setTags(event.target.value)} />
        </Field>
        <div className="span-2">
          <label className="checkbox">
            <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
            {c("ruleEnabledField")}
          </label>
        </div>
        <div className="span-2">
          <Field label={c("ruleLogsource")} htmlFor="rule-logsource">
            <Textarea id="rule-logsource" className="textarea mono" value={logsource} onChange={(event) => setLogsource(event.target.value)} rows={4} spellCheck={false} />
          </Field>
        </div>
        <div className="span-2">
          <Field label={c("ruleDefinition")} htmlFor="rule-definition">
            <Textarea id="rule-definition" className="textarea mono" value={definition} onChange={(event) => setDefinition(event.target.value)} rows={10} spellCheck={false} data-testid="rule-definition-input" />
          </Field>
        </div>
      </div>
      {formError ? <div style={{ marginTop: 10 }}><ErrorBanner compact message={formError} /></div> : null}
    </Modal>
  );
}

/* -------------------------------------------------------------- rule test */

function RuleTestModal({
  open,
  rule,
  onClose,
}: {
  open: boolean;
  rule: DetectionRule | null;
  onClose: () => void;
}) {
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const [sample, setSample] = useState('{\n  "message": "failed password for invalid user admin from 10.0.0.5",\n  "severity": "high",\n  "src_ip": "10.0.0.5",\n  "host_name": "web-01"\n}');
  const [result, setResult] = useState<RuleTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setResult(null);
      setError(null);
    }
  }, [open, rule]);

  const mutation = useMutation({
    mutationFn: () => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(sample);
      } catch (parseError) {
        throw new Error(parseError instanceof Error ? parseError.message : "invalid JSON");
      }
      const events = Array.isArray(parsed) ? parsed : [parsed];
      if (!rule) throw new Error("rule");
      return api.post<RuleTestResult>(`/siem/rules/${rule.id}/test`, { events, apply_threshold: true });
    },
    onSuccess: (data) => {
      setResult(data);
      setError(null);
    },
    onError: (err) => setError(errorText(err, c)),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={c("ruleTestTitle")}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
          <Button variant="primary" icon={FlaskConical} loading={mutation.isPending} onClick={() => mutation.mutate()} data-testid="run-rule-test">
            {c("runTest")}
          </Button>
        </>
      }
    >
      <div data-testid="rule-test-modal">
        <p className="hint" style={{ marginBottom: 8 }}>{c("ruleTestHint")}</p>
        <div className="row-between" style={{ marginBottom: 6 }}>
          <span className="section-label" style={{ margin: 0 }}>{rule?.name ?? "—"}</span>
          <Badge tone="neutral">v{rule?.version ?? 0}</Badge>
        </div>
        <Field label={c("sampleEvent")} htmlFor="rule-sample">
          <Textarea id="rule-sample" className="textarea mono" value={sample} onChange={(event) => setSample(event.target.value)} rows={10} spellCheck={false} />
        </Field>
        {error ? <div style={{ marginTop: 10 }}><ErrorBanner compact message={error} /></div> : null}
        {result ? (
          <div style={{ marginTop: 12 }} data-testid="rule-test-result">
            <div className="row wrap" style={{ gap: 6, marginBottom: 8 }}>
              <Badge tone={result.would_alert ? "danger" : "success"}>
                {c("wouldAlert")}: {result.would_alert ? c("yes") : c("no")}
              </Badge>
              <Badge tone="neutral">{c("matched")}: {result.matched_count ?? 0}</Badge>
            </div>
            <pre className="code-block">{JSON.stringify(result, null, 2)}</pre>
          </div>
        ) : null}
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------ sigma */

function SigmaImportModal({ open, onClose, onImported }: { open: boolean; onClose: () => void; onImported: () => void }) {
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const { push } = useToast();
  const [text, setText] = useState("");
  const [result, setResult] = useState<SigmaImportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setResult(null);
      setError(null);
    }
  }, [open]);

  const mutation = useMutation({
    mutationFn: () => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch (parseError) {
        throw new Error(parseError instanceof Error ? parseError.message : "invalid JSON");
      }
      const rules = Array.isArray(parsed) ? parsed : [parsed];
      return api.post<SigmaImportResponse>("/siem/rules/import", { rules });
    },
    onSuccess: (data) => {
      setResult(data);
      setError(null);
      if (data.imported.length) {
        push(`${c("imported")}: ${data.imported.length}`, "success");
        onImported();
      }
    },
    onError: (err) => setError(errorText(err, c)),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={c("sigmaTitle")}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
          <Button variant="primary" icon={UploadCloud} loading={mutation.isPending} disabled={!text.trim()} onClick={() => mutation.mutate()} data-testid="submit-sigma-import">
            {c("import")}
          </Button>
        </>
      }
    >
      <div data-testid="sigma-import-modal">
        <p className="hint" style={{ marginBottom: 8 }}>{c("sigmaHint")}</p>
        <Field label={c("sigmaInput")} htmlFor="sigma-input">
          <Textarea
            id="sigma-input"
            className="textarea mono"
            value={text}
            onChange={(event) => setText(event.target.value)}
            rows={12}
            spellCheck={false}
            placeholder={'{\n  "title": "Suspicious login",\n  "detection": { "selection": { "message|contains": "failed" }, "condition": "selection" }\n}'}
          />
        </Field>
        {error ? <div style={{ marginTop: 10 }}><ErrorBanner compact message={error} /></div> : null}
        {result ? (
          <div style={{ marginTop: 12 }} data-testid="sigma-import-result">
            <div className="row" style={{ gap: 8, marginBottom: 8 }}>
              <Badge tone="success">{c("imported")}: {result.imported.length}</Badge>
              <Badge tone={result.skipped.length ? "warning" : "neutral"}>{c("skipped")}: {result.skipped.length}</Badge>
            </div>
            {result.skipped.length ? (
              <div className="metric-list">
                {result.skipped.map((item) => (
                  <div className="metric-row" key={item.title}>
                    <span className="metric-label">{item.title}</span>
                    <span className="metric-value" style={{ fontSize: 10 }}>{item.reason}</span>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </Modal>
  );
}

/* --------------------------------------------------------------- templates */

function TemplatesModal({
  open,
  onClose,
  onUse,
}: {
  open: boolean;
  onClose: () => void;
  onUse: (template: RuleTemplate) => void;
}) {
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const query = useQuery({
    queryKey: ["siem", "rules", "templates"],
    queryFn: () => api.get<RuleTemplate[]>("/siem/rules/templates"),
    enabled: open,
    staleTime: 300_000,
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={c("templatesTitle")}
      size="lg"
      footer={<Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>}
    >
      <div data-testid="templates-modal">
        <p className="hint" style={{ marginBottom: 10 }}>{c("templatesHint")}</p>
        {query.isLoading ? (
          <div className="stack"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
        ) : query.isError ? (
          <ErrorBanner compact message={errorText(query.error, c)} onRetry={() => void query.refetch()} />
        ) : !query.data?.length ? (
          <EmptyState icon={Layers} title={c("templatesEmpty")} />
        ) : (
          <div className="stack">
            {query.data.map((template) => (
              <div className="card card-pad" key={template.key ?? template.name}>
                <div className="row-between" style={{ alignItems: "flex-start", gap: 10 }}>
                  <div style={{ minWidth: 0 }}>
                    <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                      <strong style={{ fontSize: 13 }}>{template.name}</strong>
                      {template.severity ? <SeverityBadge severity={template.severity} /> : null}
                    </div>
                    <div className="item-sub" style={{ marginTop: 4 }}>{template.description}</div>
                    <div className="chip-row" style={{ marginTop: 6 }}>
                      {(template.mitre ?? []).map((technique) => <span className="tag" key={technique}>{technique}</span>)}
                      {(template.tags ?? []).slice(0, 4).map((tag) => <span className="tag" key={tag}>{tag}</span>)}
                    </div>
                  </div>
                  <Button size="sm" icon={FileCode2} onClick={() => onUse(template)} data-testid={`use-template-${template.key ?? template.name}`}>
                    {c("useTemplate")}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
}

/* ---------------------------------------------------------------- coverage */

interface CoverageTechnique {
  technique: string;
  name: string;
  events: number;
  alerts: number;
  total: number;
}

interface CoverageResponse {
  generated_at: string;
  total_techniques: number;
  techniques: CoverageTechnique[];
}

function CoverageModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const query = useQuery({
    queryKey: ["siem", "mitre", "coverage"],
    queryFn: () => api.get<CoverageResponse>("/siem/mitre/coverage"),
    enabled: open,
    staleTime: 60_000,
  });

  const columns: Column<CoverageTechnique>[] = [
    { key: "technique", header: c("technique"), width: "110px", render: (row) => <span className="mono">{row.technique}</span> },
    { key: "name", header: c("techniqueName"), render: (row) => <span style={{ color: "var(--text-secondary)" }}>{row.name}</span> },
    { key: "events", header: c("events"), width: "88px", align: "right", render: (row) => <span className="mono">{formatNumber(row.events)}</span> },
    { key: "alerts", header: c("alerts"), width: "88px", align: "right", render: (row) => <span className="mono">{formatNumber(row.alerts)}</span> },
  ];

  return (
    <Modal open={open} onClose={onClose} title={c("coverageTitle")} size="lg" footer={<Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>}>
      <div data-testid="mitre-coverage-modal">
        <p className="hint" style={{ marginBottom: 10 }}>{c("coverageHint")}</p>
        {query.isLoading ? (
          <div className="stack"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
        ) : query.isError ? (
          <ErrorBanner compact message={errorText(query.error, c)} onRetry={() => void query.refetch()} />
        ) : !query.data?.techniques.length ? (
          <EmptyState icon={Layers} title={c("coverageEmpty")} />
        ) : (
          <>
            <div className="row-between" style={{ marginBottom: 8 }}>
              <Badge tone="neutral">{c("totalTechniques").replace("{count}", String(query.data.total_techniques))}</Badge>
              <span className="dim" style={{ fontSize: 10.5 }}>{formatDateTime(query.data.generated_at, "es-ES")}</span>
            </div>
            <DataTable columns={columns} rows={query.data.techniques} rowKey={(row) => row.technique} />
          </>
        )}
      </div>
    </Modal>
  );
}

/* -------------------------------------------------------------- alert detail */

function AlertDetailModal({
  alertId,
  onClose,
  onChanged,
}: {
  alertId: string | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const c = usePageCopy(COPY);
  const { t, lang } = useI18n();
  const { can } = useAuth();
  const { push } = useToast();
  const navigate = useNavigate();
  const [status, setStatus] = useState("new");
  const [note, setNote] = useState("");
  const [assignee, setAssignee] = useState("");
  const [promoteOpen, setPromoteOpen] = useState(false);
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");

  const query = useQuery({
    queryKey: ["siem", "alerts", "detail", alertId],
    queryFn: () => api.get<AlertDetail>(`/siem/alerts/${alertId}`),
    enabled: Boolean(alertId),
  });

  const members = useQuery({
    queryKey: ["organizations", "members", "alert-triage"],
    queryFn: () => api.get<Page<OrganizationMember>>("/organizations/current/members", { page_size: 200 }),
    enabled: Boolean(alertId) && can("user:read"),
    staleTime: 120_000,
  });

  useEffect(() => {
    if (query.data) {
      setStatus(query.data.status);
      setAssignee(query.data.assignee_id ?? "");
    }
  }, [query.data]);

  const triage = useMutation({
    mutationFn: () =>
      api.patch<AlertDetail>(`/siem/alerts/${alertId}`, {
        status,
        assignee_id: assignee || undefined,
        note: note.trim() || undefined,
      }),
    onSuccess: () => {
      push(c("triageSaved"), "success");
      setNote("");
      onChanged();
      void query.refetch();
    },
    onError: (error) => push(`${c("triageError")}: ${errorText(error, c)}`, "error"),
  });

  const promote = useMutation({
    mutationFn: () =>
      api.post<PromoteResult>(`/siem/alerts/${alertId}/promote`, {
        title: incidentTitle.trim() || undefined,
        description: incidentDescription.trim() || undefined,
      }),
    onSuccess: (result) => {
      push(c("promoted").replace("{ref}", result.incident.ref), "success");
      setPromoteOpen(false);
      onChanged();
      onClose();
      navigate(`/incidents/${result.incident_id}`);
    },
    onError: (error) => push(`${c("promoteError")}: ${errorText(error, c)}`, "error"),
  });

  return (
    <>
      <Modal
        open={alertId !== null}
        onClose={onClose}
        title={c("alertDetailTitle")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
            {query.data?.incident_id ? (
              <Button icon={Siren} onClick={() => navigate(`/incidents/${query.data?.incident_id}`)}>{c("openIncident")}</Button>
            ) : null}
            {can("incident:write") ? (
              <Button variant="primary" icon={Siren} disabled={!query.data} onClick={() => setPromoteOpen(true)} data-testid="promote-alert">
                {c("promote")}
              </Button>
            ) : null}
          </>
        }
      >
        <div data-testid="alert-detail-modal">
          {query.isLoading ? (
            <div className="stack"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
          ) : query.isError || !query.data ? (
            <ErrorBanner compact message={errorText(query.error, c)} onRetry={() => void query.refetch()} />
          ) : (
            <div className="stack">
              <div>
                <div className="row wrap" style={{ gap: 6, marginBottom: 6 }}>
                  <SeverityBadge severity={query.data.severity} />
                  <StatusBadge status={query.data.status} />
                  <Badge tone="neutral">{query.data.rule_name ?? "—"}</Badge>
                  {query.data.is_demo ? <Badge tone="amber">{c("demo")}</Badge> : null}
                </div>
                <h3 style={{ fontSize: 15 }}>{query.data.title}</h3>
                <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>{query.data.description ?? "—"}</p>
              </div>

              <div className="metric-list">
                <div className="metric-row"><span className="metric-label">{c("colCount")}</span><span className="metric-value">{formatNumber(query.data.count)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("colRisk")}</span><span className="metric-value">{query.data.risk_score.toFixed(1)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("colLastSeen")}</span><span className="metric-value">{formatDateTime(query.data.last_seen, lang)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("colAlert")}</span><span className="metric-value">{relativeTime(query.data.first_seen, lang)}</span></div>
              </div>

              <div>
                <div className="section-label">{c("alertMitre")}</div>
                <div className="chip-row">
                  {query.data.mitre.length ? query.data.mitre.map((technique) => <span className="tag" key={technique}>{technique}</span>) : <span className="dim">—</span>}
                </div>
              </div>

              <div>
                <div className="section-label">{c("alertEvents")}</div>
                <div className="chip-row">
                  {query.data.event_ids.length ? query.data.event_ids.map((id) => <span className="tag mono" key={id}>#{id}</span>) : <span className="dim">—</span>}
                </div>
              </div>

              <div>
                <div className="section-label">{c("alertEvidence")}</div>
                {Object.keys(query.data.evidence).length ? (
                  <pre className="code-block">{JSON.stringify(query.data.evidence, null, 2)}</pre>
                ) : (
                  <span className="dim" style={{ fontSize: 11 }}>{c("noEvidence")}</span>
                )}
              </div>

              <div className="divider" />
              <div className="section-label">{c("alertTriage")}</div>
              <div className="form-grid">
                <Field label={c("alertTriageStatus")} htmlFor="alert-triage-status">
                  <Select id="alert-triage-status" value={status} onChange={(event) => setStatus(event.target.value)} disabled={!can("alert:write")} data-testid="alert-triage-status">
                    {["new", "triaged", "investigating", "closed", "benign"].map((value) => <option key={value} value={value}>{value}</option>)}
                  </Select>
                </Field>
                <Field label={c("alertAssignee")} htmlFor="alert-triage-assignee">
                  {can("user:read") ? (
                    <Select
                      id="alert-triage-assignee"
                      value={assignee}
                      onChange={(event) => setAssignee(event.target.value)}
                      disabled={!can("alert:write")}
                      data-testid="alert-triage-assignee"
                    >
                      <option value="">{c("keepAssignee")}</option>
                      {members.data?.items.map((member) => (
                        <option key={member.user_id} value={member.user_id}>{member.full_name}</option>
                      ))}
                    </Select>
                  ) : (
                    <Input
                      id="alert-triage-assignee"
                      value={assignee}
                      onChange={(event) => setAssignee(event.target.value)}
                      disabled={!can("alert:write")}
                      placeholder="UUID"
                    />
                  )}
                </Field>
                <Field label={c("alertTriageNote")} htmlFor="alert-triage-note">
                  <Input id="alert-triage-note" value={note} onChange={(event) => setNote(event.target.value)} maxLength={4000} disabled={!can("alert:write")} />
                </Field>
              </div>
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <Button variant="primary" icon={Check} loading={triage.isPending} disabled={!can("alert:write")} onClick={() => triage.mutate()} data-testid="save-alert-triage">
                  {c("saveTriage")}
                </Button>
              </div>
            </div>
          )}
        </div>
      </Modal>

      <Modal
        open={promoteOpen}
        onClose={() => setPromoteOpen(false)}
        title={c("promoteTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setPromoteOpen(false)}>{t("common.cancel")}</Button>
            <Button variant="primary" icon={Siren} loading={promote.isPending} onClick={() => promote.mutate()} data-testid="confirm-promote-alert">
              {c("promoteConfirm")}
            </Button>
          </>
        }
      >
        <div data-testid="promote-alert-modal">
          <p className="hint" style={{ marginBottom: 10 }}>{c("promoteHint")}</p>
          <Field label={c("promoteIncidentTitle")} htmlFor="promote-title">
            <Input id="promote-title" value={incidentTitle} onChange={(event) => setIncidentTitle(event.target.value)} maxLength={300} />
          </Field>
          <Field label={c("promoteDescription")} htmlFor="promote-description">
            <Textarea id="promote-description" value={incidentDescription} onChange={(event) => setIncidentDescription(event.target.value)} rows={3} maxLength={4000} />
          </Field>
        </div>
      </Modal>
    </>
  );
}

/* ----------------------------------------------------------------- source */

function SourceCreateModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (source: IngestSourceCreated) => void;
}) {
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const [name, setName] = useState("");
  const [kind, setKind] = useState("api");
  const [parser, setParser] = useState("auto");
  const [generateSecret, setGenerateSecret] = useState(true);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setName("");
      setKind("api");
      setParser("auto");
      setGenerateSecret(true);
      setSecret("");
      setError(null);
    }
  }, [open]);

  const mutation = useMutation({
    mutationFn: () =>
      api.post<IngestSourceCreated>("/ingest-sources", {
        name: name.trim(),
        kind,
        parser,
        enabled: true,
        generate_hmac_secret: generateSecret,
        hmac_secret: !generateSecret && secret.trim() ? secret.trim() : undefined,
        config: {},
      }),
    onSuccess: (created) => onCreated(created),
    onError: (err) => setError(errorText(err, c)),
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={c("createSource")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button variant="primary" icon={Plus} loading={mutation.isPending} onClick={() => mutation.mutate()} data-testid="submit-source">
            {c("submitSource")}
          </Button>
        </>
      }
    >
      <div data-testid="source-create-modal">
        <p className="hint" style={{ marginBottom: 10 }}>{c("createSourceHint")}</p>
        <Field label={c("sourceName")} required htmlFor="source-name">
          <Input id="source-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={160} data-testid="source-name-input" />
        </Field>
        <div className="form-grid">
          <Field label={c("sourceKind")} htmlFor="source-kind">
            <Select id="source-kind" value={kind} onChange={(event) => setKind(event.target.value)}>
              {["api", "webhook", "syslog"].map((value) => <option key={value} value={value}>{value}</option>)}
            </Select>
          </Field>
          <Field label={c("sourceParser")} htmlFor="source-parser">
            <Select id="source-parser" value={parser} onChange={(event) => setParser(event.target.value)}>
              {["auto", "json", "cef", "leef", "syslog", "otel"].map((value) => <option key={value} value={value}>{value}</option>)}
            </Select>
          </Field>
        </div>
        <label className="checkbox" style={{ marginTop: 8 }}>
          <input type="checkbox" checked={generateSecret} onChange={(event) => setGenerateSecret(event.target.checked)} />
          {c("generateSecret")}
        </label>
        {!generateSecret ? (
          <Field label={c("customSecret")} htmlFor="source-secret">
            <Input id="source-secret" type="password" value={secret} onChange={(event) => setSecret(event.target.value)} minLength={16} maxLength={256} autoComplete="new-password" />
          </Field>
        ) : null}
        {error ? <div style={{ marginTop: 10 }}><ErrorBanner compact message={error} /></div> : null}
      </div>
    </Modal>
  );
}

function SecretRevealModal({ reveal, onClose }: { reveal: SecretReveal | null; onClose: () => void }) {
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const { push } = useToast();
  const [copied, setCopied] = useState<string | null>(null);

  const copy = async (label: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      push(c("copied"), "success");
    } catch {
      setCopied(null);
    }
  };

  return (
    <Modal
      open={reveal !== null}
      onClose={onClose}
      title={c("tokenOnceTitle")}
      footer={<Button variant="primary" onClick={onClose}>{t("common.close")}</Button>}
    >
      {reveal ? (
        <div data-testid="secret-reveal-modal">
          <div className="notice notice-warning" style={{ fontSize: 11 }}>
            <KeyRound size={13} style={{ flex: "0 0 auto" }} />
            <span>{c("tokenOnceWarning")}</span>
          </div>
          <div className="metric-list" style={{ marginTop: 10 }}>
            <div className="metric-row"><span className="metric-label">{c("sourceName")}</span><span className="metric-value">{reveal.sourceName}</span></div>
            {reveal.token ? (
              <div className="metric-row" style={{ alignItems: "flex-start" }}>
                <span className="metric-label">{c("tokenLabel")}</span>
                <span className="metric-value" style={{ display: "flex", gap: 6, alignItems: "center", wordBreak: "break-all" }}>
                  <code style={{ fontSize: 10 }}>{reveal.token}</code>
                  <Button size="sm" variant="ghost" icon={copied === "token" ? Check : Copy} onClick={() => void copy("token", reveal.token ?? "")} aria-label={c("copy")} />
                </span>
              </div>
            ) : null}
            {reveal.hmacSecret ? (
              <div className="metric-row" style={{ alignItems: "flex-start" }}>
                <span className="metric-label">{c("secretLabel")}</span>
                <span className="metric-value" style={{ display: "flex", gap: 6, alignItems: "center", wordBreak: "break-all" }}>
                  <code style={{ fontSize: 10 }}>{reveal.hmacSecret}</code>
                  <Button size="sm" variant="ghost" icon={copied === "secret" ? Check : Copy} onClick={() => void copy("secret", reveal.hmacSecret ?? "")} aria-label={c("copy")} />
                </span>
              </div>
            ) : null}
          </div>
          <div className="section-label" style={{ marginTop: 14 }}>{c("curlTitle")}</div>
          <pre className="code-block">{`curl -X POST '${window.location.origin}/api/v1/ingest/${reveal.token ?? "<TOKEN>"}' \\
  -H 'Content-Type: application/json' \\
  -d '{"message":"authentication failure","severity":"high","src_ip":"10.0.0.5"}'`}</pre>
        </div>
      ) : null}
    </Modal>
  );
}

/* ------------------------------------------------------------------ page */

export function SiemPage() {
  const c = usePageCopy(COPY);
  const { t, lang } = useI18n();
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("rules");

  /* rules */
  const [rulePage, setRulePage] = useState(1);
  const [ruleQuery, setRuleQuery] = useState("");
  const [ruleScope, setRuleScope] = useState("all");
  const [ruleEnabled, setRuleEnabled] = useState("");
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null);
  const [editorTemplate, setEditorTemplate] = useState<RuleTemplate | null>(null);
  const [testRule, setTestRule] = useState<DetectionRule | null>(null);
  const [deleteRule, setDeleteRule] = useState<DetectionRule | null>(null);
  const [sigmaOpen, setSigmaOpen] = useState(false);
  const [templatesOpen, setTemplatesOpen] = useState(false);
  const [coverageOpen, setCoverageOpen] = useState(false);

  /* alerts */
  const [alertPage, setAlertPage] = useState(1);
  const [alertQuery, setAlertQuery] = useState("");
  const [alertStatus, setAlertStatus] = useState("");
  const [alertSeverity, setAlertSeverity] = useState("");
  const [alertSort, setAlertSort] = useState("created_at");
  const [alertOrder, setAlertOrder] = useState("desc");
  const [selectedAlerts, setSelectedAlerts] = useState<string[]>([]);
  const [alertDetailId, setAlertDetailId] = useState<string | null>(null);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkStatus, setBulkStatus] = useState("triaged");
  const [bulkNote, setBulkNote] = useState("");

  /* sources */
  const [sourcePage, setSourcePage] = useState(1);
  const [sourceQuery, setSourceQuery] = useState("");
  const [sourceKind, setSourceKind] = useState("");
  const [sourceEnabled, setSourceEnabled] = useState("");
  const [sourceCreateOpen, setSourceCreateOpen] = useState(false);
  const [reveal, setReveal] = useState<SecretReveal | null>(null);
  const [rotateTarget, setRotateTarget] = useState<IngestSource | null>(null);
  const [deleteSource, setDeleteSource] = useState<IngestSource | null>(null);
  const [curlTarget, setCurlTarget] = useState<IngestSource | null>(null);

  /* retention */
  const [hotDays, setHotDays] = useState("90");
  const [coldDays, setColdDays] = useState("400");
  const [batchSize, setBatchSize] = useState("5000");
  const [purgeEnabled, setPurgeEnabled] = useState(true);
  const [purgeOpen, setPurgeOpen] = useState(false);
  const [purgeResult, setPurgeResult] = useState<PurgeResult | null>(null);

  const canWriteRules = can("alert:write");
  const canWriteAlerts = can("alert:write");
  const canWriteSources = can("event:ingest") || can("settings:write");
  const canWritePolicy = can("policy:write");

  const rules = useQuery({
    queryKey: ["siem", "rules", { rulePage, ruleQuery, ruleScope, ruleEnabled }],
    queryFn: () =>
      api.get<Page<DetectionRule>>("/siem/rules", {
        page: rulePage,
        page_size: 25,
        q: ruleQuery.trim() || undefined,
        scope: ruleScope,
        enabled: ruleEnabled === "" ? undefined : ruleEnabled === "true",
      }),
  });

  const alerts = useQuery({
    queryKey: ["siem", "alerts", { alertPage, alertQuery, alertStatus, alertSeverity, alertSort, alertOrder }],
    queryFn: () =>
      api.get<Page<AlertSummary>>("/siem/alerts", {
        page: alertPage,
        page_size: 25,
        q: alertQuery.trim() || undefined,
        status: alertStatus || undefined,
        severity: alertSeverity || undefined,
        sort: alertSort,
        order: alertOrder,
      }),
  });

  const alertStats = useQuery({
    queryKey: ["siem", "alerts", "stats"],
    queryFn: () => api.get<AlertStats>("/siem/alerts/stats", { hours: 24 }),
    refetchInterval: 60_000,
  });

  const sources = useQuery({
    queryKey: ["events", "sources", { sourcePage, sourceQuery, sourceKind, sourceEnabled }],
    queryFn: () =>
      api.get<Page<IngestSource>>("/ingest-sources", {
        page: sourcePage,
        page_size: 25,
        q: sourceQuery.trim() || undefined,
        kind: sourceKind || undefined,
        enabled: sourceEnabled === "" ? undefined : sourceEnabled === "true",
      }),
  });

  const retention = useQuery({
    queryKey: ["events", "retention"],
    queryFn: () => api.get<RetentionPolicy>("/events/retention"),
    enabled: can("policy:read"),
  });

  useEffect(() => {
    if (!retention.data) return;
    const definition = retention.data.definition;
    setHotDays(String(definition.hot_days ?? 90));
    setColdDays(String(definition.cold_days ?? 400));
    setBatchSize(String(definition.batch_size ?? 5000));
    setPurgeEnabled(definition.purge_enabled ?? true);
  }, [retention.data]);

  useEffect(() => {
    setSelectedAlerts([]);
  }, [alertPage, alertStatus, alertSeverity, alertQuery, alertSort, alertOrder]);

  const invalidateRules = () => {
    void queryClient.invalidateQueries({ queryKey: ["siem", "rules"] });
  };
  const invalidateAlerts = () => {
    void queryClient.invalidateQueries({ queryKey: ["siem", "alerts"] });
  };
  const invalidateSources = () => {
    void queryClient.invalidateQueries({ queryKey: ["events", "sources"] });
  };

  const toggleRule = useMutation({
    mutationFn: (rule: DetectionRule) =>
      api.post<DetectionRule>(`/siem/rules/${rule.id}/${rule.enabled ? "disable" : "enable"}`),
    onSuccess: (rule) => {
      push(rule.enabled ? c("ruleEnabled") : c("ruleDisabled"), "success");
      invalidateRules();
    },
    onError: (error) => push(`${c("ruleToggleError")}: ${errorText(error, c)}`, "error"),
  });

  const removeRule = useMutation({
    mutationFn: (rule: DetectionRule) => api.delete(`/siem/rules/${rule.id}`),
    onSuccess: () => {
      push(c("ruleDeleted"), "success");
      setDeleteRule(null);
      invalidateRules();
    },
    onError: (error) => push(`${c("ruleToggleError")}: ${errorText(error, c)}`, "error"),
  });

  const bulkMutation = useMutation({
    mutationFn: () =>
      api.post<BulkResult>("/siem/alerts/bulk", {
        ids: selectedAlerts,
        status: bulkStatus || undefined,
        note: bulkNote.trim() || undefined,
      }),
    onSuccess: (result) => {
      push(c("bulkDone").replace("{updated}", String(result.updated)).replace("{skipped}", String(result.skipped)), "success");
      setBulkOpen(false);
      setBulkNote("");
      setSelectedAlerts([]);
      invalidateAlerts();
    },
    onError: (error) => push(`${c("bulkError")}: ${errorText(error, c)}`, "error"),
  });

  const toggleSource = useMutation({
    mutationFn: (source: IngestSource) => api.patch<IngestSource>(`/ingest-sources/${source.id}`, { enabled: !source.enabled }),
    onSuccess: () => {
      push(c("sourceUpdated"), "success");
      invalidateSources();
    },
    onError: (error) => push(`${c("sourceToggleError")}: ${errorText(error, c)}`, "error"),
  });

  const rotateMutation = useMutation({
    mutationFn: (source: IngestSource) =>
      api.post<{ id: string; token: string; rotated_at: string }>(`/ingest-sources/${source.id}/rotate-token`),
    onSuccess: (result, source) => {
      setRotateTarget(null);
      setReveal({ title: c("rotateTitle"), token: result.token, hmacSecret: null, sourceName: source.name });
      invalidateSources();
    },
    onError: (error) => push(`${c("sourceError")}: ${errorText(error, c)}`, "error"),
  });

  const deleteSourceMutation = useMutation({
    mutationFn: (source: IngestSource) => api.delete(`/ingest-sources/${source.id}`),
    onSuccess: () => {
      push(c("sourceDeleted"), "success");
      setDeleteSource(null);
      invalidateSources();
    },
    onError: (error) => push(`${c("sourceError")}: ${errorText(error, c)}`, "error"),
  });

  const retentionMutation = useMutation({
    mutationFn: () =>
      api.put<RetentionPolicy>("/events/retention", {
        hot_days: Number(hotDays),
        cold_days: Number(coldDays),
        batch_size: Number(batchSize),
        purge_enabled: purgeEnabled,
      }),
    onSuccess: () => {
      push(c("retentionSaved"), "success");
      void queryClient.invalidateQueries({ queryKey: ["events", "retention"] });
    },
    onError: (error) => push(`${c("retentionError")}: ${errorText(error, c)}`, "error"),
  });

  const purgeMutation = useMutation({
    mutationFn: () => api.post<PurgeResult>("/events/retention/purge"),
    onSuccess: (result) => {
      setPurgeResult(result);
      setPurgeOpen(false);
      push(c("purgeDone").replace("{deleted}", String(result.deleted)).replace("{batches}", String(result.batches)), "success");
      void queryClient.invalidateQueries({ queryKey: ["events", "retention"] });
    },
    onError: (error) => push(`${c("purgeError")}: ${errorText(error, c)}`, "error"),
  });

  const ruleColumns: Column<DetectionRule>[] = [
    {
      key: "name",
      header: c("colRule"),
      render: (row) => (
        <div style={{ minWidth: 230 }}>
          <div className="primary-cell">{row.name}</div>
          <div className="cell-sub">
            {row.description ? row.description.slice(0, 90) : "—"}
          </div>
          <div className="chip-row" style={{ marginTop: 4 }}>
            {row.mitre.slice(0, 4).map((technique) => <span className="tag" key={technique}>{technique}</span>)}
            {row.tags.slice(0, 3).map((tag) => <span className="tag" key={tag}>{tag}</span>)}
          </div>
        </div>
      ),
    },
    { key: "severity", header: c("colSeverity"), width: "110px", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: c("colStatus"), width: "118px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "scope",
      header: c("colScope"),
      width: "120px",
      render: (row) => <Badge tone={row.scope === "global" ? "accent" : "neutral"}>{row.scope}</Badge>,
    },
    { key: "version", header: c("colVersion"), width: "78px", render: (row) => <span className="mono">v{row.version}</span> },
    {
      key: "enabled",
      header: c("colEnabled"),
      width: "92px",
      render: (row) => <Badge tone={row.enabled ? "success" : "neutral"}>{row.enabled ? c("yes") : c("no")}</Badge>,
    },
    {
      key: "updated",
      header: c("colUpdated"),
      width: "120px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{relativeTime(row.updated_at, lang)}</span>,
    },
    {
      key: "actions",
      header: c("colActions"),
      width: "250px",
      align: "right",
      render: (row) => (
        <div className="row" style={{ gap: 3, justifyContent: "flex-end", flexWrap: "wrap" }}>
          <Button
            size="sm"
            variant="ghost"
            icon={Pencil}
            disabled={!canWriteRules}
            onClick={() => {
              setEditingRule(row);
              setEditorTemplate(null);
              setEditorOpen(true);
            }}
            data-testid={`edit-rule-${row.id}`}
          >
            {c("edit")}
          </Button>
          <Button size="sm" variant="ghost" icon={FlaskConical} onClick={() => setTestRule(row)} data-testid={`test-rule-${row.id}`}>
            {c("test")}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={!canWriteRules}
            onClick={() => toggleRule.mutate(row)}
            data-testid={`toggle-rule-${row.id}`}
          >
            {row.enabled ? c("disable") : c("enable")}
          </Button>
          <Button size="sm" variant="ghost" icon={Trash2} disabled={!canWriteRules} onClick={() => setDeleteRule(row)} aria-label={c("delete")} />
        </div>
      ),
    },
  ];

  const alertColumns: Column<AlertSummary>[] = [
    {
      key: "select",
      header: (
        <input
          type="checkbox"
          aria-label={c("selectAll")}
          checked={Boolean(alerts.data?.items.length) && selectedAlerts.length === alerts.data?.items.length}
          onChange={(event) => setSelectedAlerts(event.target.checked ? (alerts.data?.items ?? []).map((row) => row.id) : [])}
        />
      ),
      width: "36px",
      render: (row) => (
        <input
          type="checkbox"
          aria-label={row.title}
          checked={selectedAlerts.includes(row.id)}
          onClick={(event) => event.stopPropagation()}
          onChange={(event) =>
            setSelectedAlerts((current) =>
              event.target.checked ? [...current, row.id] : current.filter((id) => id !== row.id),
            )
          }
        />
      ),
    },
    {
      key: "title",
      header: c("colAlert"),
      render: (row) => (
        <div style={{ minWidth: 230 }}>
          <div className="primary-cell" style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
            <span>{row.title}</span>
            {row.is_demo ? <Badge tone="amber">{c("demo")}</Badge> : null}
          </div>
          <div className="cell-sub">{row.rule_name ?? "—"} · {row.mitre.slice(0, 3).join(" · ") || "—"}</div>
        </div>
      ),
    },
    { key: "severity", header: c("colSeverity"), width: "110px", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: c("colStatus"), width: "118px", render: (row) => <StatusBadge status={row.status} /> },
    { key: "count", header: c("colCount"), width: "76px", align: "right", render: (row) => <span className="mono">{formatNumber(row.count)}</span> },
    { key: "risk", header: c("colRisk"), width: "78px", align: "right", render: (row) => <span className="mono">{row.risk_score.toFixed(0)}</span> },
    {
      key: "last_seen",
      header: c("colLastSeen"),
      width: "126px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{relativeTime(row.last_seen, lang)}</span>,
    },
    {
      key: "incident",
      header: c("colIncident"),
      width: "102px",
      render: (row) => row.incident_id ? <Badge tone="accent">{row.incident_id.slice(0, 8)}</Badge> : <span className="dim">—</span>,
    },
  ];

  const sourceColumns: Column<IngestSource>[] = [
    {
      key: "name",
      header: c("colSource"),
      render: (row) => (
        <div style={{ minWidth: 180 }}>
          <div className="primary-cell">{row.name}</div>
          <div className="cell-sub">{[row.kind, row.parser].join(" · ")}</div>
        </div>
      ),
    },
    {
      key: "enabled",
      header: c("colEnabled"),
      width: "92px",
      render: (row) => <Badge tone={row.enabled ? "success" : "neutral"}>{row.enabled ? c("enabled") : c("disabled")}</Badge>,
    },
    {
      key: "last_event",
      header: c("colLastEvent"),
      width: "134px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5 }}>
          {row.last_event_at ? relativeTime(row.last_event_at, lang) : c("lastEventNever")}
        </span>
      ),
    },
    { key: "events", header: c("colEvents"), width: "92px", align: "right", render: (row) => <span className="mono">{formatCompact(row.event_count)}</span> },
    {
      key: "credentials",
      header: c("colToken"),
      width: "136px",
      render: (row) => (
        <div className="row" style={{ gap: 4 }}>
          <Badge tone={row.has_token ? "success" : "neutral"}>{c("hasToken")}</Badge>
          <Badge tone={row.has_hmac_secret ? "accent" : "neutral"}>{c("hasSecret")}</Badge>
        </div>
      ),
    },
    {
      key: "actions",
      header: c("colActions"),
      width: "260px",
      align: "right",
      render: (row) => (
        <div className="row" style={{ gap: 3, justifyContent: "flex-end", flexWrap: "wrap" }}>
          <Button size="sm" variant="ghost" icon={FileCode2} onClick={() => setCurlTarget(row)}>{c("curlShow")}</Button>
          <Button size="sm" variant="ghost" icon={RotateCcw} disabled={!canWriteSources} onClick={() => setRotateTarget(row)} data-testid={`rotate-source-${row.id}`}>
            {c("rotate")}
          </Button>
          <Button size="sm" variant="ghost" disabled={!canWriteSources} onClick={() => toggleSource.mutate(row)}>
            {row.enabled ? c("disable") : c("enable")}
          </Button>
          <Button size="sm" variant="ghost" icon={Trash2} disabled={!canWriteSources} onClick={() => setDeleteSource(row)} aria-label={c("delete")} />
        </div>
      ),
    },
  ];

  const tabs = useMemo(
    () => [
      { key: "rules" as Tab, label: c("tabRules"), count: rules.data?.meta.total },
      { key: "alerts" as Tab, label: c("tabAlerts"), count: alertStats.data?.total },
      { key: "sources" as Tab, label: c("tabSources"), count: sources.data?.meta.total },
      { key: "retention" as Tab, label: c("tabRetention") },
    ],
    [alertStats.data?.total, c, rules.data?.meta.total, sources.data?.meta.total],
  );

  const headerAction =
    tab === "rules" && canWriteRules ? (
      <Button
        variant="primary"
        icon={Plus}
        onClick={() => {
          setEditingRule(null);
          setEditorTemplate(null);
          setEditorOpen(true);
        }}
        data-testid="create-rule"
      >
        {c("newRule")}
      </Button>
    ) : tab === "sources" && canWriteSources ? (
      <Button variant="primary" icon={Plus} onClick={() => setSourceCreateOpen(true)} data-testid="create-source">
        {c("newSource")}
      </Button>
    ) : null;

  function activeRefresh() {
    return tab === "rules" ? rules.refetch : tab === "alerts" ? alerts.refetch : tab === "sources" ? sources.refetch : retention.refetch;
  }

  const selectedRuleIds = selectedAlerts;

  return (
    <div className="animate-in" data-testid="page-siem">
      <PageHeader
        eyebrow={c("eyebrow")}
        title={c("title")}
        subtitle={c("subtitle")}
        actions={
          <>
            {tab === "alerts" && selectedRuleIds.length ? (
              <Button variant="primary" icon={AlertTriangle} onClick={() => setBulkOpen(true)} data-testid="bulk-alerts">
                {c("bulkAction").replace("{count}", String(selectedRuleIds.length))}
              </Button>
            ) : null}
            <Button
              icon={RefreshCw}
              onClick={() => void activeRefresh()()}
              aria-label={c("refresh")}
              data-testid="refresh-siem"
            />
            {headerAction}
          </>
        }
      />

      <Card bodyClassName="">
        <div style={{ padding: "0 12px" }}>
          <Tabs<Tab> ariaLabel={c("subtitle")} items={tabs} value={tab} onChange={setTab} />
        </div>

        {tab === "rules" ? (
          <div data-testid="siem-tab-rules">
            <div className="filters-bar" data-testid="siem-rules-filters">
              <SearchInput
                value={ruleQuery}
                onChange={(value) => {
                  setRuleQuery(value);
                  setRulePage(1);
                }}
                placeholder={c("ruleSearch")}
                ariaLabel={c("ruleSearch")}
              />
              <Select aria-label={c("colScope")} value={ruleScope} onChange={(event) => { setRuleScope(event.target.value); setRulePage(1); }}>
                <option value="all">{c("scopeAll")}</option>
                <option value="organization">{c("scopeOrg")}</option>
                <option value="global">{c("scopeGlobal")}</option>
              </Select>
              <Select aria-label={c("colEnabled")} value={ruleEnabled} onChange={(event) => { setRuleEnabled(event.target.value); setRulePage(1); }}>
                <option value="">{c("enabledAll")}</option>
                <option value="true">{c("enabledOnly")}</option>
                <option value="false">{c("disabledOnly")}</option>
              </Select>
              <Button size="sm" variant="ghost" icon={Layers} onClick={() => setTemplatesOpen(true)}>{c("templates")}</Button>
              <Button size="sm" variant="ghost" icon={UploadCloud} onClick={() => setSigmaOpen(true)} data-testid="open-sigma-import">{c("importSigma")}</Button>
              <Button size="sm" variant="ghost" icon={Archive} onClick={() => setCoverageOpen(true)} data-testid="open-coverage">{c("coverage")}</Button>
              <Badge tone="neutral"><Filter size={10} /> {formatNumber(rules.data?.meta.total ?? 0)}</Badge>
            </div>
            {rules.isError ? (
              <div style={{ padding: 12 }}><ErrorBanner compact message={errorText(rules.error, c)} onRetry={() => void rules.refetch()} /></div>
            ) : null}
            <div data-testid="siem-rules-table">
              <DataTable
                columns={ruleColumns}
                rows={rules.data?.items}
                rowKey={(row) => row.id}
                loading={rules.isLoading}
                empty={
                  <EmptyState
                    icon={ShieldCheck}
                    title={c("rulesEmpty")}
                    description={c("rulesEmptyDesc")}
                    action={canWriteRules ? <Button size="sm" variant="primary" icon={Plus} onClick={() => { setEditingRule(null); setEditorTemplate(null); setEditorOpen(true); }}>{c("newRule")}</Button> : undefined}
                  />
                }
              />
            </div>
            <Pagination meta={rules.data?.meta} onPage={setRulePage} />
          </div>
        ) : null}

        {tab === "alerts" ? (
          <div data-testid="siem-tab-alerts">
            <div className="kpi-grid" style={{ padding: 12 }}>
              <Kpi label={c("kpiTotalAlerts")} value={alertStats.data ? formatNumber(alertStats.data.total) : "—"} icon={BellRing} tone="accent" footer={<span>{formatNumber(alertStats.data?.total ?? 0)} {c("totalRecords")}</span>} />
              <Kpi label={c("kpiOpenAlerts")} value={alertStats.data ? formatNumber(alertStats.data.open) : "—"} icon={Siren} tone="warning" footer={<span>{c("alertsOpenFoot")}</span>} />
              <Kpi label={c("kpiCriticalAlerts")} value={alertStats.data ? formatNumber(alertStats.data.by_severity.critical ?? 0) : "—"} icon={AlertTriangle} tone="danger" footer={<span>{c("alertsCriticalFoot")}</span>} />
              <Kpi
                label={c("kpiVolume")}
                value={alertStats.data ? formatNumber(alertStats.data.timeline.reduce((total, point) => total + point.count, 0)) : "—"}
                icon={Database}
                tone="success"
                footer={<span>{c("alertsVolumeFoot")}</span>}
              />
            </div>
            <div className="filters-bar" data-testid="siem-alerts-filters">
              <SearchInput
                value={alertQuery}
                onChange={(value) => { setAlertQuery(value); setAlertPage(1); }}
                placeholder={c("alertSearch")}
                ariaLabel={c("alertSearch")}
              />
              <Select aria-label={c("colStatus")} value={alertStatus} onChange={(event) => { setAlertStatus(event.target.value); setAlertPage(1); }} data-testid="alerts-filter-status">
                <option value="">{c("alertAllStatuses")}</option>
                {["new", "triaged", "investigating", "closed", "benign"].map((value) => <option key={value} value={value}>{value}</option>)}
              </Select>
              <Select aria-label={c("colSeverity")} value={alertSeverity} onChange={(event) => { setAlertSeverity(event.target.value); setAlertPage(1); }} data-testid="alerts-filter-severity">
                <option value="">{c("alertAllSeverities")}</option>
                {["informational", "low", "medium", "high", "critical"].map((value) => <option key={value} value={value}>{value}</option>)}
              </Select>
              <Select
                aria-label={c("alertSort")}
                value={`${alertSort}:${alertOrder}`}
                onChange={(event) => {
                  const [sort, order] = event.target.value.split(":");
                  setAlertSort(sort);
                  setAlertOrder(order);
                  setAlertPage(1);
                }}
              >
                <option value="created_at:desc">{c("sortCreated")}</option>
                <option value="last_seen:desc">{c("sortLastSeen")}</option>
                <option value="severity:desc">{c("sortSeverity")}</option>
                <option value="risk_score:desc">{c("sortRisk")}</option>
                <option value="count:desc">{c("sortCount")}</option>
              </Select>
              {alertQuery || alertStatus || alertSeverity ? (
                <Button size="sm" variant="ghost" icon={X} onClick={() => { setAlertQuery(""); setAlertStatus(""); setAlertSeverity(""); setAlertPage(1); }}>
                  {c("clearFilters")}
                </Button>
              ) : null}
              <Badge tone="neutral"><Filter size={10} /> {formatNumber(alerts.data?.meta.total ?? 0)}</Badge>
            </div>
            {alerts.isError || alertStats.isError ? (
              <div style={{ padding: 12 }}>
                <ErrorBanner
                  compact
                  message={errorText(alerts.error ?? alertStats.error, c)}
                  onRetry={() => { void alerts.refetch(); void alertStats.refetch(); }}
                />
              </div>
            ) : null}
            <div data-testid="siem-alerts-table">
              <DataTable
                columns={alertColumns}
                rows={alerts.data?.items}
                rowKey={(row) => row.id}
                loading={alerts.isLoading}
                onRowClick={(row) => setAlertDetailId(row.id)}
                empty={
                  <EmptyState
                    icon={ShieldCheck}
                    title={alertQuery || alertStatus || alertSeverity ? c("emptyAlertsFilter") : c("emptyAlertsTitle")}
                    description={c("emptyAlertsDesc")}
                    action={
                      alertQuery || alertStatus || alertSeverity ? (
                        <Button size="sm" onClick={() => { setAlertQuery(""); setAlertStatus(""); setAlertSeverity(""); }}>{c("clearFilters")}</Button>
                      ) : undefined
                    }
                  />
                }
              />
            </div>
            <Pagination meta={alerts.data?.meta} onPage={setAlertPage} />
          </div>
        ) : null}

        {tab === "sources" ? (
          <div data-testid="siem-tab-sources">
            <div className="filters-bar" data-testid="siem-sources-filters">
              <SearchInput
                value={sourceQuery}
                onChange={(value) => { setSourceQuery(value); setSourcePage(1); }}
                placeholder={c("sourceSearch")}
                ariaLabel={c("sourceSearch")}
              />
              <Select aria-label={c("colKind")} value={sourceKind} onChange={(event) => { setSourceKind(event.target.value); setSourcePage(1); }}>
                <option value="">{c("colKind")}</option>
                {["api", "webhook", "syslog"].map((value) => <option key={value} value={value}>{value}</option>)}
              </Select>
              <Select aria-label={c("colEnabled")} value={sourceEnabled} onChange={(event) => { setSourceEnabled(event.target.value); setSourcePage(1); }}>
                <option value="">{c("enabledAll")}</option>
                <option value="true">{c("enabled")}</option>
                <option value="false">{c("disabled")}</option>
              </Select>
              <Badge tone="neutral"><Filter size={10} /> {formatNumber(sources.data?.meta.total ?? 0)}</Badge>
            </div>
            <div className="notice notice-accent" style={{ margin: 12, fontSize: 11 }}>
              <KeyRound size={13} style={{ flex: "0 0 auto" }} />
              <span>{c("createSourceHint")}</span>
            </div>
            {sources.isError ? (
              <div style={{ padding: 12 }}><ErrorBanner compact message={errorText(sources.error, c)} onRetry={() => void sources.refetch()} /></div>
            ) : null}
            <div data-testid="siem-sources-table">
              <DataTable
                columns={sourceColumns}
                rows={sources.data?.items}
                rowKey={(row) => row.id}
                loading={sources.isLoading}
                empty={
                  <EmptyState
                    icon={Database}
                    title={c("sourcesEmpty")}
                    description={c("sourcesEmptyDesc")}
                    action={canWriteSources ? <Button size="sm" variant="primary" icon={Plus} onClick={() => setSourceCreateOpen(true)}>{c("newSource")}</Button> : undefined}
                  />
                }
              />
            </div>
            <Pagination meta={sources.data?.meta} onPage={setSourcePage} />
          </div>
        ) : null}

        {tab === "retention" ? (
          <div style={{ padding: 16 }} data-testid="siem-tab-retention">
            {!can("policy:read") ? (
              <EmptyState icon={ShieldCheck} title={c("forbidden")} />
            ) : retention.isLoading ? (
              <div className="stack"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
            ) : retention.isError || !retention.data ? (
              <ErrorBanner message={errorText(retention.error, c)} onRetry={() => void retention.refetch()} />
            ) : (
              <div className="split-main">
                <Card
                  title={c("retentionTitle")}
                  subtitle={retention.data.source === "default" ? c("retentionSourceDefault") : c("retentionSourcePolicy")}
                  actions={<Badge tone="neutral">v{retention.data.version}</Badge>}
                  footer={
                    <div className="row-between" style={{ width: "100%" }}>
                      <span className="dim" style={{ fontSize: 10.5 }}>{c("updatedAt")}: {retention.data.updated_at ? relativeTime(retention.data.updated_at, lang) : "—"}</span>
                      <Button variant="primary" loading={retentionMutation.isPending} disabled={!canWritePolicy} onClick={() => retentionMutation.mutate()} data-testid="save-retention">
                        {c("saveRetention")}
                      </Button>
                    </div>
                  }
                >
                  <div className="form-grid">
                    <Field label={c("hotDays")} hint={c("hotHint")} htmlFor="retention-hot">
                      <Input id="retention-hot" type="number" min={1} max={3650} value={hotDays} onChange={(event) => setHotDays(event.target.value)} disabled={!canWritePolicy} />
                    </Field>
                    <Field label={c("coldDays")} hint={c("coldHint")} htmlFor="retention-cold">
                      <Input id="retention-cold" type="number" min={1} max={4000} value={coldDays} onChange={(event) => setColdDays(event.target.value)} disabled={!canWritePolicy} />
                    </Field>
                    <Field label={c("batchSize")} hint={c("batchHint")} htmlFor="retention-batch">
                      <Input id="retention-batch" type="number" min={100} max={50000} value={batchSize} onChange={(event) => setBatchSize(event.target.value)} disabled={!canWritePolicy} />
                    </Field>
                    <div className="field">
                      <label className="checkbox" style={{ marginTop: 24 }}>
                        <input type="checkbox" checked={purgeEnabled} onChange={(event) => setPurgeEnabled(event.target.checked)} disabled={!canWritePolicy} />
                        {c("purgeEnabled")}
                      </label>
                    </div>
                  </div>
                  <div className="metric-list" style={{ marginTop: 10 }}>
                    <div className="metric-row"><span className="metric-label">{c("effectiveCutoff")}</span><span className="metric-value">{formatDateTime(retention.data.effective_cutoff, lang)}</span></div>
                    <div className="metric-row"><span className="metric-label">{c("policyVersion")}</span><span className="metric-value">v{retention.data.version}</span></div>
                    <div className="metric-row"><span className="metric-label">{c("policySource")}</span><span className="metric-value">{retention.data.source}</span></div>
                  </div>
                </Card>

                <Card title={c("purgeTitle")} actions={<Badge tone={retention.data.definition.purge_enabled ? "warning" : "neutral"}>{retention.data.definition.purge_enabled ? c("purgeEnabled") : c("disabled")}</Badge>}>
                  <div className="notice notice-danger" style={{ fontSize: 11 }}>
                    <AlertTriangle size={13} style={{ flex: "0 0 auto" }} />
                    <span>{c("purgeWarning")}</span>
                  </div>
                  <Button
                    variant="danger"
                    icon={Trash2}
                    style={{ marginTop: 12 }}
                    disabled={!canWritePolicy || !retention.data.definition.purge_enabled}
                    onClick={() => { setPurgeResult(null); setPurgeOpen(true); }}
                    data-testid="purge-open"
                  >
                    {c("purgeNow")}
                  </Button>
                  {!retention.data.definition.purge_enabled ? <p className="hint">{c("purgeDisabled")}</p> : null}
                  {purgeResult ? (
                    <div className="notice" style={{ marginTop: 12, fontSize: 11 }} data-testid="purge-result">
                      <Check size={13} style={{ flex: "0 0 auto", color: "var(--success)" }} />
                      <span>
                        {c("purgeDone").replace("{deleted}", formatNumber(purgeResult.deleted)).replace("{batches}", String(purgeResult.batches))}
                        <br />
                        {formatDateTime(purgeResult.cutoff, lang)}
                        {purgeResult.truncated ? <><br />{c("purgeTruncated")}</> : null}
                      </span>
                    </div>
                  ) : null}
                </Card>
              </div>
            )}
          </div>
        ) : null}
      </Card>

      {rules.data?.items.some((row) => row.scope === "global") ? (
        <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
          <ShieldCheck size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
          <span>
            {c("rulesTitle")}: {formatNumber(rules.data.meta.total)} · {c("tabAlerts")}: {formatNumber(alertStats.data?.open ?? 0)} · {c("tabSources")}: {formatNumber(sources.data?.meta.total ?? 0)}
          </span>
        </div>
      ) : null}

      <RuleEditorModal
        open={editorOpen}
        rule={editingRule}
        template={editorTemplate}
        onClose={() => setEditorOpen(false)}
        onSaved={() => {
          setEditorOpen(false);
          invalidateRules();
        }}
      />
      <RuleTestModal open={testRule !== null} rule={testRule} onClose={() => setTestRule(null)} />
      <TemplatesModal
        open={templatesOpen}
        onClose={() => setTemplatesOpen(false)}
        onUse={(template) => {
          setTemplatesOpen(false);
          setEditingRule(null);
          setEditorTemplate(template);
          setEditorOpen(true);
        }}
      />
      <CoverageModal open={coverageOpen} onClose={() => setCoverageOpen(false)} />
      <SigmaImportModal open={sigmaOpen} onClose={() => setSigmaOpen(false)} onImported={invalidateRules} />
      <AlertDetailModal alertId={alertDetailId} onClose={() => setAlertDetailId(null)} onChanged={invalidateAlerts} />
      <SourceCreateModal
        open={sourceCreateOpen}
        onClose={() => setSourceCreateOpen(false)}
        onCreated={(source) => {
          setSourceCreateOpen(false);
          push(c("sourceCreated"), "success");
          invalidateSources();
          setReveal({ title: c("sourceCreated"), token: source.token, hmacSecret: source.hmac_secret, sourceName: source.name });
        }}
      />
      <SecretRevealModal reveal={reveal} onClose={() => setReveal(null)} />

      <Modal
        open={deleteRule !== null}
        onClose={() => setDeleteRule(null)}
        title={c("deleteRuleTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeleteRule(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" icon={Trash2} loading={removeRule.isPending} onClick={() => deleteRule && removeRule.mutate(deleteRule)} data-testid="confirm-delete-rule">
              {c("deleteRuleConfirm")}
            </Button>
          </>
        }
      >
        <p style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>{c("deleteRuleWarning")}</p>
        {deleteRule ? <div className="notice" style={{ marginTop: 10, fontSize: 11 }}>{deleteRule.name} · v{deleteRule.version}</div> : null}
      </Modal>

      <Modal
        open={bulkOpen}
        onClose={() => setBulkOpen(false)}
        title={c("bulkTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setBulkOpen(false)}>{t("common.cancel")}</Button>
            <Button variant="primary" loading={bulkMutation.isPending} disabled={!canWriteAlerts || selectedAlerts.length === 0} onClick={() => bulkMutation.mutate()} data-testid="confirm-bulk">
              {c("applyBulk")}
            </Button>
          </>
        }
      >
        <div data-testid="bulk-alerts-modal">
          <p className="hint" style={{ marginBottom: 10 }}>{c("bulkHint").replace("{count}", String(selectedAlerts.length))}</p>
          <Field label={c("bulkStatus")} htmlFor="bulk-status">
            <Select id="bulk-status" value={bulkStatus} onChange={(event) => setBulkStatus(event.target.value)}>
              {["triaged", "investigating", "closed", "benign", "new"].map((value) => <option key={value} value={value}>{value}</option>)}
            </Select>
          </Field>
          <Field label={c("bulkNote")} htmlFor="bulk-note">
            <Textarea id="bulk-note" value={bulkNote} onChange={(event) => setBulkNote(event.target.value)} rows={3} maxLength={4000} />
          </Field>
        </div>
      </Modal>

      <Modal
        open={rotateTarget !== null}
        onClose={() => setRotateTarget(null)}
        title={c("rotateTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setRotateTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" icon={RotateCcw} loading={rotateMutation.isPending} onClick={() => rotateTarget && rotateMutation.mutate(rotateTarget)} data-testid="confirm-rotate">
              {c("rotateConfirm")}
            </Button>
          </>
        }
      >
        <div data-testid="rotate-modal">
          <div className="notice notice-warning" style={{ fontSize: 11 }}>
            <AlertTriangle size={13} style={{ flex: "0 0 auto" }} />
            <span>{c("rotateWarning")}</span>
          </div>
          {rotateTarget ? <div className="notice" style={{ marginTop: 10, fontSize: 11 }}>{rotateTarget.name} · {rotateTarget.kind}</div> : null}
        </div>
      </Modal>

      <Modal
        open={deleteSource !== null}
        onClose={() => setDeleteSource(null)}
        title={c("deleteSourceTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeleteSource(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" icon={Trash2} loading={deleteSourceMutation.isPending} onClick={() => deleteSource && deleteSourceMutation.mutate(deleteSource)} data-testid="confirm-delete-source">
              {c("deleteSourceConfirm")}
            </Button>
          </>
        }
      >
        <p style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>{c("deleteSourceWarning")}</p>
        {deleteSource ? <div className="notice" style={{ marginTop: 10, fontSize: 11 }}>{deleteSource.name} · {deleteSource.kind}</div> : null}
      </Modal>

      <Modal
        open={curlTarget !== null}
        onClose={() => setCurlTarget(null)}
        title={c("curlTitle")}
        size="lg"
        footer={<Button variant="ghost" onClick={() => setCurlTarget(null)}>{t("common.close")}</Button>}
      >
        {curlTarget ? (
          <div data-testid="curl-example">
            <p className="hint" style={{ marginBottom: 8 }}>{c("curlHint")}</p>
            <pre className="code-block">{`curl -X POST '${window.location.origin}/api/v1/ingest/<TOKEN>' \\
  -H 'Content-Type: application/json' \\
  -d '{"message":"authentication failure","severity":"high","src_ip":"10.0.0.5"}'`}</pre>
            <div className="metric-list" style={{ marginTop: 10 }}>
              <div className="metric-row"><span className="metric-label">{c("sourceName")}</span><span className="metric-value">{curlTarget.name}</span></div>
              <div className="metric-row"><span className="metric-label">{c("sourceParser")}</span><span className="metric-value">{curlTarget.parser}</span></div>
              <div className="metric-row"><span className="metric-label">{c("colToken")}</span><span className="metric-value">{curlTarget.has_token ? c("yes") : c("no")}</span></div>
            </div>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={purgeOpen}
        onClose={() => setPurgeOpen(false)}
        title={c("purgeTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setPurgeOpen(false)}>{t("common.cancel")}</Button>
            <Button variant="danger" icon={Trash2} loading={purgeMutation.isPending} onClick={() => purgeMutation.mutate()} data-testid="confirm-purge">
              {c("purgeConfirm")}
            </Button>
          </>
        }
      >
        <div data-testid="purge-modal">
          <div className="notice notice-danger" style={{ fontSize: 11 }}>
            <AlertTriangle size={13} style={{ flex: "0 0 auto" }} />
            <span>{c("purgeWarning")}</span>
          </div>
          <div className="metric-list" style={{ marginTop: 10 }}>
            <div className="metric-row"><span className="metric-label">{c("hotDays")}</span><span className="metric-value">{hotDays}</span></div>
            <div className="metric-row"><span className="metric-label">{c("effectiveCutoff")}</span><span className="metric-value">{retention.data ? formatDateTime(retention.data.effective_cutoff, lang) : "—"}</span></div>
            <div className="metric-row"><span className="metric-label">{c("batchSize")}</span><span className="metric-value">{batchSize}</span></div>
          </div>
        </div>
      </Modal>
    </div>
  );
}

export default SiemPage;
