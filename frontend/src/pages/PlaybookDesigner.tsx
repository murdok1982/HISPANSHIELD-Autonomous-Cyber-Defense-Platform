import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowDown,
  ArrowLeft,
  ArrowUp,
  CheckCircle2,
  Code2,
  Copy,
  FlaskConical,
  Info,
  Layers,
  Plus,
  Rocket,
  Save,
  ShieldAlert,
  Trash2,
  Wand2,
} from "lucide-react";
import { api, errorMessage, isApiError, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatNumber } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  Field,
  Input,
  LinkButton,
  Modal,
  PageHeader,
  PageSkeleton,
  Select,
  StatusBadge,
  Textarea,
  useToast,
} from "../components/ui";

/* ------------------------------------------------------------------ types */

interface CatalogueAction {
  key: string;
  label: string;
  description: string;
  min_level: string;
  risk: string;
  reversible: boolean;
  target_type: string;
  capability: string | null;
  internal: boolean;
  approval_required: boolean;
  ot_allowed: boolean;
  decision: Record<string, unknown>;
}

interface Catalogue {
  actions: CatalogueAction[];
  forbidden: { key: string; reason: string }[];
  org_max_level: string;
  policy: Record<string, unknown>;
}

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
}

interface StepDraft {
  uid: string;
  key: string;
  name: string;
  action: string;
  paramsText: string;
  conditionEnabled: boolean;
  conditionField: string;
  conditionOp: string;
  conditionValue: string;
  onFailure: string;
  retries: string;
  timeout: string;
  compensationEnabled: boolean;
  compensationAction: string;
  compensationParams: string;
  defenceActionType: string;
  defenceTargetType: string;
  defenceTargetId: string;
  defenceLevel: string;
  defenceParameters: string;
  connectorCapability: string;
  connectorId: string;
  connectorParams: string;
}

interface StepPayload {
  key: string;
  name: string;
  action: string;
  params: Record<string, unknown>;
  condition: Record<string, unknown> | null;
  on_failure: string;
  retries: number;
  timeout_seconds: number;
  compensation: Record<string, unknown> | null;
}

const INTERNAL_ACTIONS = [
  "internal.investigate",
  "internal.create_incident",
  "internal.add_timeline",
  "internal.request_approval",
  "internal.notify",
] as const;

const COMBINED_ACTIONS = [...INTERNAL_ACTIONS, "connector.read", "defence.execute"] as const;

const CONDITION_OPS = [
  "eq",
  "ne",
  "gt",
  "gte",
  "lt",
  "lte",
  "in",
  "not_in",
  "contains",
  "not_contains",
  "exists",
  "startswith",
  "endswith",
  "truthy",
  "falsy",
] as const;

const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

let stepSequence = 0;
function nextUid(): string {
  stepSequence += 1;
  return `step-${Date.now()}-${stepSequence}`;
}

const EXAMPLE_DEFINITION = {
  steps: [
    {
      key: "investigate",
      name: "Investigate incident context",
      action: "internal.investigate",
      params: { focus: "incident" },
    },
    {
      key: "notify",
      name: "Notify responders",
      action: "internal.notify",
      params: { title: "Playbook execution started", severity: "high" },
    },
  ],
  triggers: { alert_severity: ["critical", "high"], rules: [] },
};

/* ------------------------------------------------------------------- copy */

const COPY = {
  es: {
    eyebrow: "Automatización · Diseñador",
    title: "Diseñador de playbooks",
    subtitle: "Editor estructurado de pasos, condiciones, compensaciones y disparadores validados por el servidor.",
    newTitle: "Nuevo playbook",
    editTitle: "Editar playbook",
    back: "Volver a SOAR",
    name: "Nombre",
    description: "Descripción",
    minAutonomy: "Autonomía mínima",
    triggers: "Disparadores",
    triggerSeverity: "Severidades de alerta",
    triggerRules: "IDs de reglas",
    triggerRulesHint: "Separados por comas.",
    steps: "Pasos del playbook",
    addStep: "Añadir paso",
    step: "Paso {n}",
    stepKey: "Clave del paso",
    stepKeyHint: "minúsculas, a-z0-9_.- (máx. 80)",
    stepName: "Nombre",
    stepAction: "Acción",
    stepParams: "Parámetros (JSON)",
    condition: "Ejecutar solo si",
    conditionField: "Campo del contexto",
    conditionOp: "Operador",
    conditionValue: "Valor (JSON o texto)",
    onFailure: "Política en caso de fallo",
    retries: "Reintentos",
    timeout: "Timeout (s)",
    compensation: "Compensación",
    compensationAction: "Acción de compensación",
    compensationParams: "Parámetros de compensación (JSON)",
    moveUp: "Subir",
    moveDown: "Bajar",
    remove: "Quitar paso",
    defenceActionType: "Acción defensiva del catálogo",
    defenceTargetType: "Tipo de objetivo",
    defenceTargetId: "ID del objetivo",
    defenceLevel: "Nivel solicitado",
    defenceParameters: "Parámetros de la acción (JSON)",
    connectorCapability: "Capacidad de lectura",
    connectorId: "ID del conector (opcional)",
    connectorParams: "Parámetros de lectura (JSON)",
    approvalHint: "Esta acción requiere un paso internal.request_approval previo.",
    irreversibleHint: "Acción no reversible.",
    forbiddenTitle: "Acciones prohibidas",
    forbiddenHint: "Las operaciones OT/IoT destructivas están bloqueadas por política y no pueden seleccionarse.",
    catalogueError: "No se pudo cargar el catálogo defensivo",
    catalogueLoading: "Cargando catálogo de acciones…",
    definitionJson: "Vista JSON de la definición",
    showJson: "Mostrar JSON",
    hideJson: "Ocultar JSON",
    copyJson: "Copiar JSON",
    copied: "Copiado",
    previewError: "La definición actual no se puede serializar: {error}",
    validate: "Validar definición",
    validating: "Validando…",
    validationValid: "Definición válida",
    validationInvalid: "Definición rechazada",
    validationErrors: "Errores de validación",
    normalized: "Definición normalizada",
    saveDraft: "Guardar borrador",
    saving: "Guardando…",
    saved: "Playbook guardado",
    saveError: "No se pudo guardar el playbook",
    nameError: "El nombre debe tener al menos 3 caracteres.",
    stepError: "El paso {n} ({field}) no es válido: {error}",
    publish: "Publicar",
    publishTitle: "Publicar playbook",
    publishWarning:
      "Publicar revalida la definición en el servidor y archiva la versión publicada anterior con el mismo nombre. Las ejecuciones usan la versión publicada.",
    publishConfirm: "Publicar versión",
    published: "Playbook publicado",
    publishError: "No se pudo publicar el playbook",
    saveFirst: "Guarda el borrador antes de publicar o simular.",
    simulate: "Simular",
    simulateTitle: "Simular con contexto",
    simulateHint: "La simulación no crea ejecuciones ni ejecuta acciones; evalúa condiciones y política.",
    simulationBadge: "SIMULACIÓN · sin efectos",
    contextJson: "Contexto (JSON)",
    incidentOptional: "Incidente (opcional)",
    noIncident: "Sin incidente",
    runSimulation: "Simular",
    simulationSummary: "{execute} de {steps} pasos se ejecutarían · {skipped} omitidos",
    wouldExecute: "Se ejecutaría",
    wouldSkip: "Omitido",
    approvalRequired: "Requiere aprobación",
    simulationError: "La simulación falló",
    emptyStepsTitle: "Empieza definiendo el primer paso",
    emptyStepsDesc:
      "Un playbook es una secuencia de pasos con acción, parámetros, condición opcional, política de fallo y compensación. Las acciones defensivas deben existir en el catálogo y las que requieren aprobación necesitan un paso previo de solicitud.",
    loadExample: "Cargar ejemplo",
    schemaTitle: "Esquema del paso",
    unsaved: "Sin guardar",
    version: "Versión",
    status: "Estado",
    permissionDenied: "No tienes permiso playbook:write para guardar cambios.",
    simulatePermission: "No tienes permiso playbook:execute para simular.",
    risk: "Riesgo",
    reversible: "Reversible",
    yes: "Sí",
    no: "No",
    minLevel: "Nivel mínimo",
    approval: "Aprobación",
    otBlocked: "OT bloqueado",
    actionsAvailable: "{count} acciones disponibles",
    policyDefault: "Política de la organización",
    catalogueUnavailable: "catálogo no disponible",
    forbiddenCount: "{count} acciones prohibidas",
    cancelled: "Cancelado",
    demo: "DEMO",
    validationRequired: "Validación correcta",
    invalidJson: "JSON inválido en {field}: {error}",
    tabEditor: "Editor",
    tabJson: "JSON",
  },
  en: {
    eyebrow: "Automation · Designer",
    title: "Playbook designer",
    subtitle: "Structured editor for steps, conditions, compensations and triggers validated server-side.",
    newTitle: "New playbook",
    editTitle: "Edit playbook",
    back: "Back to SOAR",
    name: "Name",
    description: "Description",
    minAutonomy: "Minimum autonomy",
    triggers: "Triggers",
    triggerSeverity: "Alert severities",
    triggerRules: "Rule IDs",
    triggerRulesHint: "Comma separated.",
    steps: "Playbook steps",
    addStep: "Add step",
    step: "Step {n}",
    stepKey: "Step key",
    stepKeyHint: "lowercase, a-z0-9_.- (max. 80)",
    stepName: "Name",
    stepAction: "Action",
    stepParams: "Params (JSON)",
    condition: "Run only if",
    conditionField: "Context field",
    conditionOp: "Operator",
    conditionValue: "Value (JSON or text)",
    onFailure: "Failure policy",
    retries: "Retries",
    timeout: "Timeout (s)",
    compensation: "Compensation",
    compensationAction: "Compensation action",
    compensationParams: "Compensation params (JSON)",
    moveUp: "Move up",
    moveDown: "Move down",
    remove: "Remove step",
    defenceActionType: "Defensive catalogue action",
    defenceTargetType: "Target type",
    defenceTargetId: "Target ID",
    defenceLevel: "Requested level",
    defenceParameters: "Action parameters (JSON)",
    connectorCapability: "Read capability",
    connectorId: "Connector ID (optional)",
    connectorParams: "Read params (JSON)",
    approvalHint: "This action requires a preceding internal.request_approval step.",
    irreversibleHint: "Irreversible action.",
    forbiddenTitle: "Forbidden actions",
    forbiddenHint: "Destructive OT/IoT operations are blocked by policy and cannot be selected.",
    catalogueError: "Could not load the defensive catalogue",
    catalogueLoading: "Loading action catalogue…",
    definitionJson: "Definition JSON view",
    showJson: "Show JSON",
    hideJson: "Hide JSON",
    copyJson: "Copy JSON",
    copied: "Copied",
    previewError: "The current definition cannot be serialized: {error}",
    validate: "Validate definition",
    validating: "Validating…",
    validationValid: "Valid definition",
    validationInvalid: "Definition rejected",
    validationErrors: "Validation errors",
    normalized: "Normalized definition",
    saveDraft: "Save draft",
    saving: "Saving…",
    saved: "Playbook saved",
    saveError: "Could not save the playbook",
    nameError: "Name must be at least 3 characters.",
    stepError: "Step {n} ({field}) is invalid: {error}",
    publish: "Publish",
    publishTitle: "Publish playbook",
    publishWarning:
      "Publishing revalidates the definition server-side and archives the previously published version with the same name. Executions use the published version.",
    publishConfirm: "Publish version",
    published: "Playbook published",
    publishError: "Could not publish the playbook",
    saveFirst: "Save the draft before publishing or simulating.",
    simulate: "Simulate",
    simulateTitle: "Simulate with context",
    simulateHint: "Simulation creates no executions and runs no actions; it evaluates conditions and policy.",
    simulationBadge: "SIMULATION · no side effects",
    contextJson: "Context (JSON)",
    incidentOptional: "Incident (optional)",
    noIncident: "No incident",
    runSimulation: "Simulate",
    simulationSummary: "{execute} of {steps} steps would run · {skipped} skipped",
    wouldExecute: "Would run",
    wouldSkip: "Skipped",
    approvalRequired: "Approval required",
    simulationError: "Simulation failed",
    emptyStepsTitle: "Start by defining the first step",
    emptyStepsDesc:
      "A playbook is a sequence of steps with an action, params, optional condition, failure policy and compensation. Defensive actions must exist in the catalogue and approval-gated actions need a preceding request step.",
    loadExample: "Load example",
    schemaTitle: "Step schema",
    unsaved: "Unsaved",
    version: "Version",
    status: "Status",
    permissionDenied: "You lack the playbook:write permission to save changes.",
    simulatePermission: "You lack the playbook:execute permission to simulate.",
    risk: "Risk",
    reversible: "Reversible",
    yes: "Yes",
    no: "No",
    minLevel: "Min level",
    approval: "Approval",
    otBlocked: "OT blocked",
    actionsAvailable: "{count} actions available",
    policyDefault: "Organization policy",
    catalogueUnavailable: "catalogue unavailable",
    forbiddenCount: "{count} forbidden actions",
    cancelled: "Canceled",
    demo: "DEMO",
    validationRequired: "Validated",
    invalidJson: "Invalid JSON in {field}: {error}",
    tabEditor: "Editor",
    tabJson: "JSON",
  },
};

/* ---------------------------------------------------------------- helpers */

function parseJson(text: string, field: string, c: (key: string) => string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(
      c("invalidJson")
        .replace("{field}", field)
        .replace("{error}", error instanceof Error ? error.message : "invalid JSON"),
    );
  }
}

function parseObject(text: string, field: string, c: (key: string) => string): Record<string, unknown> {
  if (!text.trim()) return {};
  const value = parseJson(text, field, c);
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(c("invalidJson").replace("{field}", field).replace("{error}", "object expected"));
  }
  return value as Record<string, unknown>;
}

function parseConditionValue(text: string, op: string): unknown {
  if (op === "exists" || op === "truthy" || op === "falsy") return undefined;
  const trimmed = text.trim();
  if (!trimmed) return "";
  try {
    return JSON.parse(trimmed);
  } catch {
    return trimmed;
  }
}

function draftFromStep(raw: Record<string, unknown>): StepDraft {
  const action = typeof raw.action === "string" ? raw.action : "internal.investigate";
  const params = (raw.params && typeof raw.params === "object" ? raw.params : {}) as Record<string, unknown>;
  const condition = (raw.condition && typeof raw.condition === "object" ? raw.condition : null) as
    | { field?: string; op?: string; value?: unknown }
    | null;
  const compensation = (raw.compensation && typeof raw.compensation === "object" ? raw.compensation : null) as
    | { action?: string; params?: Record<string, unknown> }
    | null;
  const isDefence = action === "defence.execute";
  const isConnector = action === "connector.read";
  return {
    uid: nextUid(),
    key: typeof raw.key === "string" ? raw.key : `step_${stepSequence}`,
    name: typeof raw.name === "string" ? raw.name : "",
    action,
    paramsText: !isDefence && !isConnector ? JSON.stringify(params, null, 2) : "{}",
    conditionEnabled: Boolean(condition),
    conditionField: condition?.field ?? "",
    conditionOp: condition?.op ?? "eq",
    conditionValue: condition ? JSON.stringify(condition.value ?? null, null, 2) : "",
    onFailure: typeof raw.on_failure === "string" ? raw.on_failure : "abort",
    retries: String(typeof raw.retries === "number" ? raw.retries : 0),
    timeout: String(typeof raw.timeout_seconds === "number" ? raw.timeout_seconds : 60),
    compensationEnabled: Boolean(compensation),
    compensationAction: compensation?.action ?? "internal.add_timeline",
    compensationParams: JSON.stringify(compensation?.params ?? {}, null, 2),
    defenceActionType: isDefence && typeof params.action_type === "string" ? params.action_type : "",
    defenceTargetType: isDefence && typeof params.target_type === "string" ? params.target_type : "",
    defenceTargetId: isDefence && typeof params.target_id === "string" ? params.target_id : "",
    defenceLevel: isDefence && typeof params.requested_level === "string" ? params.requested_level : "",
    defenceParameters: JSON.stringify(isDefence ? params.parameters ?? {} : {}, null, 2),
    connectorCapability: isConnector && typeof params.capability === "string" ? params.capability : "",
    connectorId: isConnector && typeof params.connector_id === "string" ? params.connector_id : "",
    connectorParams: JSON.stringify(isConnector ? params.params ?? {} : {}, null, 2),
  };
}

function emptyStep(): StepDraft {
  return {
    uid: nextUid(),
    key: `step_${stepSequence}`,
    name: "",
    action: "internal.investigate",
    paramsText: "{}",
    conditionEnabled: false,
    conditionField: "",
    conditionOp: "eq",
    conditionValue: "",
    onFailure: "abort",
    retries: "0",
    timeout: "60",
    compensationEnabled: false,
    compensationAction: "internal.add_timeline",
    compensationParams: "{}",
    defenceActionType: "",
    defenceTargetType: "",
    defenceTargetId: "",
    defenceLevel: "",
    defenceParameters: "{}",
    connectorCapability: "",
    connectorId: "",
    connectorParams: "{}",
  };
}

function buildStepPayload(draft: StepDraft, index: number, c: (key: string) => string): StepPayload {
  if (!draft.key.trim()) throw new Error(c("stepKey"));
  if (!draft.name.trim()) throw new Error(c("stepName"));
  let params: Record<string, unknown>;
  if (draft.action === "defence.execute") {
    if (!draft.defenceActionType) throw new Error(c("defenceActionType"));
    if (!draft.defenceTargetId.trim()) throw new Error(c("defenceTargetId"));
    params = {
      action_type: draft.defenceActionType,
      target_type: draft.defenceTargetType || undefined,
      target_id: draft.defenceTargetId.trim(),
      parameters: parseObject(draft.defenceParameters, c("defenceParameters"), c),
      ...(draft.defenceLevel ? { requested_level: draft.defenceLevel } : {}),
    };
  } else if (draft.action === "connector.read") {
    if (!draft.connectorCapability.trim()) throw new Error(c("connectorCapability"));
    params = {
      capability: draft.connectorCapability.trim(),
      ...(draft.connectorId.trim() ? { connector_id: draft.connectorId.trim() } : {}),
      params: parseObject(draft.connectorParams, c("connectorParams"), c),
    };
  } else {
    params = parseObject(draft.paramsText, c("stepParams"), c);
  }

  const condition = draft.conditionEnabled
    ? {
        field: draft.conditionField.trim(),
        op: draft.conditionOp,
        ...(draft.conditionOp === "exists" || draft.conditionOp === "truthy" || draft.conditionOp === "falsy"
          ? {}
          : { value: parseConditionValue(draft.conditionValue, draft.conditionOp) }),
      }
    : null;

  const compensation = draft.compensationEnabled
    ? {
        action: draft.compensationAction,
        params: parseObject(draft.compensationParams, c("compensationParams"), c),
      }
    : null;

  const retries = Number(draft.retries);
  if (!Number.isInteger(retries) || retries < 0 || retries > 3) {
    throw new Error(c("retries"));
  }
  const timeout = Number(draft.timeout);
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 3600) {
    throw new Error(c("timeout"));
  }

  try {
    return {
      key: draft.key.trim(),
      name: draft.name.trim(),
      action: draft.action,
      params,
      condition,
      on_failure: draft.onFailure,
      retries,
      timeout_seconds: timeout,
      compensation,
    };
  } catch (error) {
    throw new Error(
      c("stepError")
        .replace("{n}", String(index + 1))
        .replace("{field}", draft.key)
        .replace("{error}", error instanceof Error ? error.message : String(error)),
    );
  }
}

/* ------------------------------------------------------------------- page */

export function PlaybookDesignerPage() {
  const { playbookId } = useParams<{ playbookId?: string }>();
  const c = usePageCopy(COPY);
  const { t } = useI18n();
  const { can } = useAuth();
  const { push } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [minAutonomy, setMinAutonomy] = useState("A2");
  const [triggerSeverities, setTriggerSeverities] = useState<string[]>(["critical", "high"]);
  const [triggerRules, setTriggerRules] = useState("");
  const [steps, setSteps] = useState<StepDraft[]>([]);
  const [jsonOpen, setJsonOpen] = useState(false);
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [publishOpen, setPublishOpen] = useState(false);
  const [simulateOpen, setSimulateOpen] = useState(false);
  const [simContext, setSimContext] = useState("{}");
  const [simIncident, setSimIncident] = useState("");
  const [simulation, setSimulation] = useState<Simulation | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  const canWrite = can("playbook:write");
  const canExecute = can("playbook:execute");

  const catalogue = useQuery({
    queryKey: ["defence", "actions"],
    queryFn: () => api.get<Catalogue>("/defence/actions"),
    enabled: can("defence:read"),
    staleTime: 120_000,
  });

  const playbook = useQuery({
    queryKey: ["soar", "playbook", playbookId],
    queryFn: () => api.get<Playbook>(`/soar/playbooks/${playbookId}`),
    enabled: Boolean(playbookId),
  });

  const incidents = useQuery({
    queryKey: ["incidents", "designer-sim"],
    queryFn: () => api.get<Page<IncidentOption>>("/incidents", { page_size: 100, sort: "detected_at", order: "desc" }),
    enabled: simulateOpen,
    staleTime: 30_000,
  });

  useEffect(() => {
    if (!playbook.data) return;
    const data = playbook.data;
    setName(data.name);
    setDescription(data.description ?? "");
    setMinAutonomy(data.min_autonomy_level);
    const trigger = data.trigger ?? {};
    const severities = Array.isArray(trigger.alert_severity)
      ? trigger.alert_severity.filter((value): value is string => typeof value === "string")
      : [];
    setTriggerSeverities(severities);
    setTriggerRules(Array.isArray(trigger.rules) ? trigger.rules.filter((value): value is string => typeof value === "string").join(", ") : "");
    const rawSteps = Array.isArray(data.definition?.steps) ? (data.definition.steps as Record<string, unknown>[]) : [];
    setSteps(rawSteps.map(draftFromStep));
    setValidation(null);
    setEditorError(null);
  }, [playbook.data]);

  const catalogueActions = useMemo(
    () => (catalogue.data?.actions ?? []).filter((action) => !action.internal),
    [catalogue.data],
  );
  const forbiddenKeys = useMemo(
    () => new Set((catalogue.data?.forbidden ?? []).map((entry) => entry.key)),
    [catalogue.data],
  );
  const defenceActions = useMemo(
    () => catalogueActions.filter((action) => !forbiddenKeys.has(action.key)),
    [catalogueActions, forbiddenKeys],
  );

  const triggers = useMemo(
    () => ({
      alert_severity: triggerSeverities,
      rules: triggerRules
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean),
    }),
    [triggerRules, triggerSeverities],
  );

  const payload = useMemo(() => {
    try {
      return {
        definition: {
          steps: steps.map((draft, index) => buildStepPayload(draft, index, c)),
        },
        triggers,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  }, [c, steps, triggers]);

  const previewText = useMemo(() => {
    if ("error" in payload) return JSON.stringify({ error: payload.error }, null, 2);
    return JSON.stringify(payload, null, 2);
  }, [payload]);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["soar"] });
  };

  const validateMutation = useMutation({
    mutationFn: () => {
      if ("error" in payload) throw new Error(payload.error);
      return api.post<ValidationResult>("/soar/playbooks/validate", {
        definition: payload.definition,
        triggers: payload.triggers,
        min_autonomy_level: minAutonomy,
      });
    },
    onSuccess: (result) => {
      setValidation(result);
      setEditorError(null);
      if (result.valid) push(c("validationValid"), "success");
    },
    onError: (error) => {
      setValidation(null);
      setEditorError(errorMessage(error));
    },
  });

  const saveMutation = useMutation({
    mutationFn: () => {
      if ("error" in payload) throw new Error(payload.error);
      if (name.trim().length < 3) throw new Error(c("nameError"));
      const body = {
        name: name.trim(),
        description: description.trim() || null,
        definition: payload.definition,
        triggers: payload.triggers,
        min_autonomy_level: minAutonomy,
      };
      return playbookId
        ? api.patch<Playbook>(`/soar/playbooks/${playbookId}`, body)
        : api.post<Playbook>("/soar/playbooks", body);
    },
    onSuccess: (saved) => {
      push(c("saved"), "success");
      setEditorError(null);
      invalidate();
      if (!playbookId || saved.id !== playbookId) navigate(`/playbook-designer/${saved.id}`, { replace: true });
    },
    onError: (error) => {
      const message = isApiError(error) && error.details.length
        ? error.details.map((detail) => `${detail.field}: ${detail.message}`).join(" · ")
        : errorMessage(error);
      setEditorError(message);
      push(`${c("saveError")}: ${message}`, "error");
    },
  });

  const publishMutation = useMutation({
    mutationFn: () => {
      if (!playbookId) throw new Error(c("saveFirst"));
      return api.post<Playbook>(`/soar/playbooks/${playbookId}/publish`);
    },
    onSuccess: () => {
      push(c("published"), "success");
      setPublishOpen(false);
      invalidate();
    },
    onError: (error) => push(`${c("publishError")}: ${errorMessage(error)}`, "error"),
  });

  const simulateMutation = useMutation({
    mutationFn: () => {
      if (!playbookId) throw new Error(c("saveFirst"));
      let context: Record<string, unknown>;
      try {
        const parsed: unknown = JSON.parse(simContext || "{}");
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("object expected");
        context = parsed as Record<string, unknown>;
      } catch (error) {
        throw new Error(c("invalidJson").replace("{field}", c("contextJson")).replace("{error}", error instanceof Error ? error.message : "invalid JSON"));
      }
      return api.post<Simulation>(`/soar/playbooks/${playbookId}/simulate`, {
        context,
        incident_id: simIncident || undefined,
      });
    },
    onSuccess: (result) => {
      setSimulation(result);
      setSimError(null);
    },
    onError: (error) => setSimError(errorMessage(error)),
  });

  const updateStep = (uid: string, patch: Partial<StepDraft>) => {
    setSteps((current) => current.map((step) => (step.uid === uid ? { ...step, ...patch } : step)));
  };

  const moveStep = (index: number, direction: -1 | 1) => {
    setSteps((current) => {
      const target = index + direction;
      if (target < 0 || target >= current.length) return current;
      const copy = [...current];
      const [item] = copy.splice(index, 1);
      copy.splice(target, 0, item);
      return copy;
    });
  };

  if (playbookId && playbook.isLoading) {
    return (
      <div data-testid="page-playbook-designer">
        <PageSkeleton />
      </div>
    );
  }

  if (playbookId && (playbook.isError || !playbook.data)) {
    return (
      <div data-testid="page-playbook-designer">
        <PageHeader
          eyebrow={c("eyebrow")}
          title={c("editTitle")}
          subtitle={c("subtitle")}
          actions={<LinkButton to="/soar" icon={ArrowLeft}>{c("back")}</LinkButton>}
        />
        <ErrorBanner message={errorMessage(playbook.error)} onRetry={() => void playbook.refetch()} />
      </div>
    );
  }

  const savedPlaybook = playbook.data;
  const payloadInvalid = "error" in payload;

  return (
    <div className="animate-in" data-testid="page-playbook-designer">
      <PageHeader
        eyebrow={`${c("eyebrow")}${savedPlaybook ? ` · v${savedPlaybook.version}` : ""}`}
        title={playbookId ? c("editTitle") : c("newTitle")}
        subtitle={c("subtitle")}
        actions={
          <>
            {savedPlaybook ? <StatusBadge status={savedPlaybook.status} /> : <Badge tone="neutral">{c("unsaved")}</Badge>}
            <Badge tone="neutral">{c("version")} {savedPlaybook?.version ?? 0}</Badge>
            <LinkButton to="/soar" icon={ArrowLeft}>{c("back")}</LinkButton>
            <Button
              icon={FlaskConical}
              onClick={() => { setSimulation(null); setSimError(null); setSimulateOpen(true); }}
              disabled={!playbookId || !canExecute}
              title={!canExecute ? c("simulatePermission") : undefined}
              data-testid="simulate-playbook"
            >
              {c("simulate")}
            </Button>
            <Button
              icon={CheckCircle2}
              loading={validateMutation.isPending}
              onClick={() => validateMutation.mutate()}
              disabled={payloadInvalid}
              data-testid="validate-definition"
            >
              {validateMutation.isPending ? c("validating") : c("validate")}
            </Button>
            <Button
              variant="primary"
              icon={Save}
              loading={saveMutation.isPending}
              onClick={() => saveMutation.mutate()}
              disabled={!canWrite || payloadInvalid}
              title={!canWrite ? c("permissionDenied") : undefined}
              data-testid="save-draft"
            >
              {c("saveDraft")}
            </Button>
            {playbookId ? (
              <Button
                variant="default"
                icon={Rocket}
                onClick={() => setPublishOpen(true)}
                disabled={!canWrite}
                data-testid="publish-playbook"
              >
                {c("publish")}
              </Button>
            ) : null}
          </>
        }
      />

      {!canWrite ? <div className="notice notice-warning" style={{ marginBottom: 12, fontSize: 11 }}>{c("permissionDenied")}</div> : null}
      {editorError ? <div style={{ marginBottom: 12 }}><ErrorBanner compact message={editorError} /></div> : null}

      <div className="split-main" style={{ alignItems: "flex-start" }}>
        <div className="stack">
          <Card title={c("newTitle")} subtitle={savedPlaybook ? `v${savedPlaybook.version} · ${savedPlaybook.status}` : c("unsaved")}>
            <div className="form-grid">
              <div className="span-2">
                <Field label={c("name")} required htmlFor="playbook-name">
                  <Input id="playbook-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={200} data-testid="playbook-name-input" />
                </Field>
              </div>
              <div className="span-2">
                <Field label={c("description")} htmlFor="playbook-description">
                  <Textarea id="playbook-description" value={description} onChange={(event) => setDescription(event.target.value)} rows={3} maxLength={5000} />
                </Field>
              </div>
              <Field label={c("minAutonomy")} htmlFor="playbook-autonomy">
                <Select id="playbook-autonomy" value={minAutonomy} onChange={(event) => setMinAutonomy(event.target.value)} data-testid="playbook-autonomy-select">
                  {["A0", "A1", "A2", "A3", "A4"].map((level) => <option key={level} value={level}>{level}</option>)}
                </Select>
              </Field>
              <div className="field">
                <span className="section-label" style={{ marginBottom: 8 }}>{c("triggerSeverity")}</span>
                <div className="chip-row">
                  {SEVERITIES.map((severity) => (
                    <label className="checkbox" key={severity}>
                      <input
                        type="checkbox"
                        checked={triggerSeverities.includes(severity)}
                        onChange={(event) =>
                          setTriggerSeverities((current) =>
                            event.target.checked ? [...current, severity] : current.filter((value) => value !== severity),
                          )
                        }
                      />
                      {severity}
                    </label>
                  ))}
                </div>
              </div>
              <div className="span-2">
                <Field label={c("triggerRules")} hint={c("triggerRulesHint")} htmlFor="playbook-rules">
                  <Input id="playbook-rules" value={triggerRules} onChange={(event) => setTriggerRules(event.target.value)} />
                </Field>
              </div>
            </div>
          </Card>

          <Card
            title={c("steps")}
            subtitle={c("schemaTitle")}
            actions={<Badge tone="neutral">{formatNumber(steps.length)}</Badge>}
          >
            {steps.length === 0 ? (
              <EmptyState
                icon={Layers}
                title={c("emptyStepsTitle")}
                description={c("emptyStepsDesc")}
                action={
                  <div className="stack" style={{ alignItems: "center" }}>
                    <Button variant="primary" size="sm" icon={Plus} onClick={() => setSteps([emptyStep()])}>{c("addStep")}</Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={Wand2}
                      onClick={() =>
                        setSteps((EXAMPLE_DEFINITION.steps as Record<string, unknown>[]).map(draftFromStep))
                      }
                    >
                      {c("loadExample")}
                    </Button>
                  </div>
                }
              />
            ) : (
              <div className="stack" data-testid="steps-list">
                {steps.map((step, index) => {
                  const isDefence = step.action === "defence.execute";
                  const isConnector = step.action === "connector.read";
                  return (
                    <div className="card card-pad" key={step.uid} data-testid={`step-card-${index}`}>
                      <div className="row-between" style={{ marginBottom: 8, gap: 8 }}>
                        <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                          <strong style={{ fontSize: 12.5 }}>{c("step").replace("{n}", String(index + 1))}</strong>
                          <span className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{step.key || "—"}</span>
                          <Badge tone="neutral">{step.action}</Badge>
                        </div>
                        <div className="row" style={{ gap: 2 }}>
                          <Button size="sm" variant="ghost" icon={ArrowUp} disabled={index === 0} onClick={() => moveStep(index, -1)} aria-label={c("moveUp")} />
                          <Button size="sm" variant="ghost" icon={ArrowDown} disabled={index === steps.length - 1} onClick={() => moveStep(index, 1)} aria-label={c("moveDown")} />
                          <Button
                            size="sm"
                            variant="ghost"
                            icon={Trash2}
                            onClick={() => setSteps((current) => current.filter((item) => item.uid !== step.uid))}
                            aria-label={c("remove")}
                          />
                        </div>
                      </div>

                      <div className="form-grid">
                        <Field label={c("stepKey")} hint={c("stepKeyHint")} htmlFor={`step-key-${step.uid}`}>
                          <Input id={`step-key-${step.uid}`} className="mono" value={step.key} onChange={(event) => updateStep(step.uid, { key: event.target.value })} maxLength={80} />
                        </Field>
                        <Field label={c("stepName")} htmlFor={`step-name-${step.uid}`}>
                          <Input id={`step-name-${step.uid}`} value={step.name} onChange={(event) => updateStep(step.uid, { name: event.target.value })} maxLength={200} />
                        </Field>
                        <Field label={c("stepAction")} htmlFor={`step-action-${step.uid}`}>
                          <Select
                            id={`step-action-${step.uid}`}
                            value={step.action}
                            onChange={(event) => updateStep(step.uid, { action: event.target.value })}
                            data-testid={`step-action-${index}`}
                          >
                            {COMBINED_ACTIONS.map((action) => (
                              <option
                                key={action}
                                value={action}
                                disabled={action === "defence.execute" && !catalogue.data?.actions.length}
                              >
                                {action === "defence.execute" && !catalogue.data?.actions.length ? `${action} (${c("catalogueUnavailable")})` : action}
                              </option>
                            ))}
                          </Select>
                        </Field>
                        <Field label={c("timeout")} htmlFor={`step-timeout-${step.uid}`}>
                          <Input
                            id={`step-timeout-${step.uid}`}
                            type="number"
                            min={1}
                            max={3600}
                            value={step.timeout}
                            onChange={(event) => updateStep(step.uid, { timeout: event.target.value })}
                          />
                        </Field>
                        <Field label={c("retries")} htmlFor={`step-retries-${step.uid}`}>
                          <Input
                            id={`step-retries-${step.uid}`}
                            type="number"
                            min={0}
                            max={3}
                            value={step.retries}
                            onChange={(event) => updateStep(step.uid, { retries: event.target.value })}
                          />
                        </Field>
                        <Field label={c("onFailure")} htmlFor={`step-failure-${step.uid}`}>
                          <Select id={`step-failure-${step.uid}`} value={step.onFailure} onChange={(event) => updateStep(step.uid, { onFailure: event.target.value })}>
                            {["abort", "compensate", "continue"].map((value) => <option key={value} value={value}>{value}</option>)}
                          </Select>
                        </Field>

                        {isDefence ? (
                          <>
                            <div className="span-2">
                              <Field label={c("defenceActionType")} required htmlFor={`step-defence-${step.uid}`}>
                                <Select
                                  id={`step-defence-${step.uid}`}
                                  value={step.defenceActionType}
                                  onChange={(event) => {
                                    const selected = defenceActions.find((action) => action.key === event.target.value);
                                    updateStep(step.uid, {
                                      defenceActionType: event.target.value,
                                      defenceTargetType: selected?.target_type ?? step.defenceTargetType,
                                      defenceLevel: selected?.min_level ?? step.defenceLevel,
                                    });
                                  }}
                                  data-testid={`step-defence-action-${index}`}
                                >
                                  <option value="">{c("defenceActionType")}</option>
                                  {defenceActions.map((action) => (
                                    <option key={action.key} value={action.key}>{action.label} · {action.key}</option>
                                  ))}
                                </Select>
                              </Field>
                              {catalogue.isLoading ? <span className="hint">{c("catalogueLoading")}</span> : null}
                              {catalogue.isError ? <ErrorBanner compact message={c("catalogueError")} /> : null}
                              {step.defenceActionType ? (
                                (() => {
                                  const selected = defenceActions.find((action) => action.key === step.defenceActionType);
                                  if (!selected) return null;
                                  return (
                                    <div className="row wrap" style={{ gap: 4, marginTop: 4 }}>
                                      <Badge tone={selected.risk === "critical" || selected.risk === "high" ? "danger" : selected.risk === "medium" ? "warning" : "neutral"}>{c("risk")} {selected.risk}</Badge>
                                      <Badge tone="neutral">{c("minLevel")} {selected.min_level}</Badge>
                                      <Badge tone={selected.reversible ? "success" : "warning"}>{c("reversible")}: {selected.reversible ? c("yes") : c("no")}</Badge>
                                      {selected.approval_required ? <Badge tone="warning">{c("approvalRequired")}</Badge> : null}
                                      {!selected.ot_allowed ? <Badge tone="danger">{c("otBlocked")}</Badge> : null}
                                    </div>
                                  );
                                })()
                              ) : null}
                              {step.defenceActionType && defenceActions.find((action) => action.key === step.defenceActionType)?.approval_required ? (
                                <p className="hint">{c("approvalHint")}</p>
                              ) : null}
                            </div>
                            <Field label={c("defenceTargetType")} htmlFor={`step-target-type-${step.uid}`}>
                              <Input id={`step-target-type-${step.uid}`} value={step.defenceTargetType} onChange={(event) => updateStep(step.uid, { defenceTargetType: event.target.value })} />
                            </Field>
                            <Field label={c("defenceTargetId")} required htmlFor={`step-target-id-${step.uid}`}>
                              <Input id={`step-target-id-${step.uid}`} className="mono" value={step.defenceTargetId} onChange={(event) => updateStep(step.uid, { defenceTargetId: event.target.value })} maxLength={300} />
                            </Field>
                            <Field label={c("defenceLevel")} htmlFor={`step-level-${step.uid}`}>
                              <Select id={`step-level-${step.uid}`} value={step.defenceLevel} onChange={(event) => updateStep(step.uid, { defenceLevel: event.target.value })}>
                                <option value="">{c("policyDefault")}</option>
                                {["A0", "A1", "A2", "A3", "A4"].map((level) => <option key={level} value={level}>{level}</option>)}
                              </Select>
                            </Field>
                            <div className="span-2">
                              <Field label={c("defenceParameters")} htmlFor={`step-defence-params-${step.uid}`}>
                                <Textarea id={`step-defence-params-${step.uid}`} className="textarea mono" value={step.defenceParameters} onChange={(event) => updateStep(step.uid, { defenceParameters: event.target.value })} rows={4} spellCheck={false} />
                              </Field>
                            </div>
                          </>
                        ) : isConnector ? (
                          <>
                            <Field label={c("connectorCapability")} required htmlFor={`step-capability-${step.uid}`}>
                              <Input id={`step-capability-${step.uid}`} className="mono" value={step.connectorCapability} onChange={(event) => updateStep(step.uid, { connectorCapability: event.target.value })} placeholder="read_events" />
                            </Field>
                            <Field label={c("connectorId")} htmlFor={`step-connector-${step.uid}`}>
                              <Input id={`step-connector-${step.uid}`} className="mono" value={step.connectorId} onChange={(event) => updateStep(step.uid, { connectorId: event.target.value })} />
                            </Field>
                            <div className="span-2">
                              <Field label={c("connectorParams")} htmlFor={`step-connector-params-${step.uid}`}>
                                <Textarea id={`step-connector-params-${step.uid}`} className="textarea mono" value={step.connectorParams} onChange={(event) => updateStep(step.uid, { connectorParams: event.target.value })} rows={3} spellCheck={false} />
                              </Field>
                            </div>
                          </>
                        ) : (
                          <div className="span-2">
                            <Field label={c("stepParams")} htmlFor={`step-params-${step.uid}`}>
                              <Textarea id={`step-params-${step.uid}`} className="textarea mono" value={step.paramsText} onChange={(event) => updateStep(step.uid, { paramsText: event.target.value })} rows={3} spellCheck={false} />
                            </Field>
                          </div>
                        )}

                        <div className="span-2">
                          <label className="checkbox">
                            <input type="checkbox" checked={step.conditionEnabled} onChange={(event) => updateStep(step.uid, { conditionEnabled: event.target.checked })} />
                            {c("condition")}
                          </label>
                        </div>
                        {step.conditionEnabled ? (
                          <>
                            <Field label={c("conditionField")} htmlFor={`step-condition-field-${step.uid}`}>
                              <Input id={`step-condition-field-${step.uid}`} className="mono" value={step.conditionField} onChange={(event) => updateStep(step.uid, { conditionField: event.target.value })} placeholder="incident.severity" />
                            </Field>
                            <Field label={c("conditionOp")} htmlFor={`step-condition-op-${step.uid}`}>
                              <Select id={`step-condition-op-${step.uid}`} value={step.conditionOp} onChange={(event) => updateStep(step.uid, { conditionOp: event.target.value })}>
                                {CONDITION_OPS.map((op) => <option key={op} value={op}>{op}</option>)}
                              </Select>
                            </Field>
                            <div className="span-2">
                              <Field label={c("conditionValue")} htmlFor={`step-condition-value-${step.uid}`}>
                                <Input id={`step-condition-value-${step.uid}`} className="mono" value={step.conditionValue} onChange={(event) => updateStep(step.uid, { conditionValue: event.target.value })} />
                              </Field>
                            </div>
                          </>
                        ) : null}

                        <div className="span-2">
                          <label className="checkbox">
                            <input type="checkbox" checked={step.compensationEnabled} onChange={(event) => updateStep(step.uid, { compensationEnabled: event.target.checked })} />
                            {c("compensation")}
                          </label>
                        </div>
                        {step.compensationEnabled ? (
                          <>
                            <Field label={c("compensationAction")} htmlFor={`step-comp-action-${step.uid}`}>
                              <Select id={`step-comp-action-${step.uid}`} value={step.compensationAction} onChange={(event) => updateStep(step.uid, { compensationAction: event.target.value })}>
                                {COMBINED_ACTIONS.map((action) => <option key={action} value={action}>{action}</option>)}
                              </Select>
                            </Field>
                            <div className="span-2">
                              <Field label={c("compensationParams")} htmlFor={`step-comp-params-${step.uid}`}>
                                <Textarea id={`step-comp-params-${step.uid}`} className="textarea mono" value={step.compensationParams} onChange={(event) => updateStep(step.uid, { compensationParams: event.target.value })} rows={3} spellCheck={false} />
                              </Field>
                            </div>
                          </>
                        ) : null}
                      </div>
                    </div>
                  );
                })}
                <Button icon={Plus} onClick={() => setSteps((current) => [...current, emptyStep()])} data-testid="add-step">
                  {c("addStep")}
                </Button>
              </div>
            )}
          </Card>

          {validation ? (
            <Card
              title={c("validate")}
              actions={<Badge tone={validation.valid ? "success" : "danger"}>{validation.valid ? c("validationValid") : c("validationInvalid")}</Badge>}
            >
              <div data-testid="designer-validation">
                {validation.errors.length ? (
                  <div className="metric-list">
                    {validation.errors.map((issue, index) => (
                      <div className="metric-row" key={`${issue.field}-${index}`}>
                        <span className="metric-label mono" style={{ fontSize: 10 }}>{issue.field}</span>
                        <span className="metric-value" style={{ fontSize: 10.5, color: "var(--danger)" }}>{issue.message}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="notice notice-accent" style={{ fontSize: 11 }}>
                    <CheckCircle2 size={13} style={{ flex: "0 0 auto" }} />
                    <span>{c("validationValid")}</span>
                  </div>
                )}
                {validation.normalized ? (
                  <>
                    <div className="section-label" style={{ marginTop: 10 }}>{c("normalized")}</div>
                    <pre className="code-block">{JSON.stringify(validation.normalized, null, 2)}</pre>
                  </>
                ) : null}
              </div>
            </Card>
          ) : null}
        </div>

        <div className="stack">
          <Card
            title={c("definitionJson")}
            actions={
              <div className="row" style={{ gap: 4 }}>
                <Button size="sm" variant="ghost" icon={Code2} onClick={() => setJsonOpen((value) => !value)}>
                  {jsonOpen ? c("hideJson") : c("showJson")}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  icon={Copy}
                  onClick={() => {
                    void navigator.clipboard?.writeText(previewText).then(() => push(c("copied"), "success"));
                  }}
                  aria-label={c("copyJson")}
                />
              </div>
            }
          >
            {jsonOpen ? (
              <>
                {payloadInvalid ? (
                  <div className="notice notice-warning" style={{ fontSize: 11 }}>
                    <AlertTriangle size={13} style={{ flex: "0 0 auto" }} />
                    <span>{c("previewError").replace("{error}", "error" in payload ? payload.error ?? "—" : "—")}</span>
                  </div>
                ) : null}
                <pre className="code-block" style={{ marginTop: 8 }} data-testid="definition-json">{previewText}</pre>
              </>
            ) : (
              <div className="metric-list">
                <div className="metric-row"><span className="metric-label">{c("steps")}</span><span className="metric-value">{formatNumber(steps.length)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("minAutonomy")}</span><span className="metric-value">{minAutonomy}</span></div>
                <div className="metric-row"><span className="metric-label">{c("triggerSeverity")}</span><span className="metric-value">{triggerSeverities.join(", ") || "—"}</span></div>
                <div className="metric-row"><span className="metric-label">{c("version")}</span><span className="metric-value">v{savedPlaybook?.version ?? 0}</span></div>
              </div>
            )}
            {payloadInvalid ? <p className="hint">{c("previewError").replace("{error}", "error" in payload ? payload.error ?? "—" : "—")}</p> : null}
          </Card>

          <Card
            title={c("forbiddenTitle")}
            subtitle={c("forbiddenHint")}
            actions={<Badge tone={forbiddenKeys.size ? "danger" : "success"}>{formatNumber(forbiddenKeys.size)}</Badge>}
          >
            {catalogue.isLoading ? (
              <div className="stack"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
            ) : catalogue.isError ? (
              <ErrorBanner compact message={c("catalogueError")} onRetry={() => void catalogue.refetch()} />
            ) : (
              <>
                <div className="row wrap" style={{ gap: 6, marginBottom: 8 }}>
                  <Badge tone="neutral">{c("actionsAvailable").replace("{count}", String(defenceActions.length))}</Badge>
                  <Badge tone="neutral">{c("forbiddenCount").replace("{count}", String(forbiddenKeys.size))}</Badge>
                  {catalogue.data ? <Badge tone="accent">{catalogue.data.org_max_level}</Badge> : null}
                </div>
                {forbiddenKeys.size ? (
                  <div className="chip-row">
                    {catalogue.data?.forbidden.map((entry) => (
                      <span className="tag" key={entry.key} title={entry.reason}>{entry.key}</span>
                    ))}
                  </div>
                ) : null}
              </>
            )}
          </Card>

          <Card title={c("schemaTitle")}>
            <pre className="code-block">{`{
  "steps": [
    {
      "key": "investigate",
      "name": "Investigate incident context",
      "action": "internal.investigate",
      "params": { "focus": "incident" },
      "condition": null,
      "on_failure": "abort",
      "retries": 0,
      "timeout_seconds": 60,
      "compensation": null
    }
  ],
  "triggers": { "alert_severity": ["critical"], "rules": [] }
}`}</pre>
            <p className="hint">
              {c("emptyStepsDesc")}
            </p>
          </Card>
        </div>
      </div>

      <Modal
        open={publishOpen}
        onClose={() => setPublishOpen(false)}
        title={c("publishTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setPublishOpen(false)}>{t("common.cancel")}</Button>
            <Button variant="primary" icon={Rocket} loading={publishMutation.isPending} onClick={() => publishMutation.mutate()} data-testid="confirm-publish-playbook">
              {c("publishConfirm")}
            </Button>
          </>
        }
      >
        <div data-testid="designer-publish-modal">
          <div className="notice notice-warning" style={{ fontSize: 11 }}>
            <ShieldAlert size={13} style={{ flex: "0 0 auto" }} />
            <span>{c("publishWarning")}</span>
          </div>
          <div className="metric-list" style={{ marginTop: 10 }}>
            <div className="metric-row"><span className="metric-label">{c("name")}</span><span className="metric-value">{name || "—"}</span></div>
            <div className="metric-row"><span className="metric-label">{c("version")}</span><span className="metric-value">v{savedPlaybook?.version ?? 0}</span></div>
            <div className="metric-row"><span className="metric-label">{c("steps")}</span><span className="metric-value">{formatNumber(steps.length)}</span></div>
            <div className="metric-row"><span className="metric-label">{c("minAutonomy")}</span><span className="metric-value">{minAutonomy}</span></div>
          </div>
        </div>
      </Modal>

      <Modal
        open={simulateOpen}
        onClose={() => setSimulateOpen(false)}
        title={c("simulateTitle")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setSimulateOpen(false)}>{t("common.close")}</Button>
            <Button
              variant="primary"
              icon={FlaskConical}
              loading={simulateMutation.isPending}
              disabled={!playbookId || !canExecute}
              onClick={() => simulateMutation.mutate()}
              data-testid="run-designer-simulation"
            >
              {c("runSimulation")}
            </Button>
          </>
        }
      >
        <div data-testid="designer-simulate-modal">
          <div className="notice notice-accent" style={{ fontSize: 11 }}>
            <Info size={13} style={{ flex: "0 0 auto" }} />
            <span>{c("simulateHint")}</span>
          </div>
          <div className="form-grid" style={{ marginTop: 10 }}>
            <Field label={c("incidentOptional")} htmlFor="designer-sim-incident">
              <Select id="designer-sim-incident" value={simIncident} onChange={(event) => setSimIncident(event.target.value)}>
                <option value="">{c("noIncident")}</option>
                {incidents.data?.items.map((incident) => <option key={incident.id} value={incident.id}>{incident.ref} · {incident.title}</option>)}
              </Select>
            </Field>
            <div className="field">
              <span className="section-label" style={{ marginBottom: 8 }}>{c("version")}</span>
              <div className="row" style={{ gap: 6 }}>
                <Badge tone="neutral">v{savedPlaybook?.version ?? 0}</Badge>
                <StatusBadge status={savedPlaybook?.status ?? "draft"} />
              </div>
            </div>
            <div className="span-2">
              <Field label={c("contextJson")} htmlFor="designer-sim-context">
                <Textarea id="designer-sim-context" className="textarea mono" value={simContext} onChange={(event) => setSimContext(event.target.value)} rows={6} spellCheck={false} />
              </Field>
            </div>
          </div>
          {simError ? <div style={{ marginTop: 10 }}><ErrorBanner compact message={`${c("simulationError")}: ${simError}`} /></div> : null}
          {simulation ? (
            <div style={{ marginTop: 12 }} data-testid="designer-simulation-result">
              <div className="row wrap" style={{ gap: 6, marginBottom: 8 }}>
                <Badge tone="accent">{c("simulationBadge")}</Badge>
                <Badge tone="neutral">
                  {c("simulationSummary")
                    .replace("{execute}", String(simulation.summary.would_execute))
                    .replace("{steps}", String(simulation.summary.steps))
                    .replace("{skipped}", String(simulation.summary.skipped))}
                </Badge>
              </div>
              <div className="stack">
                {simulation.steps.map((step) => (
                  <div className="card card-pad" key={`${step.position}-${step.key}`}>
                    <div className="row wrap" style={{ gap: 6 }}>
                      <span className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>{step.key}</span>
                      <strong style={{ fontSize: 12.5 }}>{step.name}</strong>
                      <Badge tone={step.would_execute ? "success" : "neutral"}>{step.would_execute ? c("wouldExecute") : c("wouldSkip")}</Badge>
                      {step.approval_required ? <Badge tone="warning">{c("approvalRequired")}</Badge> : null}
                    </div>
                    <div className="item-sub">{step.action}</div>
                    {step.reason ? <div className="hint">{step.reason}</div> : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </Modal>
    </div>
  );
}

export default PlaybookDesignerPage;
