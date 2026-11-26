import { useId, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertOctagon,
  Ban,
  Check,
  ClipboardList,
  FileCode2,
  KeyRound,
  Lock,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
  X,
} from "lucide-react";
import { api, errorMessage, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, type Lang } from "../lib/i18n";
import { formatDateTime, humanize, relativeTime } from "../lib/format";
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
  Pagination,
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
  JsonEditor,
  MetaRows,
  PreBlock,
  apiFieldErrors,
  parseJsonRecord,
  useGovernCopy,
} from "../components/features/govern/common";
import { ApiTokensPanel, SecurityCards } from "../components/features/govern/security";

/* --------------------------------------------------------------- contracts */

type TabKey = "members" | "policies" | "killswitches" | "approvals" | "tokens" | "security";

const TAB_KEYS: TabKey[] = ["members", "policies", "killswitches", "approvals", "tokens", "security"];

const ROLES = [
  "org_admin",
  "soc_manager",
  "soc_analyst",
  "incident_responder",
  "threat_analyst",
  "vulnerability_manager",
  "compliance_officer",
  "auditor",
  "viewer",
] as const;

type MemberRole = (typeof ROLES)[number];

const POLICY_KINDS = ["autonomy", "access", "retention", "notification"] as const;
type PolicyKind = (typeof POLICY_KINDS)[number];

const KILL_SCOPES = ["organization", "connector", "autonomy", "global"] as const;
type KillScope = (typeof KILL_SCOPES)[number];

interface Member {
  id: string;
  user_id: string;
  email: string;
  full_name: string;
  role: string;
  status: string;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
}

interface Policy {
  id: string;
  org_id: string | null;
  name: string;
  kind: string;
  version: number;
  enabled: boolean;
  definition: Record<string, unknown>;
  description: string | null;
  created_at: string;
  updated_at: string;
}

interface KillSwitch {
  id: string;
  org_id: string | null;
  scope: string;
  target_id: string | null;
  engaged: boolean;
  reason: string;
  engaged_by: string | null;
  engaged_at: string;
  released_by: string | null;
  released_at: string | null;
}

interface Approval {
  id: string;
  org_id: string;
  request_type: string;
  resource_type: string;
  resource_id: string | null;
  payload: Record<string, unknown>;
  status: string;
  requested_by: string | null;
  decided_by: string | null;
  decided_at: string | null;
  reason: string | null;
  expires_at: string | null;
  created_at: string;
}

interface ConnectorOption {
  id: string;
  name: string;
  connector_type: string;
}

interface MemberFormState {
  email: string;
  fullName: string;
  role: MemberRole;
  password: string;
}

const EMPTY_MEMBER_FORM: MemberFormState = { email: "", fullName: "", role: "soc_analyst", password: "" };

interface PolicyFormState {
  name: string;
  kind: PolicyKind;
  description: string;
  enabled: boolean;
  definitionText: string;
}

const EMPTY_POLICY_FORM: PolicyFormState = {
  name: "",
  kind: "autonomy",
  description: "",
  enabled: true,
  definitionText: "{}",
};

/* -------------------------------------------------------------------- copy */

const COPY: Record<Lang, Record<string, string>> = {
  es: {
    eyebrow: "Administración · Organización",
    title: "Administración del sistema",
    subtitle: "Miembros, políticas, kill switches, aprobaciones y credenciales del tenant activo.",
    tabMembers: "Miembros",
    tabPolicies: "Políticas",
    tabKill: "Kill switches",
    tabApprovals: "Aprobaciones",
    tabTokens: "Tokens de API",
    tabSecurity: "Seguridad",
    noPermission: "No tienes permiso para esta sección.",
    membersTitle: "Miembros de la organización",
    membersSub: "Roles estáticos y auditables; el servidor es la autoridad final.",
    invite: "Añadir miembro",
    editMember: "Editar miembro",
    email: "Correo",
    fullName: "Nombre completo",
    role: "Rol",
    status: "Estado",
    mfa: "MFA",
    lastLogin: "Último acceso",
    memberSince: "Alta",
    updated: "Actualizado",
    noMembers: "Sin miembros",
    noMembersHint: "Añade el primer operador con el rol mínimo necesario.",
    memberCreated: "Miembro añadido",
    memberUpdated: "Miembro actualizado",
    memberRemoved: "Miembro eliminado",
    removeMember: "Eliminar miembro",
    removeMemberWarning:
      "Se revoca el acceso de esta cuenta a la organización activa. Si es el último administrador activo, el servidor rechazará la operación.",
    suspend: "Suspender",
    activate: "Reactivar",
    password: "Contraseña inicial",
    passwordHint: "Obligatoria solo si la cuenta no existe. Mínimo 12 caracteres y 3 clases de caracteres.",
    passwordPolicy: "Mínimo 12 caracteres, al menos 3 de minúsculas/mayúsculas/dígitos/símbolos, sin contener el usuario.",
    emailRequired: "Introduce un correo válido.",
    nameRequired: "El nombre debe tener al menos 2 caracteres.",
    roleDescriptions: "Descripción de roles",
    roleOrgAdmin: "Administración total de la organización (miembros, políticas, conectores) salvo acciones de plataforma.",
    roleSocManager: "Gestión del SOC: alertas, incidentes, playbooks, conectores y autonomía.",
    roleSocAnalyst: "Triaje, investigación y respuesta propuesta; sin administración.",
    roleIncidentResponder: "Contención y respuesta ejecutada dentro de política.",
    roleThreatAnalyst: "Inteligencia de amenazas, indicadores y feeds.",
    roleVulnManager: "Inventario, vulnerabilidades y superficie de ataque.",
    roleCompliance: "Marcos, evaluaciones, evidencias e informes regulatorios.",
    roleAuditor: "Lectura completa y verificación de la cadena de auditoría.",
    roleViewer: "Solo lectura operativa.",
    lastAdminGuard: "La organización debe conservar al menos un administrador activo.",
    selfGuard: "No puedes suspender ni eliminar tu propia membresía.",
    actionFailed: "La operación falló",
    clearActionError: "Descartar",
    policiesTitle: "Políticas",
    policiesSub: "Definiciones versionadas; cada guardado incrementa la versión y se audita.",
    newPolicy: "Nueva política",
    editPolicy: "Editar política",
    policyName: "Nombre",
    policyKind: "Tipo",
    description: "Descripción",
    version: "Versión",
    definition: "Definición JSON",
    definitionHint: "Objeto JSON evaluado por el motor de políticas. Se valida en el servidor.",
    enabled: "Habilitada",
    enabledOff: "Deshabilitada",
    noPolicies: "Sin políticas",
    noPoliciesHint: "Crea políticas de autonomía, acceso, retención o notificación.",
    policyCreated: "Política creada",
    policyUpdated: "Política actualizada",
    kindAutonomy: "Autonomía",
    kindAccess: "Acceso",
    kindRetention: "Retención",
    kindNotification: "Notificación",
    kindAutonomyHint: "Niveles, acciones permitidas y aprobaciones requeridas.",
    kindAccessHint: "Reglas ABAC, horarios y restricciones por recurso.",
    kindRetentionHint: "Días de retención, legal hold y minimización.",
    kindNotificationHint: "Canales, severidades y destinatarios.",
    versionNote: "Guardar crea una nueva versión inmutable de la definición.",
    invalidDefinition: "La definición debe ser un objeto JSON válido.",
    killTitle: "Kill switches",
    killSub: "Contención fail-closed: mientras esté activo, las acciones autónomas quedan bloqueadas.",
    killFailClosed: "El sistema falla cerrado: si la política o el estado del kill switch no pueden evaluarse, la acción se deniega.",
    engageKill: "Activar kill switch",
    effectiveSwitches: "Switches efectivos",
    noEffective: "Ningún kill switch activo",
    noEffectiveHint: "Las acciones autónomas se evalúan según la política vigente.",
    scope: "Ámbito",
    target: "Objetivo",
    reason: "Motivo",
    reasonHint: "Obligatorio, mínimo 5 caracteres. Se registra en auditoría.",
    engagedBy: "Activado por",
    engagedAt: "Activado",
    releasedBy: "Liberado por",
    releasedAt: "Liberado",
    release: "Liberar",
    releaseTitle: "Liberar kill switch",
    releaseWarning:
      "Al liberar, las acciones autónomas vuelven a evaluarse según la política. Verifica que la causa raíz esté resuelta antes de continuar.",
    engaged: "Activo",
    released: "Liberado",
    scopeOrganization: "Organización",
    scopeConnector: "Conector",
    scopeAutonomy: "Autonomía",
    scopeGlobal: "Global",
    globalOnlyAdmin: "Solo un administrador de plataforma puede activar o liberar el kill switch global.",
    targetRequired: "Este ámbito requiere un objetivo.",
    targetConnector: "Selecciona el conector afectado.",
    targetAutonomy: "Selecciona el nivel de autonomía a bloquear.",
    reasonRequired: "Indica un motivo de al menos 5 caracteres.",
    killEngaged: "Kill switch activado",
    killReleased: "Kill switch liberado",
    killAll: "Historial de kill switches",
    noHistory: "Sin registros de kill switches",
    confirmEngage: "Confirmar activación",
    confirmEngageWarning:
      "La contención es inmediata y afecta a todas las acciones del ámbito seleccionado. Comprueba el radio de impacto antes de confirmar.",
    approvalsTitle: "Solicitudes de aprobación",
    approvalsSub: "Separación de funciones: quien solicita no puede aprobar su propia acción.",
    approve: "Aprobar",
    reject: "Rechazar",
    decision: "Decisión",
    decisionReason: "Motivo de la decisión",
    decisionHint: "Obligatorio, mínimo 3 caracteres. Se conserva en auditoría.",
    decideTitle: "Decidir aprobación",
    noApprovals: "Sin solicitudes",
    noApprovalsHint: "Las acciones que requieren aprobación aparecerán aquí.",
    requestedBy: "Solicitada por",
    decidedBy: "Decidida por",
    createdAt: "Creada",
    expiresAt: "Caduca",
    expired: "Caducada",
    expiredHint: "La solicitud ha caducado y ya no puede decidirse.",
    approvalApproved: "Solicitud aprobada",
    approvalRejected: "Solicitud rechazada",
    approvalError: "No se pudo registrar la decisión",
    payload: "Payload",
    requestType: "Tipo de solicitud",
    resource: "Recurso",
    filterStatus: "Estado",
    approveAction: "Aprobación",
    rejectAction: "Rechazo",
    all: "Todas",
    pending: "Pendiente",
    approved: "Aprobada",
    rejected: "Rechazada",
    details: "Detalle",
    close: "Cerrar",
    save: "Guardar",
    cancel: "Cancelar",
    create: "Crear",
    refresh: "Actualizar",
    remove: "Eliminar",
    statusActive: "Activo",
    statusSuspended: "Suspendido",
    yes: "Sí",
    no: "No",
    mfaEnabled: "Activo",
    mfaDisabled: "Inactivo",
    membersFilter: "Buscar por nombre o correo…",
    permissionsNote: "Los permisos efectivos se calculan solo desde el rol de membresía en el servidor.",
  },
  en: {
    eyebrow: "Administration · Organization",
    title: "System administration",
    subtitle: "Members, policies, kill switches, approvals and credentials for the active tenant.",
    tabMembers: "Members",
    tabPolicies: "Policies",
    tabKill: "Kill switches",
    tabApprovals: "Approvals",
    tabTokens: "API tokens",
    tabSecurity: "Security",
    noPermission: "You do not have permission for this section.",
    membersTitle: "Organization members",
    membersSub: "Static, auditable roles; the server remains authoritative.",
    invite: "Add member",
    editMember: "Edit member",
    email: "Email",
    fullName: "Full name",
    role: "Role",
    status: "Status",
    mfa: "MFA",
    lastLogin: "Last sign-in",
    memberSince: "Joined",
    updated: "Updated",
    noMembers: "No members",
    noMembersHint: "Add the first operator with the minimum necessary role.",
    memberCreated: "Member added",
    memberUpdated: "Member updated",
    memberRemoved: "Member removed",
    removeMember: "Remove member",
    removeMemberWarning:
      "This account loses access to the active organization. If it is the last active administrator the server will reject the operation.",
    suspend: "Suspend",
    activate: "Reactivate",
    password: "Initial password",
    passwordHint: "Required only for a new account. At least 12 characters and 3 character classes.",
    passwordPolicy: "At least 12 characters, 3 of lowercase/uppercase/digits/symbols, and not containing the account name.",
    emailRequired: "Enter a valid email.",
    nameRequired: "Name must be at least 2 characters.",
    roleDescriptions: "Role descriptions",
    roleOrgAdmin: "Full organization administration (members, policies, connectors) except platform actions.",
    roleSocManager: "SOC management: alerts, incidents, playbooks, connectors and autonomy.",
    roleSocAnalyst: "Triage, investigation and proposed response; no administration.",
    roleIncidentResponder: "Containment and response executed within policy.",
    roleThreatAnalyst: "Threat intelligence, indicators and feeds.",
    roleVulnManager: "Inventory, vulnerabilities and attack surface.",
    roleCompliance: "Frameworks, assessments, evidence and regulatory reports.",
    roleAuditor: "Full read access and audit chain verification.",
    roleViewer: "Operational read-only.",
    lastAdminGuard: "The organization must retain at least one active administrator.",
    selfGuard: "You cannot suspend or remove your own membership.",
    actionFailed: "The operation failed",
    clearActionError: "Dismiss",
    policiesTitle: "Policies",
    policiesSub: "Versioned definitions; every save increments the version and is audited.",
    newPolicy: "New policy",
    editPolicy: "Edit policy",
    policyName: "Name",
    policyKind: "Kind",
    description: "Description",
    version: "Version",
    definition: "JSON definition",
    definitionHint: "JSON object evaluated by the policy engine. Validated server-side.",
    enabled: "Enabled",
    enabledOff: "Disabled",
    noPolicies: "No policies",
    noPoliciesHint: "Create autonomy, access, retention or notification policies.",
    policyCreated: "Policy created",
    policyUpdated: "Policy updated",
    kindAutonomy: "Autonomy",
    kindAccess: "Access",
    kindRetention: "Retention",
    kindNotification: "Notification",
    kindAutonomyHint: "Levels, allowed actions and required approvals.",
    kindAccessHint: "ABAC rules, schedules and resource restrictions.",
    kindRetentionHint: "Retention days, legal hold and minimisation.",
    kindNotificationHint: "Channels, severities and recipients.",
    versionNote: "Saving creates a new immutable version of the definition.",
    invalidDefinition: "The definition must be a valid JSON object.",
    killTitle: "Kill switches",
    killSub: "Fail-closed containment: while engaged, autonomous actions are blocked.",
    killFailClosed: "The system fails closed: if policy or kill-switch state cannot be evaluated, the action is denied.",
    engageKill: "Engage kill switch",
    effectiveSwitches: "Effective switches",
    noEffective: "No active kill switch",
    noEffectiveHint: "Autonomous actions are evaluated against the current policy.",
    scope: "Scope",
    target: "Target",
    reason: "Reason",
    reasonHint: "Required, at least 5 characters. Recorded in the audit trail.",
    engagedBy: "Engaged by",
    engagedAt: "Engaged",
    releasedBy: "Released by",
    releasedAt: "Released",
    release: "Release",
    releaseTitle: "Release kill switch",
    releaseWarning:
      "Releasing re-evaluates autonomous actions against policy. Verify the root cause is resolved before continuing.",
    engaged: "Engaged",
    released: "Released",
    scopeOrganization: "Organization",
    scopeConnector: "Connector",
    scopeAutonomy: "Autonomy",
    scopeGlobal: "Global",
    globalOnlyAdmin: "Only a platform administrator can engage or release the global kill switch.",
    targetRequired: "This scope requires a target.",
    targetConnector: "Select the affected connector.",
    targetAutonomy: "Select the autonomy level to block.",
    reasonRequired: "Provide a reason of at least 5 characters.",
    killEngaged: "Kill switch engaged",
    killReleased: "Kill switch released",
    killAll: "Kill switch history",
    noHistory: "No kill switch records",
    confirmEngage: "Confirm engagement",
    confirmEngageWarning:
      "Containment is immediate and affects every action in the selected scope. Review the blast radius before confirming.",
    approvalsTitle: "Approval requests",
    approvalsSub: "Separation of duties: the requester cannot approve their own action.",
    approve: "Approve",
    reject: "Reject",
    decision: "Decision",
    decisionReason: "Decision reason",
    decisionHint: "Required, at least 3 characters. Retained in the audit trail.",
    decideTitle: "Decide approval",
    noApprovals: "No requests",
    noApprovalsHint: "Actions requiring approval will appear here.",
    requestedBy: "Requested by",
    decidedBy: "Decided by",
    createdAt: "Created",
    expiresAt: "Expires",
    expired: "Expired",
    expiredHint: "The request has expired and can no longer be decided.",
    approvalApproved: "Request approved",
    approvalRejected: "Request rejected",
    approvalError: "The decision could not be recorded",
    payload: "Payload",
    requestType: "Request type",
    resource: "Resource",
    filterStatus: "Status",
    approveAction: "Approval",
    rejectAction: "Rejection",
    all: "All",
    pending: "Pending",
    approved: "Approved",
    rejected: "Rejected",
    details: "Detail",
    close: "Close",
    save: "Save",
    cancel: "Cancel",
    create: "Create",
    refresh: "Refresh",
    remove: "Remove",
    statusActive: "Active",
    statusSuspended: "Suspended",
    yes: "Yes",
    no: "No",
    mfaEnabled: "Enabled",
    mfaDisabled: "Disabled",
    membersFilter: "Search by name or email…",
    permissionsNote: "Effective permissions are computed from the membership role server-side only.",
  },
};

function roleKey(role: string): string {
  const map: Record<string, string> = {
    platform_admin: "roleOrgAdmin",
    org_admin: "roleOrgAdmin",
    soc_manager: "roleSocManager",
    soc_analyst: "roleSocAnalyst",
    incident_responder: "roleIncidentResponder",
    threat_analyst: "roleThreatAnalyst",
    vulnerability_manager: "roleVulnManager",
    compliance_officer: "roleCompliance",
    auditor: "roleAuditor",
    viewer: "roleViewer",
  };
  return map[role] ?? "";
}

function policyKindLabel(kind: string, t: (key: string) => string): string {
  if (kind === "autonomy") return t("kindAutonomy");
  if (kind === "access") return t("kindAccess");
  if (kind === "retention") return t("kindRetention");
  if (kind === "notification") return t("kindNotification");
  return humanize(kind);
}

function policyKindHint(kind: string, t: (key: string) => string): string {
  if (kind === "autonomy") return t("kindAutonomyHint");
  if (kind === "access") return t("kindAccessHint");
  if (kind === "retention") return t("kindRetentionHint");
  if (kind === "notification") return t("kindNotificationHint");
  return "";
}

function killScopeLabel(scope: string, t: (key: string) => string): string {
  if (scope === "organization") return t("scopeOrganization");
  if (scope === "connector") return t("scopeConnector");
  if (scope === "autonomy") return t("scopeAutonomy");
  if (scope === "global") return t("scopeGlobal");
  return humanize(scope);
}

/* ----------------------------------------------------------------- members */

function MembersTab({ canManage }: { canManage: boolean }) {
  const t = useGovernCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState<MemberFormState>(EMPTY_MEMBER_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [editing, setEditing] = useState<Member | null>(null);
  const [editRole, setEditRole] = useState<MemberRole>("soc_analyst");
  const [editStatus, setEditStatus] = useState<"active" | "suspended">("active");
  const [editError, setEditError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Member | null>(null);
  const [pendingMemberUpdate, setPendingMemberUpdate] = useState<{ member: Member; role: MemberRole; status: "active" | "suspended" } | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const membersQuery = useQuery({
    queryKey: ["admin", "members", { q, page }],
    queryFn: () => api.get<Page<Member>>("/organizations/current/members", { page, page_size: 50, q: q || undefined }),
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<Member>("/organizations/current/members", body),
    onSuccess: async () => {
      setCreateOpen(false);
      setForm(EMPTY_MEMBER_FORM);
      setFormError(null);
      setFieldErrors({});
      toast.push(t("memberCreated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["admin", "members"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const updateMutation = useMutation({
    mutationFn: (payload: { id: string; body: Record<string, unknown> }) => api.patch<Member>(`/organizations/current/members/${payload.id}`, payload.body),
    onSuccess: async () => {
      setEditing(null);
      setPendingMemberUpdate(null);
      setEditError(null);
      toast.push(t("memberUpdated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["admin", "members"] });
    },
    onError: (error) => {
      setPendingMemberUpdate(null);
      setEditError(errorMessage(error));
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (member: Member) => api.delete<void>(`/organizations/current/members/${member.id}`),
    onSuccess: async () => {
      setDeleteTarget(null);
      toast.push(t("memberRemoved"), "success");
      await queryClient.invalidateQueries({ queryKey: ["admin", "members"] });
    },
    onError: (error) => {
      setDeleteTarget(null);
      setActionError(`${t("actionFailed")}: ${errorMessage(error)}`);
      toast.push(errorMessage(error), "error");
    },
  });

  const submitCreate = () => {
    setFormError(null);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(form.email.trim())) {
      setFormError(t("emailRequired"));
      return;
    }
    if (form.fullName.trim().length < 2) {
      setFormError(t("nameRequired"));
      return;
    }
    createMutation.mutate({
      email: form.email.trim(),
      full_name: form.fullName.trim(),
      role: form.role,
      ...(form.password ? { password: form.password } : {}),
    });
  };

  const columns: Column<Member>[] = [
    {
      key: "member",
      header: t("fullName"),
      render: (row) => (
        <div style={{ minWidth: 190 }}>
          <div className="primary-cell">{row.full_name}</div>
          <div className="cell-sub mono">{row.email}</div>
          <div className="cell-sub">{t("memberSince")}: {formatDateTime(row.created_at, lang)}</div>
        </div>
      ),
    },
    {
      key: "role",
      header: t("role"),
      width: "170px",
      render: (row) => (
        <div className="stack" style={{ gap: 2 }}>
          <Badge tone={row.role === "org_admin" ? "accent" : "neutral"}>{row.role}</Badge>
          <span style={{ fontSize: 10, color: "var(--dim)" }}>{t(roleKey(row.role))}</span>
        </div>
      ),
    },
    {
      key: "status",
      header: t("status"),
      width: "110px",
      render: (row) => <StatusBadge status={row.status} label={row.status === "active" ? t("statusActive") : row.status === "suspended" ? t("statusSuspended") : humanize(row.status)} />,
    },
    {
      key: "mfa",
      header: t("mfa"),
      width: "90px",
      render: (row) => <Badge tone={row.mfa_enabled ? "success" : "danger"}>{row.mfa_enabled ? t("mfaEnabled") : t("mfaDisabled")}</Badge>,
    },
    {
      key: "lastLogin",
      header: t("lastLogin"),
      width: "150px",
      render: (row) => (
        <div>
          <div className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.last_login_at, lang)}</div>
          <div className="cell-sub">{row.last_login_at ? relativeTime(row.last_login_at, lang) : "—"}</div>
        </div>
      ),
    },
    {
      key: "actions",
      header: t("common.actions"),
      width: "200px",
      align: "right",
      render: (row) =>
        canManage ? (
          <div className="row wrap" style={{ gap: 3, justifyContent: "flex-end" }}>
            <Button
              size="sm"
              variant="ghost"
              icon={Pencil}
              aria-label={t("editMember")}
              onClick={() => {
                setEditing(row);
                setEditRole(row.role as MemberRole);
                setEditStatus(row.status === "suspended" ? "suspended" : "active");
                setEditError(null);
              }}
              data-testid="member-edit"
            />
            <Button size="sm" variant="ghost" icon={Trash2} aria-label={t("removeMember")} onClick={() => setDeleteTarget(row)} data-testid="member-remove" />
          </div>
        ) : (
          <span className="dim" style={{ fontSize: 10 }}>{t("noPermission")}</span>
        ),
    },
  ];

  return (
    <div className="stack" data-testid="admin-members">
      {actionError ? (
        <div className="notice notice-danger">
          <ShieldAlert size={14} style={{ flex: "0 0 auto" }} />
          <span>{actionError}</span>
          <Button size="sm" variant="ghost" onClick={() => setActionError(null)}>{t("clearActionError")}</Button>
        </div>
      ) : null}
      <div className="notice">{t("permissionsNote")}</div>
      <Card
        title={t("membersTitle")}
        subtitle={t("membersSub")}
        actions={
          canManage ? (
            <Button
              size="sm"
              variant="primary"
              icon={UserPlus}
              onClick={() => {
                setCreateOpen(true);
                setForm(EMPTY_MEMBER_FORM);
                setFormError(null);
                setFieldErrors({});
              }}
              data-testid="member-create-open"
            >
              {t("invite")}
            </Button>
          ) : undefined
        }
        bodyClassName=""
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="row wrap">
            <div style={{ flex: 1, minWidth: 220 }}>
              <SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder={t("membersFilter")} ariaLabel={t("membersFilter")} />
            </div>
            <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("refresh")} onClick={() => void membersQuery.refetch()} />
          </div>
        </div>
        {membersQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(membersQuery.error)} onRetry={() => void membersQuery.refetch()} />
          </div>
        ) : (
          <>
            <div data-testid="member-table">
              <DataTable
                columns={columns}
                rows={membersQuery.data?.items}
                rowKey={(row) => row.id}
                loading={membersQuery.isLoading}
                empty={
                  <EmptyState
                    icon={Users}
                    title={t("noMembers")}
                    description={t("noMembersHint")}
                    action={canManage ? <Button size="sm" onClick={() => setCreateOpen(true)}>{t("invite")}</Button> : undefined}
                  />
                }
              />
            </div>
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={membersQuery.data?.meta} onPage={setPage} />
            </div>
          </>
        )}
      </Card>

      <Card title={t("roleDescriptions")} subtitle={t("membersSub")}>
        <div className="grid-2">
          {ROLES.map((role) => (
            <div className="list-item" key={role} style={{ padding: "7px 0" }}>
              <div>
                <div className="row" style={{ gap: 6 }}>
                  <span className="mono" style={{ fontSize: 10.5, color: "var(--accent)" }}>{role}</span>
                </div>
                <div className="item-sub">{t(roleKey(role))}</div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={t("invite")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={createMutation.isPending}>{t("cancel")}</Button>
            <Button variant="primary" loading={createMutation.isPending} onClick={submitCreate} data-testid="member-create-submit">
              {t("invite")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="form-grid">
            <Field label={t("email")} htmlFor={`${idPrefix}-member-email`} error={fieldErrors.email} required>
              <Input id={`${idPrefix}-member-email`} type="email" value={form.email} maxLength={255} onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))} data-testid="member-email" />
            </Field>
            <Field label={t("fullName")} htmlFor={`${idPrefix}-member-name`} error={fieldErrors.full_name} required>
              <Input id={`${idPrefix}-member-name`} value={form.fullName} maxLength={200} onChange={(event) => setForm((current) => ({ ...current, fullName: event.target.value }))} />
            </Field>
            <Field label={t("role")} htmlFor={`${idPrefix}-member-role`} hint={t(roleKey(form.role))} required>
              <Select id={`${idPrefix}-member-role`} value={form.role} onChange={(event) => setForm((current) => ({ ...current, role: event.target.value as MemberRole }))} data-testid="member-role">
                {ROLES.map((role) => <option key={role} value={role}>{role}</option>)}
              </Select>
            </Field>
            <Field label={t("password")} htmlFor={`${idPrefix}-member-password`} hint={t("passwordHint")} error={fieldErrors.password}>
              <Input id={`${idPrefix}-member-password`} type="password" autoComplete="new-password" value={form.password} onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))} />
            </Field>
          </div>
          <div className="notice" style={{ fontSize: 11 }}>{t("passwordPolicy")}</div>
          {formError ? <ErrorBanner message={formError} /> : null}
        </div>
      </Modal>

      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={t("editMember")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditing(null)} disabled={updateMutation.isPending}>{t("cancel")}</Button>
            <Button
              variant="primary"
              loading={updateMutation.isPending}
              onClick={() => {
                if (!editing) return;
                setEditError(null);
                const changesRole = editing.role !== editRole;
                const suspends = editStatus === "suspended" && editing.status !== "suspended";
                if (changesRole || suspends) {
                  setPendingMemberUpdate({ member: editing, role: editRole, status: editStatus });
                  return;
                }
                updateMutation.mutate({ id: editing.id, body: { role: editRole, status: editStatus } });
              }}
              data-testid="member-edit-submit"
            >
              {t("save")}
            </Button>
          </>
        }
      >
        {editing ? (
          <div className="stack">
            <MetaRows
              items={[
                { label: t("fullName"), value: editing.full_name },
                { label: t("email"), value: editing.email },
                { label: t("role"), value: humanize(editing.role) },
              ]}
            />
            <Field label={t("role")} htmlFor={`${idPrefix}-edit-role`} hint={t(roleKey(editRole))}>
              <Select id={`${idPrefix}-edit-role`} value={editRole} onChange={(event) => setEditRole(event.target.value as MemberRole)}>
                {ROLES.map((role) => <option key={role} value={role}>{role}</option>)}
              </Select>
            </Field>
            <Field label={t("status")} htmlFor={`${idPrefix}-edit-status`}>
              <Select id={`${idPrefix}-edit-status`} value={editStatus} onChange={(event) => setEditStatus(event.target.value as "active" | "suspended")}>
                <option value="active">{t("statusActive")}</option>
                <option value="suspended">{t("statusSuspended")}</option>
              </Select>
            </Field>
            <div className="notice notice-warning" style={{ fontSize: 11 }}>{t("lastAdminGuard")} {t("selfGuard")}</div>
            {editError ? <ErrorBanner message={editError} /> : null}
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={pendingMemberUpdate !== null}
        onClose={() => setPendingMemberUpdate(null)}
        onConfirm={() => {
          if (!pendingMemberUpdate) return;
          updateMutation.mutate({
            id: pendingMemberUpdate.member.id,
            body: { role: pendingMemberUpdate.role, status: pendingMemberUpdate.status },
          });
        }}
        title={t("editMember")}
        description={
          pendingMemberUpdate
            ? `${pendingMemberUpdate.member.email} · ${pendingMemberUpdate.member.role} → ${pendingMemberUpdate.role} · ${pendingMemberUpdate.status}`
            : undefined
        }
        warning={`${t("removeMemberWarning")} ${t("lastAdminGuard")}`}
        confirmLabel={t("save")}
        cancelLabel={t("cancel")}
        busy={updateMutation.isPending}
        testId="member-role-confirm"
      />

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => { if (deleteTarget) deleteMutation.mutate(deleteTarget); }}
        title={t("removeMember")}
        description={deleteTarget ? `${deleteTarget.full_name} · ${deleteTarget.email}` : undefined}
        warning={`${t("removeMemberWarning")} ${t("lastAdminGuard")}`}
        confirmLabel={t("remove")}
        cancelLabel={t("cancel")}
        busy={deleteMutation.isPending}
        testId="member-remove-confirm"
      />
    </div>
  );
}

/* ---------------------------------------------------------------- policies */

function PoliciesTab({ canWrite }: { canWrite: boolean }) {
  const t = useGovernCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [kindFilter, setKindFilter] = useState("");
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Policy | null>(null);
  const [form, setForm] = useState<PolicyFormState>(EMPTY_POLICY_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const policiesQuery = useQuery({
    queryKey: ["admin", "policies"],
    queryFn: () => api.get<Policy[]>("/organizations/current/policies"),
  });

  const definitionParsed = parseJsonRecord(form.definitionText);

  const openCreate = () => {
    setEditing(null);
    setForm({ ...EMPTY_POLICY_FORM });
    setFormError(null);
    setFieldErrors({});
    setFormOpen(true);
  };

  const openEdit = (policy: Policy) => {
    setEditing(policy);
    setForm({
      name: policy.name,
      kind: policy.kind as PolicyKind,
      description: policy.description ?? "",
      enabled: policy.enabled,
      definitionText: JSON.stringify(policy.definition ?? {}, null, 2),
    });
    setFormError(null);
    setFieldErrors({});
    setFormOpen(true);
  };

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<Policy>("/organizations/current/policies", body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(t("policyCreated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["admin", "policies"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const updateMutation = useMutation({
    mutationFn: (payload: { id: string; body: Record<string, unknown> }) => api.patch<Policy>(`/organizations/current/policies/${payload.id}`, payload.body),
    onSuccess: async () => {
      setFormOpen(false);
      toast.push(t("policyUpdated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["admin", "policies"] });
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const toggleMutation = useMutation({
    mutationFn: (policy: Policy) => api.patch<Policy>(`/organizations/current/policies/${policy.id}`, { enabled: !policy.enabled }),
    onSuccess: async () => {
      toast.push(t("policyUpdated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["admin", "policies"] });
    },
    onError: (error) => toast.push(errorMessage(error), "error"),
  });

  const submit = () => {
    setFormError(null);
    if (form.name.trim().length < 2) {
      setFormError(t("policyName"));
      return;
    }
    if (!definitionParsed.ok) {
      setFormError(t("invalidDefinition"));
      return;
    }
    if (editing) {
      updateMutation.mutate({
        id: editing.id,
        body: {
          definition: definitionParsed.value,
          description: form.description.trim() || null,
          enabled: form.enabled,
        },
      });
    } else {
      createMutation.mutate({
        name: form.name.trim(),
        kind: form.kind,
        definition: definitionParsed.value,
        description: form.description.trim() || null,
        enabled: form.enabled,
      });
    }
  };

  const policies = (policiesQuery.data ?? []).filter((policy) => !kindFilter || policy.kind === kindFilter);

  const columns: Column<Policy>[] = [
    {
      key: "name",
      header: t("policyName"),
      render: (row) => (
        <div style={{ minWidth: 210 }}>
          <div className="row wrap" style={{ gap: 6 }}>
            <span className="primary-cell">{row.name}</span>
            <Badge tone="neutral">{policyKindLabel(row.kind, t)}</Badge>
            <Badge tone={row.enabled ? "success" : "neutral"}>{row.enabled ? t("enabled") : t("enabledOff")}</Badge>
          </div>
          <div className="cell-sub">{row.description ?? "—"}</div>
          <div className="cell-sub mono">v{row.version} · {row.org_id === null ? t("scopeGlobal") : t("scopeOrganization")}</div>
        </div>
      ),
    },
    {
      key: "version",
      header: t("version"),
      width: "90px",
      align: "right",
      render: (row) => <span className="mono">v{row.version}</span>,
    },
    {
      key: "updated",
      header: t("updated"),
      width: "150px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.updated_at, lang)}</span>,
    },
    {
      key: "actions",
      header: t("common.actions"),
      width: "230px",
      align: "right",
      render: (row) =>
        canWrite ? (
          <div className="row wrap" style={{ gap: 3, justifyContent: "flex-end" }}>
            <Button size="sm" variant="ghost" icon={Pencil} aria-label={t("editPolicy")} onClick={() => openEdit(row)} data-testid="policy-edit" />
            <Button
              size="sm"
              variant="ghost"
              icon={Power}
              aria-label={row.enabled ? t("enabledOff") : t("enabled")}
              loading={toggleMutation.isPending}
              onClick={() => toggleMutation.mutate(row)}
              data-testid="policy-toggle"
            >
              {row.enabled ? t("enabledOff") : t("enabled")}
            </Button>
          </div>
        ) : (
          <span className="dim" style={{ fontSize: 10 }}>{t("noPermission")}</span>
        ),
    },
  ];

  return (
    <div className="stack" data-testid="admin-policies">
      <Card
        title={t("policiesTitle")}
        subtitle={t("policiesSub")}
        actions={
          <div className="row wrap" style={{ gap: 6 }}>
            <Select value={kindFilter} onChange={(event) => setKindFilter(event.target.value)} aria-label={t("policyKind")} style={{ width: 160 }} data-testid="policy-kind-filter">
              <option value="">{t("all")}</option>
              {POLICY_KINDS.map((kind) => <option key={kind} value={kind}>{policyKindLabel(kind, t)}</option>)}
            </Select>
            {canWrite ? (
              <Button size="sm" variant="primary" icon={Plus} onClick={openCreate} data-testid="policy-create-open">{t("newPolicy")}</Button>
            ) : null}
            <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("refresh")} onClick={() => void policiesQuery.refetch()} />
          </div>
        }
        bodyClassName=""
      >
        {policiesQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(policiesQuery.error)} onRetry={() => void policiesQuery.refetch()} />
          </div>
        ) : (
          <div data-testid="policy-table">
            <DataTable
              columns={columns}
              rows={policiesQuery.isLoading ? undefined : policies}
              rowKey={(row) => row.id}
              loading={policiesQuery.isLoading}
              empty={<EmptyState icon={FileCode2} title={t("noPolicies")} description={t("noPoliciesHint")} action={canWrite ? <Button size="sm" onClick={openCreate}>{t("newPolicy")}</Button> : undefined} />}
            />
          </div>
        )}
      </Card>

      <div className="grid-2">
        {POLICY_KINDS.map((kind) => (
          <div className="card card-pad stack" key={kind} style={{ gap: 3 }}>
            <div className="row" style={{ gap: 6 }}>
              <ClipboardList size={13} style={{ color: "var(--accent)" }} />
              <span className="primary-cell">{policyKindLabel(kind, t)}</span>
            </div>
            <span style={{ fontSize: 11.5, color: "var(--muted)" }}>{policyKindHint(kind, t)}</span>
          </div>
        ))}
      </div>

      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={editing ? t("editPolicy") : t("newPolicy")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setFormOpen(false)} disabled={createMutation.isPending || updateMutation.isPending}>{t("cancel")}</Button>
            <Button variant="primary" loading={createMutation.isPending || updateMutation.isPending} onClick={submit} data-testid="policy-submit">
              {editing ? t("save") : t("create")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="notice">{t("versionNote")}</div>
          <div className="form-grid">
            <Field label={t("policyName")} htmlFor={`${idPrefix}-policy-name`} error={fieldErrors.name} required>
              <Input id={`${idPrefix}-policy-name`} value={form.name} maxLength={120} disabled={editing !== null} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} />
            </Field>
            <Field label={t("policyKind")} htmlFor={`${idPrefix}-policy-kind`} hint={policyKindHint(form.kind, t)}>
              <Select id={`${idPrefix}-policy-kind`} value={form.kind} disabled={editing !== null} onChange={(event) => setForm((current) => ({ ...current, kind: event.target.value as PolicyKind }))}>
                {POLICY_KINDS.map((kind) => <option key={kind} value={kind}>{policyKindLabel(kind, t)}</option>)}
              </Select>
            </Field>
            <div className="span-2">
              <Field label={t("description")} htmlFor={`${idPrefix}-policy-desc`} error={fieldErrors.description}>
                <Textarea id={`${idPrefix}-policy-desc`} rows={2} maxLength={2000} value={form.description} onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))} />
              </Field>
            </div>
            <div className="span-2">
              <JsonEditor
                id={`${idPrefix}-policy-def`}
                label={t("definition")}
                value={form.definitionText}
                onChange={(value) => setForm((current) => ({ ...current, definitionText: value }))}
                hint={t("definitionHint")}
                error={!definitionParsed.ok ? t("invalidDefinition") : fieldErrors.definition}
                rows={10}
                testId="policy-definition"
              />
            </div>
            <label className="checkbox">
              <input type="checkbox" checked={form.enabled} onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))} />
              {t("enabled")}
            </label>
          </div>
          {formError ? <ErrorBanner message={formError} /> : null}
        </div>
      </Modal>
    </div>
  );
}

/* ------------------------------------------------------------ kill switches */

function KillSwitchesTab({ canOperate, isPlatformAdmin }: { canOperate: boolean; isPlatformAdmin: boolean }) {
  const t = useGovernCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const { can } = useAuth();
  const [formOpen, setFormOpen] = useState(false);
  const [scope, setScope] = useState<KillScope>("organization");
  const [targetId, setTargetId] = useState("");
  const [reason, setReason] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [pendingEngage, setPendingEngage] = useState<{ scope: KillScope; target: string | null; reason: string } | null>(null);
  const [releaseTarget, setReleaseTarget] = useState<KillSwitch | null>(null);

  const switchesQuery = useQuery({
    queryKey: ["admin", "kill-switches"],
    queryFn: () => api.get<KillSwitch[]>("/organizations/current/kill-switches"),
  });

  const canReadConnectors = can("connector:read");
  const connectorsQuery = useQuery({
    queryKey: ["admin", "kill-switches", "connectors"],
    queryFn: () => api.get<Page<ConnectorOption>>("/connectors", { page: 1, page_size: 200 }),
    enabled: formOpen && canReadConnectors,
  });

  const engageMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<KillSwitch>("/organizations/current/kill-switches", body),
    onSuccess: async () => {
      setPendingEngage(null);
      setFormOpen(false);
      setReason("");
      setTargetId("");
      setScope("organization");
      toast.push(t("killEngaged"), "success");
      await queryClient.invalidateQueries({ queryKey: ["admin", "kill-switches"] });
    },
    onError: (error) => {
      setPendingEngage(null);
      setFormError(errorMessage(error));
    },
  });

  const releaseMutation = useMutation({
    mutationFn: (sw: KillSwitch) => api.post<KillSwitch>(`/organizations/current/kill-switches/${sw.id}/release`),
    onSuccess: async () => {
      setReleaseTarget(null);
      toast.push(t("killReleased"), "success");
      await queryClient.invalidateQueries({ queryKey: ["admin", "kill-switches"] });
    },
    onError: (error) => {
      setReleaseTarget(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const switches = switchesQuery.data ?? [];
  const effective = switches.filter((sw) => sw.engaged);

  const requestEngage = () => {
    setFormError(null);
    if (scope === "global" && !isPlatformAdmin) {
      setFormError(t("globalOnlyAdmin"));
      return;
    }
    if ((scope === "connector" || scope === "autonomy") && !targetId) {
      setFormError(t("targetRequired"));
      return;
    }
    if (reason.trim().length < 5) {
      setFormError(t("reasonRequired"));
      return;
    }
    setPendingEngage({
      scope,
      target: scope === "organization" || scope === "global" ? null : targetId,
      reason: reason.trim(),
    });
  };

  const columns: Column<KillSwitch>[] = [
    {
      key: "scope",
      header: t("scope"),
      width: "160px",
      render: (row) => (
        <div className="stack" style={{ gap: 2 }}>
          <Badge tone={row.scope === "global" ? "critical" : row.scope === "autonomy" ? "danger" : "warning"}>{killScopeLabel(row.scope, t)}</Badge>
          {row.target_id ? <span className="cell-sub mono">{row.target_id}</span> : null}
        </div>
      ),
    },
    {
      key: "status",
      header: t("status"),
      width: "110px",
      render: (row) => <Badge tone={row.engaged ? "danger" : "neutral"}>{row.engaged ? t("engaged") : t("released")}</Badge>,
    },
    {
      key: "reason",
      header: t("reason"),
      render: (row) => (
        <div style={{ minWidth: 180 }}>
          <div style={{ fontSize: 11.5 }}>{row.reason}</div>
          <div className="cell-sub">{row.engaged_by ?? "—"} · {formatDateTime(row.engaged_at, lang)}</div>
          {row.released_at ? <div className="cell-sub">{row.released_by} · {formatDateTime(row.released_at, lang)}</div> : null}
        </div>
      ),
    },
    {
      key: "actions",
      header: t("common.actions"),
      width: "120px",
      align: "right",
      render: (row) =>
        canOperate && row.engaged ? (
          <Button size="sm" variant="ghost" onClick={() => setReleaseTarget(row)} data-testid="kill-release">
            {t("release")}
          </Button>
        ) : (
          <span className="dim" style={{ fontSize: 10 }}>{row.engaged ? t("engaged") : "—"}</span>
        ),
    },
  ];

  return (
    <div className="stack" data-testid="admin-killswitches">
      <div className="notice notice-danger">
        <AlertOctagon size={14} style={{ flex: "0 0 auto" }} />
        <div>
          <strong>{t("killSub")}</strong>
          <div style={{ marginTop: 2, fontSize: 11.5 }}>{t("killFailClosed")}</div>
        </div>
      </div>

      <Card
        title={t("effectiveSwitches")}
        subtitle={t("killSub")}
        actions={
          canOperate ? (
            <Button
              size="sm"
              variant="danger"
              icon={Ban}
              onClick={() => {
                setFormOpen(true);
                setReason("");
                setTargetId("");
                setScope("organization");
                setFormError(null);
              }}
              data-testid="kill-engage-open"
            >
              {t("engageKill")}
            </Button>
          ) : undefined
        }
      >
        {switchesQuery.isLoading ? (
          <div className="skeleton skeleton-row" />
        ) : effective.length === 0 ? (
          <EmptyState icon={ShieldCheck} title={t("noEffective")} description={t("noEffectiveHint")} />
        ) : (
          <div className="stack">
            {effective.map((sw) => (
              <div className="list-item" key={sw.id}>
                <AlertOctagon size={15} style={{ color: "var(--danger)", flex: "0 0 auto", marginTop: 2 }} />
                <div>
                  <div className="row wrap" style={{ gap: 6 }}>
                    <Badge tone={sw.scope === "global" ? "critical" : "danger"}>{killScopeLabel(sw.scope, t)}</Badge>
                    {sw.target_id ? <span className="tag mono">{sw.target_id}</span> : null}
                    <span className="item-title">{sw.reason}</span>
                  </div>
                  <div className="item-sub">
                    {t("engagedBy")}: {sw.engaged_by ?? "—"} · {formatDateTime(sw.engaged_at, lang)}
                  </div>
                </div>
                <div className="item-side">
                  {canOperate ? <Button size="sm" variant="ghost" onClick={() => setReleaseTarget(sw)}>{t("release")}</Button> : null}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title={t("killAll")} bodyClassName="">
        {switchesQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(switchesQuery.error)} onRetry={() => void switchesQuery.refetch()} />
          </div>
        ) : (
          <div data-testid="killswitch-table">
            <DataTable
              columns={columns}
              rows={switches}
              rowKey={(row) => row.id}
              loading={switchesQuery.isLoading}
              empty={<EmptyState icon={ShieldCheck} title={t("noHistory")} />}
            />
          </div>
        )}
      </Card>

      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={t("engageKill")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setFormOpen(false)} disabled={engageMutation.isPending}>{t("cancel")}</Button>
            <Button variant="danger" onClick={requestEngage} data-testid="kill-engage-submit">{t("engageKill")}</Button>
          </>
        }
      >
        <div className="stack">
          <div className="notice notice-danger">{t("killFailClosed")}</div>
          <Field label={t("scope")} htmlFor={`${idPrefix}-kill-scope`} required>
            <Select
              id={`${idPrefix}-kill-scope`}
              value={scope}
              onChange={(event) => { setScope(event.target.value as KillScope); setTargetId(""); setFormError(null); }}
              data-testid="kill-scope"
            >
              {KILL_SCOPES.map((value) => (
                <option key={value} value={value} disabled={value === "global" && !isPlatformAdmin}>
                  {killScopeLabel(value, t)}
                </option>
              ))}
            </Select>
          </Field>
          {!isPlatformAdmin ? <span className="dim" style={{ fontSize: 11 }}>{t("globalOnlyAdmin")}</span> : null}
          {scope === "connector" ? (
            <Field label={t("target")} htmlFor={`${idPrefix}-kill-target`} hint={t("targetConnector")} required>
              {canReadConnectors ? (
                <Select id={`${idPrefix}-kill-target`} value={targetId} onChange={(event) => setTargetId(event.target.value)} data-testid="kill-target">
                  <option value="">—</option>
                  {(connectorsQuery.data?.items ?? []).map((connector) => (
                    <option key={connector.id} value={connector.id}>{connector.name} ({connector.connector_type})</option>
                  ))}
                </Select>
              ) : (
                <Input id={`${idPrefix}-kill-target`} value={targetId} maxLength={80} onChange={(event) => setTargetId(event.target.value)} className="mono" />
              )}
            </Field>
          ) : null}
          {scope === "autonomy" ? (
            <Field label={t("target")} htmlFor={`${idPrefix}-kill-autonomy`} hint={t("targetAutonomy")} required>
              <Select id={`${idPrefix}-kill-autonomy`} value={targetId} onChange={(event) => setTargetId(event.target.value)} data-testid="kill-target">
                <option value="">—</option>
                {["A0", "A1", "A2", "A3", "A4"].map((level) => <option key={level} value={level}>{level}</option>)}
              </Select>
            </Field>
          ) : null}
          <Field label={t("reason")} htmlFor={`${idPrefix}-kill-reason`} hint={t("reasonHint")} required>
            <Textarea
              id={`${idPrefix}-kill-reason`}
              rows={3}
              maxLength={500}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              data-testid="kill-reason"
            />
          </Field>
          {formError ? <ErrorBanner message={formError} /> : null}
        </div>
      </Modal>

      <ConfirmDialog
        open={pendingEngage !== null}
        onClose={() => setPendingEngage(null)}
        onConfirm={() => {
          if (!pendingEngage) return;
          engageMutation.mutate({
            scope: pendingEngage.scope,
            target_id: pendingEngage.target,
            reason: pendingEngage.reason,
          });
        }}
        title={t("confirmEngage")}
        description={pendingEngage ? `${killScopeLabel(pendingEngage.scope, t)}${pendingEngage.target ? ` · ${pendingEngage.target}` : ""} — ${pendingEngage.reason}` : undefined}
        warning={t("confirmEngageWarning")}
        confirmLabel={t("engageKill")}
        cancelLabel={t("cancel")}
        busy={engageMutation.isPending}
        testId="kill-engage-confirm"
      />

      <ConfirmDialog
        open={releaseTarget !== null}
        onClose={() => setReleaseTarget(null)}
        onConfirm={() => { if (releaseTarget) releaseMutation.mutate(releaseTarget); }}
        title={t("releaseTitle")}
        description={releaseTarget ? `${killScopeLabel(releaseTarget.scope, t)}${releaseTarget.target_id ? ` · ${releaseTarget.target_id}` : ""}` : undefined}
        warning={t("releaseWarning")}
        confirmLabel={t("release")}
        cancelLabel={t("cancel")}
        busy={releaseMutation.isPending}
        testId="kill-release-confirm"
      />
    </div>
  );
}

/* ---------------------------------------------------------------- approvals */

function ApprovalsTab({ canDecide }: { canDecide: boolean }) {
  const t = useGovernCopy(COPY);
  const { lang } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [status, setStatus] = useState("pending");
  const [page, setPage] = useState(1);
  const [detail, setDetail] = useState<Approval | null>(null);
  const [deciding, setDeciding] = useState<{ approval: Approval; decision: "approved" | "rejected" } | null>(null);
  const [decisionReason, setDecisionReason] = useState("");
  const [decisionError, setDecisionError] = useState<string | null>(null);

  const approvalsQuery = useQuery({
    queryKey: ["admin", "approvals", { status, page }],
    queryFn: () =>
      api.get<Page<Approval>>("/organizations/current/approvals", {
        page,
        page_size: 25,
        status: status || undefined,
      }),
  });

  const decideMutation = useMutation({
    mutationFn: (payload: { approval: Approval; decision: "approved" | "rejected"; reason: string }) =>
      api.post<Approval>(`/organizations/current/approvals/${payload.approval.id}/decision`, {
        decision: payload.decision,
        reason: payload.reason,
      }),
    onSuccess: async (_result, payload) => {
      setDeciding(null);
      setDecisionReason("");
      setDecisionError(null);
      toast.push(payload.decision === "approved" ? t("approvalApproved") : t("approvalRejected"), "success");
      await queryClient.invalidateQueries({ queryKey: ["admin", "approvals"] });
    },
    onError: (error) => setDecisionError(errorMessage(error)),
  });

  const columns: Column<Approval>[] = [
    {
      key: "request",
      header: t("requestType"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div className="primary-cell mono" style={{ fontSize: 11.5 }}>{row.request_type}</div>
          <div className="cell-sub">{row.resource_type}{row.resource_id ? ` · ${row.resource_id.slice(0, 10)}` : ""}</div>
          <div className="cell-sub">{t("createdAt")}: {formatDateTime(row.created_at, lang)}</div>
        </div>
      ),
    },
    {
      key: "requestedBy",
      header: t("requestedBy"),
      width: "160px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.requested_by ?? "—"}</span>,
    },
    {
      key: "status",
      header: t("status"),
      width: "110px",
      render: (row) => <StatusBadge status={row.status} label={row.status === "pending" ? t("pending") : row.status === "approved" ? t("approved") : row.status === "rejected" ? t("rejected") : humanize(row.status)} />,
    },
    {
      key: "expires",
      header: t("expiresAt"),
      width: "150px",
      render: (row) => {
        const expired = row.expires_at ? new Date(row.expires_at).getTime() < Date.now() : false;
        return (
          <div>
            <div className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.expires_at, lang)}</div>
            {expired && row.status === "pending" ? <div className="cell-sub" style={{ color: "var(--danger)" }}>{t("expired")}</div> : null}
          </div>
        );
      },
    },
    {
      key: "actions",
      header: t("common.actions"),
      width: "210px",
      align: "right",
      render: (row) => {
        const expired = row.expires_at ? new Date(row.expires_at).getTime() < Date.now() : false;
        const actionable = canDecide && row.status === "pending" && !expired;
        return (
          <div className="row wrap" style={{ gap: 3, justifyContent: "flex-end" }}>
            <Button size="sm" variant="ghost" onClick={() => setDetail(row)} data-testid="approval-detail">
              {t("details")}
            </Button>
            {actionable ? (
              <>
                <Button
                  size="sm"
                  variant="primary"
                  icon={Check}
                  onClick={() => { setDeciding({ approval: row, decision: "approved" }); setDecisionReason(""); setDecisionError(null); }}
                  data-testid="approval-approve"
                >
                  {t("approve")}
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  icon={X}
                  onClick={() => { setDeciding({ approval: row, decision: "rejected" }); setDecisionReason(""); setDecisionError(null); }}
                  data-testid="approval-reject"
                >
                  {t("reject")}
                </Button>
              </>
            ) : expired && row.status === "pending" ? (
              <span className="dim" style={{ fontSize: 10 }}>{t("expiredHint")}</span>
            ) : null}
          </div>
        );
      },
    },
  ];

  return (
    <div className="stack" data-testid="admin-approvals">
      <div className="notice notice-accent">
        <ShieldCheck size={14} style={{ flex: "0 0 auto" }} />
        <span>{t("approvalsSub")}</span>
      </div>
      <Card
        title={t("approvalsTitle")}
        subtitle={t("approvalsSub")}
        actions={
          <div className="row" style={{ gap: 6 }}>
            <Select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1); }} aria-label={t("filterStatus")} style={{ width: 150 }} data-testid="approval-status-filter">
              <option value="">{t("all")}</option>
              <option value="pending">{t("pending")}</option>
              <option value="approved">{t("approved")}</option>
              <option value="rejected">{t("rejected")}</option>
              <option value="expired">{t("expired")}</option>
            </Select>
            <Button size="sm" variant="ghost" icon={RefreshCw} aria-label={t("refresh")} onClick={() => void approvalsQuery.refetch()} />
          </div>
        }
        bodyClassName=""
      >
        {approvalsQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={errorMessage(approvalsQuery.error)} onRetry={() => void approvalsQuery.refetch()} />
          </div>
        ) : (
          <>
            <div data-testid="approval-table">
              <DataTable
                columns={columns}
                rows={approvalsQuery.data?.items}
                rowKey={(row) => row.id}
                loading={approvalsQuery.isLoading}
                empty={<EmptyState icon={ShieldCheck} title={t("noApprovals")} description={t("noApprovalsHint")} />}
              />
            </div>
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={approvalsQuery.data?.meta} onPage={setPage} />
            </div>
          </>
        )}
      </Card>

      <Modal open={detail !== null} onClose={() => setDetail(null)} title={t("details")} size="lg" footer={<Button onClick={() => setDetail(null)}>{t("close")}</Button>}>
        {detail ? (
          <div className="stack">
            <div className="row wrap">
              <StatusBadge status={detail.status} />
              <Badge tone="neutral">{detail.request_type}</Badge>
              <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{detail.id}</span>
            </div>
            <MetaRows
              items={[
                { label: t("requestType"), value: detail.request_type },
                { label: t("resource"), value: `${detail.resource_type}${detail.resource_id ? ` · ${detail.resource_id}` : ""}` },
                { label: t("requestedBy"), value: detail.requested_by ?? "—" },
                { label: t("createdAt"), value: formatDateTime(detail.created_at, lang) },
                { label: t("expiresAt"), value: formatDateTime(detail.expires_at, lang) },
                { label: t("decisionReason"), value: detail.reason ?? "—" },
                { label: t("decidedBy"), value: detail.decided_by ?? "—" },
              ]}
            />
            <PreBlock value={detail.payload} label={t("payload")} />
          </div>
        ) : null}
      </Modal>

      <Modal
        open={deciding !== null}
        onClose={() => setDeciding(null)}
        title={t("decideTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeciding(null)} disabled={decideMutation.isPending}>{t("cancel")}</Button>
            <Button
              variant={deciding?.decision === "rejected" ? "danger" : "primary"}
              loading={decideMutation.isPending}
              disabled={decisionReason.trim().length < 3}
              onClick={() => {
                if (!deciding) return;
                setDecisionError(null);
                decideMutation.mutate({ approval: deciding.approval, decision: deciding.decision, reason: decisionReason.trim() });
              }}
              data-testid="approval-decide-submit"
            >
              {deciding?.decision === "rejected" ? t("reject") : t("approve")}
            </Button>
          </>
        }
      >
        {deciding ? (
          <div className="stack">
            <MetaRows
              items={[
                { label: t("requestType"), value: deciding.approval.request_type },
                { label: t("requestedBy"), value: deciding.approval.requested_by ?? "—" },
                { label: t("decision"), value: deciding.decision === "approved" ? t("approveAction") : t("rejectAction") },
              ]}
            />
            <Field label={t("decisionReason")} htmlFor={`${idPrefix}-decision`} hint={t("decisionHint")} required>
              <Textarea id={`${idPrefix}-decision`} rows={4} maxLength={1000} value={decisionReason} onChange={(event) => setDecisionReason(event.target.value)} data-testid="approval-reason" />
            </Field>
            {decisionError ? <ErrorBanner message={`${t("approvalError")}: ${decisionError}`} /> : null}
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

/* -------------------------------------------------------------------- page */

export function AdminPage() {
  const t = useGovernCopy(COPY);
  const { session, can } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("tab");
  const initial: TabKey = TAB_KEYS.includes(requested as TabKey) ? (requested as TabKey) : "members";
  const [tab, setTab] = useState<TabKey>(initial);

  const canMembers = can("user:read");
  const canManageMembers = can("user:manage");
  const canPolicies = can("policy:read");
  const canWritePolicies = can("policy:write");
  const canKillSwitches = can("defence:read");
  const canOperateKillSwitches = can("killswitch:operate");
  const canApprovals = can("approval:read");
  const canDecideApprovals = can("approval:decide");
  const canTokens = can("apikey:manage");
  const isPlatformAdmin = session?.user.is_platform_admin ?? false;

  const tabs = useMemo(() => {
    const items: { key: TabKey; label: string }[] = [];
    if (canMembers) items.push({ key: "members", label: t("tabMembers") });
    if (canPolicies) items.push({ key: "policies", label: t("tabPolicies") });
    if (canKillSwitches) items.push({ key: "killswitches", label: t("tabKill") });
    if (canApprovals) items.push({ key: "approvals", label: t("tabApprovals") });
    if (canTokens) items.push({ key: "tokens", label: t("tabTokens") });
    items.push({ key: "security", label: t("tabSecurity") });
    return items;
  }, [canMembers, canPolicies, canKillSwitches, canApprovals, canTokens, t]);

  const active = tabs.some((item) => item.key === tab) ? tab : tabs[0]?.key ?? "security";

  const changeTab = (next: TabKey) => {
    setTab(next);
    setSearchParams({ tab: next }, { replace: true });
  };

  return (
    <div className="animate-in" data-testid="page-admin">
      <PageHeader
        eyebrow={t("eyebrow")}
        title={t("title")}
        subtitle={t("subtitle")}
        actions={
          <>
            <Badge tone="accent"><ShieldCheck size={11} /> {session?.organization.name ?? "—"}</Badge>
            {isPlatformAdmin ? <Badge tone="success">{t("scopeGlobal")}</Badge> : null}
            <Badge tone="neutral">{session?.role ?? "—"}</Badge>
          </>
        }
      />

      <div style={{ marginBottom: 12 }}>
        <Tabs<TabKey> ariaLabel={t("title")} items={tabs} value={active} onChange={changeTab} />
      </div>

      {active === "members" && canMembers ? <MembersTab canManage={canManageMembers} /> : null}
      {active === "policies" && canPolicies ? <PoliciesTab canWrite={canWritePolicies} /> : null}
      {active === "killswitches" && canKillSwitches ? <KillSwitchesTab canOperate={canOperateKillSwitches} isPlatformAdmin={isPlatformAdmin} /> : null}
      {active === "approvals" && canApprovals ? <ApprovalsTab canDecide={canDecideApprovals} /> : null}
      {active === "tokens" && canTokens ? (
        <Card title={t("tabTokens")} subtitle={t("permissionsNote")}>
          <ApiTokensPanel />
        </Card>
      ) : null}
      {active === "security" ? <SecurityCards /> : null}

      {active !== "security" && !tabs.some((item) => item.key === active) ? (
        <Card><EmptyState icon={Lock} title={t("noPermission")} /></Card>
      ) : null}

      <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
        <KeyRound size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
        <span>{t("permissionsNote")}</span>
      </div>
    </div>
  );
}

export default AdminPage;
