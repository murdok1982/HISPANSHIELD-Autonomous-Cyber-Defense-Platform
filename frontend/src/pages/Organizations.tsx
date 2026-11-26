import { useId, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowRightLeft,
  Building2,
  Crosshair,
  Globe2,
  Landmark,
  Lock,
  MapPin,
  Pencil,
  Plus,
  RefreshCw,
  ShieldCheck,
  Users,
} from "lucide-react";
import { api, errorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, type Lang } from "../lib/i18n";
import { formatDate, formatDateTime, formatNumber, humanize } from "../lib/format";
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
  useToast,
} from "../components/ui";
import {
  ConfirmDialog,
  MetaRows,
  apiFieldErrors,
  slugify,
  useGovernCopy,
} from "../components/features/govern/common";

/* --------------------------------------------------------------- contracts */

interface Organization {
  id: string;
  slug: string;
  name: string;
  kind: string;
  country: string;
  sector: string;
  tier: string;
  autonomy_level: string;
  status: string;
  settings: Record<string, unknown>;
  is_demo: boolean;
  created_at: string;
}

type AutonomyLevel = "A0" | "A1" | "A2" | "A3" | "A4";
type OrgKind = "private" | "public" | "critical_infrastructure" | "alliance";
type OrgTier = "standard" | "high" | "critical";
type LevelKey = AutonomyLevel;

const AUTONOMY_LEVELS: AutonomyLevel[] = ["A0", "A1", "A2", "A3", "A4"];
const ORG_KINDS: OrgKind[] = ["private", "public", "critical_infrastructure", "alliance"];
const ORG_TIERS: OrgTier[] = ["standard", "high", "critical"];

interface OrgFormState {
  name: string;
  slug: string;
  kind: OrgKind;
  country: string;
  sector: string;
  tier: OrgTier;
  autonomy: AutonomyLevel;
}

const EMPTY_ORG_FORM: OrgFormState = {
  name: "",
  slug: "",
  kind: "private",
  country: "ES",
  sector: "general",
  tier: "standard",
  autonomy: "A1",
};

/* -------------------------------------------------------------------- copy */

const COPY: Record<Lang, Record<string, string>> = {
  es: {
    eyebrow: "Gobierno · Organizaciones",
    title: "Organizaciones y aislamiento multi-tenant",
    subtitle: "Perfil de cada organización visible, cambio de ámbito y nivel de autonomía gobernado.",
    isolationTitle: "Aislamiento de tenant",
    isolation:
      "Cada consulta se ejecuta con el ámbito de la organización activa. Cambiar de organización reajusta todos los datos, permisos y evidencias; ningún dato de otro tenant es accesible desde esta sesión.",
    switchWarning:
      "Al cambiar de organización se recarga la sesión completa y todas las vistas se reajustan al nuevo tenant. Los datos no se fusionan entre organizaciones.",
    switchConfirm: "Cambiar organización",
    createOrg: "Crear organización",
    createOrgHint: "Solo administradores de plataforma. El slug es estable y se usa en el login.",
    editCurrent: "Editar organización activa",
    visibleOrgs: "Organizaciones visibles",
    currentRole: "Rol en la organización activa",
    currentAutonomy: "Autonomía activa",
    tenants: "Tenants",
    current: "Actual",
    switch: "Cambiar",
    detail: "Perfil",
    role: "Rol",
    kind: "Tipo",
    country: "País",
    sector: "Sector",
    tier: "Nivel de criticidad",
    autonomy: "Autonomía",
    status: "Estado",
    demo: "DEMO",
    demoTooltip: "Organización de demostración: los datos no representan telemetría real.",
    createdAt: "Creada",
    noOrgs: "Sin organizaciones visibles",
    noOrgsHint: "Tu cuenta no tiene membresías activas o no hay organizaciones creadas.",
    loadFailed: "No se pudieron cargar las organizaciones.",
    noPermission: "No tienes permiso para ver organizaciones.",
    profile: "Perfil de la organización",
    profileHint: "Datos del tenant y configuración de autonomía.",
    settings: "Ajustes",
    autonomyLevels: "Niveles de autonomía",
    autonomyA0: "A0 · Observar: detecta, alerta y recomienda. Ninguna acción externa.",
    autonomyA1: "A1 · Recomendar: propone la acción con simulación; un humano la ejecuta.",
    autonomyA2: "A2 · Actuar con aprobación: requiere una persona distinta del solicitante.",
    autonomyA3: "A3 · Actuar dentro de política: acciones reversibles con revisión posterior.",
    autonomyA4: "A4 · Alto impacto: doble aprobación y ventana temporal limitada.",
    autonomyWarning:
      "Subir la autonomía amplía las acciones que la plataforma puede ejecutar. El cambio se audita y la política se reevalúa en el servidor.",
    changeAutonomyConfirm: "Confirmar cambio de autonomía",
    autonomyBlast: "Esta organización pasará de {from} a {to}. Las acciones admitidas por la nueva política podrán ejecutarse según el nivel y sus aprobaciones.",
    save: "Guardar",
    cancel: "Cancelar",
    close: "Cerrar",
    name: "Nombre",
    slug: "Slug",
    nameRequired: "El nombre debe tener al menos 2 caracteres.",
    slugInvalid: "El slug debe tener 2–80 caracteres en minúsculas, números y guiones.",
    countryInvalid: "El país debe ser un código ISO de 2 letras.",
    created: "Organización creada",
    updated: "Organización actualizada",
    switched: "Cambiando de organización…",
    switchError: "No se pudo cambiar de organización.",
    currentOrg: "Organización activa",
    memberSince: "Miembro",
    allOrgsHint: "Los administradores de plataforma ven todas las organizaciones.",
    membersLink: "Gestionar miembros",
    policiesLink: "Ver políticas",
    demoNotice: "Organización de demostración: los datos sembrados no son telemetría operativa.",
    scopeNote: "Las credenciales, evidencias y auditoría están particionadas por organización.",
    refresh: "Actualizar",
    tierStandard: "Estándar",
    tierHigh: "Alta",
    tierCritical: "Crítica",
    kindPrivate: "Privada",
    kindPublic: "Pública",
    kindCritical: "Infraestructura crítica",
    kindAlliance: "Alianza",
    noPlatformAdmin: "Solo un administrador de plataforma puede crear organizaciones.",
  },
  en: {
    eyebrow: "Governance · Organizations",
    title: "Organizations and multi-tenant isolation",
    subtitle: "Every visible organization profile, scoped switching and governed autonomy level.",
    isolationTitle: "Tenant isolation",
    isolation:
      "Every query runs with the active organization scope. Switching organization re-scopes all data, permissions and evidence; no other tenant data is reachable from this session.",
    switchWarning:
      "Switching organization reloads the full session and re-scopes every view to the new tenant. Data is never merged across organizations.",
    switchConfirm: "Switch organization",
    createOrg: "Create organization",
    createOrgHint: "Platform administrators only. The slug is stable and used at sign-in.",
    editCurrent: "Edit active organization",
    visibleOrgs: "Visible organizations",
    currentRole: "Role in the active organization",
    currentAutonomy: "Active autonomy",
    tenants: "Tenants",
    current: "Current",
    switch: "Switch",
    detail: "Profile",
    role: "Role",
    kind: "Type",
    country: "Country",
    sector: "Sector",
    tier: "Criticality tier",
    autonomy: "Autonomy",
    status: "Status",
    demo: "DEMO",
    demoTooltip: "Demonstration organization: data does not represent live telemetry.",
    createdAt: "Created",
    noOrgs: "No visible organizations",
    noOrgsHint: "Your account has no active memberships or no organizations exist yet.",
    loadFailed: "Organizations could not be loaded.",
    noPermission: "You do not have permission to view organizations.",
    profile: "Organization profile",
    profileHint: "Tenant data and autonomy configuration.",
    settings: "Settings",
    autonomyLevels: "Autonomy levels",
    autonomyA0: "A0 · Observe: detect, alert and recommend. No external action.",
    autonomyA1: "A1 · Recommend: proposes the action with simulation; a human executes it.",
    autonomyA2: "A2 · Act with approval: requires a person other than the requester.",
    autonomyA3: "A3 · Act within policy: reversible actions with post-review.",
    autonomyA4: "A4 · High impact: double approval and a time-boxed window.",
    autonomyWarning:
      "Raising autonomy expands the actions the platform may execute. The change is audited and the policy is re-evaluated server-side.",
    changeAutonomyConfirm: "Confirm autonomy change",
    autonomyBlast: "This organization will move from {from} to {to}. Actions allowed by the new policy may execute according to the level and its approvals.",
    save: "Save",
    cancel: "Cancel",
    close: "Close",
    name: "Name",
    slug: "Slug",
    nameRequired: "Name must be at least 2 characters.",
    slugInvalid: "Slug must be 2–80 characters using lowercase letters, digits and hyphens.",
    countryInvalid: "Country must be a 2-letter ISO code.",
    created: "Organization created",
    updated: "Organization updated",
    switched: "Switching organization…",
    switchError: "The organization could not be switched.",
    currentOrg: "Active organization",
    memberSince: "Member",
    allOrgsHint: "Platform administrators see every organization.",
    membersLink: "Manage members",
    policiesLink: "View policies",
    demoNotice: "Demonstration organization: seeded data is not operational telemetry.",
    scopeNote: "Credentials, evidence and audit records are partitioned per organization.",
    refresh: "Refresh",
    tierStandard: "Standard",
    tierHigh: "High",
    tierCritical: "Critical",
    kindPrivate: "Private",
    kindPublic: "Public",
    kindCritical: "Critical infrastructure",
    kindAlliance: "Alliance",
    noPlatformAdmin: "Only a platform administrator can create organizations.",
  },
};

function kindLabel(kind: string, t: (key: string) => string): string {
  if (kind === "private") return t("kindPrivate");
  if (kind === "public") return t("kindPublic");
  if (kind === "critical_infrastructure") return t("kindCritical");
  if (kind === "alliance") return t("kindAlliance");
  return humanize(kind);
}

function tierLabel(tier: string, t: (key: string) => string): string {
  if (tier === "standard") return t("tierStandard");
  if (tier === "high") return t("tierHigh");
  if (tier === "critical") return t("tierCritical");
  return humanize(tier);
}

function autonomyDescription(level: string, t: (key: string) => string): string {
  if (level === "A0") return t("autonomyA0");
  if (level === "A1") return t("autonomyA1");
  if (level === "A2") return t("autonomyA2");
  if (level === "A3") return t("autonomyA3");
  if (level === "A4") return t("autonomyA4");
  return level;
}

function autonomyTone(level: string): "success" | "accent" | "warning" | "danger" | "critical" {
  if (level === "A0") return "success";
  if (level === "A1") return "accent";
  if (level === "A2") return "warning";
  if (level === "A3") return "danger";
  return "critical";
}

/* -------------------------------------------------------------------- page */

export function OrganizationsPage() {
  const t = useGovernCopy(COPY);
  const { lang } = useI18n();
  const { session, can, switchOrganization, refresh } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState<OrgFormState>(EMPTY_ORG_FORM);
  const [slugEdited, setSlugEdited] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createFieldErrors, setCreateFieldErrors] = useState<Record<string, string>>({});
  const [switchTarget, setSwitchTarget] = useState<Organization | null>(null);
  const [switching, setSwitching] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState<OrgFormState>(EMPTY_ORG_FORM);
  const [editError, setEditError] = useState<string | null>(null);
  const [editFieldErrors, setEditFieldErrors] = useState<Record<string, string>>({});
  const [pendingAutonomy, setPendingAutonomy] = useState<{ from: string; to: LevelKey } | null>(null);

  const canRead = can("org:read");
  const canWrite = can("org:write");
  const isPlatformAdmin = session?.user.is_platform_admin ?? false;

  const orgsQuery = useQuery({
    queryKey: ["organizations", "list"],
    queryFn: () => api.get<Organization[]>("/organizations"),
    enabled: canRead,
  });

  const detailQuery = useQuery({
    queryKey: ["organizations", "detail", selectedId],
    queryFn: () => api.get<Organization>(`/organizations/${selectedId}`),
    enabled: selectedId !== null && (isPlatformAdmin || selectedId === session?.organization.id),
  });

  const roleByOrg = useMemo(() => {
    const map = new Map<string, string | null>();
    for (const org of session?.organizations ?? []) map.set(org.id, org.role);
    return map;
  }, [session]);

  const organizations = orgsQuery.data ?? [];
  const selected = organizations.find((org) => org.id === selectedId) ?? null;
  const profile = detailQuery.data ?? selected;
  const currentOrgId = session?.organization.id;

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<Organization>("/organizations", body),
    onSuccess: async () => {
      setCreateOpen(false);
      setCreateForm(EMPTY_ORG_FORM);
      setSlugEdited(false);
      toast.push(t("created"), "success");
      await queryClient.invalidateQueries({ queryKey: ["organizations"] });
    },
    onError: (error) => {
      setCreateError(errorMessage(error));
      setCreateFieldErrors(apiFieldErrors(error));
    },
  });

  const updateMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.patch<Organization>("/organizations/current", body),
    onSuccess: async () => {
      setEditOpen(false);
      setPendingAutonomy(null);
      toast.push(t("updated"), "success");
      await queryClient.invalidateQueries({ queryKey: ["organizations"] });
      await refresh();
    },
    onError: (error) => {
      setPendingAutonomy(null);
      setEditError(errorMessage(error));
      setEditFieldErrors(apiFieldErrors(error));
    },
  });

  const openEdit = (org: Organization) => {
    setEditForm({
      name: org.name,
      slug: org.slug,
      kind: org.kind as OrgKind,
      country: org.country,
      sector: org.sector,
      tier: org.tier as OrgTier,
      autonomy: org.autonomy_level as AutonomyLevel,
    });
    setEditError(null);
    setEditFieldErrors({});
    setEditOpen(true);
  };

  const validateCreate = (): string | null => {
    if (createForm.name.trim().length < 2) return t("nameRequired");
    if (!/^[a-z0-9](?:[a-z0-9-]{1,78}[a-z0-9])?$/.test(createForm.slug)) return t("slugInvalid");
    if (!/^[A-Za-z]{2}$/.test(createForm.country)) return t("countryInvalid");
    return null;
  };

  const validateEdit = (): string | null => {
    if (editForm.name.trim().length < 2) return t("nameRequired");
    if (!/^[A-Za-z]{2}$/.test(editForm.country)) return t("countryInvalid");
    return null;
  };

  const submitEdit = () => {
    setEditError(null);
    const invalid = validateEdit();
    if (invalid) {
      setEditError(invalid);
      return;
    }
    const current = organizations.find((org) => org.id === currentOrgId);
    if (current && editForm.autonomy !== current.autonomy_level) {
      setPendingAutonomy({ from: current.autonomy_level, to: editForm.autonomy });
      return;
    }
    updateMutation.mutate({
      name: editForm.name.trim(),
      kind: editForm.kind,
      country: editForm.country.toUpperCase(),
      sector: editForm.sector.trim() || "general",
      tier: editForm.tier,
      autonomy_level: editForm.autonomy,
    });
  };

  const confirmSwitch = async () => {
    if (!switchTarget) return;
    setSwitching(true);
    try {
      await switchOrganization(switchTarget.id);
    } catch (error) {
      setSwitching(false);
      setSwitchTarget(null);
      toast.push(`${t("switchError")} ${errorMessage(error)}`, "error");
    }
  };

  if (!canRead) {
    return (
      <div className="animate-in" data-testid="page-organizations">
        <PageHeader eyebrow={t("eyebrow")} title={t("title")} subtitle={t("subtitle")} />
        <Card><EmptyState icon={Lock} title={t("noPermission")} /></Card>
      </div>
    );
  }

  if (orgsQuery.isLoading) return <PageSkeleton />;

  return (
    <div className="animate-in" data-testid="page-organizations">
      <PageHeader
        eyebrow={t("eyebrow")}
        title={t("title")}
        subtitle={t("subtitle")}
        actions={
          <>
            <Badge tone="accent"><ShieldCheck size={11} /> {session?.organization.name ?? "—"}</Badge>
            <Badge tone={autonomyTone(session?.autonomy_level ?? "A0")}>{t("autonomy")} {session?.autonomy_level ?? "—"}</Badge>
            {isPlatformAdmin && canWrite ? (
              <Button
                variant="primary"
                icon={Plus}
                onClick={() => {
                  setCreateOpen(true);
                  setCreateForm(EMPTY_ORG_FORM);
                  setSlugEdited(false);
                  setCreateError(null);
                  setCreateFieldErrors({});
                }}
                data-testid="org-create-open"
              >
                {t("createOrg")}
              </Button>
            ) : null}
            <Button variant="ghost" icon={RefreshCw} aria-label={t("refresh")} onClick={() => void orgsQuery.refetch()} />
          </>
        }
      />

      <div className="notice notice-accent" style={{ marginBottom: 12 }} data-testid="org-isolation">
        <Globe2 size={14} style={{ flex: "0 0 auto" }} />
        <div>
          <strong>{t("isolationTitle")}</strong>
          <div style={{ marginTop: 2, fontSize: 11.5 }}>{t("isolation")}</div>
        </div>
      </div>

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <div className="card kpi">
          <div className="kpi-label"><Building2 size={13} style={{ color: "var(--accent)" }} />{t("visibleOrgs")}</div>
          <div className="kpi-value">{formatNumber(organizations.length)}</div>
          <div className="kpi-foot">{isPlatformAdmin ? t("allOrgsHint") : t("scopeNote")}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label"><Users size={13} style={{ color: "var(--muted)" }} />{t("currentRole")}</div>
          <div className="kpi-value" style={{ fontSize: 15 }}>{session?.role ?? "—"}</div>
          <div className="kpi-foot">{session?.user.email}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label"><Crosshair size={13} style={{ color: "var(--warning)" }} />{t("currentAutonomy")}</div>
          <div className="kpi-value kpi-warning">{session?.autonomy_level ?? "—"}</div>
          <div className="kpi-foot">{autonomyDescription(session?.autonomy_level ?? "A0", t)}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label"><Landmark size={13} style={{ color: "var(--success)" }} />{t("tenants")}</div>
          <div className="kpi-value kpi-success">{formatNumber(session?.organizations.length ?? 0)}</div>
          <div className="kpi-foot">{t("memberSince")}: {formatDate(session?.user.created_at, lang)}</div>
        </div>
      </div>

      {orgsQuery.isError ? (
        <ErrorBanner message={`${t("loadFailed")} ${errorMessage(orgsQuery.error)}`} onRetry={() => void orgsQuery.refetch()} />
      ) : organizations.length === 0 ? (
        <Card>
          <EmptyState
            icon={Building2}
            title={t("noOrgs")}
            description={t("noOrgsHint")}
            action={isPlatformAdmin && canWrite ? <Button size="sm" onClick={() => setCreateOpen(true)}>{t("createOrg")}</Button> : undefined}
          />
        </Card>
      ) : (
        <div className="grid-2" data-testid="org-grid">
          {organizations.map((org) => {
            const isCurrent = org.id === currentOrgId;
            return (
              <div className="card card-pad stack" key={org.id} data-testid="org-card">
                <div className="row-between wrap" style={{ alignItems: "flex-start" }}>
                  <div>
                    <div className="row wrap" style={{ gap: 6 }}>
                      <h3 style={{ fontSize: 15 }}>{org.name}</h3>
                      {isCurrent ? <Badge tone="accent">{t("current")}</Badge> : null}
                      {org.is_demo ? <Badge tone="amber">{t("demo")}</Badge> : null}
                    </div>
                    <div className="mono" style={{ fontSize: 10.5, color: "var(--dim)", marginTop: 2 }}>{org.slug}</div>
                  </div>
                  <StatusBadge status={org.status} />
                </div>
                {org.is_demo ? <div className="demo-banner">{t("demoNotice")}</div> : null}
                <div className="chip-row">
                  <Badge tone="neutral"><Building2 size={10} /> {kindLabel(org.kind, t)}</Badge>
                  <Badge tone="neutral">{tierLabel(org.tier, t)}</Badge>
                  <Badge tone={autonomyTone(org.autonomy_level)}>{org.autonomy_level}</Badge>
                  <span className="tag"><MapPin size={10} /> {org.country}</span>
                  <span className="tag">{org.sector}</span>
                  <span className="tag">{t("role")}: {roleByOrg.get(org.id) ?? (isPlatformAdmin ? "platform_admin" : "—")}</span>
                </div>
                <div className="row wrap" style={{ gap: 6 }}>
                  {isCurrent ? (
                    canWrite ? (
                      <Button size="sm" icon={Pencil} onClick={() => openEdit(org)} data-testid="org-edit-current">
                        {t("editCurrent")}
                      </Button>
                    ) : null
                  ) : (
                    <Button size="sm" icon={ArrowRightLeft} onClick={() => setSwitchTarget(org)} data-testid="org-switch">
                      {t("switch")}
                    </Button>
                  )}
                  <Button size="sm" variant="ghost" onClick={() => setSelectedId(org.id)} data-testid="org-detail-open">
                    {t("detail")}
                  </Button>
                  {isCurrent ? (
                    <>
                      <LinkButton to="/admin" size="sm" variant="ghost" icon={Users}>{t("membersLink")}</LinkButton>
                      <LinkButton to="/admin?tab=policies" size="sm" variant="ghost">{t("policiesLink")}</LinkButton>
                    </>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="notice" style={{ marginTop: 12, fontSize: 11 }}>
        <ShieldCheck size={13} style={{ flex: "0 0 auto", color: "var(--success)" }} />
        <span>{t("scopeNote")}</span>
      </div>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={t("createOrg")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={createMutation.isPending}>{t("cancel")}</Button>
            <Button
              variant="primary"
              loading={createMutation.isPending}
              disabled={!isPlatformAdmin}
              onClick={() => {
                setCreateError(null);
                const invalid = validateCreate();
                if (invalid) {
                  setCreateError(invalid);
                  return;
                }
                createMutation.mutate({
                  name: createForm.name.trim(),
                  slug: createForm.slug,
                  kind: createForm.kind,
                  country: createForm.country.toUpperCase(),
                  sector: createForm.sector.trim() || "general",
                  tier: createForm.tier,
                  autonomy_level: createForm.autonomy,
                });
              }}
              data-testid="org-create-submit"
            >
              {t("createOrg")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="notice">{t("createOrgHint")}</div>
          <div className="form-grid">
            <Field label={t("name")} htmlFor={`${idPrefix}-org-name`} error={createFieldErrors.name} required>
              <Input
                id={`${idPrefix}-org-name`}
                value={createForm.name}
                maxLength={200}
                onChange={(event) => {
                  const name = event.target.value;
                  setCreateForm((current) => ({
                    ...current,
                    name,
                    slug: slugEdited ? current.slug : slugify(name),
                  }));
                }}
                data-testid="org-name"
              />
            </Field>
            <Field label={t("slug")} htmlFor={`${idPrefix}-org-slug`} error={createFieldErrors.slug} hint={t("createOrgHint")} required>
              <Input
                id={`${idPrefix}-org-slug`}
                value={createForm.slug}
                maxLength={80}
                className="mono"
                onChange={(event) => {
                  setSlugEdited(true);
                  setCreateForm((current) => ({ ...current, slug: event.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "") }));
                }}
                data-testid="org-slug"
              />
            </Field>
            <Field label={t("kind")} htmlFor={`${idPrefix}-org-kind`}>
              <Select id={`${idPrefix}-org-kind`} value={createForm.kind} onChange={(event) => setCreateForm((current) => ({ ...current, kind: event.target.value as OrgKind }))}>
                {ORG_KINDS.map((kind) => <option key={kind} value={kind}>{kindLabel(kind, t)}</option>)}
              </Select>
            </Field>
            <Field label={t("country")} htmlFor={`${idPrefix}-org-country`} error={createFieldErrors.country} hint="ISO 3166-1 alpha-2">
              <Input
                id={`${idPrefix}-org-country`}
                value={createForm.country}
                maxLength={2}
                onChange={(event) => setCreateForm((current) => ({ ...current, country: event.target.value.toUpperCase().replace(/[^A-Z]/g, "") }))}
              />
            </Field>
            <Field label={t("sector")} htmlFor={`${idPrefix}-org-sector`}>
              <Input id={`${idPrefix}-org-sector`} value={createForm.sector} maxLength={80} onChange={(event) => setCreateForm((current) => ({ ...current, sector: event.target.value }))} />
            </Field>
            <Field label={t("tier")} htmlFor={`${idPrefix}-org-tier`}>
              <Select id={`${idPrefix}-org-tier`} value={createForm.tier} onChange={(event) => setCreateForm((current) => ({ ...current, tier: event.target.value as OrgTier }))}>
                {ORG_TIERS.map((tier) => <option key={tier} value={tier}>{tierLabel(tier, t)}</option>)}
              </Select>
            </Field>
          </div>
          <Field label={t("autonomy")} htmlFor={`${idPrefix}-org-autonomy`} hint={autonomyDescription(createForm.autonomy, t)}>
            <Select id={`${idPrefix}-org-autonomy`} value={createForm.autonomy} onChange={(event) => setCreateForm((current) => ({ ...current, autonomy: event.target.value as AutonomyLevel }))}>
              {AUTONOMY_LEVELS.map((level) => <option key={level} value={level}>{level} — {autonomyDescription(level, t)}</option>)}
            </Select>
          </Field>
          {createError ? <ErrorBanner message={createError} /> : null}
          {!isPlatformAdmin ? <div className="notice notice-warning">{t("noPlatformAdmin")}</div> : null}
        </div>
      </Modal>

      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title={t("editCurrent")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditOpen(false)} disabled={updateMutation.isPending}>{t("cancel")}</Button>
            <Button variant="primary" loading={updateMutation.isPending} onClick={submitEdit} data-testid="org-edit-submit">
              {t("save")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="form-grid">
            <Field label={t("name")} htmlFor={`${idPrefix}-edit-name`} error={editFieldErrors.name} required>
              <Input id={`${idPrefix}-edit-name`} value={editForm.name} maxLength={200} onChange={(event) => setEditForm((current) => ({ ...current, name: event.target.value }))} />
            </Field>
            <Field label={t("slug")} htmlFor={`${idPrefix}-edit-slug`} hint={t("slug")}>
              <Input id={`${idPrefix}-edit-slug`} value={editForm.slug} readOnly className="mono" />
            </Field>
            <Field label={t("kind")} htmlFor={`${idPrefix}-edit-kind`}>
              <Select id={`${idPrefix}-edit-kind`} value={editForm.kind} onChange={(event) => setEditForm((current) => ({ ...current, kind: event.target.value as OrgKind }))}>
                {ORG_KINDS.map((kind) => <option key={kind} value={kind}>{kindLabel(kind, t)}</option>)}
              </Select>
            </Field>
            <Field label={t("country")} htmlFor={`${idPrefix}-edit-country`} error={editFieldErrors.country}>
              <Input
                id={`${idPrefix}-edit-country`}
                value={editForm.country}
                maxLength={2}
                onChange={(event) => setEditForm((current) => ({ ...current, country: event.target.value.toUpperCase().replace(/[^A-Z]/g, "") }))}
              />
            </Field>
            <Field label={t("sector")} htmlFor={`${idPrefix}-edit-sector`}>
              <Input id={`${idPrefix}-edit-sector`} value={editForm.sector} maxLength={80} onChange={(event) => setEditForm((current) => ({ ...current, sector: event.target.value }))} />
            </Field>
            <Field label={t("tier")} htmlFor={`${idPrefix}-edit-tier`}>
              <Select id={`${idPrefix}-edit-tier`} value={editForm.tier} onChange={(event) => setEditForm((current) => ({ ...current, tier: event.target.value as OrgTier }))}>
                {ORG_TIERS.map((tier) => <option key={tier} value={tier}>{tierLabel(tier, t)}</option>)}
              </Select>
            </Field>
          </div>
          <Field label={t("autonomy")} htmlFor={`${idPrefix}-edit-autonomy`} hint={autonomyDescription(editForm.autonomy, t)}>
            <Select id={`${idPrefix}-edit-autonomy`} value={editForm.autonomy} onChange={(event) => setEditForm((current) => ({ ...current, autonomy: event.target.value as AutonomyLevel }))} data-testid="org-edit-autonomy">
              {AUTONOMY_LEVELS.map((level) => <option key={level} value={level}>{level} — {autonomyDescription(level, t)}</option>)}
            </Select>
          </Field>
          <div className="notice notice-warning">{t("autonomyWarning")}</div>
          <div>
            <div className="section-label">{t("autonomyLevels")}</div>
            <div className="stack" style={{ gap: 4 }}>
              {AUTONOMY_LEVELS.map((level) => (
                <div className="row" style={{ gap: 8, alignItems: "flex-start" }} key={level}>
                  <Badge tone={autonomyTone(level)}>{level}</Badge>
                  <span style={{ fontSize: 11.5, color: "var(--text-secondary)" }}>{autonomyDescription(level, t)}</span>
                </div>
              ))}
            </div>
          </div>
          {editError ? <ErrorBanner message={editError} /> : null}
        </div>
      </Modal>

      <Modal
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        title={t("profile")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setSelectedId(null)}>{t("close")}</Button>
            {profile && profile.id !== currentOrgId ? (
              <Button variant="primary" icon={ArrowRightLeft} onClick={() => { setSwitchTarget(profile); setSelectedId(null); }}>
                {t("switch")}
              </Button>
            ) : null}
            {profile && profile.id === currentOrgId && canWrite ? (
              <Button variant="primary" icon={Pencil} onClick={() => { setSelectedId(null); openEdit(profile); }}>
                {t("editCurrent")}
              </Button>
            ) : null}
          </>
        }
      >
        {profile ? (
          <div className="stack" data-testid="org-detail">
            <div className="row-between wrap">
              <div>
                <div className="row wrap" style={{ gap: 6 }}>
                  <h3 style={{ fontSize: 16 }}>{profile.name}</h3>
                  {profile.is_demo ? <Badge tone="amber">{t("demo")}</Badge> : null}
                </div>
                <div className="mono" style={{ fontSize: 10.5, color: "var(--dim)" }}>{profile.slug}</div>
              </div>
              <StatusBadge status={profile.status} />
            </div>
            {profile.is_demo ? <div className="demo-banner">{t("demoNotice")}</div> : null}
            <MetaRows
              items={[
                { label: t("kind"), value: kindLabel(profile.kind, t) },
                { label: t("tier"), value: tierLabel(profile.tier, t) },
                { label: t("country"), value: profile.country },
                { label: t("sector"), value: profile.sector },
                { label: t("autonomy"), value: <Badge tone={autonomyTone(profile.autonomy_level)}>{profile.autonomy_level}</Badge> },
                { label: t("createdAt"), value: formatDateTime(profile.created_at, lang) },
                { label: t("role"), value: roleByOrg.get(profile.id) ?? (isPlatformAdmin ? "platform_admin" : "—") },
                { label: t("status"), value: humanize(profile.status) },
              ]}
            />
            <div>
              <div className="section-label">{t("autonomyLevels")}</div>
              <div className="stack" style={{ gap: 4 }}>
                {AUTONOMY_LEVELS.map((level) => (
                  <div className="row" style={{ gap: 8, alignItems: "flex-start" }} key={level}>
                    <Badge tone={autonomyTone(level)}>{level}</Badge>
                    <span style={{ fontSize: 11.5, color: level === profile.autonomy_level ? "var(--text)" : "var(--muted)" }}>
                      {autonomyDescription(level, t)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            {detailQuery.isError ? (
              <span className="dim" style={{ fontSize: 11 }}>
                {errorMessage(detailQuery.error)}
              </span>
            ) : null}
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={switchTarget !== null}
        onClose={() => setSwitchTarget(null)}
        onConfirm={() => void confirmSwitch()}
        title={t("switchConfirm")}
        description={switchTarget ? `${t("currentOrg")}: ${session?.organization.name ?? "—"} → ${switchTarget.name}` : undefined}
        warning={t("switchWarning")}
        confirmLabel={t("switchConfirm")}
        cancelLabel={t("cancel")}
        tone="primary"
        busy={switching}
        testId="org-switch-confirm"
      />

      <ConfirmDialog
        open={pendingAutonomy !== null}
        onClose={() => setPendingAutonomy(null)}
        onConfirm={() => {
          updateMutation.mutate({
            name: editForm.name.trim(),
            kind: editForm.kind,
            country: editForm.country.toUpperCase(),
            sector: editForm.sector.trim() || "general",
            tier: editForm.tier,
            autonomy_level: editForm.autonomy,
          });
        }}
        title={t("changeAutonomyConfirm")}
        description={
          pendingAutonomy
            ? t("autonomyBlast").replace("{from}", pendingAutonomy.from).replace("{to}", pendingAutonomy.to)
            : undefined
        }
        warning={t("autonomyWarning")}
        confirmLabel={t("save")}
        cancelLabel={t("cancel")}
        busy={updateMutation.isPending}
        testId="org-autonomy-confirm"
      />
    </div>
  );
}

export default OrganizationsPage;
