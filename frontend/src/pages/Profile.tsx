import { useState } from "react";
import {
  ArrowRightLeft,
  Building2,
  Clock,
  KeyRound,
  Mail,
  MapPin,
  ShieldCheck,
} from "lucide-react";
import { errorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, type Lang } from "../lib/i18n";
import { formatDateTime, formatNumber, humanize, initials, relativeTime } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  LinkButton,
  PageHeader,
  StatusBadge,
  useToast,
} from "../components/ui";
import { ConfirmDialog, MetaRows, useGovernCopy } from "../components/features/govern/common";
import { ChangePasswordPanel, MfaPanel } from "../components/features/govern/security";

const COPY: Record<Lang, Record<string, string>> = {
  es: {
    eyebrow: "Cuenta · Perfil",
    title: "Mi perfil",
    subtitle: "Identidad, organizaciones, permisos efectivos y seguridad de la cuenta.",
    user: "Identidad",
    fullName: "Nombre",
    email: "Correo",
    accountStatus: "Estado de la cuenta",
    platformAdmin: "Administrador de plataforma",
    lastLogin: "Último acceso",
    createdAt: "Cuenta creada",
    organizations: "Organizaciones",
    organizationsHint: "El cambio de organización reajusta todos los datos de la sesión.",
    current: "Actual",
    switch: "Cambiar",
    switchConfirm: "Cambiar de organización",
    switchWarning: "La sesión se recarga y todas las vistas se reajustan al nuevo tenant. Los datos no se mezclan entre organizaciones.",
    rolePermissions: "Rol y permisos",
    role: "Rol",
    autonomy: "Autonomía",
    permissions: "Permisos efectivos",
    showAll: "Ver todos",
    showLess: "Ver menos",
    permissionsHint: "Los permisos se calculan desde el rol de membresía en el servidor. El cliente solo oculta acciones.",
    localeTimezone: "Idioma y zona horaria",
    locale: "Idioma",
    timezone: "Zona horaria",
    sessionExpires: "La sesión expira",
    expires: "Caduca",
    mfa: "Verificación en dos pasos",
    mfaOn: "activa",
    mfaOff: "inactiva",
    password: "Contraseña",
    apiTokens: "Tokens de API",
    apiTokensHint: "Gestiona credenciales de automatización con mínimo privilegio.",
    manageTokens: "Gestionar tokens",
    noTokenPermission: "Tu rol no puede gestionar tokens de API.",
    memberSince: "Miembro desde",
    noOrganizations: "Sin organizaciones",
    close: "Cerrar",
    cancel: "Cancelar",
    switched: "Cambiando de organización…",
    switchError: "No se pudo cambiar de organización",
    refresh: "Actualizar",
  },
  en: {
    eyebrow: "Account · Profile",
    title: "My profile",
    subtitle: "Identity, organizations, effective permissions and account security.",
    user: "Identity",
    fullName: "Name",
    email: "Email",
    accountStatus: "Account status",
    platformAdmin: "Platform administrator",
    lastLogin: "Last sign-in",
    createdAt: "Account created",
    organizations: "Organizations",
    organizationsHint: "Switching organization re-scopes all session data.",
    current: "Current",
    switch: "Switch",
    switchConfirm: "Switch organization",
    switchWarning: "The session reloads and every view re-scopes to the new tenant. Data is never mixed across organizations.",
    rolePermissions: "Role and permissions",
    role: "Role",
    autonomy: "Autonomy",
    permissions: "Effective permissions",
    showAll: "Show all",
    showLess: "Show less",
    permissionsHint: "Permissions are computed from the membership role server-side. The client only hides actions.",
    localeTimezone: "Locale and timezone",
    locale: "Locale",
    timezone: "Timezone",
    sessionExpires: "Session expires",
    expires: "Expires",
    mfa: "Two-step verification",
    mfaOn: "on",
    mfaOff: "off",
    password: "Password",
    apiTokens: "API tokens",
    apiTokensHint: "Manage least-privilege automation credentials.",
    manageTokens: "Manage tokens",
    noTokenPermission: "Your role cannot manage API tokens.",
    memberSince: "Member since",
    noOrganizations: "No organizations",
    close: "Close",
    cancel: "Cancel",
    switched: "Switching organization…",
    switchError: "The organization could not be switched",
    refresh: "Refresh",
  },
};

interface SwitchTarget {
  id: string;
  name: string;
}

export function ProfilePage() {
  const t = useGovernCopy(COPY);
  const { lang } = useI18n();
  const { session, can, refresh, switchOrganization } = useAuth();
  const toast = useToast();
  const [showAllPermissions, setShowAllPermissions] = useState(false);
  const [switchTarget, setSwitchTarget] = useState<SwitchTarget | null>(null);
  const [switching, setSwitching] = useState(false);

  if (!session) return null;

  const permissions = session.permissions;
  const visiblePermissions = showAllPermissions ? permissions : permissions.slice(0, 24);
  const canManageTokens = can("apikey:manage");

  const confirmSwitch = async () => {
    if (!switchTarget) return;
    setSwitching(true);
    try {
      await switchOrganization(switchTarget.id);
    } catch (error) {
      setSwitching(false);
      setSwitchTarget(null);
      toast.push(`${t("switchError")}: ${errorMessage(error)}`, "error");
    }
  };

  return (
    <div className="animate-in" data-testid="page-profile">
      <PageHeader
        eyebrow={t("eyebrow")}
        title={t("title")}
        subtitle={t("subtitle")}
        actions={
          <>
            <Badge tone={session.user.mfa_enabled ? "success" : "warning"}>
              <ShieldCheck size={11} /> MFA {session.user.mfa_enabled ? t("mfaOn") : t("mfaOff")}
            </Badge>
            <Button variant="ghost" onClick={() => void refresh()} data-testid="profile-refresh">
              {t("refresh")}
            </Button>
          </>
        }
      />

      <div className="split-main">
        <div className="stack">
          <Card title={t("user")} subtitle={session.organization.name}>
            <div className="stack">
              <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
                <div
                  className="avatar"
                  style={{ width: 44, height: 44, fontSize: 15, flex: "0 0 auto" }}
                  aria-hidden="true"
                >
                  {initials(session.user.full_name)}
                </div>
                <div style={{ minWidth: 0 }}>
                  <h3 style={{ fontSize: 16 }}>{session.user.full_name}</h3>
                  <div className="row wrap" style={{ gap: 6, marginTop: 3 }}>
                    <span className="mono" style={{ fontSize: 11, color: "var(--muted)" }}>
                      <Mail size={11} /> {session.user.email}
                    </span>
                    <StatusBadge status={session.user.status} />
                    {session.user.is_platform_admin ? <Badge tone="accent">{t("platformAdmin")}</Badge> : null}
                  </div>
                </div>
              </div>
              <MetaRows
                items={[
                  { label: t("lastLogin"), value: `${formatDateTime(session.user.last_login_at, lang)} · ${session.user.last_login_at ? relativeTime(session.user.last_login_at, lang) : "—"}` },
                  { label: t("createdAt"), value: formatDateTime(session.user.created_at, lang) },
                  { label: t("sessionExpires"), value: formatDateTime(session.expires_at, lang) },
                  { label: t("role"), value: <Badge tone="neutral">{session.role}</Badge> },
                  { label: t("autonomy"), value: <Badge tone="accent">{session.autonomy_level}</Badge> },
                ]}
              />
            </div>
          </Card>

          <Card
            title={t("rolePermissions")}
            subtitle={t("permissionsHint")}
            actions={<Badge tone="accent">{formatNumber(permissions.length)}</Badge>}
          >
            <div className="stack">
              <div className="chip-row">
                {visiblePermissions.length === 0 ? (
                  <span className="dim" style={{ fontSize: 11 }}>—</span>
                ) : (
                  visiblePermissions.map((permission) => (
                    <span className="tag" key={permission}>{permission}</span>
                  ))
                )}
              </div>
              {permissions.length > 24 ? (
                <Button size="sm" variant="ghost" onClick={() => setShowAllPermissions((current) => !current)} data-testid="profile-permissions-toggle">
                  {showAllPermissions ? t("showLess") : `${t("showAll")} (${formatNumber(permissions.length)})`}
                </Button>
              ) : null}
            </div>
          </Card>

          <Card title={t("localeTimezone")} subtitle={`${session.user.locale} · ${session.user.timezone}`}>
            <MetaRows
              items={[
                { label: t("locale"), value: <span className="mono">{session.user.locale}</span> },
                { label: t("timezone"), value: <span className="mono">{session.user.timezone}</span> },
                { label: t("memberSince"), value: formatDateTime(session.user.created_at, lang) },
              ]}
            />
          </Card>

          <Card
            title={t("apiTokens")}
            subtitle={t("apiTokensHint")}
            actions={
              canManageTokens ? (
                <LinkButton to="/admin?tab=tokens" size="sm" icon={KeyRound} variant="primary">
                  {t("manageTokens")}
                </LinkButton>
              ) : (
                <span className="dim" style={{ fontSize: 11 }}>{t("noTokenPermission")}</span>
              )
            }
          >
            <div className="notice" style={{ fontSize: 11 }}>
              <KeyRound size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
              <span>{t("apiTokensHint")} {t("permissionsHint")}</span>
            </div>
          </Card>
        </div>

        <div className="stack">
          <Card title={t("organizations")} subtitle={t("organizationsHint")}>
            {session.organizations.length === 0 ? (
              <span className="dim" style={{ fontSize: 11 }}>{t("noOrganizations")}</span>
            ) : (
              <div className="stack">
                {session.organizations.map((org) => {
                  const isCurrent = org.id === session.organization.id;
                  return (
                    <div className="list-item" key={org.id} data-testid="profile-org-row">
                      <Building2 size={14} style={{ color: isCurrent ? "var(--accent)" : "var(--dim)", flex: "0 0 auto", marginTop: 2 }} />
                      <div style={{ minWidth: 0 }}>
                        <div className="row wrap" style={{ gap: 5 }}>
                          <span className="item-title">{org.name}</span>
                          {isCurrent ? <Badge tone="accent">{t("current")}</Badge> : null}
                        </div>
                        <div className="item-sub mono">{org.slug} · {org.kind}</div>
                        <div className="item-sub">{t("role")}: {org.role ?? "—"}</div>
                      </div>
                      <div className="item-side">
                        {isCurrent ? (
                          <Badge tone="success"><MapPin size={10} /> {t("current")}</Badge>
                        ) : (
                          <Button
                            size="sm"
                            variant="ghost"
                            icon={ArrowRightLeft}
                            onClick={() => setSwitchTarget({ id: org.id, name: org.name })}
                            data-testid="profile-org-switch"
                          >
                            {t("switch")}
                          </Button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>

          <Card title={t("mfa")}>
            <MfaPanel />
          </Card>

          <Card title={t("password")}>
            <ChangePasswordPanel />
          </Card>

          <div className="notice" style={{ fontSize: 11 }}>
            <Clock size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} />
            <span>{t("sessionExpires")}: {formatDateTime(session.expires_at, lang)} · {humanize(session.role)}</span>
          </div>
        </div>
      </div>

      <ConfirmDialog
        open={switchTarget !== null}
        onClose={() => setSwitchTarget(null)}
        onConfirm={() => void confirmSwitch()}
        title={t("switchConfirm")}
        description={switchTarget ? `${session.organization.name} → ${switchTarget.name}` : undefined}
        warning={t("switchWarning")}
        confirmLabel={t("switchConfirm")}
        cancelLabel={t("cancel")}
        tone="primary"
        busy={switching}
        testId="profile-switch-confirm"
      />

      {switchTarget ? (
        <span className="sr-only" data-testid="profile-switch-target">{switchTarget.name}</span>
      ) : null}

      <div className="sr-only" aria-live="polite">
        {switching ? t("switched") : ""}
      </div>

    </div>
  );
}

export default ProfilePage;
