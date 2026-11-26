import { useId, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  KeyRound,
  QrCode,
  ShieldCheck,
  ShieldOff,
  Trash2,
} from "lucide-react";
import { api, errorMessage } from "../../../lib/api";
import { useAuth } from "../../../lib/auth";
import { useI18n, type Lang } from "../../../lib/i18n";
import { formatDateTime, formatNumber, relativeTime } from "../../../lib/format";
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
  StatusBadge,
  useToast,
  type Column,
} from "../../ui";
import { ConfirmDialog, MetaRows, SecretOnce, apiFieldErrors, useGovernCopy } from "./common";


const SECURE_COPY: Record<Lang, Record<string, string>> = {
  es: {
    "secure.enabled": "Activado",
    "secure.disabled": "Desactivado",
    "secure.mfaOnHint": "La verificación en dos pasos protege el acceso a acciones sensibles.",
    "secure.mfaOffHint": "Recomendado: activa TOTP antes de operar con autonomía.",
    "secure.disableMfa": "Desactivar MFA",
    "secure.enrollMfa": "Activar MFA (TOTP)",
    "secure.step1": "1. Registra el secreto en tu aplicación TOTP",
    "secure.scanHint": "Introduce el secreto en tu autenticador o importa el URI otpauth. El secreto no se volverá a mostrar.",
    "secure.totpSecret": "Secreto TOTP",
    "secure.otpauthUri": "URI otpauth",
    "secure.step2": "2. Confirma con un código",
    "secure.activationCode": "Código de activación",
    "secure.activate": "Activar",
    "secure.password": "Contraseña",
    "secure.totpCode": "Código TOTP",
    "secure.lastLogin": "Último acceso",
    "secure.enrollStarted": "Enrolamiento iniciado",
    "secure.mfaEnabled": "MFA activado",
    "secure.mfaDisabled": "MFA desactivado",
    "secure.disableWarning": "Al desactivar MFA tu cuenta queda protegida solo por contraseña. La acción requiere contraseña actual y código TOTP válido.",
    "secure.currentPassword": "Contraseña actual",
    "secure.newPassword": "Nueva contraseña",
    "secure.confirmPassword": "Repetir nueva contraseña",
    "secure.passwordPolicy": "Mínimo 12 caracteres y al menos 3 de: minúsculas, mayúsculas, dígitos, símbolos. No puede contener tu usuario.",
    "secure.passwordTooShort": "La contraseña debe tener al menos 12 caracteres.",
    "secure.passwordMismatch": "Las contraseñas no coinciden.",
    "secure.passwordChanged": "Contraseña actualizada",
    "secure.changePassword": "Cambiar contraseña",
    "secure.passwordSessionHint": "El cambio se aplica a tu cuenta y queda auditado.",
    "secure.account": "Cuenta",
    "secure.role": "Rol",
    "secure.organization": "Organización",
    "secure.permissions": "Permisos",
    "secure.sessionExpires": "La sesión expira",
    "secure.mfa": "Verificación en dos pasos",
    "secure.locale": "Idioma y zona horaria",
    "secure.apiTokens": "Tokens de API",
    "secure.apiTokensHint": "Credenciales de automatización limitadas a tus permisos. Se muestran una sola vez.",
    "secure.createToken": "Crear token",
    "secure.noTokens": "Sin tokens activos",
    "secure.noTokensHint": "Crea un token para automatizaciones y guárdalo en tu gestor de secretos.",
    "secure.tokenName": "Nombre del token",
    "secure.tokenNamePlaceholder": "Automatización SOC",
    "secure.scopes": "Scopes",
    "secure.expires": "Caduca",
    "secure.expired": "Caducado",
    "secure.neverExpires": "Sin caducidad",
    "secure.lastUsed": "Último uso",
    "secure.revoke": "Revocar",
    "secure.tokenCreated": "Token creado",
    "secure.tokenRevoked": "Token revocado",
    "secure.expiresDays": "Días de validez",
    "secure.expiresDaysHint": "1–365 días; vacío para sin caducidad.",
    "secure.expiresInvalid": "Introduce un número entre 1 y 365.",
    "secure.scopesHint": "Sin scopes seleccionados, el token hereda todos tus permisos actuales. Aplica mínimo privilegio.",
    "secure.scopeSearch": "Buscar scope…",
    "secure.selectVisible": "Seleccionar visibles",
    "secure.clearAll": "Quitar todos",
    "secure.noScopeMatches": "Ningún scope coincide.",
    "secure.prefix": "Prefijo",
    "secure.tokenValue": "Valor del token",
    "secure.tokenOnceWarning": "Copia este token ahora. No se volverá a mostrar y el servidor solo guarda su hash.",
    "secure.revokeToken": "Revocar token",
    "secure.revokeTokenDesc": "El token dejará de autenticar de inmediato.",
    "secure.revokeTokenWarning": "Cualquier automatización que use este token fallará. No se puede deshacer.",
    "secure.session": "Sesión actual",
    "secure.sessionSub": "Contexto de autenticación y ámbito activo.",
    "secure.mfaSub": "Segundo factor TOTP para operadores.",
    "secure.passwordSub": "Rotación de credencial con política de robustez.",
  },
  en: {
    "secure.enabled": "Enabled",
    "secure.disabled": "Disabled",
    "secure.mfaOnHint": "Two-step verification protects access to sensitive actions.",
    "secure.mfaOffHint": "Recommended: enable TOTP before operating with autonomy.",
    "secure.disableMfa": "Disable MFA",
    "secure.enrollMfa": "Enable MFA (TOTP)",
    "secure.step1": "1. Register the secret in your TOTP app",
    "secure.scanHint": "Enter the secret in your authenticator or import the otpauth URI. The secret is never shown again.",
    "secure.totpSecret": "TOTP secret",
    "secure.otpauthUri": "otpauth URI",
    "secure.step2": "2. Confirm with a code",
    "secure.activationCode": "Activation code",
    "secure.activate": "Activate",
    "secure.password": "Password",
    "secure.totpCode": "TOTP code",
    "secure.lastLogin": "Last sign-in",
    "secure.enrollStarted": "Enrollment started",
    "secure.mfaEnabled": "MFA enabled",
    "secure.mfaDisabled": "MFA disabled",
    "secure.disableWarning": "Disabling MFA leaves your account protected by password only. The action requires the current password and a valid TOTP code.",
    "secure.currentPassword": "Current password",
    "secure.newPassword": "New password",
    "secure.confirmPassword": "Repeat new password",
    "secure.passwordPolicy": "At least 12 characters and 3 of: lowercase, uppercase, digits, symbols. It must not contain your account name.",
    "secure.passwordTooShort": "Password must be at least 12 characters.",
    "secure.passwordMismatch": "Passwords do not match.",
    "secure.passwordChanged": "Password updated",
    "secure.changePassword": "Change password",
    "secure.passwordSessionHint": "The change applies to your account and is audited.",
    "secure.account": "Account",
    "secure.role": "Role",
    "secure.organization": "Organization",
    "secure.permissions": "Permissions",
    "secure.sessionExpires": "Session expires",
    "secure.mfa": "Two-step verification",
    "secure.locale": "Locale and timezone",
    "secure.apiTokens": "API tokens",
    "secure.apiTokensHint": "Automation credentials limited to your permissions. Shown exactly once.",
    "secure.createToken": "Create token",
    "secure.noTokens": "No active tokens",
    "secure.noTokensHint": "Create a token for automation and store it in your secret manager.",
    "secure.tokenName": "Token name",
    "secure.tokenNamePlaceholder": "SOC automation",
    "secure.scopes": "Scopes",
    "secure.expires": "Expires",
    "secure.expired": "Expired",
    "secure.neverExpires": "No expiry",
    "secure.lastUsed": "Last used",
    "secure.revoke": "Revoke",
    "secure.tokenCreated": "Token created",
    "secure.tokenRevoked": "Token revoked",
    "secure.expiresDays": "Validity days",
    "secure.expiresDaysHint": "1–365 days; empty for no expiry.",
    "secure.expiresInvalid": "Enter a number between 1 and 365.",
    "secure.scopesHint": "With no scopes selected the token inherits all your current permissions. Apply least privilege.",
    "secure.scopeSearch": "Search scope…",
    "secure.selectVisible": "Select visible",
    "secure.clearAll": "Clear all",
    "secure.noScopeMatches": "No scope matches.",
    "secure.prefix": "Prefix",
    "secure.tokenValue": "Token value",
    "secure.tokenOnceWarning": "Copy this token now. It is never shown again and the server only stores its hash.",
    "secure.revokeToken": "Revoke token",
    "secure.revokeTokenDesc": "The token stops authenticating immediately.",
    "secure.revokeTokenWarning": "Any automation using this token will fail. This cannot be undone.",
    "secure.session": "Current session",
    "secure.sessionSub": "Authentication context and active scope.",
    "secure.mfaSub": "TOTP second factor for operators.",
    "secure.passwordSub": "Credential rotation with a strength policy.",
  },
};

/* ------------------------------------------------------------------- types */

interface MfaEnrollment {
  secret: string;
  otpauth_uri: string;
  issuer: string;
}

interface ApiTokenInfo {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
}

interface ApiTokenCreated {
  id: string;
  name: string;
  token: string;
  prefix: string;
  scopes: string[];
  expires_at: string | null;
}

interface PermissionEntry {
  key: string;
  description: string;
}

interface PermissionsCatalogue {
  permissions: PermissionEntry[];
  roles: Record<string, string[]>;
}

function groupSecret(secret: string): string {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}

function isExpired(value: string | null): boolean {
  if (!value) return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && date.getTime() < Date.now();
}

/* --------------------------------------------------------------- MFA panel */

export function MfaPanel() {
  const { session, refresh } = useAuth();
  const { lang } = useI18n();
  const t = useGovernCopy(SECURE_COPY);
  const toast = useToast();
  const idPrefix = useId();
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [activationCode, setActivationCode] = useState("");
  const [disableOpen, setDisableOpen] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const mfaEnabled = session?.user.mfa_enabled ?? false;

  const enrollMutation = useMutation({
    mutationFn: () => api.post<MfaEnrollment>("/auth/mfa/enroll"),
    onSuccess: (result) => {
      setEnrollment(result);
      toast.push(t("secure.enrollStarted"), "success");
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      toast.push(errorMessage(error), "error");
    },
  });

  const activateMutation = useMutation({
    mutationFn: (code: string) => api.post<{ message: string }>("/auth/mfa/activate", { code }),
    onSuccess: async () => {
      setEnrollment(null);
      setActivationCode("");
      setFormError(null);
      toast.push(t("secure.mfaEnabled"), "success");
      await refresh();
    },
    onError: (error) => {
      setFormError(errorMessage(error));
    },
  });

  const disableMutation = useMutation({
    mutationFn: () => api.post<{ message: string }>("/auth/mfa/disable", { password: disablePassword, code: disableCode }),
    onSuccess: async () => {
      setDisableOpen(false);
      setDisablePassword("");
      setDisableCode("");
      setFormError(null);
      toast.push(t("secure.mfaDisabled"), "success");
      await refresh();
    },
    onError: (error) => {
      setFormError(errorMessage(error));
    },
  });

  return (
    <div className="stack" data-testid="security-mfa">
      <div className="row-between wrap">
        <div className="row" style={{ gap: 8 }}>
          {mfaEnabled ? (
            <Badge tone="success"><ShieldCheck size={11} /> MFA {t("secure.enabled")}</Badge>
          ) : (
            <Badge tone="danger"><ShieldOff size={11} /> MFA {t("secure.disabled")}</Badge>
          )}
          <span className="dim" style={{ fontSize: 11.5 }}>
            {mfaEnabled ? t("secure.mfaOnHint") : t("secure.mfaOffHint")}
          </span>
        </div>
        {mfaEnabled ? (
          <Button size="sm" variant="danger" onClick={() => { setFormError(null); setDisableOpen(true); }} data-testid="security-mfa-disable-open">
            {t("secure.disableMfa")}
          </Button>
        ) : (
          <Button
            size="sm"
            variant="primary"
            icon={QrCode}
            loading={enrollMutation.isPending}
            onClick={() => { setFormError(null); enrollMutation.mutate(); }}
            data-testid="security-mfa-enroll"
          >
            {t("secure.enrollMfa")}
          </Button>
        )}
      </div>

      {formError && !disableOpen ? <ErrorBanner compact message={formError} /> : null}

      {enrollment ? (
        <div className="card card-pad stack" data-testid="security-mfa-enrollment">
          <div className="section-label">{t("secure.step1")}</div>
          <p className="muted" style={{ fontSize: 12 }}>{t("secure.scanHint")}</p>
          <div>
            <div className="section-label">{t("secure.totpSecret")}</div>
            <div className="row wrap" style={{ gap: 6 }}>
              <code className="mono" style={{ fontSize: 13, letterSpacing: "0.08em", color: "var(--accent)" }} data-testid="security-mfa-secret">
                {groupSecret(enrollment.secret)}
              </code>
            </div>
          </div>
          <div>
            <div className="section-label">{t("secure.otpauthUri")}</div>
            <pre className="code-block" style={{ fontSize: 10.5 }} data-testid="security-mfa-uri">{enrollment.otpauth_uri}</pre>
          </div>
          <div className="section-label">{t("secure.step2")}</div>
          <div className="row wrap" style={{ gap: 8, alignItems: "flex-end" }}>
            <Field label={t("secure.activationCode")} htmlFor={`${idPrefix}-activate`}>
              <Input
                id={`${idPrefix}-activate`}
                value={activationCode}
                onChange={(event) => setActivationCode(event.target.value.replace(/\D/g, "").slice(0, 8))}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                className="mono"
                data-testid="security-mfa-code"
              />
            </Field>
            <Button
              variant="primary"
              loading={activateMutation.isPending}
              disabled={!/^\d{6,8}$/.test(activationCode)}
              onClick={() => activateMutation.mutate(activationCode)}
              data-testid="security-mfa-activate"
            >
              {t("secure.activate")}
            </Button>
            <Button variant="ghost" onClick={() => { setEnrollment(null); setActivationCode(""); }}>
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      ) : null}

      <Modal
        open={disableOpen}
        onClose={() => setDisableOpen(false)}
        title={t("secure.disableMfa")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setDisableOpen(false)} disabled={disableMutation.isPending}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="danger"
              loading={disableMutation.isPending}
              disabled={disablePassword.length === 0 || !/^\d{6,8}$/.test(disableCode)}
              onClick={() => disableMutation.mutate()}
              data-testid="security-mfa-disable-submit"
            >
              {t("secure.disableMfa")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="notice notice-warning">{t("secure.disableWarning")}</div>
          <Field label={t("secure.password")} htmlFor={`${idPrefix}-disable-password`} required>
            <Input
              id={`${idPrefix}-disable-password`}
              type="password"
              autoComplete="current-password"
              value={disablePassword}
              onChange={(event) => setDisablePassword(event.target.value)}
            />
          </Field>
          <Field label={t("secure.totpCode")} htmlFor={`${idPrefix}-disable-code`} required>
            <Input
              id={`${idPrefix}-disable-code`}
              value={disableCode}
              onChange={(event) => setDisableCode(event.target.value.replace(/\D/g, "").slice(0, 8))}
              inputMode="numeric"
              autoComplete="one-time-code"
              className="mono"
            />
          </Field>
          {formError ? <ErrorBanner compact message={formError} /> : null}
          <span className="dim" style={{ fontSize: 11 }}>
            {t("secure.lastLogin")}: {formatDateTime(session?.user.last_login_at, lang)} ·{" "}
            {session?.user.last_login_at ? relativeTime(session.user.last_login_at, lang) : "—"}
          </span>
        </div>
      </Modal>
    </div>
  );
}

/* -------------------------------------------------------- change password */

export function ChangePasswordPanel() {
  const t = useGovernCopy(SECURE_COPY);
  const toast = useToast();
  const idPrefix = useId();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const mutation = useMutation({
    mutationFn: () => api.post<{ message: string }>("/auth/change-password", {
      current_password: currentPassword,
      new_password: newPassword,
    }),
    onSuccess: () => {
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setError(null);
      setFieldErrors({});
      toast.push(t("secure.passwordChanged"), "success");
    },
    onError: (err) => {
      setFieldErrors(apiFieldErrors(err));
      setError(errorMessage(err));
    },
  });

  const mismatch = confirmPassword.length > 0 && newPassword !== confirmPassword;
  const tooShort = newPassword.length > 0 && newPassword.length < 12;

  return (
    <form
      className="stack"
      data-testid="security-password"
      onSubmit={(event) => {
        event.preventDefault();
        setError(null);
        if (newPassword !== confirmPassword || newPassword.length < 12) return;
        mutation.mutate();
      }}
    >
      <div className="form-grid">
        <div className="span-2">
          <Field label={t("secure.currentPassword")} htmlFor={`${idPrefix}-current`} required>
            <Input
              id={`${idPrefix}-current`}
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(event) => setCurrentPassword(event.target.value)}
            />
          </Field>
        </div>
        <Field
          label={t("secure.newPassword")}
          htmlFor={`${idPrefix}-new`}
          hint={t("secure.passwordPolicy")}
          error={fieldErrors.new_password ?? (tooShort ? t("secure.passwordTooShort") : undefined)}
          required
        >
          <Input
            id={`${idPrefix}-new`}
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            aria-invalid={tooShort || Boolean(fieldErrors.new_password) ? true : undefined}
          />
        </Field>
        <Field
          label={t("secure.confirmPassword")}
          htmlFor={`${idPrefix}-confirm`}
          error={mismatch ? t("secure.passwordMismatch") : undefined}
          required
        >
          <Input
            id={`${idPrefix}-confirm`}
            type="password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            aria-invalid={mismatch ? true : undefined}
          />
        </Field>
      </div>
      {error ? <ErrorBanner compact message={error} /> : null}
      <div className="row">
        <Button
          type="submit"
          variant="primary"
          loading={mutation.isPending}
          disabled={!currentPassword || newPassword.length < 12 || newPassword !== confirmPassword}
          data-testid="security-password-submit"
        >
          {t("secure.changePassword")}
        </Button>
        <span className="dim" style={{ fontSize: 11 }}>{t("secure.passwordSessionHint")}</span>
      </div>
    </form>
  );
}

/* ---------------------------------------------------------- session summary */

export function SessionSummary() {
  const { session } = useAuth();
  const { lang } = useI18n();
  const t = useGovernCopy(SECURE_COPY);
  if (!session) return null;
  return (
    <div className="stack" data-testid="security-session">
      <MetaRows
        items={[
          { label: t("secure.account"), value: session.user.email },
          { label: t("secure.role"), value: <StatusBadge status={session.role} label={session.role} /> },
          { label: t("secure.organization"), value: session.organization.name },
          { label: t("common.autonomy"), value: <span className="mono">{session.autonomy_level}</span> },
          { label: t("secure.permissions"), value: <span className="mono">{formatNumber(session.permissions.length)}</span> },
          { label: t("secure.sessionExpires"), value: <span className="mono">{formatDateTime(session.expires_at, lang)}</span> },
          {
            label: t("secure.mfa"),
            value: session.user.mfa_enabled ? <Badge tone="success">{t("secure.enabled")}</Badge> : <Badge tone="danger">{t("secure.disabled")}</Badge>,
          },
          { label: t("secure.locale"), value: `${session.user.locale} · ${session.user.timezone}` },
        ]}
      />
    </div>
  );
}

/* ------------------------------------------------------------- API tokens */

interface TokenFormState {
  name: string;
  expiresDays: string;
  scopes: string[];
}

const EMPTY_TOKEN_FORM: TokenFormState = { name: "", expiresDays: "90", scopes: [] };

export function ApiTokensPanel() {
  const { lang } = useI18n();
  const t = useGovernCopy(SECURE_COPY);
  const toast = useToast();
  const queryClient = useQueryClient();
  const idPrefix = useId();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<TokenFormState>(EMPTY_TOKEN_FORM);
  const [scopeSearch, setScopeSearch] = useState("");
  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  const [revoking, setRevoking] = useState<ApiTokenInfo | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const tokensQuery = useQuery({
    queryKey: ["auth", "api-tokens"],
    queryFn: () => api.get<ApiTokenInfo[]>("/auth/api-tokens"),
  });

  const permissionsQuery = useQuery({
    queryKey: ["auth", "permissions"],
    queryFn: () => api.get<PermissionsCatalogue>("/auth/permissions"),
  });

  const createMutation = useMutation({
    mutationFn: (payload: { name: string; scopes: string[]; expires_days?: number }) =>
      api.post<ApiTokenCreated>("/auth/api-tokens", payload),
    onSuccess: async (result) => {
      setOpen(false);
      setCreated(result);
      setForm(EMPTY_TOKEN_FORM);
      setFieldErrors({});
      setFormError(null);
      await queryClient.invalidateQueries({ queryKey: ["auth", "api-tokens"] });
      toast.push(t("secure.tokenCreated"), "success");
    },
    onError: (error) => {
      setFormError(errorMessage(error));
      setFieldErrors(apiFieldErrors(error));
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (token: ApiTokenInfo) => api.delete<{ message: string }>(`/auth/api-tokens/${token.id}`),
    onSuccess: async () => {
      setRevoking(null);
      await queryClient.invalidateQueries({ queryKey: ["auth", "api-tokens"] });
      toast.push(t("secure.tokenRevoked"), "success");
    },
    onError: (error) => {
      setRevoking(null);
      toast.push(errorMessage(error), "error");
    },
  });

  const visiblePermissions = useMemo(() => {
    const entries = permissionsQuery.data?.permissions ?? [];
    const needle = scopeSearch.trim().toLowerCase();
    if (!needle) return entries;
    return entries.filter((entry) => entry.key.includes(needle) || entry.description.toLowerCase().includes(needle));
  }, [permissionsQuery.data, scopeSearch]);

  const columns: Column<ApiTokenInfo>[] = [
    {
      key: "name",
      header: t("secure.tokenName"),
      render: (row) => (
        <div>
          <div className="primary-cell">{row.name}</div>
          <div className="cell-sub mono">{row.prefix}…</div>
        </div>
      ),
    },
    {
      key: "scopes",
      header: t("secure.scopes"),
      width: "120px",
      render: (row) => <Badge tone={row.scopes.length ? "accent" : "neutral"}>{formatNumber(row.scopes.length)}</Badge>,
    },
    {
      key: "created",
      header: t("common.created"),
      width: "150px",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{formatDateTime(row.created_at, lang)}</span>,
    },
    {
      key: "expires",
      header: t("secure.expires"),
      width: "160px",
      render: (row) =>
        row.expires_at ? (
          isExpired(row.expires_at) ? (
            <Badge tone="danger">{t("secure.expired")}</Badge>
          ) : (
            <span className="mono" style={{ fontSize: 11 }}>{formatDateTime(row.expires_at, lang)}</span>
          )
        ) : (
          <span className="dim">{t("secure.neverExpires")}</span>
        ),
    },
    {
      key: "lastUsed",
      header: t("secure.lastUsed"),
      width: "140px",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.last_used_at ? relativeTime(row.last_used_at, lang) : "—"}</span>,
    },
    {
      key: "actions",
      header: "",
      width: "70px",
      align: "right",
      render: (row) => (
        <Button
          size="sm"
          variant="ghost"
          icon={Trash2}
          aria-label={t("secure.revoke")}
          onClick={() => setRevoking(row)}
          data-testid="security-token-revoke"
        />
      ),
    },
  ];

  const expiresInvalid = form.expiresDays.length > 0 && (!/^\d+$/.test(form.expiresDays) || Number(form.expiresDays) < 1 || Number(form.expiresDays) > 365);

  return (
    <div className="stack" data-testid="security-tokens">
      <div className="row-between wrap">
        <div>
          <div className="section-label" style={{ marginBottom: 2 }}>{t("secure.apiTokens")}</div>
          <span className="dim" style={{ fontSize: 11.5 }}>{t("secure.apiTokensHint")}</span>
        </div>
        <Button size="sm" variant="primary" icon={KeyRound} onClick={() => { setOpen(true); setForm({ ...EMPTY_TOKEN_FORM, scopes: [] }); setFormError(null); setFieldErrors({}); }} data-testid="security-token-open">
          {t("secure.createToken")}
        </Button>
      </div>

      {tokensQuery.isError ? (
        <ErrorBanner message={errorMessage(tokensQuery.error)} onRetry={() => void tokensQuery.refetch()} />
      ) : (
        <DataTable
          columns={columns}
          rows={tokensQuery.data}
          rowKey={(row) => row.id}
          loading={tokensQuery.isLoading}
          empty={
            <EmptyState
              icon={KeyRound}
              title={t("secure.noTokens")}
              description={t("secure.noTokensHint")}
              action={<Button size="sm" onClick={() => setOpen(true)}>{t("secure.createToken")}</Button>}
            />
          }
        />
      )}

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title={t("secure.createToken")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={createMutation.isPending}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              loading={createMutation.isPending}
              disabled={form.name.trim().length < 2 || expiresInvalid}
              onClick={() => {
                setFormError(null);
                if (expiresInvalid) return;
                createMutation.mutate({
                  name: form.name.trim(),
                  scopes: form.scopes,
                  ...(form.expiresDays ? { expires_days: Number(form.expiresDays) } : {}),
                });
              }}
              data-testid="security-token-submit"
            >
              {t("secure.createToken")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <div className="form-grid">
            <Field label={t("secure.tokenName")} htmlFor={`${idPrefix}-token-name`} error={fieldErrors.name} required>
              <Input
                id={`${idPrefix}-token-name`}
                value={form.name}
                maxLength={120}
                onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                placeholder={t("secure.tokenNamePlaceholder")}
              />
            </Field>
            <Field
              label={t("secure.expiresDays")}
              htmlFor={`${idPrefix}-token-days`}
              hint={t("secure.expiresDaysHint")}
              error={expiresInvalid ? t("secure.expiresInvalid") : undefined}
            >
              <Input
                id={`${idPrefix}-token-days`}
                value={form.expiresDays}
                inputMode="numeric"
                onChange={(event) => setForm((current) => ({ ...current, expiresDays: event.target.value.replace(/\D/g, "").slice(0, 3) }))}
                aria-invalid={expiresInvalid ? true : undefined}
              />
            </Field>
          </div>
          <div className="notice">
            {t("secure.scopesHint")}
          </div>
          <div className="row-between wrap">
            <div className="section-label" style={{ marginBottom: 0 }}>
              {t("secure.scopes")} · {formatNumber(form.scopes.length)}
            </div>
            <div className="row" style={{ gap: 6 }}>
              <Input
                value={scopeSearch}
                onChange={(event) => setScopeSearch(event.target.value)}
                placeholder={t("secure.scopeSearch")}
                aria-label={t("secure.scopeSearch")}
                style={{ width: 190 }}
              />
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setForm((current) => ({ ...current, scopes: visiblePermissions.map((entry) => entry.key) }))}
              >
                {t("secure.selectVisible")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setForm((current) => ({ ...current, scopes: [] }))}>
                {t("secure.clearAll")}
              </Button>
            </div>
          </div>
          {permissionsQuery.isError ? (
            <ErrorBanner compact message={errorMessage(permissionsQuery.error)} onRetry={() => void permissionsQuery.refetch()} />
          ) : (
            <div
              style={{ maxHeight: 260, overflowY: "auto", border: "1px solid var(--border)", borderRadius: 8, padding: 8 }}
              role="group"
              aria-label={t("secure.scopes")}
            >
              {permissionsQuery.isLoading ? (
                <span className="dim" style={{ fontSize: 12 }}>{t("common.loading")}</span>
              ) : visiblePermissions.length === 0 ? (
                <span className="dim" style={{ fontSize: 12 }}>{t("secure.noScopeMatches")}</span>
              ) : (
                visiblePermissions.map((entry) => {
                  const checked = form.scopes.includes(entry.key);
                  return (
                    <label
                      key={entry.key}
                      className="checkbox"
                      style={{ display: "flex", alignItems: "flex-start", gap: 8, padding: "4px 2px", width: "100%" }}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() =>
                          setForm((current) => ({
                            ...current,
                            scopes: checked ? current.scopes.filter((key) => key !== entry.key) : [...current.scopes, entry.key],
                          }))
                        }
                        style={{ marginTop: 2 }}
                      />
                      <span style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                        <span className="mono" style={{ fontSize: 11, color: "var(--text-secondary)" }}>{entry.key}</span>
                        <span style={{ fontSize: 11, color: "var(--dim)" }}>{entry.description}</span>
                      </span>
                    </label>
                  );
                })
              )}
            </div>
          )}
          {formError ? <ErrorBanner compact message={formError} /> : null}
        </div>
      </Modal>

      <Modal
        open={created !== null}
        onClose={() => setCreated(null)}
        title={t("secure.tokenCreated")}
        footer={<Button variant="primary" onClick={() => setCreated(null)}>{t("common.close")}</Button>}
      >
        {created ? (
          <div className="stack">
            <SecretOnce
              label={t("secure.tokenValue")}
              value={created.token}
              warning={t("secure.tokenOnceWarning")}
              testId="security-token-secret"
            />
            <MetaRows
              items={[
                { label: t("secure.tokenName"), value: created.name },
                { label: t("secure.prefix"), value: <span className="mono">{created.prefix}</span> },
                { label: t("secure.expires"), value: created.expires_at ? formatDateTime(created.expires_at, lang) : t("secure.neverExpires") },
                { label: t("secure.scopes"), value: <span className="mono">{formatNumber(created.scopes.length)}</span> },
              ]}
            />
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        onConfirm={() => { if (revoking) revokeMutation.mutate(revoking); }}
        title={t("secure.revokeToken")}
        description={revoking ? `${t("secure.revokeTokenDesc")} · ${revoking.name}` : undefined}
        warning={t("secure.revokeTokenWarning")}
        confirmLabel={t("secure.revoke")}
        cancelLabel={t("common.cancel")}
        busy={revokeMutation.isPending}
        testId="security-token-revoke-confirm"
      />
    </div>
  );
}

/* --------------------------------------------------------------- composite */

export function SecurityCards() {
  const t = useGovernCopy(SECURE_COPY);
  return (
    <div className="stack">
      <Card title={t("secure.session")} subtitle={t("secure.sessionSub")}>
        <SessionSummary />
      </Card>
      <Card title={t("secure.mfa")} subtitle={t("secure.mfaSub")}>
        <MfaPanel />
      </Card>
      <Card title={t("secure.password")} subtitle={t("secure.passwordSub")}>
        <ChangePasswordPanel />
      </Card>
    </div>
  );
}
