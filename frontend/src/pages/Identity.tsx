import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  BadgeCheck,
  Fingerprint,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  ShieldQuestion,
  UserCog,
  UserX,
  Users,
} from "lucide-react";
import { api } from "../lib/api";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatDateTime, formatNumber, relativeTime } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
  Kpi,
  LinkButton,
  PageHeader,
  PageSkeleton,
  ProgressBar,
  SeverityBadge,
  StatusBadge,
  type Column,
} from "../components/ui";
import {
  AdoptionMeter,
  DataQualityNotice,
  PostureHero,
  RecommendationList,
  type PostureSummaryBase,
} from "../components/features/protect/common";

interface IdentityAssetRow {
  id: string;
  name: string;
  subtype: string | null;
  criticality: number;
}

interface FailedUser {
  user_name: string;
  count: number;
}

interface IdentityAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  mitre: string[];
}

interface IdentityFinding {
  id: string;
  title: string;
  severity: string;
}

interface IdentityPosture extends PostureSummaryBase {
  identities: {
    assets: number;
    members: number;
    mfa_enabled: number;
    mfa_percent: number;
    rows: IdentityAssetRow[];
  };
  failed_logins: {
    window_days: number;
    total: number;
    top_users: FailedUser[];
  };
  identity_alerts: IdentityAlert[];
  identity_findings: IdentityFinding[];
}

const PRIVILEGED_TOKENS = ["admin", "privileged", "root", "superuser", "service", "system", "breakglass"];

const copy = {
  es: {
    "eyebrow": "Protección · Identidad",
    "title": "Seguridad de identidad",
    "subtitle":
      "Adopción de MFA sobre los registros reales de usuarios, identidades privilegiadas inventariadas y abuso de autenticación observado en la telemetría.",
    "refreshed": "Actualizado",
    "posture": "Postura de identidad",
    "mfa": "Adopción de MFA",
    "mfaHint": "Calculada a partir de los miembros activos de la organización y su campo mfa_enabled.",
    "members": "Miembros activos",
    "withMfa": "Con MFA",
    "withoutMfa": "Sin MFA",
    "mfaPercent": "Cobertura MFA",
    "computedNote":
      "La cobertura se calcula server-side sumando los usuarios activos con MFA habilitado y dividiéndolos entre los miembros activos. No se estima ni se simula.",
    "manageMembers": "Gestionar miembros",
    "privileged": "Identidades privilegiadas",
    "privilegedHint":
      "Activos de tipo identidad cuyo subtipo registrado indica privilegio (admin, root, service, breakglass…). La clasificación se deriva del subtipo real, no de una suposición.",
    "identityAssets": "Activos de identidad",
    "identityAssetsHint": "Cuentas y entidades de identidad inventariadas por el descubrimiento.",
    "failed": "Fallos de autenticación",
    "failedHint": "Eventos de inicio de sesión fallido en los últimos {days} días.",
    "window": "Ventana",
    "total": "Total",
    "topUsers": "Usuarios con más fallos",
    "noFailed": "Sin fallos de autenticación en la ventana",
    "alertTitle": "Alertas de identidad",
    "alertHint": "Alertas abiertas sobre cuentas válidas, fuerza bruta, MFA o credenciales.",
    "findingTitle": "Hallazgos de identidad",
    "findingHint": "Hallazgos abiertos sobre IAM, privilegios o cuentas obsoletas.",
    "assetsTable": "Identidades inventariadas",
    "asset": "Identidad",
    "subtype": "Subtipo",
    "criticality": "Criticidad",
    "privilegedFlag": "Privilegiada",
    "alert": "Alerta",
    "severity": "Severidad",
    "status": "Estado",
    "techniques": "Técnicas",
    "user": "Usuario",
    "count": "Fallos",
    "emptyAssets": "Sin activos de identidad inventariados",
    "emptyAssetsHint": "Conecta el proveedor de identidad o registra cuentas para medir privilegios.",
    "emptyAlerts": "Sin alertas de identidad abiertas",
    "emptyAlertsHint": "La correlación no ha detectado abuso de credenciales o cuentas válidas.",
    "emptyFindings": "Sin hallazgos de identidad abiertos",
    "emptyFindingsHint": "El descubrimiento no ha registrado privilegios excesivos ni cuentas obsoletas.",
    "insufficientTitle": "Sin datos suficientes para evaluar la identidad",
    "insufficientBody":
      "No hay miembros, activos de identidad ni fallos de autenticación registrados. Conecta el proveedor de identidad para obtener una postura verificable.",
    "noScore": "La puntuación se omite mientras no existan datos del dominio.",
    "recommendations": "Plan de mejora",
    "recommendationsHint": "Cada recomendación cita los usuarios, alertas o hallazgos reales que la justifican.",
    "goAdmin": "Miembros de la organización",
    "goIncidents": "Incidentes",
    "goAssets": "Ver identidades",
    "derived": "Derivado del subtipo registrado",
    "coverage": "Cobertura",
    "noSubtype": "Sin subtipo",
    "lastUpdated": "Última evaluación",
    "mfaMissing": "{count} miembros sin segundo factor",
  },
  en: {
    "eyebrow": "Protect · Identity",
    "title": "Identity security",
    "subtitle":
      "MFA adoption over real user records, inventoried privileged identities and authentication abuse observed in telemetry.",
    "refreshed": "Updated",
    "posture": "Identity posture",
    "mfa": "MFA adoption",
    "mfaHint": "Computed from active organization members and their mfa_enabled field.",
    "members": "Active members",
    "withMfa": "With MFA",
    "withoutMfa": "Without MFA",
    "mfaPercent": "MFA coverage",
    "computedNote":
      "Coverage is computed server-side by dividing active users with MFA enabled by active members. It is never estimated or simulated.",
    "manageMembers": "Manage members",
    "privileged": "Privileged identities",
    "privilegedHint":
      "Identity assets whose recorded subtype indicates privilege (admin, root, service, breakglass…). Classification is derived from the real subtype, not assumed.",
    "identityAssets": "Identity assets",
    "identityAssetsHint": "Accounts and identity entities inventoried by discovery.",
    "failed": "Authentication failures",
    "failedHint": "Failed login events over the last {days} days.",
    "window": "Window",
    "total": "Total",
    "topUsers": "Users with the most failures",
    "noFailed": "No authentication failures in the window",
    "alertTitle": "Identity alerts",
    "alertHint": "Open alerts about valid accounts, brute force, MFA or credentials.",
    "findingTitle": "Identity findings",
    "findingHint": "Open findings about IAM, privileges or stale accounts.",
    "assetsTable": "Inventoried identities",
    "asset": "Identity",
    "subtype": "Subtype",
    "criticality": "Criticality",
    "privilegedFlag": "Privileged",
    "alert": "Alert",
    "severity": "Severity",
    "status": "Status",
    "techniques": "Techniques",
    "user": "User",
    "count": "Failures",
    "emptyAssets": "No identity assets inventoried",
    "emptyAssetsHint": "Connect the identity provider or register accounts to measure privileges.",
    "emptyAlerts": "No open identity alerts",
    "emptyAlertsHint": "Correlation has not detected credential or valid-account abuse.",
    "emptyFindings": "No open identity findings",
    "emptyFindingsHint": "Discovery has not recorded excessive privileges or stale accounts.",
    "insufficientTitle": "Not enough data to assess identity",
    "insufficientBody":
      "No members, identity assets or authentication failures are recorded. Connect the identity provider to obtain a verifiable posture.",
    "noScore": "The score is omitted while no domain data exists.",
    "recommendations": "Improvement plan",
    "recommendationsHint": "Every recommendation cites the real users, alerts or findings behind it.",
    "goAdmin": "Organization members",
    "goIncidents": "Incidents",
    "goAssets": "View identities",
    "derived": "Derived from recorded subtype",
    "coverage": "Coverage",
    "noSubtype": "No subtype",
    "lastUpdated": "Last assessment",
    "mfaMissing": "{count} members without a second factor",
  },
};

function isPrivileged(row: IdentityAssetRow): boolean {
  const subtype = (row.subtype ?? "").toLowerCase();
  const name = row.name.toLowerCase();
  return PRIVILEGED_TOKENS.some((token) => subtype.includes(token) || name.includes(token));
}

export function IdentityPage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(copy);
  const query = useQuery({
    queryKey: ["posture", "identity"],
    queryFn: () => api.get<IdentityPosture>("/posture/identity"),
  });

  if (query.isLoading) return <PageSkeleton />;
  if (query.isError || !query.data) {
    return (
      <div data-testid="page-identity">
        <PageHeader eyebrow={c("eyebrow")} title={c("title")} subtitle={c("subtitle")} />
        <ErrorBanner message={t("errors.retryHint")} onRetry={() => void query.refetch()} />
      </div>
    );
  }

  const data = query.data;
  const insufficient = data.data_quality === "insufficient_data";
  const privilegedRows = data.identities.rows.filter(isPrivileged);
  const withoutMfa = Math.max(0, data.identities.members - data.identities.mfa_enabled);

  const assetColumns: Column<IdentityAssetRow>[] = [
    {
      key: "name",
      header: c("asset"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <Link to={`/assets/${row.id}`} style={{ color: "var(--text)", fontWeight: 500 }}>{row.name}</Link>
          <div className="cell-sub mono">{row.id.slice(0, 8)}</div>
        </div>
      ),
    },
    {
      key: "subtype",
      header: c("subtype"),
      width: "170px",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.subtype ?? c("noSubtype")}</span>,
    },
    {
      key: "criticality",
      header: c("criticality"),
      width: "96px",
      align: "center",
      render: (row) => <Badge tone={row.criticality >= 4 ? "danger" : row.criticality >= 3 ? "warning" : "neutral"}>{row.criticality}</Badge>,
    },
    {
      key: "privileged",
      header: c("privilegedFlag"),
      width: "130px",
      render: (row) => (isPrivileged(row) ? <Badge tone="warning">{c("privilegedFlag")}</Badge> : <span className="dim">—</span>),
    },
  ];

  const alertColumns: Column<IdentityAlert>[] = [
    {
      key: "title",
      header: c("alert"),
      render: (row) => <div style={{ minWidth: 220, color: "var(--text)" }}>{row.title}</div>,
    },
    { key: "severity", header: c("severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: c("status"), width: "128px", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "mitre",
      header: c("techniques"),
      width: "180px",
      render: (row) => (
        <div className="chip-row">
          {row.mitre.length ? row.mitre.slice(0, 3).map((technique) => <span className="tag" key={technique}>{technique}</span>) : <span className="dim">—</span>}
        </div>
      ),
    },
  ];

  const failedColumns: Column<FailedUser>[] = [
    { key: "user", header: c("user"), render: (row) => <span className="mono">{row.user_name}</span> },
    {
      key: "count",
      header: c("count"),
      width: "90px",
      align: "right",
      render: (row) => <span className="mono" style={{ color: "var(--danger)" }}>{formatNumber(row.count)}</span>,
    },
  ];

  return (
    <div className="animate-in" data-testid="page-identity">
      <PageHeader
        eyebrow={c("eyebrow")}
        title={c("title")}
        subtitle={c("subtitle")}
        actions={
          <>
            <span className="mono hide-mobile" style={{ fontSize: 10, color: "var(--dim)" }}>
              {c("refreshed")} {formatDateTime(data.generated_at, lang)}
            </span>
            <Button icon={RefreshCw} onClick={() => void query.refetch()} aria-label={t("common.refresh")} data-testid="refresh-identity" />
            <LinkButton to="/incidents" icon={Fingerprint}>{c("goIncidents")}</LinkButton>
            <LinkButton to="/admin" variant="primary" icon={UserCog}>{c("manageMembers")}</LinkButton>
          </>
        }
      />

      <div style={{ marginBottom: 12 }}>
        <DataQualityNotice quality={data.data_quality} />
      </div>

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi
          label={c("mfaPercent")}
          value={data.identities.mfa_percent.toFixed(1)}
          suffix="%"
          icon={BadgeCheck}
          tone={data.identities.mfa_percent >= 100 ? "success" : data.identities.mfa_percent >= 50 ? "warning" : "danger"}
          footer={<span>{formatNumber(data.identities.mfa_enabled)}/{formatNumber(data.identities.members)} {c("withMfa").toLowerCase()}</span>}
        />
        <Kpi
          label={c("privileged")}
          value={formatNumber(privilegedRows.length)}
          icon={KeyRound}
          tone={privilegedRows.length ? "warning" : "success"}
          footer={<span>{c("derived")}</span>}
        />
        <Kpi
          label={c("failed")}
          value={formatNumber(data.failed_logins.total)}
          icon={UserX}
          tone={data.failed_logins.total ? "danger" : "success"}
          footer={<span>{data.failed_logins.window_days} d · {formatNumber(data.identity_alerts.length)} {c("alertTitle").toLowerCase()}</span>}
        />
        <Kpi
          label={c("identityAssets")}
          value={formatNumber(data.identities.assets)}
          icon={Fingerprint}
          tone="accent"
          footer={<span>{formatNumber(data.identities.members)} {c("members").toLowerCase()}</span>}
        />
      </div>

      {insufficient ? (
        <Card title={c("posture")}>
          <EmptyState
            icon={ShieldQuestion}
            title={c("insufficientTitle")}
            description={c("insufficientBody")}
            action={<LinkButton to="/admin" size="sm" variant="primary" icon={UserCog}>{c("manageMembers")}</LinkButton>}
          />
          <div className="notice" style={{ marginTop: 10 }}>{c("noScore")}</div>
        </Card>
      ) : (
        <div style={{ marginBottom: 12 }}>
          <PostureHero
            score={data.score}
            level={data.level}
            quality={data.data_quality}
            factors={data.factors}
            generatedAt={data.generated_at}
          />
        </div>
      )}

      <div className="split-main" style={{ marginBottom: 12 }}>
        <div className="stack">
          <Card
            title={c("mfa")}
            subtitle={c("mfaHint")}
            actions={<Badge tone={data.identities.mfa_percent >= 100 ? "success" : "warning"}>{c("coverage")}</Badge>}
          >
            <div className="row wrap" style={{ gap: 22, alignItems: "flex-start" }}>
              <div style={{ flex: "1 1 240px", minWidth: 220 }}>
                <AdoptionMeter
                  value={data.identities.mfa_percent}
                  label={c("mfaPercent")}
                  hint={c("mfaMissing").replace("{count}", String(withoutMfa))}
                />
                <div className="stat-inline" style={{ marginTop: 14 }}>
                  <div>
                    <span className="label">{c("members")}</span>
                    <span className="value">{formatNumber(data.identities.members)}</span>
                  </div>
                  <div>
                    <span className="label">{c("withMfa")}</span>
                    <span className="value" style={{ color: "var(--success)" }}>{formatNumber(data.identities.mfa_enabled)}</span>
                  </div>
                  <div>
                    <span className="label">{c("withoutMfa")}</span>
                    <span className="value" style={{ color: withoutMfa ? "var(--danger)" : "var(--success)" }}>{formatNumber(withoutMfa)}</span>
                  </div>
                </div>
              </div>
              <div className="notice notice-accent" style={{ flex: "1 1 220px", fontSize: 11.5 }}>
                <ShieldCheck size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
                <span>{c("computedNote")}</span>
              </div>
            </div>
            <div style={{ marginTop: 10 }}>
              <ProgressBar value={data.identities.mfa_percent} tone={data.identities.mfa_percent >= 100 ? "var(--success)" : "var(--warning)"} />
            </div>
            <div style={{ marginTop: 10 }}>
              <LinkButton to="/admin" size="sm" variant="ghost" icon={Users}>{c("goAdmin")}</LinkButton>
            </div>
          </Card>

          <Card title={c("assetsTable")} subtitle={c("identityAssetsHint")} bodyClassName="">
            <div data-testid="identity-assets-table">
              <DataTable
                columns={assetColumns}
                rows={data.identities.rows}
                rowKey={(row) => row.id}
                empty={
                  <EmptyState
                    icon={Fingerprint}
                    title={c("emptyAssets")}
                    description={c("emptyAssetsHint")}
                    action={<LinkButton to="/assets" size="sm">{c("goAssets")}</LinkButton>}
                  />
                }
              />
            </div>
          </Card>

          <Card title={c("findingTitle")} subtitle={c("findingHint")}>
            {data.identity_findings.length === 0 ? (
              <EmptyState icon={ShieldCheck} title={c("emptyFindings")} description={c("emptyFindingsHint")} />
            ) : (
              <div className="metric-list" data-testid="identity-findings">
                {data.identity_findings.map((finding) => (
                  <div className="metric-row" key={finding.id}>
                    <span className="metric-label" style={{ color: "var(--text-secondary)" }}>{finding.title}</span>
                    <SeverityBadge severity={finding.severity} />
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

        <div className="stack">
          <Card
            title={c("failed")}
            subtitle={c("failedHint").replace("{days}", String(data.failed_logins.window_days))}
            actions={<Badge tone={data.failed_logins.total ? "danger" : "success"}>{formatNumber(data.failed_logins.total)}</Badge>}
          >
            {data.failed_logins.total === 0 ? (
              <EmptyState icon={ShieldCheck} title={c("noFailed")} />
            ) : (
              <>
                <div className="stat-inline" style={{ marginBottom: 10 }}>
                  <div>
                    <span className="label">{c("total")}</span>
                    <span className="value" style={{ color: "var(--danger)" }}>{formatNumber(data.failed_logins.total)}</span>
                  </div>
                  <div>
                    <span className="label">{c("window")}</span>
                    <span className="value">{data.failed_logins.window_days} d</span>
                  </div>
                </div>
                <div className="section-label">{c("topUsers")}</div>
                <div data-testid="identity-failed-users">
                  <DataTable
                    columns={failedColumns}
                    rows={data.failed_logins.top_users}
                    rowKey={(row) => row.user_name}
                    empty={<EmptyState icon={ShieldCheck} title={c("noFailed")} />}
                  />
                </div>
              </>
            )}
          </Card>

          <Card title={c("alertTitle")} subtitle={c("alertHint")} bodyClassName="">
            <div data-testid="identity-alerts-table">
              <DataTable
                columns={alertColumns}
                rows={data.identity_alerts}
                rowKey={(row) => row.id}
                empty={<EmptyState icon={ShieldCheck} title={c("emptyAlerts")} description={c("emptyAlertsHint")} />}
              />
            </div>
          </Card>
        </div>
      </div>

      <div style={{ marginBottom: 12 }}>
        <Card title={c("recommendations")} subtitle={c("recommendationsHint")} bodyClassName="card-body">
          <RecommendationList recommendations={data.recommendations} />
        </Card>
      </div>

      <div className="notice" style={{ fontSize: 11 }}>
        <BadgeCheck size={14} style={{ flex: "0 0 auto", color: "var(--success)" }} />
        <span>
          {c("lastUpdated")}: {relativeTime(data.generated_at, lang)} · {c("mfaPercent")} {data.identities.mfa_percent.toFixed(1)}% ·{" "}
          {formatNumber(privilegedRows.length)} {c("privileged").toLowerCase()} · {formatNumber(data.failed_logins.total)} {c("failed").toLowerCase()}
        </span>
        <Link to="/admin" style={{ marginLeft: "auto", fontSize: 11 }}>
          {c("manageMembers")} <ArrowUpRight size={11} />
        </Link>
      </div>
    </div>
  );
}

export default IdentityPage;
