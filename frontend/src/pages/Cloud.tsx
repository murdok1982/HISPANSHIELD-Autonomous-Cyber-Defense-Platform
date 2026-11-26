import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Boxes,
  Cloud,
  Database,
  Globe2,
  HardDrive,
  KeyRound,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { api, type Page } from "../lib/api";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatDateTime, formatNumber, humanize, relativeTime } from "../lib/format";
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
  SeverityBadge,
  SeverityBars,
  StatusBadge,
  TableSkeleton,
  type Column,
} from "../components/ui";
import {
  DataQualityNotice,
  PostureHero,
  RecommendationList,
  type PostureSummaryBase,
} from "../components/features/protect/common";

interface CloudAssetRow {
  id: string;
  name: string;
  subtype: string | null;
  provider: string | null;
  criticality: number;
  status: string;
}

interface CloudFinding {
  id: string;
  title: string;
  severity: string;
  asset_id: string | null;
}

interface CloudPosture extends PostureSummaryBase {
  assets: {
    total: number;
    by_provider: Record<string, number>;
    by_subtype: Record<string, number>;
    rows: CloudAssetRow[];
  };
  public_storage_findings: CloudFinding[];
  identity_findings: CloudFinding[];
  vulnerabilities: { open_total: number; by_severity: Record<string, number> };
}

interface AssetRecord {
  id: string;
  name: string;
  kind: string;
  subtype: string | null;
  vendor: string | null;
  metadata: Record<string, unknown>;
}

const copy = {
  es: {
    "eyebrow": "Protección · Cloud",
    "title": "Seguridad cloud",
    "subtitle":
      "Exposición de almacenamiento, identidades con privilegios, vulnerabilidades y distribución de activos cloud calculados desde registros reales.",
    "refreshed": "Actualizado",
    "posture": "Postura cloud",
    "assets": "Activos cloud",
    "assetsHint": "Activos con tipo cloud inventariados por el descubrimiento o de forma manual.",
    "publicStorage": "Storage público",
    "publicStorageHint": "Hallazgos abiertos que describen buckets u objetos accesibles públicamente.",
    "identity": "Identidad y privilegios",
    "identityHint": "Hallazgos abiertos sobre IAM, roles, credenciales o privilegios excesivos.",
    "vulns": "Vulnerabilidades cloud",
    "vulnsHint": "Vulnerabilidades abiertas asociadas a activos de tipo cloud.",
    "providers": "Proveedores",
    "services": "Servicios / subtipos",
    "regions": "Regiones",
    "regionsHint": "Región declarada en los metadatos del activo. Los activos sin región registrada se agrupan como «sin región».",
    "noRegion": "Sin región",
    "noProvider": "Sin proveedor",
    "unknown": "No especificado",
    "publicStorageTable": "Hallazgos de almacenamiento público",
    "identityTable": "Hallazgos de identidad y privilegios",
    "assetsTable": "Inventario cloud",
    "finding": "Hallazgo",
    "asset": "Activo",
    "assetName": "Activo",
    "provider": "Proveedor",
    "service": "Servicio",
    "criticality": "Criticidad",
    "status": "Estado",
    "evidence": "Evidencia",
    "emptyStorage": "Sin hallazgos de storage público",
    "emptyStorageHint": "El descubrimiento no ha encontrado buckets u objetos expuestos.",
    "emptyIdentity": "Sin hallazgos de identidad cloud",
    "emptyIdentityHint": "No se han detectado roles, credenciales o privilegios excesivos.",
    "emptyAssets": "Sin activos cloud inventariados",
    "emptyAssetsHint": "Conecta el proveedor cloud o registra los activos para habilitar la evaluación de postura.",
    "emptyVulns": "Sin vulnerabilidades abiertas en activos cloud",
    "insufficientTitle": "Sin datos suficientes para evaluar la nube",
    "insufficientBody":
      "No hay activos cloud, hallazgos ni vulnerabilidades registradas. Conecta un proveedor para obtener datos verificables.",
    "noScore": "La puntuación se omite mientras no existan datos del dominio.",
    "connect": "Conectar proveedor",
    "goAssets": "Ver activos",
    "goVulns": "Vulnerabilidades",
    "recommendations": "Plan de mejora",
    "recommendationsHint": "Cada recomendación cita el número real de hallazgos o vulnerabilidades que la motiva.",
    "cloudAssets": "Activos",
    "openVulns": "Abiertas",
    "criticalVulns": "Críticas",
    "highVulns": "Altas",
    "open": "abiertas",
    "breakdown": "Distribución cloud",
    "rowsNote": "Muestra de hasta 50 activos devuelta por la API de postura.",
    "lastUpdated": "Última evaluación",
  },
  en: {
    "eyebrow": "Protect · Cloud",
    "title": "Cloud security",
    "subtitle":
      "Storage exposure, privileged identities, vulnerabilities and cloud asset distribution computed from real records.",
    "refreshed": "Updated",
    "posture": "Cloud posture",
    "assets": "Cloud assets",
    "assetsHint": "Assets of kind cloud inventoried by discovery or manually.",
    "publicStorage": "Public storage",
    "publicStorageHint": "Open findings describing publicly reachable buckets or objects.",
    "identity": "Identity & privilege",
    "identityHint": "Open findings about IAM, roles, credentials or excessive privileges.",
    "vulns": "Cloud vulnerabilities",
    "vulnsHint": "Open vulnerabilities linked to cloud assets.",
    "providers": "Providers",
    "services": "Services / subtypes",
    "regions": "Regions",
    "regionsHint": "Region declared in asset metadata. Assets without a recorded region are grouped as “no region”.",
    "noRegion": "No region",
    "noProvider": "No provider",
    "unknown": "Unspecified",
    "publicStorageTable": "Public storage findings",
    "identityTable": "Identity and privilege findings",
    "assetsTable": "Cloud inventory",
    "finding": "Finding",
    "asset": "Asset",
    "assetName": "Asset",
    "provider": "Provider",
    "service": "Service",
    "criticality": "Criticality",
    "status": "Status",
    "evidence": "Evidence",
    "emptyStorage": "No public storage findings",
    "emptyStorageHint": "Discovery has not found exposed buckets or objects.",
    "emptyIdentity": "No cloud identity findings",
    "emptyIdentityHint": "No excessive roles, credentials or privileges were detected.",
    "emptyAssets": "No cloud assets inventoried",
    "emptyAssetsHint": "Connect the cloud provider or register assets to enable posture assessment.",
    "emptyVulns": "No open vulnerabilities on cloud assets",
    "insufficientTitle": "Not enough data to assess the cloud",
    "insufficientBody":
      "No cloud assets, findings or vulnerabilities are recorded. Connect a provider to obtain verifiable data.",
    "noScore": "The score is omitted while no domain data exists.",
    "connect": "Connect provider",
    "goAssets": "View assets",
    "goVulns": "Vulnerabilities",
    "recommendations": "Improvement plan",
    "recommendationsHint": "Every recommendation cites the real number of findings or vulnerabilities behind it.",
    "cloudAssets": "Assets",
    "openVulns": "Open",
    "criticalVulns": "Critical",
    "highVulns": "High",
    "open": "open",
    "breakdown": "Cloud distribution",
    "rowsNote": "Sample of up to 50 assets returned by the posture API.",
    "lastUpdated": "Last assessment",
  },
};

function regionOf(asset: AssetRecord): string {
  const metadata = asset.metadata ?? {};
  for (const key of ["region", "cloud_region", "aws_region", "azure_region", "gcp_region", "location"]) {
    const value = metadata[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function countMap(values: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

function findingColumns(c: (key: string) => string, t: (key: string) => string): Column<CloudFinding>[] {
  return [
    {
      key: "finding",
      header: c("finding"),
      render: (row) => <div style={{ minWidth: 220, color: "var(--text)" }}>{row.title}</div>,
    },
    { key: "severity", header: t("common.severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "asset",
      header: c("asset"),
      width: "190px",
      render: (row) =>
        row.asset_id ? (
          <Link to={`/assets/${row.asset_id}`} className="mono" style={{ fontSize: 11 }}>
            {row.asset_id.slice(0, 8)} <ArrowUpRight size={10} />
          </Link>
        ) : (
          <span className="dim">—</span>
        ),
    },
  ];
}

export function CloudPage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(copy);
  const query = useQuery({
    queryKey: ["posture", "cloud"],
    queryFn: () => api.get<CloudPosture>("/posture/cloud"),
  });
  const regionQuery = useQuery({
    queryKey: ["assets", "cloud", "regions"],
    queryFn: () => api.get<Page<AssetRecord>>("/assets", { kind: "cloud", page: 1, page_size: 200 }),
    enabled: query.isSuccess,
  });

  if (query.isLoading) return <PageSkeleton />;
  if (query.isError || !query.data) {
    return (
      <div data-testid="page-cloud">
        <PageHeader eyebrow={c("eyebrow")} title={c("title")} subtitle={c("subtitle")} />
        <ErrorBanner message={t("errors.retryHint")} onRetry={() => void query.refetch()} />
      </div>
    );
  }

  const data = query.data;
  const insufficient = data.data_quality === "insufficient_data";
  const vulns = data.vulnerabilities.by_severity;
  const providerEntries = Object.entries(data.assets.by_provider).sort(([, a], [, b]) => b - a);
  const serviceEntries = Object.entries(data.assets.by_subtype).sort(([, a], [, b]) => b - a);
  const regions = regionQuery.data
    ? countMap(regionQuery.data.items.map((asset) => regionOf(asset) || c("noRegion")))
    : {};
  const regionEntries = Object.entries(regions).sort(([, a], [, b]) => b - a);
  const findingsColumns = findingColumns(c, t);

  const assetColumns: Column<CloudAssetRow>[] = [
    {
      key: "name",
      header: c("assetName"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <Link to={`/assets/${row.id}`} style={{ color: "var(--text)", fontWeight: 500 }}>{row.name}</Link>
          <div className="cell-sub mono">{row.id.slice(0, 8)}</div>
        </div>
      ),
    },
    {
      key: "provider",
      header: c("provider"),
      width: "140px",
      render: (row) => <span className="tag">{row.provider ?? c("noProvider")}</span>,
    },
    {
      key: "service",
      header: c("service"),
      width: "150px",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.subtype ?? c("unknown")}</span>,
    },
    {
      key: "criticality",
      header: c("criticality"),
      width: "96px",
      align: "center",
      render: (row) => <Badge tone={row.criticality >= 4 ? "danger" : row.criticality >= 3 ? "warning" : "neutral"}>{row.criticality}</Badge>,
    },
    { key: "status", header: c("status"), width: "120px", render: (row) => <StatusBadge status={row.status} /> },
  ];

  return (
    <div className="animate-in" data-testid="page-cloud">
      <PageHeader
        eyebrow={c("eyebrow")}
        title={c("title")}
        subtitle={c("subtitle")}
        actions={
          <>
            <span className="mono hide-mobile" style={{ fontSize: 10, color: "var(--dim)" }}>
              {c("refreshed")} {formatDateTime(data.generated_at, lang)}
            </span>
            <Button icon={RefreshCw} onClick={() => void query.refetch()} aria-label={t("common.refresh")} data-testid="refresh-cloud" />
            <LinkButton to="/assets" icon={Boxes}>{c("goAssets")}</LinkButton>
            <LinkButton to="/integrations" variant="primary" icon={Cloud}>{c("connect")}</LinkButton>
          </>
        }
      />

      <div style={{ marginBottom: 12 }}>
        <DataQualityNotice quality={data.data_quality} />
      </div>

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi
          label={c("assets")}
          value={formatNumber(data.assets.total)}
          icon={Boxes}
          tone="accent"
          footer={<span>{formatNumber(providerEntries.length)} {c("providers").toLowerCase()}</span>}
        />
        <Kpi
          label={c("publicStorage")}
          value={formatNumber(data.public_storage_findings.length)}
          icon={HardDrive}
          tone={data.public_storage_findings.length ? "danger" : "success"}
          footer={<span>{formatNumber(data.assets.by_subtype.bucket ?? data.assets.by_subtype.storage ?? 0)} storage · {formatNumber(data.assets.by_subtype.instance ?? 0)} compute</span>}
        />
        <Kpi
          label={c("identity")}
          value={formatNumber(data.identity_findings.length)}
          icon={KeyRound}
          tone={data.identity_findings.length ? "warning" : "success"}
          footer={<span>{formatNumber(vulns.critical ?? 0)} {c("criticalVulns").toLowerCase()} · {formatNumber(vulns.high ?? 0)} {c("highVulns").toLowerCase()}</span>}
        />
        <Kpi
          label={c("vulns")}
          value={formatNumber(data.vulnerabilities.open_total)}
          icon={TriangleAlert}
          tone={data.vulnerabilities.open_total ? "warning" : "success"}
          footer={<span>{formatNumber(vulns.critical ?? 0)} {t("common.critical").toLowerCase()} · {formatNumber(vulns.high ?? 0)} {t("common.high").toLowerCase()}</span>}
        />
      </div>

      {insufficient ? (
        <Card title={c("posture")}>
          <EmptyState
            icon={ShieldCheck}
            title={c("insufficientTitle")}
            description={c("insufficientBody")}
            action={<LinkButton to="/integrations" size="sm" variant="primary" icon={Cloud}>{c("connect")}</LinkButton>}
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

      <div className="grid-3" style={{ marginBottom: 12 }}>
        <Card title={c("providers")} subtitle={c("breakdown")}>
          {providerEntries.length === 0 ? (
            <EmptyState icon={Cloud} title={c("emptyAssets")} description={c("emptyAssetsHint")} />
          ) : (
            <div className="metric-list">
              {providerEntries.map(([provider, count]) => (
                <div className="metric-row" key={provider}>
                  <span className="metric-label"><Cloud size={13} aria-hidden="true" /> {humanize(provider)}</span>
                  <span className="metric-value">{formatNumber(count)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title={c("services")} subtitle={`${formatNumber(data.assets.total)} ${c("cloudAssets").toLowerCase()}`}>
          {serviceEntries.length === 0 ? (
            <EmptyState icon={Database} title={c("emptyAssets")} description={c("emptyAssetsHint")} />
          ) : (
            <div className="metric-list">
              {serviceEntries.slice(0, 10).map(([service, count]) => (
                <div className="metric-row" key={service}>
                  <span className="metric-label"><Database size={13} aria-hidden="true" /> {humanize(service)}</span>
                  <span className="metric-value">{formatNumber(count)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title={c("regions")} subtitle={c("regionsHint")}>
          {regionQuery.isLoading ? (
            <TableSkeleton rows={4} />
          ) : regionQuery.isError ? (
            <ErrorBanner compact message={t("errors.loadFailed")} onRetry={() => void regionQuery.refetch()} />
          ) : regionEntries.length === 0 ? (
            <EmptyState icon={Globe2} title={c("noRegion")} description={c("emptyAssetsHint")} />
          ) : (
            <div className="metric-list">
              {regionEntries.slice(0, 10).map(([region, count]) => (
                <div className="metric-row" key={region}>
                  <span className="metric-label"><Globe2 size={13} aria-hidden="true" /> {region}</span>
                  <span className="metric-value">{formatNumber(count)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="split-main" style={{ marginBottom: 12 }}>
        <div className="stack">
          <Card title={c("publicStorageTable")} subtitle={c("publicStorageHint")} bodyClassName="">
            <div data-testid="cloud-storage-table">
              <DataTable
                columns={findingsColumns}
                rows={data.public_storage_findings}
                rowKey={(row) => row.id}
                empty={<EmptyState icon={ShieldCheck} title={c("emptyStorage")} description={c("emptyStorageHint")} />}
              />
            </div>
          </Card>

          <Card title={c("identityTable")} subtitle={c("identityHint")} bodyClassName="">
            <div data-testid="cloud-identity-table">
              <DataTable
                columns={findingsColumns}
                rows={data.identity_findings}
                rowKey={(row) => row.id}
                empty={<EmptyState icon={KeyRound} title={c("emptyIdentity")} description={c("emptyIdentityHint")} />}
              />
            </div>
          </Card>

          <Card title={c("assetsTable")} subtitle={c("rowsNote")} bodyClassName="">
            <div data-testid="cloud-assets-table">
              <DataTable
                columns={assetColumns}
                rows={data.assets.rows}
                rowKey={(row) => row.id}
                empty={
                  <EmptyState
                    icon={Boxes}
                    title={c("emptyAssets")}
                    description={c("emptyAssetsHint")}
                    action={<LinkButton to="/integrations" size="sm">{c("connect")}</LinkButton>}
                  />
                }
              />
            </div>
          </Card>
        </div>

        <div className="stack">
          <Card title={c("vulns")} subtitle={c("vulnsHint")} actions={<Badge tone={vulns.critical ? "critical" : "neutral"}>{formatNumber(data.vulnerabilities.open_total)} {c("open")}</Badge>}>
            {data.vulnerabilities.open_total === 0 ? (
              <EmptyState icon={ShieldCheck} title={c("emptyVulns")} />
            ) : (
              <SeverityBars
                data={["critical", "high", "medium", "low"].map((severity) => ({
                  label: t(`common.${severity}`),
                  value: vulns[severity] ?? 0,
                  color: severity === "critical" ? "var(--critical)" : severity === "high" ? "var(--danger)" : severity === "medium" ? "var(--warning)" : "var(--accent)",
                }))}
              />
            )}
            <div style={{ marginTop: 10 }}>
              <LinkButton to="/vulnerabilities" size="sm" variant="ghost" icon={TriangleAlert}>{c("goVulns")}</LinkButton>
            </div>
          </Card>

          <Card title={c("recommendations")} subtitle={c("recommendationsHint")} bodyClassName="card-body">
            <RecommendationList recommendations={data.recommendations} />
          </Card>
        </div>
      </div>

      <div className="notice" style={{ fontSize: 11 }}>
        <ShieldAlert size={14} style={{ flex: "0 0 auto", color: "var(--warning)" }} />
        <span>
          {c("lastUpdated")}: {relativeTime(data.generated_at, lang)} · {formatNumber(data.public_storage_findings.length)} storage ·{" "}
          {formatNumber(data.identity_findings.length)} {c("identity").toLowerCase()} · {formatNumber(data.vulnerabilities.open_total)} {c("openVulns").toLowerCase()}
        </span>
        <Link to="/assets" style={{ marginLeft: "auto", fontSize: 11 }}>
          {c("goAssets")} <ArrowUpRight size={11} />
        </Link>
      </div>
    </div>
  );
}

export default CloudPage;
