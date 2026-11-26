import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowUpRight,
  Cable,
  Crosshair,
  GitBranch,
  Network,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Siren,
} from "lucide-react";
import { api } from "../lib/api";
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
  StatusBadge,
  type Column,
} from "../components/ui";
import {
  DataQualityNotice,
  PostureHero,
  RecommendationList,
  type PostureSummaryBase,
} from "../components/features/protect/common";

interface NetworkAssetRow {
  id: string;
  name: string;
  kind: string;
  criticality: number;
  ip_addresses: string[];
  zone_id: string | null;
}

interface ExposureFinding {
  id: string;
  kind: string;
  title: string;
  severity: string;
  asset_id: string | null;
  last_seen: string;
}

interface LateralAlert {
  id: string;
  title: string;
  severity: string;
  count: number;
  mitre: string[];
  last_seen: string;
}

interface SegmentationGap {
  kind: string;
  count: number;
  asset_ids?: string[];
  zone_ids?: string[];
  purdue_levels?: number[];
}

interface NetworkPosture extends PostureSummaryBase {
  assets: {
    total: number;
    by_kind: Record<string, number>;
    with_ip_addresses: number;
    criticality_counts: Record<string, number>;
    rows: NetworkAssetRow[];
  };
  exposed_findings: ExposureFinding[];
  lateral_movement_alerts: LateralAlert[];
  zones: {
    total: number;
    conduits: number;
    purdue_levels: number[];
    segmentation_gaps: SegmentationGap[];
  };
  connectors: {
    network_total: number;
    by_status: Record<string, number>;
    degraded_ids: string[];
  };
}

const copy = {
  es: {
    "eyebrow": "Protección · Red",
    "title": "Seguridad de red",
    "subtitle":
      "Exposición de servicios, higiene de segmentación y señales de movimiento lateral derivadas de activos, hallazgos, zonas y alertas reales.",
    "refreshed": "Actualizado",
    "exposed": "Hallazgos de exposición",
    "exposedHint": "Hallazgos abiertos que describen puertos, servicios o exposición pública.",
    "lateral": "Alertas de movimiento lateral",
    "lateralHint": "Alertas abiertas que citan técnicas ATT&CK de desplazamiento lateral.",
    "gaps": "Brechas de segmentación",
    "gapsHint": "Activos OT sin zona, conductos sin nivel de seguridad o ausencia de conducto IT/OT.",
    "assets": "Activos de red",
    "assetsHint": "Activos inventariados con tipo network/ip y direcciones IP registradas.",
    "posture": "Postura de red",
    "recommendations": "Plan de mejora",
    "recommendationsHint": "Cada tarjeta cita el número real de hallazgos, alertas o conectores que la justifica.",
    "assetsByKind": "Activos por subtipo",
    "criticality": "Distribución por criticidad",
    "withIp": "Con direcciones IP",
    "withoutIp": "Sin direcciones IP",
    "zones": "Zonas y conductos",
    "purdue": "Niveles Purdue documentados",
    "conduits": "Conductos",
    "zoneTotal": "Zonas",
    "noGaps": "Sin brechas de segmentación detectadas en los datos actuales",
    "gapsEmptyHint": "Asigna zonas a los activos OT y declara conductos con un nivel de seguridad requerido.",
    "gap.unzoned_ot_assets": "Activos OT sin zona asignada",
    "gap.conduit_without_required_sl": "Conductos sin nivel de seguridad requerido",
    "gap.missing_it_ot_conduit": "Sin conducto declarado entre niveles Purdue IT y OT",
    "connectors": "Salud de firewall / IDS",
    "connectorTotal": "Conectores de red",
    "degraded": "Degradados",
    "noConnectors": "Sin conectores de red registrados",
    "noConnectorsHint": "Configura un firewall, IDS/IPS o sensor de red para medir visibilidad y control.",
    "exposedTable": "Servicios y hallazgos de exposición",
    "finding": "Hallazgo",
    "asset": "Activo",
    "lastSeen": "Última observación",
    "lateralTable": "Alertas de movimiento lateral",
    "alert": "Alerta",
    "techniques": "Técnicas",
    "count": "Eventos",
    "emptyExposed": "No hay hallazgos de exposición abiertos",
    "emptyExposedHint": "El descubrimiento no ha registrado servicios expuestos en este momento.",
    "emptyLateral": "No hay alertas de movimiento lateral abiertas",
    "emptyLateralHint": "La correlación no ha detectado técnicas de desplazamiento lateral activas.",
    "goAssets": "Ver activos",
    "goSurface": "Superficie de ataque",
    "goVulns": "Vulnerabilidades",
    "editAsset": "Abrir activo",
    "insufficientTitle": "Sin datos suficientes para puntuar la red",
    "insufficientBody":
      "Inventaría activos de red, conecta un firewall/IDS y registra hallazgos para obtener una postura verificable.",
    "noScore": "La puntuación se omite mientras no existan fuentes de datos del dominio.",
    "assetsEmpty": "Sin activos de red inventariados",
    "assetsEmptyHint": "Registra hosts, rangos o dispositivos de red para empezar a medir exposición.",
    "evidenced": "Evidencia citada",
    "state": "Estado",
    "networkRows": "Activos con dirección IP",
    "rowsNote": "Muestra de hasta 50 activos de red devuelta por la API de postura.",
    "noRows": "Sin filas de activos en la muestra",
  },
  en: {
    "eyebrow": "Protect · Network",
    "title": "Network security",
    "subtitle":
      "Service exposure, segmentation hygiene and lateral movement signals derived from real assets, findings, zones and alerts.",
    "refreshed": "Updated",
    "exposed": "Exposure findings",
    "exposedHint": "Open findings describing ports, services or public exposure.",
    "lateral": "Lateral movement alerts",
    "lateralHint": "Open alerts referencing ATT&CK lateral movement techniques.",
    "gaps": "Segmentation gaps",
    "gapsHint": "OT assets without a zone, conduits without a security level, or a missing IT/OT conduit.",
    "assets": "Network assets",
    "assetsHint": "Inventoried assets of kind network/ip with recorded IP addresses.",
    "posture": "Network posture",
    "recommendations": "Improvement plan",
    "recommendationsHint": "Every card cites the real number of findings, alerts or connectors behind it.",
    "assetsByKind": "Assets by subtype",
    "criticality": "Criticality distribution",
    "withIp": "With IP addresses",
    "withoutIp": "Without IP addresses",
    "zones": "Zones and conduits",
    "purdue": "Documented Purdue levels",
    "conduits": "Conduits",
    "zoneTotal": "Zones",
    "noGaps": "No segmentation gaps detected in the current data",
    "gapsEmptyHint": "Assign OT assets to zones and declare conduits with a required security level.",
    "gap.unzoned_ot_assets": "OT assets without an assigned zone",
    "gap.conduit_without_required_sl": "Conduits without a required security level",
    "gap.missing_it_ot_conduit": "No declared conduit between Purdue IT and OT levels",
    "connectors": "Firewall / IDS health",
    "connectorTotal": "Network connectors",
    "degraded": "Degraded",
    "noConnectors": "No network connectors registered",
    "noConnectorsHint": "Configure a firewall, IDS/IPS or network sensor to measure visibility and control.",
    "exposedTable": "Exposed services and findings",
    "finding": "Finding",
    "asset": "Asset",
    "lastSeen": "Last seen",
    "lateralTable": "Lateral movement alerts",
    "alert": "Alert",
    "techniques": "Techniques",
    "count": "Events",
    "emptyExposed": "No open exposure findings",
    "emptyExposedHint": "Discovery has not recorded exposed services at this time.",
    "emptyLateral": "No open lateral movement alerts",
    "emptyLateralHint": "Correlation has not detected active lateral movement techniques.",
    "goAssets": "View assets",
    "goSurface": "Attack surface",
    "goVulns": "Vulnerabilities",
    "editAsset": "Open asset",
    "insufficientTitle": "Not enough data to score the network",
    "insufficientBody":
      "Inventory network assets, connect a firewall/IDS and record findings to obtain a verifiable posture.",
    "noScore": "The score is omitted while no domain data sources exist.",
    "assetsEmpty": "No network assets inventoried",
    "assetsEmptyHint": "Register hosts, ranges or network devices to start measuring exposure.",
    "evidenced": "Cited evidence",
    "state": "Status",
    "networkRows": "Assets with an IP address",
    "rowsNote": "Sample of up to 50 network assets returned by the posture API.",
    "noRows": "No asset rows in the sample",
  },
};

function gapLabel(kind: string, c: (key: string) => string): string {
  return c(`gap.${kind}`);
}

export function NetworkPage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(copy);
  const query = useQuery({
    queryKey: ["posture", "network"],
    queryFn: () => api.get<NetworkPosture>("/posture/network"),
  });

  if (query.isLoading) return <PageSkeleton />;
  if (query.isError || !query.data) {
    return (
      <div data-testid="page-network">
        <PageHeader eyebrow={c("eyebrow")} title={c("title")} subtitle={c("subtitle")} />
        <ErrorBanner message={t("errors.retryHint")} onRetry={() => void query.refetch()} />
      </div>
    );
  }

  const data = query.data;
  const insufficient = data.data_quality === "insufficient_data";
  const findings = data.exposed_findings;
  const lateral = data.lateral_movement_alerts;
  const gaps = data.zones.segmentation_gaps;
  const kindEntries = Object.entries(data.assets.by_kind);
  const criticalityEntries = Object.entries(data.assets.criticality_counts);
  const connectorStatuses = Object.entries(data.connectors.by_status);
  const assetRows = data.assets.rows.filter((asset) => asset.ip_addresses.length > 0);

  const findingColumns: Column<ExposureFinding>[] = [
    {
      key: "finding",
      header: c("finding"),
      render: (row) => (
        <div style={{ minWidth: 220 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.title}</div>
          <div className="cell-sub mono">{row.kind}</div>
        </div>
      ),
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
    {
      key: "last",
      header: c("lastSeen"),
      width: "140px",
      align: "right",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)" }}>
          {relativeTime(row.last_seen, lang)}
        </span>
      ),
    },
  ];

  const lateralColumns: Column<LateralAlert>[] = [
    {
      key: "alert",
      header: c("alert"),
      render: (row) => (
        <div style={{ minWidth: 220 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.title}</div>
          <div className="cell-sub">{relativeTime(row.last_seen, lang)}</div>
        </div>
      ),
    },
    { key: "severity", header: t("common.severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "count",
      header: c("count"),
      width: "88px",
      align: "right",
      render: (row) => <span className="mono">{formatNumber(row.count)}</span>,
    },
    {
      key: "mitre",
      header: c("techniques"),
      width: "200px",
      render: (row) => (
        <div className="chip-row">
          {row.mitre.length ? row.mitre.slice(0, 3).map((technique) => <span className="tag" key={technique}>{technique}</span>) : <span className="dim">—</span>}
        </div>
      ),
    },
  ];

  return (
    <div className="animate-in" data-testid="page-network">
      <PageHeader
        eyebrow={c("eyebrow")}
        title={c("title")}
        subtitle={c("subtitle")}
        actions={
          <>
            <span className="mono hide-mobile" style={{ fontSize: 10, color: "var(--dim)" }}>
              {c("refreshed")} {formatDateTime(data.generated_at, lang)}
            </span>
            <Button icon={RefreshCw} onClick={() => void query.refetch()} aria-label={t("common.refresh")} data-testid="refresh-network" />
            <LinkButton to="/assets" icon={Server}>{c("goAssets")}</LinkButton>
            <LinkButton to="/attack-surface" variant="primary" icon={Crosshair}>{c("goSurface")}</LinkButton>
          </>
        }
      />

      <div style={{ marginBottom: 12 }}>
        <DataQualityNotice quality={data.data_quality} />
      </div>

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi
          label={c("exposed")}
          value={formatNumber(findings.length)}
          icon={ShieldAlert}
          tone={findings.some((item) => item.severity === "critical") ? "danger" : findings.length ? "warning" : "success"}
          footer={<span>{formatNumber(data.assets.with_ip_addresses)} {c("withIp").toLowerCase()}</span>}
        />
        <Kpi
          label={c("lateral")}
          value={formatNumber(lateral.length)}
          icon={Siren}
          tone={lateral.length ? "danger" : "success"}
          footer={<span>{formatNumber(lateral.reduce((total, item) => total + item.count, 0))} {c("count").toLowerCase()}</span>}
        />
        <Kpi
          label={c("gaps")}
          value={formatNumber(gaps.length)}
          icon={GitBranch}
          tone={gaps.length ? "warning" : "success"}
          footer={<span>{formatNumber(data.zones.total)} {c("zoneTotal").toLowerCase()} · {formatNumber(data.zones.conduits)} {c("conduits").toLowerCase()}</span>}
        />
        <Kpi
          label={c("assets")}
          value={formatNumber(data.assets.total)}
          icon={Network}
          tone="accent"
          footer={<span>{formatNumber(data.assets.by_kind.network ?? 0)} network · {formatNumber(data.assets.by_kind.ip ?? 0)} ip</span>}
        />
      </div>

      {insufficient ? (
        <Card title={c("posture")} bodyClassName="card-body">
          <EmptyState
            icon={ShieldCheck}
            title={c("insufficientTitle")}
            description={c("insufficientBody")}
            action={<LinkButton to="/assets" size="sm" variant="primary" icon={Server}>{c("goAssets")}</LinkButton>}
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
        <Card title={c("assetsByKind")} subtitle={`${formatNumber(data.assets.total)} ${c("assets").toLowerCase()}`}>
          {kindEntries.length === 0 ? (
            <EmptyState icon={Server} title={c("assetsEmpty")} description={c("assetsEmptyHint")} />
          ) : (
            <div className="metric-list">
              {kindEntries.map(([kind, count]) => (
                <div className="metric-row" key={kind}>
                  <span className="metric-label"><Activity size={13} aria-hidden="true" /> {humanize(kind)}</span>
                  <span className="metric-value">{formatNumber(count)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title={c("criticality")}>
          {criticalityEntries.length === 0 ? (
            <EmptyState icon={ShieldCheck} title={c("noRows")} />
          ) : (
            <div className="metric-list">
              {criticalityEntries
                .sort(([a], [b]) => Number(b) - Number(a))
                .map(([level, count]) => (
                  <div className="metric-row" key={level}>
                    <span className="metric-label">
                      {t(
                        Number(level) >= 5
                          ? "common.critical"
                          : Number(level) === 4
                            ? "common.high"
                            : Number(level) === 3
                              ? "common.medium"
                              : Number(level) === 2
                                ? "common.low"
                                : "common.info",
                      )}
                    </span>
                    <span className="metric-value">{formatNumber(count)}</span>
                  </div>
                ))}
            </div>
          )}
          <div className="divider" />
          <div className="stat-inline">
            <div>
              <span className="label">{c("withIp")}</span>
              <span className="value">{formatNumber(data.assets.with_ip_addresses)}</span>
            </div>
            <div>
              <span className="label">{c("withoutIp")}</span>
              <span className="value">{formatNumber(Math.max(0, data.assets.total - data.assets.with_ip_addresses))}</span>
            </div>
          </div>
        </Card>

        <Card title={c("zones")} subtitle={`${formatNumber(data.zones.total)} ${c("zoneTotal").toLowerCase()}`}>
          <div className="metric-list">
            <div className="metric-row">
              <span className="metric-label">{c("conduits")}</span>
              <span className="metric-value">{formatNumber(data.zones.conduits)}</span>
            </div>
            <div className="metric-row">
              <span className="metric-label">{c("purdue")}</span>
              <span className="metric-value">{data.zones.purdue_levels.length ? data.zones.purdue_levels.join(", ") : "—"}</span>
            </div>
            <div className="metric-row">
              <span className="metric-label">{c("gaps")}</span>
              <span className="metric-value" style={{ color: gaps.length ? "var(--warning)" : "var(--success)" }}>{formatNumber(gaps.length)}</span>
            </div>
          </div>
          <div className="divider" />
          {gaps.length === 0 ? (
            <div className="notice notice-accent">{c("noGaps")}</div>
          ) : (
            <div className="metric-list">
              {gaps.map((gap) => (
                <div className="metric-row" key={gap.kind} data-testid={`segmentation-gap-${gap.kind}`}>
                  <span className="metric-label" style={{ flexDirection: "column", alignItems: "flex-start", gap: 1 }}>
                    <span>{gapLabel(gap.kind, c)}</span>
                    {gap.purdue_levels?.length ? <span className="dim" style={{ fontSize: 10 }}>Purdue {gap.purdue_levels.join(" / ")}</span> : null}
                  </span>
                  <span className="metric-value" style={{ color: "var(--warning)" }}>{formatNumber(gap.count)}</span>
                </div>
              ))}
            </div>
          )}
          <div style={{ marginTop: 8 }}>
            <Link to="/iot-ot" style={{ fontSize: 11 }}>
              {c("gaps")} → {t("nav.iotOt")} <ArrowUpRight size={10} />
            </Link>
          </div>
        </Card>
      </div>

      <div className="split-main" style={{ marginBottom: 12 }}>
        <Card
          title={c("exposedTable")}
          subtitle={c("exposedHint")}
          bodyClassName=""
          actions={<Badge tone={findings.length ? "danger" : "success"}>{formatNumber(findings.length)}</Badge>}
        >
          <div data-testid="network-findings-table">
            <DataTable
              columns={findingColumns}
              rows={findings}
              rowKey={(row) => row.id}
              empty={
                <EmptyState
                  icon={ShieldCheck}
                  title={c("emptyExposed")}
                  description={c("emptyExposedHint")}
                  action={<LinkButton to="/attack-surface" size="sm">{c("goSurface")}</LinkButton>}
                />
              }
            />
          </div>
        </Card>

        <div className="stack">
          <Card title={c("connectors")} subtitle={c("connectorTotal")}>
            {data.connectors.network_total === 0 ? (
              <EmptyState
                icon={Cable}
                title={c("noConnectors")}
                description={c("noConnectorsHint")}
                action={<LinkButton to="/integrations" size="sm" variant="primary">{t("nav.integrations")}</LinkButton>}
              />
            ) : (
              <>
                <div className="stat-inline" style={{ marginBottom: 10 }}>
                  <div>
                    <span className="label">{c("connectorTotal")}</span>
                    <span className="value">{formatNumber(data.connectors.network_total)}</span>
                  </div>
                  <div>
                    <span className="label">{c("degraded")}</span>
                    <span className="value" style={{ color: data.connectors.degraded_ids.length ? "var(--danger)" : "var(--success)" }}>
                      {formatNumber(data.connectors.degraded_ids.length)}
                    </span>
                  </div>
                </div>
                {connectorStatuses.length ? (
                  <div className="metric-list">
                    {connectorStatuses.map(([status, count]) => (
                      <div className="metric-row" key={status}>
                        <span className="metric-label"><StatusBadge status={status} /></span>
                        <span className="metric-value">{formatNumber(count)}</span>
                      </div>
                    ))}
                  </div>
                ) : null}
              </>
            )}
          </Card>

          <Card title={c("lateralTable")} subtitle={c("lateralHint")} bodyClassName="">
            <div data-testid="network-lateral-table">
              <DataTable
                columns={lateralColumns}
                rows={lateral}
                rowKey={(row) => row.id}
                empty={<EmptyState icon={ShieldCheck} title={c("emptyLateral")} description={c("emptyLateralHint")} />}
              />
            </div>
          </Card>
        </div>
      </div>

      <div className="split-main" style={{ marginBottom: 12 }}>
        <Card title={c("recommendations")} subtitle={c("recommendationsHint")} bodyClassName="card-body">
          <RecommendationList recommendations={data.recommendations} />
        </Card>

        <Card title={c("networkRows")} subtitle={c("rowsNote")} bodyClassName="">
          {assetRows.length === 0 ? (
            <EmptyState
              icon={Server}
              title={data.assets.total === 0 ? c("assetsEmpty") : c("noRows")}
              description={c("assetsEmptyHint")}
            />
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>{c("asset")}</th>
                    <th>{c("withIp")}</th>
                    <th style={{ textAlign: "right" }}>{t("common.details")}</th>
                  </tr>
                </thead>
                <tbody>
                  {assetRows.slice(0, 12).map((asset) => (
                    <tr key={asset.id}>
                      <td>
                        <div className="primary-cell">{asset.name}</div>
                        <div className="cell-sub">{humanize(asset.kind)}</div>
                      </td>
                      <td>
                        <div className="chip-row">
                          {asset.ip_addresses.length ? (
                            asset.ip_addresses.slice(0, 3).map((ip) => <span className="tag" key={ip}>{ip}</span>)
                          ) : (
                            <span className="dim">—</span>
                          )}
                        </div>
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <LinkButton to={`/assets/${asset.id}`} size="sm" variant="ghost">{c("editAsset")}</LinkButton>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <div className="notice" style={{ fontSize: 11 }}>
        <ShieldCheck size={14} style={{ flex: "0 0 auto", color: "var(--success)" }} />
        <span>
          {c("evidenced")}: {formatNumber(findings.length)} · {formatNumber(lateral.length)} · {formatNumber(gaps.length)} ·{" "}
          {t("common.lastUpdated", { time: relativeTime(data.generated_at, lang) })}
        </span>
        <LinkButton to="/vulnerabilities" size="sm" variant="ghost" icon={Crosshair}>{c("goVulns")}</LinkButton>
      </div>
    </div>
  );
}

export default NetworkPage;
