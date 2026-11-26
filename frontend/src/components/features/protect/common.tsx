import { useState } from "react";
import { Check, ClipboardCopy, Info, ShieldQuestion } from "lucide-react";
import { formatDateTime, formatNumber, humanize } from "../../../lib/format";
import { useI18n, usePageCopy, type Lang } from "../../../lib/i18n";
import {
  Badge,
  Card,
  EmptyState,
  ProgressBar,
  ScoreRing,
  SeverityBadge,
} from "../../ui";

/* ------------------------------------------------------------------ types */

export interface PostureFactor {
  factor: string;
  impact: number;
  detail: Record<string, unknown>;
}

export interface PostureRecommendation {
  id: string;
  severity: string;
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
}

export interface PostureSummaryBase {
  generated_at: string;
  score: number;
  level: string;
  data_quality: string;
  factors: PostureFactor[];
  recommendations: PostureRecommendation[];
}

/* ------------------------------------------------------------------- copy */

const copy: Record<Lang, Record<string, string>> = {
  es: {
    "score": "Puntuación de postura",
    "level": "Nivel",
    "factors": "Factores de riesgo",
    "noFactors": "Sin factores de riesgo activos en los datos actuales",
    "generated": "Calculado",
    "quality": "Calidad del dato",
    "quality.ok": "Completa",
    "quality.partial": "Parcial",
    "quality.insufficient_data": "Datos insuficientes",
    "evidence": "Evidencia",
    "recommendations": "Recomendaciones",
    "noRecommendations": "No hay recomendaciones: no se han detectado desviaciones en los datos disponibles.",
    "insufficientTitle": "Datos insuficientes para calcular la postura",
    "insufficientBody":
      "HISPANSHIELD no inventa telemetría. Conecta las fuentes del dominio o inventaría los activos para obtener una puntuación verificable.",
    "partialBody": "Parte de las fuentes del dominio no aporta datos; la puntuación puede estar incompleta.",
    "impact": "impacto",
    "copy": "Copiar",
    "copied": "Copiado",
    "level.strong": "Sólida",
    "level.moderate": "Moderada",
    "level.weak": "Débil",
    "level.critical": "Crítica",
  },
  en: {
    "score": "Posture score",
    "level": "Level",
    "factors": "Risk factors",
    "noFactors": "No active risk factors in the current data",
    "generated": "Computed",
    "quality": "Data quality",
    "quality.ok": "Complete",
    "quality.partial": "Partial",
    "quality.insufficient_data": "Insufficient data",
    "evidence": "Evidence",
    "recommendations": "Recommendations",
    "noRecommendations": "No recommendations: no deviations were detected in the available data.",
    "insufficientTitle": "Not enough data to compute posture",
    "insufficientBody":
      "HISPANSHIELD never invents telemetry. Connect the domain sources or inventory the assets to obtain a verifiable score.",
    "partialBody": "Some domain sources are not reporting; the score may be incomplete.",
    "impact": "impact",
    "copy": "Copy",
    "copied": "Copied",
    "level.strong": "Strong",
    "level.moderate": "Moderate",
    "level.weak": "Weak",
    "level.critical": "Critical",
  },
};

const FACTOR_LABELS: Record<string, { es: string; en: string }> = {
  exposed_services: { es: "Servicios expuestos", en: "Exposed services" },
  lateral_movement_signals: { es: "Señales de movimiento lateral", en: "Lateral movement signals" },
  segmentation_gaps: { es: "Brechas de segmentación", en: "Segmentation gaps" },
  network_control_health: { es: "Salud de controles de red", en: "Network control health" },
  public_storage: { es: "Almacenamiento público", en: "Public storage" },
  cloud_identity_findings: { es: "Hallazgos de identidad cloud", en: "Cloud identity findings" },
  cloud_vulnerabilities: { es: "Vulnerabilidades cloud", en: "Cloud vulnerabilities" },
  mfa_adoption: { es: "Adopción de MFA", en: "MFA adoption" },
  failed_logins_30d: { es: "Inicios de sesión fallidos (30 d)", en: "Failed logins (30 d)" },
  identity_alerts: { es: "Alertas de identidad", en: "Identity alerts" },
  identity_findings: { es: "Hallazgos de identidad", en: "Identity findings" },
};

const DETAIL_LABELS: Record<string, { es: string; en: string }> = {
  open_findings: { es: "hallazgos abiertos", en: "open findings" },
  open_alerts: { es: "alertas abiertas", en: "open alerts" },
  open_exposed_findings: { es: "hallazgos de exposición", en: "exposed findings" },
  open_lateral_alerts: { es: "alertas laterales", en: "lateral alerts" },
  unzoned_ot_assets: { es: "activos OT sin zona", en: "unzoned OT assets" },
  conduits_without_required_sl: { es: "conductos sin SL", en: "conduits without SL" },
  missing_it_ot_conduit: { es: "conducto IT/OT ausente", en: "missing IT/OT conduit" },
  degraded_connectors: { es: "conectores degradados", en: "degraded connectors" },
  network_connectors: { es: "conectores de red", en: "network connectors" },
  critical: { es: "críticas", en: "critical" },
  high: { es: "altas", en: "high" },
  members: { es: "miembros", en: "members" },
  mfa_enabled: { es: "con MFA", en: "with MFA" },
  mfa_percent: { es: "% MFA", en: "MFA %" },
  failed_logins: { es: "fallos de acceso", en: "failed logins" },
  window_days: { es: "ventana (días)", en: "window (days)" },
  zone_count: { es: "zonas", en: "zones" },
  cloud_assets: { es: "activos cloud", en: "cloud assets" },
  connectors: { es: "conectores", en: "connectors" },
};

const EVIDENCE_LABELS: Record<string, { es: string; en: string }> = {
  finding_ids: { es: "hallazgos citados", en: "cited findings" },
  alert_ids: { es: "alertas citadas", en: "cited alerts" },
  connector_ids: { es: "conectores citados", en: "cited connectors" },
  zone_ids: { es: "zonas citadas", en: "cited zones" },
  asset_ids: { es: "activos citados", en: "cited assets" },
  public_storage_findings: { es: "hallazgos de storage público", en: "public storage findings" },
  identity_findings: { es: "hallazgos de identidad", en: "identity findings" },
  open_identity_alerts: { es: "alertas de identidad abiertas", en: "open identity alerts" },
  missing_mfa_user_ids: { es: "usuarios sin MFA", en: "users without MFA" },
  top_users: { es: "usuarios afectados", en: "affected users" },
  status_counts: { es: "conteo por estado", en: "status counts" },
  by_severity: { es: "por severidad", en: "by severity" },
  gaps: { es: "brechas", en: "gaps" },
  techniques: { es: "técnicas", en: "techniques" },
  assets: { es: "activos citados", en: "cited assets" },
  findings: { es: "hallazgos", en: "findings" },
};

const RECOMMENDATIONS: Record<string, { es: { title: string; detail: string }; en: { title: string; detail: string } }> = {
  "NET-01": {
    es: {
      title: "Reducir los servicios de red expuestos",
      detail: "Cierra, filtra o autentica los servicios accesibles desde Internet identificados por los hallazgos de exposición.",
    },
    en: {
      title: "Reduce exposed network services",
      detail: "Close, filter or authenticate internet-reachable services identified by exposure findings.",
    },
  },
  "NET-02": {
    es: {
      title: "Investigar señales de movimiento lateral",
      detail: "Las alertas referencian técnicas de movimiento lateral; valida la segmentación y la higiene de credenciales.",
    },
    en: {
      title: "Investigate lateral movement signals",
      detail: "Alerts reference lateral movement techniques; validate segmentation and credential hygiene.",
    },
  },
  "NET-03": {
    es: {
      title: "Cerrar brechas de segmentación IEC 62443",
      detail: "Asigna los activos OT a zonas y declara conductos con un nivel de seguridad requerido.",
    },
    en: {
      title: "Close IEC 62443 segmentation gaps",
      detail: "Assign OT assets to zones and declare conduits with a required security level.",
    },
  },
  "NET-04": {
    es: {
      title: "Restaurar la salud de conectores de firewall/IDS",
      detail: "Los conectores de control de red están degradados; la visibilidad puede ser incompleta.",
    },
    en: {
      title: "Restore firewall/IDS connector health",
      detail: "Network control connectors are degraded; visibility may be incomplete.",
    },
  },
  "CLOUD-01": {
    es: {
      title: "Remediar el almacenamiento cloud público",
      detail: "Bloquea la lectura/escritura pública en buckets u objetos señalados por los hallazgos de postura.",
    },
    en: {
      title: "Remediate public cloud storage",
      detail: "Block public read/write on buckets or objects flagged by posture findings.",
    },
  },
  "CLOUD-02": {
    es: {
      title: "Restringir identidades y permisos cloud",
      detail: "Elimina permisos comodín y aplica mínimo privilegio en los roles cloud.",
    },
    en: {
      title: "Tighten cloud identities and permissions",
      detail: "Remove wildcard permissions and enforce least privilege on cloud roles.",
    },
  },
  "CLOUD-03": {
    es: {
      title: "Parchear cargas de trabajo cloud",
      detail: "Prioriza vulnerabilidades críticas y explotadas conocidas en activos cloud.",
    },
    en: {
      title: "Patch cloud workloads",
      detail: "Prioritise critical and known-exploited vulnerabilities on cloud assets.",
    },
  },
  "CLOUD-04": {
    es: {
      title: "Conectar un proveedor cloud",
      detail: "No hay activos cloud inventariados; la postura no puede evaluarse hasta configurar un conector.",
    },
    en: {
      title: "Connect a cloud provider",
      detail: "No cloud assets are inventoried; posture cannot be assessed until a connector is configured.",
    },
  },
  "ID-01": {
    es: {
      title: "Aumentar la adopción de MFA",
      detail: "Exige MFA TOTP a todos los miembros activos de la organización.",
    },
    en: {
      title: "Increase MFA adoption",
      detail: "Enforce TOTP MFA for every active organization member.",
    },
  },
  "ID-02": {
    es: {
      title: "Investigar fallos de autenticación",
      detail: "Los inicios de sesión fallidos repetidos pueden indicar password spraying o credential stuffing.",
    },
    en: {
      title: "Investigate authentication failures",
      detail: "Repeated failed logins may indicate password spraying or credential stuffing.",
    },
  },
  "ID-03": {
    es: {
      title: "Revisar alertas relacionadas con identidad",
      detail: "Triaja alertas que referencian cuentas válidas, fuerza bruta o abuso de MFA.",
    },
    en: {
      title: "Review identity-related alerts",
      detail: "Triage alerts referencing valid accounts, brute force or MFA abuse.",
    },
  },
  "ID-04": {
    es: {
      title: "Remediar hallazgos de identidad",
      detail: "Elimina identidades obsoletas y privilegios excesivos detectados por el descubrimiento.",
    },
    en: {
      title: "Remediate identity findings",
      detail: "Remove stale identities and excessive privileges detected by discovery.",
    },
  },
};

/* --------------------------------------------------------------- helpers */

export function levelTone(level: string): "success" | "warning" | "danger" | "critical" | "neutral" {
  if (level === "strong") return "success";
  if (level === "moderate") return "warning";
  if (level === "weak") return "danger";
  if (level === "critical") return "critical";
  return "neutral";
}

export function levelLabel(level: string, lang: Lang): string {
  return copy[lang][`level.${level}`] ?? humanize(level);
}

export function factorLabel(key: string, lang: Lang): string {
  const entry = FACTOR_LABELS[key];
  const fallback = copy[lang];
  if (!entry) return humanize(key);
  return entry[lang] ?? fallback["factors"];
}

export function recommendationText(
  recommendation: PostureRecommendation,
  lang: Lang,
): { title: string; detail: string } {
  const entry = RECOMMENDATIONS[recommendation.id];
  if (entry) return entry[lang];
  return { title: recommendation.title, detail: recommendation.detail };
}

function detailValue(value: unknown, lang: Lang): string {
  if (typeof value === "number") return formatNumber(value);
  if (typeof value === "boolean") return lang === "es" ? (value ? "sí" : "no") : value ? "yes" : "no";
  if (Array.isArray(value)) return formatNumber(value.length);
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .slice(0, 4)
      .map(([key, item]) => `${humanize(key)} ${String(item)}`)
      .join(" · ");
  }
  return String(value);
}

export function factorDetailText(detail: Record<string, unknown>, lang: Lang): string {
  return Object.entries(detail)
    .filter(([, value]) => value !== null && value !== undefined)
    .slice(0, 4)
    .map(([key, value]) => `${DETAIL_LABELS[key]?.[lang] ?? humanize(key)}: ${detailValue(value, lang)}`)
    .join(" · ");
}

export function evidenceEntries(evidence: Record<string, unknown>, lang: Lang): { label: string; value: string }[] {
  const entries: { label: string; value: string }[] = [];
  for (const [key, raw] of Object.entries(evidence)) {
    if (raw === null || raw === undefined) continue;
    let value: string;
    if (Array.isArray(raw)) {
      value = formatNumber(raw.length);
    } else if (typeof raw === "number") {
      value = key.endsWith("percent") ? `${raw}%` : formatNumber(raw);
    } else if (typeof raw === "boolean") {
      value = lang === "es" ? (raw ? "Sí" : "No") : raw ? "Yes" : "No";
    } else if (typeof raw === "object") {
      value = Object.entries(raw as Record<string, unknown>)
        .slice(0, 6)
        .map(([innerKey, innerValue]) => `${humanize(innerKey)} ${String(innerValue)}`)
        .join(" · ");
    } else {
      value = String(raw);
    }
    entries.push({ label: EVIDENCE_LABELS[key]?.[lang] ?? humanize(key), value });
  }
  return entries;
}

export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/* ------------------------------------------------------------ components */

export function PostureHero({
  score,
  level,
  quality,
  factors,
  generatedAt,
}: {
  score: number;
  level: string;
  quality: string;
  factors: PostureFactor[];
  generatedAt: string;
}) {
  const { lang } = useI18n();
  const c = usePageCopy(copy);
  const tone = levelTone(level);
  const ringTone =
    tone === "success" ? "var(--success)" : tone === "warning" ? "var(--warning)" : tone === "critical" ? "var(--critical)" : "var(--danger)";

  return (
    <Card
      title={c("score")}
      subtitle={c("generated") + " · " + formatDateTime(generatedAt, lang)}
      actions={
        <div className="row wrap" style={{ gap: 6 }}>
          <Badge tone={tone}>{levelLabel(level, lang)}</Badge>
          <Badge tone={quality === "ok" ? "neutral" : quality === "partial" ? "warning" : "danger"}>
            {c(`quality.${quality}`)}
          </Badge>
        </div>
      }
    >
      <div className="row wrap" style={{ gap: 24, alignItems: "flex-start" }}>
        <ScoreRing score={score} label={c("score")} tone={ringTone} />
        <div style={{ flex: 1, minWidth: 220 }}>
          <div className="section-label">{c("factors")}</div>
          {factors.length === 0 ? (
            <div className="notice notice-accent">{c("noFactors")}</div>
          ) : (
            <div className="metric-list">
              {factors.map((factor) => (
                <div className="metric-row" key={factor.factor}>
                  <span className="metric-label" style={{ flexDirection: "column", alignItems: "flex-start", gap: 1 }}>
                    <span>{factorLabel(factor.factor, lang)}</span>
                    <span className="dim" style={{ fontSize: 10.5 }}>
                      {factorDetailText(factor.detail, lang)}
                    </span>
                  </span>
                  <span className="metric-value" style={{ color: "var(--danger)" }}>
                    −{formatNumber(factor.impact)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}

export function DataQualityNotice({ quality }: { quality: string }) {
  const c = usePageCopy(copy);
  if (quality === "ok") return null;
  if (quality === "insufficient_data") {
    return (
      <div className="notice notice-warning" role="status" data-testid="insufficient-data">
        <ShieldQuestion size={15} style={{ flex: "0 0 auto" }} aria-hidden="true" />
        <div>
          <strong>{c("insufficientTitle")}</strong>
          <div style={{ marginTop: 3 }}>{c("insufficientBody")}</div>
        </div>
      </div>
    );
  }
  return (
    <div className="notice" role="status">
      <Info size={14} style={{ flex: "0 0 auto", color: "var(--warning)" }} aria-hidden="true" />
      <span>{c("partialBody")}</span>
    </div>
  );
}

export function RecommendationList({ recommendations }: { recommendations: PostureRecommendation[] }) {
  const { lang } = useI18n();
  const c = usePageCopy(copy);
  if (recommendations.length === 0) {
    return <EmptyState icon={Check} title={c("recommendations")} description={c("noRecommendations")} />;
  }
  return (
    <div className="stack" data-testid="recommendations">
      {recommendations.map((recommendation) => {
        const text = recommendationText(recommendation, lang);
        const evidence = evidenceEntries(recommendation.evidence, lang);
        return (
          <article
            key={recommendation.id}
            className="card card-pad"
            style={{ borderLeft: "3px solid var(--border-strong)" }}
            data-testid={`recommendation-${recommendation.id}`}
          >
            <div className="row-between wrap" style={{ gap: 8, alignItems: "flex-start" }}>
              <div style={{ minWidth: 0 }}>
                <div className="mono" style={{ fontSize: 10, color: "var(--accent)", marginBottom: 3 }}>
                  {recommendation.id}
                </div>
                <h3 style={{ fontSize: 13.5 }}>{text.title}</h3>
                <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                  {text.detail}
                </p>
              </div>
              <SeverityBadge severity={recommendation.severity} />
            </div>
            {evidence.length ? (
              <div style={{ marginTop: 10 }}>
                <div className="section-label">{c("evidence")}</div>
                <div className="chip-row">
                  {evidence.map((item) => (
                    <span className="tag" key={`${recommendation.id}-${item.label}`}>
                      {item.label}: {item.value}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </article>
        );
      })}
    </div>
  );
}

export function AdoptionMeter({ value, label, hint }: { value: number; label: string; hint?: string }) {
  return (
    <div>
      <div className="row-between" style={{ fontSize: 12, marginBottom: 5 }}>
        <span className="muted">{label}</span>
        <span className="mono" style={{ color: value < 100 ? "var(--warning)" : "var(--success)" }}>
          {value.toFixed(1)}%
        </span>
      </div>
      <ProgressBar value={value} tone={value < 100 ? "var(--warning)" : "var(--success)"} />
      {hint ? (
        <div className="dim" style={{ fontSize: 10.5, marginTop: 5 }}>
          {hint}
        </div>
      ) : null}
    </div>
  );
}

export function CopyField({ label, value }: { label: string; value: string }) {
  const c = usePageCopy(copy);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2200);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="field">
      <label htmlFor={`copy-${label.replace(/\s+/g, "-").toLowerCase()}`}>{label}</label>
      <div className="row" style={{ gap: 6 }}>
        <input
          id={`copy-${label.replace(/\s+/g, "-").toLowerCase()}`}
          className="input mono"
          readOnly
          value={value}
          onFocus={(event) => event.currentTarget.select()}
          style={{ fontSize: 11.5 }}
        />
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => void handleCopy()}
          aria-label={c("copy")}
          data-testid="copy-secret"
        >
          {copied ? <Check size={13} aria-hidden="true" /> : <ClipboardCopy size={13} aria-hidden="true" />}
          {copied ? c("copied") : c("copy")}
        </button>
      </div>
    </div>
  );
}
