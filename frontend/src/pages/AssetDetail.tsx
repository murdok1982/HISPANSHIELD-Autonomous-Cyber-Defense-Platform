import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  ChevronLeft,
  GitBranch,
  Network,
  Plus,
  RefreshCw,
  ShieldAlert,
  Trash2,
  Waypoints,
} from "lucide-react";
import { api, errorMessage, isApiError, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatDateTime, formatNumber, humanize, relativeTime } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
  Field,
  Input,
  LinkButton,
  PageHeader,
  PageSkeleton,
  Pagination,
  ProgressBar,
  SearchInput,
  Select,
  SeverityBadge,
  SeverityBars,
  StatusBadge,
  TableSkeleton,
  Tabs,
  useToast,
  type Column,
} from "../components/ui";
import {
  ConfirmModal,
  CopyButton,
  CriticalityMeter,
  DemoTag,
  JsonBlock,
  MetaRow,
  TagList,
  fieldErrors,
  SEVERITY_LEVELS,
} from "../components/features/detect/shared";
import { AssetGraphView } from "../components/features/detect/graph";
import type {
  Asset,
  AssetDetail,
  AssetGraph,
  AssetIdentity,
  AssetVulnerability,
  Relationship,
  Zone,
} from "../components/features/detect/types";

const COPY = {
  es: {
    "detail.eyebrow": "Exposición · Activo",
    "detail.back": "Volver al inventario",
    "detail.loadError": "No se pudo cargar el activo",
    "detail.notFound": "Activo no encontrado",
    "detail.notFoundHint": "El activo no existe, fue retirado o pertenece a otra organización.",
    "detail.refresh": "Actualizar activo",
    "detail.criticality": "Criticidad",
    "detail.kind": "Tipo",
    "detail.status": "Estado",
    "detail.lastSeen": "Última observación",
    "detail.environment": "Entorno",
    "detail.demo": "Activo de demostración",
    "detail.tab.overview": "Resumen",
    "detail.tab.relationships": "Relaciones",
    "detail.tab.vulnerabilities": "Vulnerabilidades",
    "detail.tab.identities": "Identidades",
    "detail.zone": "Zona",
    "detail.overview.facts": "Hechos del activo",
    "detail.overview.ownership": "Propiedad y descubrimiento",
    "detail.overview.tags": "Etiquetas",
    "detail.overview.metadata": "Metadatos",
    "detail.overview.noTags": "Sin etiquetas",
    "detail.overview.noMetadata": "Sin metadatos adicionales",
    "detail.overview.name": "Nombre",
    "detail.overview.key": "Clave",
    "detail.overview.subtype": "Subtipo",
    "detail.overview.os": "Sistema operativo",
    "detail.overview.vendor": "Fabricante",
    "detail.overview.model": "Modelo",
    "detail.overview.firmware": "Firmware",
    "detail.overview.serial": "Número de serie",
    "detail.overview.location": "Ubicación",
    "detail.overview.owner": "Propietario",
    "detail.overview.discovery": "Origen de descubrimiento",
    "detail.overview.confidence": "Confianza",
    "detail.overview.firstSeen": "Primera observación",
    "detail.overview.lastSeen": "Última observación",
    "detail.overview.lastScanned": "Último escaneo",
    "detail.overview.created": "Alta",
    "detail.overview.updated": "Actualizado",
    "detail.overview.ips": "Direcciones IP",
    "detail.overview.hostnames": "Hostnames",
    "detail.overview.macs": "Direcciones MAC",
    "detail.overview.iot": "Detalle IoT",
    "detail.overview.ot": "Detalle OT",
    "detail.overview.protocols": "Protocolos",
    "detail.overview.connectivity": "Conectividad",
    "detail.overview.edgeGateway": "Gateway de borde",
    "detail.overview.firmwareVersion": "Versión de firmware",
    "detail.overview.lastTelemetry": "Última telemetría",
    "detail.overview.posture": "Postura de seguridad",
    "detail.overview.controller": "Modelo de controlador",
    "detail.overview.baseline": "Línea base",
    "detail.overview.safetyCritical": "Seguridad funcional crítica",
    "detail.overview.passiveOnly": "Solo monitorización pasiva",
    "detail.overview.safetyNotice": "Los activos OT/ICS solo se supervisan en modo pasivo. HISPANSHIELD no ejecuta sondeos activos, reinicios ni escrituras de registro sobre ellos.",
    "detail.overview.vulnSummary": "Conteo de vulnerabilidades",
    "detail.overview.vulnSummaryHint": "Datos del back-end de vulnerabilidades; no incluye CVEs sin activo asignado.",
    "detail.vuln.total": "Total",
    "detail.vuln.open": "Abiertas",
    "detail.vuln.reopened": "Reabiertas",
    "detail.vuln.kev": "Explotadas (KEV)",
    "detail.vuln.bySeverity": "Por severidad",
    "detail.vuln.none": "Sin vulnerabilidades registradas",
    "detail.vuln.noneHint": "Importa CVEs o ejecuta un análisis de exposición para poblar el inventario.",
    "detail.vuln.openAll": "Abrir en gestión de vulnerabilidades",
    "detail.vuln.filter.status": "Estado",
    "detail.vuln.filter.severity": "Severidad",
    "detail.vuln.filter.allStatuses": "Todos los estados",
    "detail.vuln.filter.allSeverities": "Todas las severidades",
    "detail.vuln.col.cve": "CVE / Título",
    "detail.vuln.col.severity": "Severidad",
    "detail.vuln.col.status": "Estado",
    "detail.vuln.col.cvss": "CVSS",
    "detail.vuln.col.epss": "EPSS",
    "detail.vuln.col.kev": "KEV",
    "detail.vuln.col.priority": "Prioridad",
    "detail.vuln.col.due": "Vencimiento",
    "detail.rel.graph": "Grafo de relaciones",
    "detail.rel.graphHint": "Diseño radial determinista por profundidad BFS; sin simulación física.",
    "detail.rel.depth": "Profundidad",
    "detail.rel.depthHint": "1-3",
    "detail.rel.list": "Relaciones",
    "detail.rel.counterpart": "Contraparte",
    "detail.rel.direction": "Dirección",
    "detail.rel.kind": "Relación",
    "detail.rel.confidence": "Confianza",
    "detail.rel.firstSeen": "Primera observación",
    "detail.rel.actions": "Acciones",
    "detail.rel.remove": "Eliminar relación",
    "detail.rel.removeTitle": "Eliminar relación",
    "detail.rel.removeDescription": "La relación se eliminará y el grafo se recalculará. Los activos no se modifican. La operación queda registrada en auditoría.",
    "detail.rel.removed": "Relación eliminada",
    "detail.rel.removeFailed": "No se pudo eliminar la relación",
    "detail.rel.created": "Relación creada",
    "detail.rel.createFailed": "No se pudo crear la relación",
    "detail.rel.add": "Añadir relación",
    "detail.rel.addHint": "Selecciona el activo destino y describe el tipo de relación. La confianza indica la certeza del descubrimiento.",
    "detail.rel.target": "Activo destino",
    "detail.rel.targetSearch": "Buscar activo por nombre o clave…",
    "detail.rel.targetEmpty": "Sin resultados para esta búsqueda",
    "detail.rel.targetSelected": "Destino seleccionado",
    "detail.rel.select": "Seleccionar",
    "detail.rel.submit": "Crear relación",
    "detail.rel.empty": "Este activo aún no tiene relaciones",
    "detail.rel.emptyHint": "Añade una relación para construir el contexto de exposición y movimiento lateral.",
    "detail.rel.graphError": "No se pudo cargar el grafo",
    "detail.rel.error": "No se pudieron cargar las relaciones",
    "detail.rel.direction.outbound": "Saliente",
    "detail.rel.direction.inbound": "Entrante",
    "detail.rel.direction.bidirectional": "Bidireccional",
    "detail.identity.title": "Identidades del activo",
    "detail.identity.hint": "IPs, MAC, hostnames, certificados o identidades de usuario que resuelven a este activo.",
    "detail.identity.kind": "Tipo",
    "detail.identity.value": "Valor",
    "detail.identity.confidence": "Confianza",
    "detail.identity.created": "Añadida",
    "detail.identity.add": "Añadir identidad",
    "detail.identity.submit": "Añadir identidad",
    "detail.identity.createdOk": "Identidad añadida",
    "detail.identity.failed": "No se pudo añadir la identidad",
    "detail.identity.empty": "Sin identidades asociadas",
    "detail.identity.emptyHint": "Añade una identidad para que la correlación resuelva telemetría a este activo.",
    "detail.identity.kindRequired": "Selecciona un tipo",
    "detail.identity.valueRequired": "El valor es obligatorio",
    "detail.kind.host": "Host",
    "detail.kind.network": "Red",
    "detail.kind.cloud": "Cloud",
    "detail.kind.iot": "IoT",
    "detail.kind.ot": "OT",
    "detail.kind.identity": "Identidad",
    "detail.kind.service": "Servicio",
    "detail.env.production": "Producción",
    "detail.env.staging": "Preproducción",
    "detail.env.development": "Desarrollo",
    "detail.env.test": "Pruebas",
    "detail.status.active": "Activo",
    "detail.status.inactive": "Inactivo",
    "detail.status.retired": "Retirado",
    "detail.status.quarantined": "Cuarentena",
    "detail.status.unknown": "Desconocido",
    "detail.status.open": "Abierta",
    "detail.status.reopened": "Reabierta",
    "detail.status.mitigated": "Mitigada",
    "detail.status.accepted": "Aceptada",
    "detail.status.false_positive": "Falso positivo",
    "detail.relKind.connects_to": "Conecta con",
    "detail.relKind.depends_on": "Depende de",
    "detail.relKind.hosts": "Aloja",
    "detail.relKind.member_of": "Pertenece a",
    "detail.relKind.routes_to": "Enruta hacia",
    "detail.relKind.authenticates_to": "Se autentica contra",
    "detail.count": "elementos",
  },
  en: {
    "detail.eyebrow": "Exposure · Asset",
    "detail.back": "Back to inventory",
    "detail.loadError": "Could not load the asset",
    "detail.notFound": "Asset not found",
    "detail.notFoundHint": "The asset does not exist, was retired or belongs to another organization.",
    "detail.refresh": "Refresh asset",
    "detail.criticality": "Criticality",
    "detail.kind": "Kind",
    "detail.status": "Status",
    "detail.lastSeen": "Last seen",
    "detail.environment": "Environment",
    "detail.demo": "Demonstration asset",
    "detail.tab.overview": "Overview",
    "detail.tab.relationships": "Relationships",
    "detail.tab.vulnerabilities": "Vulnerabilities",
    "detail.tab.identities": "Identities",
    "detail.zone": "Zone",
    "detail.overview.facts": "Asset facts",
    "detail.overview.ownership": "Ownership and discovery",
    "detail.overview.tags": "Tags",
    "detail.overview.metadata": "Metadata",
    "detail.overview.noTags": "No tags",
    "detail.overview.noMetadata": "No additional metadata",
    "detail.overview.name": "Name",
    "detail.overview.key": "Key",
    "detail.overview.subtype": "Subtype",
    "detail.overview.os": "Operating system",
    "detail.overview.vendor": "Vendor",
    "detail.overview.model": "Model",
    "detail.overview.firmware": "Firmware",
    "detail.overview.serial": "Serial number",
    "detail.overview.location": "Location",
    "detail.overview.owner": "Owner",
    "detail.overview.discovery": "Discovery source",
    "detail.overview.confidence": "Confidence",
    "detail.overview.firstSeen": "First seen",
    "detail.overview.lastSeen": "Last seen",
    "detail.overview.lastScanned": "Last scanned",
    "detail.overview.created": "Created",
    "detail.overview.updated": "Updated",
    "detail.overview.ips": "IP addresses",
    "detail.overview.hostnames": "Hostnames",
    "detail.overview.macs": "MAC addresses",
    "detail.overview.iot": "IoT detail",
    "detail.overview.ot": "OT detail",
    "detail.overview.protocols": "Protocols",
    "detail.overview.connectivity": "Connectivity",
    "detail.overview.edgeGateway": "Edge gateway",
    "detail.overview.firmwareVersion": "Firmware version",
    "detail.overview.lastTelemetry": "Last telemetry",
    "detail.overview.posture": "Security posture",
    "detail.overview.controller": "Controller model",
    "detail.overview.baseline": "Baseline",
    "detail.overview.safetyCritical": "Safety critical",
    "detail.overview.passiveOnly": "Passive monitoring only",
    "detail.overview.safetyNotice": "OT/ICS assets are monitored passively only. HISPANSHIELD never runs active scans, reboots or register writes against them.",
    "detail.overview.vulnSummary": "Vulnerability counts",
    "detail.overview.vulnSummaryHint": "From the vulnerability back end; CVEs without an assigned asset are excluded.",
    "detail.vuln.total": "Total",
    "detail.vuln.open": "Open",
    "detail.vuln.reopened": "Reopened",
    "detail.vuln.kev": "Known exploited (KEV)",
    "detail.vuln.bySeverity": "By severity",
    "detail.vuln.none": "No vulnerabilities recorded",
    "detail.vuln.noneHint": "Import CVEs or run an exposure analysis to populate the inventory.",
    "detail.vuln.openAll": "Open in vulnerability management",
    "detail.vuln.filter.status": "Status",
    "detail.vuln.filter.severity": "Severity",
    "detail.vuln.filter.allStatuses": "All statuses",
    "detail.vuln.filter.allSeverities": "All severities",
    "detail.vuln.col.cve": "CVE / Title",
    "detail.vuln.col.severity": "Severity",
    "detail.vuln.col.status": "Status",
    "detail.vuln.col.cvss": "CVSS",
    "detail.vuln.col.epss": "EPSS",
    "detail.vuln.col.kev": "KEV",
    "detail.vuln.col.priority": "Priority",
    "detail.vuln.col.due": "Due",
    "detail.rel.graph": "Relationship graph",
    "detail.rel.graphHint": "Deterministic radial layout by BFS depth; no physics simulation.",
    "detail.rel.depth": "Depth",
    "detail.rel.depthHint": "1-3",
    "detail.rel.list": "Relationships",
    "detail.rel.counterpart": "Counterpart",
    "detail.rel.direction": "Direction",
    "detail.rel.kind": "Relationship",
    "detail.rel.confidence": "Confidence",
    "detail.rel.firstSeen": "First seen",
    "detail.rel.actions": "Actions",
    "detail.rel.remove": "Remove relationship",
    "detail.rel.removeTitle": "Remove relationship",
    "detail.rel.removeDescription": "The relationship will be removed and the graph recalculated. Assets are not modified. The action is audited.",
    "detail.rel.removed": "Relationship removed",
    "detail.rel.removeFailed": "Could not remove the relationship",
    "detail.rel.created": "Relationship created",
    "detail.rel.createFailed": "Could not create the relationship",
    "detail.rel.add": "Add relationship",
    "detail.rel.addHint": "Pick the target asset and describe the relationship. Confidence states how certain the discovery is.",
    "detail.rel.target": "Target asset",
    "detail.rel.targetSearch": "Search assets by name or key…",
    "detail.rel.targetEmpty": "No results for this search",
    "detail.rel.targetSelected": "Selected target",
    "detail.rel.select": "Select",
    "detail.rel.submit": "Create relationship",
    "detail.rel.empty": "This asset has no relationships yet",
    "detail.rel.emptyHint": "Add a relationship to build exposure and lateral-movement context.",
    "detail.rel.graphError": "Could not load the graph",
    "detail.rel.error": "Could not load relationships",
    "detail.rel.direction.outbound": "Outbound",
    "detail.rel.direction.inbound": "Inbound",
    "detail.rel.direction.bidirectional": "Bidirectional",
    "detail.identity.title": "Asset identities",
    "detail.identity.hint": "IPs, MACs, hostnames, certificates or user identities resolving to this asset.",
    "detail.identity.kind": "Kind",
    "detail.identity.value": "Value",
    "detail.identity.confidence": "Confidence",
    "detail.identity.created": "Added",
    "detail.identity.add": "Add identity",
    "detail.identity.submit": "Add identity",
    "detail.identity.createdOk": "Identity added",
    "detail.identity.failed": "Could not add the identity",
    "detail.identity.empty": "No identities attached",
    "detail.identity.emptyHint": "Add an identity so correlation can resolve telemetry to this asset.",
    "detail.identity.kindRequired": "Select a kind",
    "detail.identity.valueRequired": "Value is required",
    "detail.kind.host": "Host",
    "detail.kind.network": "Network",
    "detail.kind.cloud": "Cloud",
    "detail.kind.iot": "IoT",
    "detail.kind.ot": "OT",
    "detail.kind.identity": "Identity",
    "detail.kind.service": "Service",
    "detail.env.production": "Production",
    "detail.env.staging": "Staging",
    "detail.env.development": "Development",
    "detail.env.test": "Test",
    "detail.status.active": "Active",
    "detail.status.inactive": "Inactive",
    "detail.status.retired": "Retired",
    "detail.status.quarantined": "Quarantined",
    "detail.status.unknown": "Unknown",
    "detail.status.open": "Open",
    "detail.status.reopened": "Reopened",
    "detail.status.mitigated": "Mitigated",
    "detail.status.accepted": "Accepted",
    "detail.status.false_positive": "False positive",
    "detail.relKind.connects_to": "Connects to",
    "detail.relKind.depends_on": "Depends on",
    "detail.relKind.hosts": "Hosts",
    "detail.relKind.member_of": "Member of",
    "detail.relKind.routes_to": "Routes to",
    "detail.relKind.authenticates_to": "Authenticates to",
    "detail.count": "items",
  },
} as const;

const RELATIONSHIP_KINDS = ["connects_to", "depends_on", "hosts", "member_of", "routes_to", "authenticates_to"] as const;
const IDENTITY_KINDS = [
  "ip",
  "mac",
  "hostname",
  "domain",
  "serial",
  "cert_cn",
  "cert_sha256",
  "email",
  "username",
  "uid",
  "uri",
  "telemetry_protocol",
] as const;
const VULN_STATUSES = ["open", "reopened", "mitigated", "accepted", "false_positive"] as const;

type TabKey = "overview" | "relationships" | "vulnerabilities" | "identities";

export function AssetDetailPage() {
  const { assetId } = useParams<{ assetId: string }>();
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const canWrite = can("asset:write");

  const [tab, setTab] = useState<TabKey>("overview");
  const [depth, setDepth] = useState(1);

  const [targetSearch, setTargetSearch] = useState("");
  const [targetId, setTargetId] = useState("");
  const [relKind, setRelKind] = useState<(typeof RELATIONSHIP_KINDS)[number]>("connects_to");
  const [relConfidence, setRelConfidence] = useState("100");
  const [relErrors, setRelErrors] = useState<Record<string, string>>({});
  const [removeTarget, setRemoveTarget] = useState<Relationship | null>(null);

  const [identityKind, setIdentityKind] = useState<(typeof IDENTITY_KINDS)[number]>("ip");
  const [identityValue, setIdentityValue] = useState("");
  const [identityConfidence, setIdentityConfidence] = useState("100");
  const [identityErrors, setIdentityErrors] = useState<Record<string, string>>({});

  const [vulnPage, setVulnPage] = useState(1);
  const [vulnStatus, setVulnStatus] = useState("");
  const [vulnSeverity, setVulnSeverity] = useState("");

  const assetQuery = useQuery({
    queryKey: ["assets", "detail", assetId],
    queryFn: () => api.get<AssetDetail>(`/assets/${assetId}`),
    enabled: Boolean(assetId),
  });

  const zonesQuery = useQuery({
    queryKey: ["assets", "zones"],
    queryFn: () => api.get<Page<Zone>>("/assets/zones", { page: 1, page_size: 200 }),
    staleTime: 120_000,
  });

  const graphQuery = useQuery({
    queryKey: ["assets", "graph", assetId, depth],
    queryFn: () => api.get<AssetGraph>(`/assets/${assetId}/graph`, { depth }),
    enabled: Boolean(assetId) && tab === "relationships",
  });

  const identitiesQuery = useQuery({
    queryKey: ["assets", "identities", assetId],
    queryFn: () => api.get<AssetIdentity[]>(`/assets/${assetId}/identities`),
    enabled: Boolean(assetId) && tab === "identities",
  });

  const vulnerabilitiesQuery = useQuery({
    queryKey: ["assets", "vulnerabilities", assetId, { vulnPage, vulnStatus, vulnSeverity }],
    queryFn: () =>
      api.get<Page<AssetVulnerability>>(`/assets/${assetId}/vulnerabilities`, {
        page: vulnPage,
        page_size: 20,
        status: vulnStatus || undefined,
        severity: vulnSeverity || undefined,
      }),
    enabled: Boolean(assetId) && tab === "vulnerabilities",
  });

  const targetQuery = useQuery({
    queryKey: ["assets", "target-search", targetSearch],
    queryFn: () => api.get<Page<Asset>>("/assets", { q: targetSearch, page: 1, page_size: 10 }),
    enabled: targetSearch.trim().length >= 2,
  });

  const createRelationship = useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.post<Relationship>(`/assets/${assetId}/relationships`, payload),
    onSuccess: () => {
      push(c("detail.rel.created"), "success");
      setTargetSearch("");
      setTargetId("");
      setRelErrors({});
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (error) => {
      setRelErrors(fieldErrors(error));
      push(`${c("detail.rel.createFailed")}: ${errorMessage(error)}`, "error");
    },
  });

  const deleteRelationship = useMutation({
    mutationFn: (relationshipId: string) => api.delete<void>(`/assets/relationships/${relationshipId}`),
    onSuccess: () => {
      push(c("detail.rel.removed"), "success");
      setRemoveTarget(null);
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (error) => push(`${c("detail.rel.removeFailed")}: ${errorMessage(error)}`, "error"),
  });

  const addIdentity = useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.post<AssetIdentity>(`/assets/${assetId}/identities`, payload),
    onSuccess: () => {
      push(c("detail.identity.createdOk"), "success");
      setIdentityValue("");
      setIdentityErrors({});
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (error) => {
      setIdentityErrors(fieldErrors(error));
      push(`${c("detail.identity.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  if (assetQuery.isLoading) return <PageSkeleton />;

  if (assetQuery.isError || !assetQuery.data) {
    const notFound = isApiError(assetQuery.error) && assetQuery.error.status === 404;
    return (
      <div data-testid="page-asset-detail">
        <PageHeader eyebrow={c("detail.eyebrow")} title={notFound ? c("detail.notFound") : c("detail.loadError")} />
        <ErrorBanner
          title={notFound ? c("detail.notFound") : c("detail.loadError")}
          message={notFound ? c("detail.notFoundHint") : errorMessage(assetQuery.error)}
          onRetry={notFound ? undefined : () => void assetQuery.refetch()}
        />
        <div style={{ marginTop: 12 }}>
          <LinkButton to="/assets" icon={ChevronLeft}>{c("detail.back")}</LinkButton>
        </div>
      </div>
    );
  }

  const asset = assetQuery.data;
  const zone = (zonesQuery.data?.items ?? []).find((item) => item.id === asset.zone_id);

  const relationships = asset.relationships;
  const vulnSummary = asset.vulnerability_summary;
  const vulnerabilityRows = vulnerabilitiesQuery.data?.items ?? [];

  const vulnColumns: Column<AssetVulnerability>[] = [
    {
      key: "cve",
      header: c("detail.vuln.col.cve"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <Link
            to={`/vulnerabilities?asset=${asset.id}&vuln=${row.id}`}
            style={{ color: "var(--text)", fontWeight: 500 }}
            onClick={(event) => event.stopPropagation()}
          >
            {row.cve_id ?? row.title}
          </Link>
          {row.cve_id ? (
            <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>{row.title}</div>
          ) : null}
        </div>
      ),
    },
    { key: "severity", header: c("detail.vuln.col.severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "status",
      header: c("detail.vuln.col.status"),
      width: "128px",
      render: (row) => <StatusBadge status={row.status} label={copyOr(c, `detail.status.${row.status}`, humanize(row.status))} />,
    },
    {
      key: "cvss",
      header: c("detail.vuln.col.cvss"),
      width: "72px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.cvss_score?.toFixed(1) ?? "—"}</span>,
    },
    {
      key: "epss",
      header: c("detail.vuln.col.epss"),
      width: "76px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.epss_score !== null ? `${(row.epss_score * 100).toFixed(1)}%` : "—"}</span>,
    },
    {
      key: "kev",
      header: c("detail.vuln.col.kev"),
      width: "70px",
      render: (row) => (row.kev ? <Badge tone="danger">KEV</Badge> : <span className="dim">—</span>),
    },
    {
      key: "priority",
      header: c("detail.vuln.col.priority"),
      width: "90px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11, color: "var(--warning)" }}>{row.priority_score.toFixed(1)}</span>,
    },
    {
      key: "due",
      header: c("detail.vuln.col.due"),
      width: "120px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5, color: row.due_at && new Date(row.due_at) < new Date() ? "var(--danger)" : "var(--muted)" }}>
          {row.due_at ? formatDateTime(row.due_at, lang) : "—"}
        </span>
      ),
    },
  ];

  const relColumns: Column<Relationship>[] = [
    {
      key: "counterpart",
      header: c("detail.rel.counterpart"),
      render: (row) =>
        row.counterpart ? (
          <Link to={`/assets/${row.counterpart.id}`} style={{ color: "var(--text)", fontWeight: 500 }}>
            {row.counterpart.name}
            <span className="mono" style={{ display: "block", fontSize: 10, color: "var(--dim)" }}>{row.counterpart.asset_key}</span>
          </Link>
        ) : (
          <span className="mono" style={{ fontSize: 10.5 }}>{row.target_asset_id}</span>
        ),
    },
    {
      key: "kind",
      header: c("detail.rel.kind"),
      width: "140px",
      render: (row) => <span className="tag">{copyOr(c, `detail.relKind.${row.kind}`, humanize(row.kind))}</span>,
    },
    {
      key: "direction",
      header: c("detail.rel.direction"),
      width: "110px",
      render: (row) => <Badge tone="neutral">{directionLabel(row.direction, c)}</Badge>,
    },
    {
      key: "confidence",
      header: c("detail.rel.confidence"),
      width: "104px",
      render: (row) => (
        <div style={{ minWidth: 64 }}>
          <div className="mono" style={{ fontSize: 10.5, marginBottom: 4 }}>{row.confidence}%</div>
          <ProgressBar value={row.confidence} tone={row.confidence >= 80 ? "var(--success)" : "var(--warning)"} />
        </div>
      ),
    },
    {
      key: "first_seen",
      header: c("detail.rel.firstSeen"),
      width: "126px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.first_seen, lang)}</span>,
    },
    {
      key: "actions",
      header: c("detail.rel.actions"),
      width: "64px",
      align: "right",
      render: (row) =>
        canWrite ? (
          <Button
            size="sm"
            variant="ghost"
            icon={Trash2}
            aria-label={c("detail.rel.remove")}
            onClick={(event) => {
              event.stopPropagation();
              setRemoveTarget(row);
            }}
          />
        ) : null,
    },
  ];

  const identityColumns: Column<AssetIdentity>[] = [
    { key: "kind", header: c("detail.identity.kind"), width: "150px", render: (row) => <span className="tag">{row.kind}</span> },
    {
      key: "value",
      header: c("detail.identity.value"),
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.value}</span>,
    },
    {
      key: "confidence",
      header: c("detail.identity.confidence"),
      width: "130px",
      render: (row) => (
        <div className="row" style={{ gap: 8 }}>
          <ProgressBar value={row.confidence} />
          <span className="mono" style={{ fontSize: 10.5 }}>{row.confidence}%</span>
        </div>
      ),
    },
    {
      key: "created",
      header: c("detail.identity.created"),
      width: "140px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.created_at, lang)}</span>,
    },
  ];

  const tabs = [
    { key: "overview" as TabKey, label: c("detail.tab.overview") },
    { key: "relationships" as TabKey, label: c("detail.tab.relationships"), count: relationships.length },
    { key: "vulnerabilities" as TabKey, label: c("detail.tab.vulnerabilities"), count: vulnSummary.total },
    { key: "identities" as TabKey, label: c("detail.tab.identities"), count: asset.identities.length },
  ];

  return (
    <div className="animate-in" data-testid="page-asset-detail">
      <PageHeader
        eyebrow={c("detail.eyebrow")}
        title={asset.name}
        subtitle={asset.asset_key}
        actions={
          <>
            <LinkButton to="/assets" icon={ChevronLeft}>{c("detail.back")}</LinkButton>
            <Button icon={RefreshCw} onClick={() => void assetQuery.refetch()} aria-label={c("detail.refresh")} />
          </>
        }
      />

      <div className="card card-pad" style={{ marginBottom: 12 }}>
        <div className="row wrap" style={{ gap: 10 }}>
          <span className="row" style={{ gap: 7 }}>
            <span className="dim" style={{ fontSize: 11 }}>{c("detail.criticality")}</span>
            <CriticalityMeter value={asset.criticality} />
            <span className="mono" style={{ fontSize: 10.5 }}>{asset.criticality}/5</span>
          </span>
          <Badge tone="neutral">{copyOr(c, `detail.kind.${asset.kind}`, humanize(asset.kind))}</Badge>
          {asset.subtype ? <span className="tag">{asset.subtype}</span> : null}
          <StatusBadge status={asset.status} label={copyOr(c, `detail.status.${asset.status}`, humanize(asset.status))} />
          <span className="tag">{copyOr(c, `detail.env.${asset.environment}`, humanize(asset.environment))}</span>
          <span className="dim" style={{ fontSize: 11 }}>
            {c("detail.lastSeen")}: <span className="mono">{relativeTime(asset.last_seen, lang)}</span>
          </span>
          {asset.is_demo ? <DemoTag label={c("detail.demo")} /> : null}
        </div>
      </div>

      <div style={{ marginBottom: 12 }}>
        <Tabs items={tabs} value={tab} onChange={setTab} ariaLabel={c("detail.eyebrow")} />
      </div>

      {tab === "overview" ? (
        <OverviewTab asset={asset} zoneName={zone?.name ?? null} />
      ) : null}

      {tab === "relationships" ? (
        <div className="stack">
          <div className="split-main">
            <Card
              title={c("detail.rel.graph")}
              subtitle={c("detail.rel.graphHint")}
              actions={
                <div className="segmented" role="group" aria-label={`${c("detail.rel.depth")} (${c("detail.rel.depthHint")})`}>
                  {[1, 2, 3].map((level) => (
                    <button
                      key={level}
                      type="button"
                      className={depth === level ? "active" : undefined}
                      onClick={() => setDepth(level)}
                      aria-pressed={depth === level}
                      data-testid={`graph-depth-${level}`}
                    >
                      {level}
                    </button>
                  ))}
                </div>
              }
            >
              {graphQuery.isLoading ? (
                <TableSkeleton rows={5} />
              ) : graphQuery.isError ? (
                <ErrorBanner
                  title={c("detail.rel.graphError")}
                  message={errorMessage(graphQuery.error)}
                  onRetry={() => void graphQuery.refetch()}
                />
              ) : graphQuery.data ? (
                <AssetGraphView graph={graphQuery.data} />
              ) : (
                <EmptyState icon={GitBranch} title={c("detail.rel.empty")} description={c("detail.rel.emptyHint")} />
              )}
            </Card>

            <Card title={c("detail.rel.add")} subtitle={c("detail.rel.addHint")}>
              {canWrite ? (
                <div className="stack">
                  <Field label={c("detail.rel.target")} htmlFor="relationship-target" required error={relErrors.target_asset_id}>
                    <SearchInput
                      value={targetSearch}
                      onChange={(value) => {
                        setTargetSearch(value);
                        setTargetId("");
                      }}
                      placeholder={c("detail.rel.targetSearch")}
                      ariaLabel={c("detail.rel.target")}
                    />
                  </Field>
                  {targetSearch.trim().length >= 2 ? (
                    <div className="metric-list" style={{ maxHeight: 220, overflowY: "auto" }} aria-live="polite">
                      {targetQuery.isLoading ? (
                        <span className="dim" style={{ fontSize: 11 }}>{t("common.loading")}</span>
                      ) : targetQuery.isError ? (
                        <ErrorBanner compact message={errorMessage(targetQuery.error)} onRetry={() => void targetQuery.refetch()} />
                      ) : (targetQuery.data?.items ?? []).filter((item) => item.id !== asset.id).length === 0 ? (
                        <span className="dim" style={{ fontSize: 11 }}>{c("detail.rel.targetEmpty")}</span>
                      ) : (
                        (targetQuery.data?.items ?? [])
                          .filter((item) => item.id !== asset.id)
                          .map((item) => (
                            <label key={item.id} className="list-item" style={{ cursor: "pointer", gap: 10 }}>
                              <input
                                type="radio"
                                name="relationship-target"
                                checked={targetId === item.id}
                                onChange={() => setTargetId(item.id)}
                                style={{ accentColor: "var(--accent)" }}
                                aria-label={`${item.name} (${item.asset_key})`}
                              />
                              <div style={{ minWidth: 0, flex: 1 }}>
                                <div className="item-title">{item.name}</div>
                                <div className="item-sub mono">{item.asset_key} · {item.kind}</div>
                              </div>
                              <CriticalityMeter value={item.criticality} />
                            </label>
                          ))
                      )}
                    </div>
                  ) : (
                    <span className="hint" style={{ fontSize: 11, color: "var(--dim)" }}>{c("detail.rel.targetSearch")}</span>
                  )}

                  <div className="form-grid">
                    <Field label={c("detail.rel.kind")} htmlFor="relationship-kind" required error={relErrors.kind}>
                      <Select
                        id="relationship-kind"
                        value={relKind}
                        onChange={(event) => setRelKind(event.target.value as (typeof RELATIONSHIP_KINDS)[number])}
                        data-testid="relationship-kind"
                      >
                        {RELATIONSHIP_KINDS.map((kind) => (
                          <option key={kind} value={kind}>{copyOr(c, `detail.relKind.${kind}`, humanize(kind))}</option>
                        ))}
                      </Select>
                    </Field>
                    <Field label={`${c("detail.rel.confidence")} (%)`} htmlFor="relationship-confidence" error={relErrors.confidence}>
                      <Input
                        id="relationship-confidence"
                        type="number"
                        min={0}
                        max={100}
                        value={relConfidence}
                        onChange={(event) => setRelConfidence(event.target.value)}
                      />
                    </Field>
                  </div>

                  {targetId ? (
                    <div className="notice notice-accent" style={{ fontSize: 11 }}>
                      {c("detail.rel.targetSelected")}: <span className="mono">{targetQuery.data?.items.find((item) => item.id === targetId)?.name ?? targetId}</span>
                    </div>
                  ) : null}

                  <Button
                    variant="primary"
                    icon={Plus}
                    loading={createRelationship.isPending}
                    disabled={!targetId}
                    onClick={() => {
                      if (!targetId) {
                        setRelErrors({ target_asset_id: c("detail.rel.target") });
                        return;
                      }
                      createRelationship.mutate({
                        target_asset_id: targetId,
                        kind: relKind,
                        confidence: Math.max(0, Math.min(100, Number(relConfidence) || 0)),
                      });
                    }}
                    data-testid="submit-relationship"
                  >
                    {c("detail.rel.submit")}
                  </Button>
                </div>
              ) : (
                <p className="muted" style={{ fontSize: 12 }}>{t("common.permissionDenied")}</p>
              )}
            </Card>
          </div>

          <Card title={c("detail.rel.list")} subtitle={`${relationships.length} ${c("detail.count")}`} bodyClassName="">
            <div data-testid="table-relationships">
              <DataTable
                columns={relColumns}
                rows={relationships}
                rowKey={(row) => row.id}
                empty={
                  <EmptyState
                    icon={Waypoints}
                    title={c("detail.rel.empty")}
                    description={c("detail.rel.emptyHint")}
                  />
                }
              />
            </div>
          </Card>
        </div>
      ) : null}

      {tab === "vulnerabilities" ? (
        <Card
          title={c("detail.tab.vulnerabilities")}
          subtitle={`${formatNumber(vulnSummary.total)} ${c("detail.count")}`}
          actions={
            <LinkButton to={`/vulnerabilities?asset=${asset.id}`} size="sm" icon={ArrowUpRight}>
              {c("detail.vuln.openAll")}
            </LinkButton>
          }
          bodyClassName=""
        >
          <div className="filters-bar" role="group" aria-label={t("common.filters")}>
            <Select
              value={vulnStatus}
              onChange={(event) => {
                setVulnStatus(event.target.value);
                setVulnPage(1);
              }}
              aria-label={c("detail.vuln.filter.status")}
              data-testid="filter-vuln-status"
            >
              <option value="">{c("detail.vuln.filter.allStatuses")}</option>
              {VULN_STATUSES.map((status) => (
                <option key={status} value={status}>{copyOr(c, `detail.status.${status}`, humanize(status))}</option>
              ))}
            </Select>
            <Select
              value={vulnSeverity}
              onChange={(event) => {
                setVulnSeverity(event.target.value);
                setVulnPage(1);
              }}
              aria-label={c("detail.vuln.filter.severity")}
              data-testid="filter-vuln-severity"
            >
              <option value="">{c("detail.vuln.filter.allSeverities")}</option>
              {SEVERITY_LEVELS.map((level) => (
                <option key={level.id} value={level.value}>{t(`common.${level.value}`)}</option>
              ))}
            </Select>
            <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => void vulnerabilitiesQuery.refetch()}>
              {t("common.refresh")}
            </Button>
          </div>
          <div data-testid="table-asset-vulnerabilities">
            <DataTable
              columns={vulnColumns}
              rows={vulnerabilityRows}
              rowKey={(row) => row.id}
              loading={vulnerabilitiesQuery.isLoading}
              error={
                vulnerabilitiesQuery.isError ? (
                  <ErrorBanner message={errorMessage(vulnerabilitiesQuery.error)} onRetry={() => void vulnerabilitiesQuery.refetch()} />
                ) : undefined
              }
              empty={
                <EmptyState
                  icon={ShieldAlert}
                  title={c("detail.vuln.none")}
                  description={c("detail.vuln.noneHint")}
                  action={<LinkButton to={`/vulnerabilities?asset=${asset.id}`} size="sm">{c("detail.vuln.openAll")}</LinkButton>}
                />
              }
            />
          </div>
          <Pagination meta={vulnerabilitiesQuery.data?.meta} onPage={setVulnPage} />
        </Card>
      ) : null}

      {tab === "identities" ? (
        <Card
          title={c("detail.identity.title")}
          subtitle={c("detail.identity.hint")}
          bodyClassName=""
        >
          {canWrite ? (
            <div style={{ padding: 12, borderBottom: "1px solid var(--border)" }}>
              <div className="form-grid">
                <Field label={c("detail.identity.kind")} htmlFor="identity-kind" required error={identityErrors.kind}>
                  <Select
                    id="identity-kind"
                    value={identityKind}
                    onChange={(event) => setIdentityKind(event.target.value as (typeof IDENTITY_KINDS)[number])}
                    data-testid="identity-kind"
                  >
                    {IDENTITY_KINDS.map((kind) => (
                      <option key={kind} value={kind}>{kind}</option>
                    ))}
                  </Select>
                </Field>
                <Field label={c("detail.identity.value")} htmlFor="identity-value" required error={identityErrors.value}>
                  <Input
                    id="identity-value"
                    className="mono"
                    value={identityValue}
                    onChange={(event) => setIdentityValue(event.target.value)}
                    data-testid="identity-value"
                  />
                </Field>
                <Field label={`${c("detail.identity.confidence")} (%)`} htmlFor="identity-confidence" error={identityErrors.confidence}>
                  <Input
                    id="identity-confidence"
                    type="number"
                    min={0}
                    max={100}
                    value={identityConfidence}
                    onChange={(event) => setIdentityConfidence(event.target.value)}
                  />
                </Field>
                <div style={{ display: "flex", alignItems: "flex-end" }}>
                  <Button
                    variant="primary"
                    icon={Plus}
                    loading={addIdentity.isPending}
                    onClick={() => {
                      if (!identityValue.trim()) {
                        setIdentityErrors({ value: c("detail.identity.valueRequired") });
                        return;
                      }
                      addIdentity.mutate({
                        kind: identityKind,
                        value: identityValue.trim(),
                        confidence: Math.max(0, Math.min(100, Number(identityConfidence) || 0)),
                      });
                    }}
                    data-testid="submit-identity"
                  >
                    {c("detail.identity.submit")}
                  </Button>
                </div>
              </div>
            </div>
          ) : null}

          <div data-testid="table-identities">
            <DataTable
              columns={identityColumns}
              rows={identitiesQuery.data}
              rowKey={(row) => row.id}
              loading={identitiesQuery.isLoading}
              error={
                identitiesQuery.isError ? (
                  <ErrorBanner message={errorMessage(identitiesQuery.error)} onRetry={() => void identitiesQuery.refetch()} />
                ) : undefined
              }
              empty={
                <EmptyState icon={Network} title={c("detail.identity.empty")} description={c("detail.identity.emptyHint")} />
              }
            />
          </div>
        </Card>
      ) : null}

      <ConfirmModal
        open={removeTarget !== null}
        onClose={() => setRemoveTarget(null)}
        title={c("detail.rel.removeTitle")}
        description={c("detail.rel.removeDescription")}
        confirmLabel={c("detail.rel.remove")}
        loading={deleteRelationship.isPending}
        danger
        onConfirm={() => {
          if (removeTarget) deleteRelationship.mutate(removeTarget.id);
        }}
      />
    </div>
  );
}

function copyOr(copy: (key: string) => string, key: string, fallback: string): string {
  const translated = copy(key);
  return translated === key ? fallback : translated;
}

function directionLabel(direction: string, copy: (key: string) => string): string {
  return copyOr(copy, `detail.rel.direction.${direction}`, humanize(direction));
}

function OverviewTab({ asset, zoneName }: { asset: AssetDetail; zoneName: string | null }) {
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const summary = asset.vulnerability_summary;

  const severityBars = ["critical", "high", "medium", "low", "info"].map((severity) => ({
    label: t(`common.${severity}`),
    value: summary.by_severity[severity] ?? 0,
    color:
      severity === "critical"
        ? "var(--critical)"
        : severity === "high"
          ? "var(--danger)"
          : severity === "medium"
            ? "var(--warning)"
            : severity === "low"
              ? "var(--accent)"
              : "var(--muted)",
  }));

  return (
    <div className="stack">
      <div className="grid-2">
        <Card title={c("detail.overview.facts")}>
          <div className="metric-list">
            <MetaRow label={c("detail.overview.name")}>{asset.name}</MetaRow>
            <MetaRow label={c("detail.overview.key")}><span className="mono">{asset.asset_key}</span></MetaRow>
            <MetaRow label={c("detail.overview.subtype")}>{asset.subtype ?? "—"}</MetaRow>
            <MetaRow label={c("detail.overview.os")}>{asset.os_name ?? "—"}</MetaRow>
            <MetaRow label={c("detail.overview.vendor")}>{asset.vendor ?? "—"}</MetaRow>
            <MetaRow label={c("detail.overview.model")}>{asset.model ?? "—"}</MetaRow>
            <MetaRow label={c("detail.overview.firmware")}>{asset.firmware ?? "—"}</MetaRow>
            <MetaRow label={c("detail.overview.serial")}><span className="mono">{asset.serial_number ?? "—"}</span></MetaRow>
            <MetaRow label={c("detail.overview.location")}>{asset.location ?? "—"}</MetaRow>
            <MetaRow label={c("detail.overview.ips")}>
              <span className="mono">{asset.ip_addresses.length ? asset.ip_addresses.join(", ") : "—"}</span>
            </MetaRow>
            <MetaRow label={c("detail.overview.hostnames")}>
              <span className="mono">{asset.hostnames.length ? asset.hostnames.join(", ") : "—"}</span>
            </MetaRow>
            <MetaRow label={c("detail.overview.macs")}>
              <span className="mono">{asset.mac_addresses.length ? asset.mac_addresses.join(", ") : "—"}</span>
            </MetaRow>
          </div>
        </Card>

        <div className="stack">
          <Card title={c("detail.overview.ownership")}>
            <div className="metric-list">
              <MetaRow label={c("detail.overview.owner")}>{asset.owner ?? "—"}</MetaRow>
              <MetaRow label={c("detail.zone")}>{zoneName ?? asset.zone_id ?? "—"}</MetaRow>
              <MetaRow label={c("detail.overview.discovery")}>{asset.discovery_source}</MetaRow>
              <MetaRow label={c("detail.overview.confidence")}>
                <span className="row" style={{ gap: 8, justifyContent: "flex-end" }}>
                  <ProgressBar value={asset.confidence} tone={asset.confidence >= 80 ? "var(--success)" : "var(--warning)"} />
                  <span className="mono">{asset.confidence}%</span>
                </span>
              </MetaRow>
              <MetaRow label={c("detail.overview.firstSeen")}>{formatDateTime(asset.first_seen, lang)}</MetaRow>
              <MetaRow label={c("detail.overview.lastSeen")}>{formatDateTime(asset.last_seen, lang)}</MetaRow>
              <MetaRow label={c("detail.overview.lastScanned")}>{asset.last_scanned_at ? formatDateTime(asset.last_scanned_at, lang) : "—"}</MetaRow>
              <MetaRow label={c("detail.overview.created")}>{formatDateTime(asset.created_at, lang)}</MetaRow>
              <MetaRow label={c("detail.overview.updated")}>{formatDateTime(asset.updated_at, lang)}</MetaRow>
            </div>
          </Card>

          <Card title={c("detail.overview.tags")}>
            <TagList tags={asset.tags} emptyLabel={c("detail.overview.noTags")} />
          </Card>
        </div>
      </div>

      <Card
        title={c("detail.overview.vulnSummary")}
        subtitle={c("detail.overview.vulnSummaryHint")}
        actions={<LinkButton to={`/vulnerabilities?asset=${asset.id}`} size="sm" icon={ArrowUpRight}>{c("detail.vuln.openAll")}</LinkButton>}
      >
        {summary.total === 0 ? (
          <EmptyState icon={ShieldAlert} title={c("detail.vuln.none")} description={c("detail.vuln.noneHint")} />
        ) : (
          <div className="grid-2">
            <div className="stat-inline">
              <div>
                <span className="label">{c("detail.vuln.total")}</span>
                <span className="value">{formatNumber(summary.total)}</span>
              </div>
              <div>
                <span className="label">{c("detail.vuln.open")}</span>
                <span className="value" style={{ color: summary.open ? "var(--danger)" : "var(--success)" }}>{formatNumber(summary.open)}</span>
              </div>
              <div>
                <span className="label">{c("detail.vuln.reopened")}</span>
                <span className="value">{formatNumber(summary.reopened)}</span>
              </div>
              <div>
                <span className="label">{c("detail.vuln.kev")}</span>
                <span className="value" style={{ color: summary.kev ? "var(--critical)" : "var(--success)" }}>{formatNumber(summary.kev)}</span>
              </div>
            </div>
            <div>
              <div className="section-label">{c("detail.vuln.bySeverity")}</div>
              <SeverityBars data={severityBars} />
            </div>
          </div>
        )}
      </Card>

      {asset.ot ? (
        <div className="stack">
          <div className="notice notice-warning">
            <ShieldAlert size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
            <span>{c("detail.overview.safetyNotice")}</span>
          </div>
          <Card
            title={c("detail.overview.ot")}
            actions={
              <div className="row wrap" style={{ gap: 6 }}>
                <Badge tone={asset.ot.safety_critical ? "critical" : "neutral"}>
                  {c("detail.overview.safetyCritical")}
                </Badge>
                <Badge tone={asset.ot.passive_only ? "warning" : "neutral"}>
                  {c("detail.overview.passiveOnly")}
                </Badge>
              </div>
            }
          >
            <div className="grid-2">
              <div className="metric-list">
                <MetaRow label={c("detail.overview.protocols")}>
                  <span className="mono">{asset.ot.protocols.length ? asset.ot.protocols.join(", ") : "—"}</span>
                </MetaRow>
                <MetaRow label={c("detail.overview.controller")}>{asset.ot.controller_model ?? "—"}</MetaRow>
                <MetaRow label={c("detail.overview.firmwareVersion")}>{asset.ot.firmware_version ?? "—"}</MetaRow>
                <MetaRow label={c("detail.overview.lastTelemetry")}>
                  {asset.ot.last_telemetry_at ? formatDateTime(asset.ot.last_telemetry_at, lang) : "—"}
                </MetaRow>
                <MetaRow label={c("detail.zone")}>{zoneName ?? asset.ot.zone_id ?? "—"}</MetaRow>
              </div>
              <div>
                <div className="row-between">
                  <div className="section-label" style={{ marginBottom: 0 }}>{c("detail.overview.baseline")}</div>
                  <CopyButton text={JSON.stringify(asset.ot.baseline, null, 2)} />
                </div>
                <JsonBlock value={asset.ot.baseline} ariaLabel={c("detail.overview.baseline")} />
              </div>
            </div>
          </Card>
        </div>
      ) : null}

      {asset.iot ? (
        <Card title={c("detail.overview.iot")}>
          <div className="grid-2">
            <div className="metric-list">
              <MetaRow label={c("detail.overview.protocols")}>
                <span className="mono">{asset.iot.protocols.length ? asset.iot.protocols.join(", ") : "—"}</span>
              </MetaRow>
              <MetaRow label={c("detail.overview.connectivity")}>{asset.iot.connectivity ?? "—"}</MetaRow>
              <MetaRow label={c("detail.overview.edgeGateway")}><span className="mono">{asset.iot.edge_gateway_id ?? "—"}</span></MetaRow>
              <MetaRow label={c("detail.overview.firmwareVersion")}>{asset.iot.firmware_version ?? "—"}</MetaRow>
              <MetaRow label={c("detail.overview.lastTelemetry")}>
                {asset.iot.last_telemetry_at ? formatDateTime(asset.iot.last_telemetry_at, lang) : "—"}
              </MetaRow>
            </div>
            <div>
              <div className="row-between">
                <div className="section-label" style={{ marginBottom: 0 }}>{c("detail.overview.posture")}</div>
                <CopyButton text={JSON.stringify(asset.iot.security_posture, null, 2)} />
              </div>
              <JsonBlock value={asset.iot.security_posture} ariaLabel={c("detail.overview.posture")} />
            </div>
          </div>
        </Card>
      ) : null}

      <Card
        title={c("detail.overview.metadata")}
        actions={<CopyButton text={JSON.stringify(asset.metadata, null, 2)} />}
      >
        {Object.keys(asset.metadata).length ? (
          <JsonBlock value={asset.metadata} ariaLabel={c("detail.overview.metadata")} />
        ) : (
          <span className="dim" style={{ fontSize: 11.5 }}>{c("detail.overview.noMetadata")}</span>
        )}
      </Card>
    </div>
  );
}

export default AssetDetailPage;
