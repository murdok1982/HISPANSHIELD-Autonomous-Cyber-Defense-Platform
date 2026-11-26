import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronUp,
  Download,
  Layers,
  Plus,
  RefreshCw,
  ScanSearch,
  Server,
  Upload,
} from "lucide-react";
import { api, errorMessage, isApiError, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { downloadCsv, formatNumber, relativeTime } from "../lib/format";
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
  Modal,
  PageHeader,
  PageSkeleton,
  Pagination,
  ProgressBar,
  SearchInput,
  Select,
  TableSkeleton,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";
import {
  CriticalityMeter,
  DemoTag,
  FilterBar,
  ImportErrors,
  csvStamp,
  fieldErrors,
  isIpAddress,
  parseCommaList,
  useDebouncedValue,
} from "../components/features/detect/shared";
import type { Asset, AssetImportResult, Zone } from "../components/features/detect/types";

const COPY = {
  es: {
    "assets.eyebrow": "Exposición · CAASM",
    "assets.title": "Inteligencia de activos",
    "assets.subtitle": "Inventario consolidado con identidad, criticidad, propietario y confianza de descubrimiento.",
    "assets.new": "Nuevo activo",
    "assets.import": "Importar",
    "assets.export": "Exportar CSV",
    "assets.exported": "Página actual exportada a CSV",
    "assets.exportFail": "No se pudo exportar el CSV",
    "assets.exportEmpty": "No hay activos que exportar en esta página",
    "assets.search": "Buscar por nombre, clave, propietario, IP u hostname…",
    "assets.filter.kind": "Tipo",
    "assets.filter.criticality": "Criticidad",
    "assets.filter.environment": "Entorno",
    "assets.filter.status": "Estado",
    "assets.filter.zone": "Zona",
    "assets.filter.subtype": "Subtipo",
    "assets.filter.subtypePlaceholder": "Filtrar subtipo",
    "assets.filter.sort": "Ordenar por",
    "assets.filter.allKinds": "Todos los tipos",
    "assets.filter.allCriticality": "Toda criticidad",
    "assets.filter.allEnvironments": "Todos los entornos",
    "assets.filter.allStatuses": "Todos los estados",
    "assets.filter.allZones": "Todas las zonas",
    "assets.filter.order": "Invertir orden",
    "assets.filter.clear": "Limpiar filtros",
    "assets.sort.last_seen": "Última observación",
    "assets.sort.name": "Nombre",
    "assets.sort.criticality": "Criticidad",
    "assets.sort.confidence": "Confianza",
    "assets.sort.created_at": "Fecha de alta",
    "assets.table.asset": "Activo",
    "assets.table.kind": "Tipo",
    "assets.table.criticality": "Criticidad",
    "assets.table.environment": "Entorno",
    "assets.table.ips": "IPs",
    "assets.table.owner": "Propietario",
    "assets.table.confidence": "Confianza",
    "assets.table.lastSeen": "Última vez",
    "assets.table.vulns": "Vulns.",
    "assets.table.tags": "Etiquetas",
    "assets.kind.host": "Host",
    "assets.kind.network": "Red",
    "assets.kind.cloud": "Cloud",
    "assets.kind.iot": "IoT",
    "assets.kind.ot": "OT",
    "assets.kind.identity": "Identidad",
    "assets.kind.service": "Servicio",
    "assets.environment.production": "Producción",
    "assets.environment.staging": "Preproducción",
    "assets.environment.development": "Desarrollo",
    "assets.environment.test": "Pruebas",
    "assets.status.active": "Activo",
    "assets.status.inactive": "Inactivo",
    "assets.status.retired": "Retirado",
    "assets.status.quarantined": "Cuarentena",
    "assets.status.unknown": "Desconocido",
    "assets.empty.title": "Aún no hay activos inventariados",
    "assets.empty.description": "Crea el primer activo o importa un lote JSON acotado para construir el grafo de exposición.",
    "assets.empty.action": "Crear activo",
    "assets.noResults.title": "Ningún activo coincide con los filtros",
    "assets.noResults.description": "Ajusta los filtros o limpia la búsqueda para ver el inventario completo.",
    "assets.count": "activos",
    "assets.create.title": "Crear activo",
    "assets.create.description": "La clave de activo es estable e idempotente: identifica al activo entre descubrimientos.",
    "assets.create.name": "Nombre",
    "assets.create.key": "Clave de activo",
    "assets.create.keyHint": "Letras, números y . _ : / - (máx. 200)",
    "assets.create.kind": "Tipo de activo",
    "assets.create.criticality": "Criticidad (1-5)",
    "assets.create.environment": "Entorno",
    "assets.create.subtype": "Subtipo",
    "assets.create.ips": "Direcciones IP",
    "assets.create.ipsHint": "Separadas por comas",
    "assets.create.owner": "Propietario",
    "assets.create.zone": "Zona",
    "assets.create.tags": "Etiquetas",
    "assets.create.tagsHint": "Separadas por comas",
    "assets.create.submit": "Crear activo",
    "assets.create.success": "Activo creado",
    "assets.create.failed": "No se pudo crear el activo",
    "assets.create.required": "Obligatorio",
    "assets.create.invalidKey": "Formato de clave no válido",
    "assets.create.invalidIp": "Dirección IP no válida",
    "assets.create.invalidCriticality": "La criticidad debe estar entre 1 y 5",
    "assets.import.title": "Importación masiva de activos",
    "assets.import.description": "Pega un array JSON de hasta 500 activos. La importación es idempotente por asset_key.",
    "assets.import.json": "JSON de activos",
    "assets.import.placeholder": "[{\"asset_key\": \"...\", \"name\": \"...\", \"kind\": \"host\"}]",
    "assets.import.file": "Cargar desde archivo",
    "assets.import.submit": "Importar activos",
    "assets.import.invalidJson": "El texto no es JSON válido",
    "assets.import.invalidShape": "Debe ser un array de objetos o { items: [...] }",
    "assets.import.empty": "Añade al menos una fila",
    "assets.import.tooMany": "Máximo 500 filas por importación",
    "assets.import.tooBig": "El archivo supera el límite de 2 MB",
    "assets.import.success": "Importación completada",
    "assets.import.failed": "No se pudo importar",
    "assets.import.created": "Creados",
    "assets.import.updated": "Actualizados",
    "assets.import.skipped": "Sin cambios",
    "assets.import.errors": "Errores",
    "assets.import.total": "Filas procesadas",
    "assets.import.noErrors": "Sin errores de validación",
    "assets.loadFailed": "No se pudo cargar el inventario",
  },
  en: {
    "assets.eyebrow": "Exposure · CAASM",
    "assets.title": "Asset intelligence",
    "assets.subtitle": "Consolidated inventory with identity, criticality, ownership and discovery confidence.",
    "assets.new": "New asset",
    "assets.import": "Import",
    "assets.export": "Export CSV",
    "assets.exported": "Current page exported to CSV",
    "assets.exportFail": "Could not export the CSV",
    "assets.exportEmpty": "No assets to export on this page",
    "assets.search": "Search by name, key, owner, IP or hostname…",
    "assets.filter.kind": "Kind",
    "assets.filter.criticality": "Criticality",
    "assets.filter.environment": "Environment",
    "assets.filter.status": "Status",
    "assets.filter.zone": "Zone",
    "assets.filter.subtype": "Subtype",
    "assets.filter.subtypePlaceholder": "Filter subtype",
    "assets.filter.sort": "Sort by",
    "assets.filter.allKinds": "All kinds",
    "assets.filter.allCriticality": "Any criticality",
    "assets.filter.allEnvironments": "All environments",
    "assets.filter.allStatuses": "All statuses",
    "assets.filter.allZones": "All zones",
    "assets.filter.order": "Reverse order",
    "assets.filter.clear": "Clear filters",
    "assets.sort.last_seen": "Last seen",
    "assets.sort.name": "Name",
    "assets.sort.criticality": "Criticality",
    "assets.sort.confidence": "Confidence",
    "assets.sort.created_at": "Created",
    "assets.table.asset": "Asset",
    "assets.table.kind": "Kind",
    "assets.table.criticality": "Criticality",
    "assets.table.environment": "Environment",
    "assets.table.ips": "IPs",
    "assets.table.owner": "Owner",
    "assets.table.confidence": "Confidence",
    "assets.table.lastSeen": "Last seen",
    "assets.table.vulns": "Vulns",
    "assets.table.tags": "Tags",
    "assets.kind.host": "Host",
    "assets.kind.network": "Network",
    "assets.kind.cloud": "Cloud",
    "assets.kind.iot": "IoT",
    "assets.kind.ot": "OT",
    "assets.kind.identity": "Identity",
    "assets.kind.service": "Service",
    "assets.environment.production": "Production",
    "assets.environment.staging": "Staging",
    "assets.environment.development": "Development",
    "assets.environment.test": "Test",
    "assets.status.active": "Active",
    "assets.status.inactive": "Inactive",
    "assets.status.retired": "Retired",
    "assets.status.quarantined": "Quarantined",
    "assets.status.unknown": "Unknown",
    "assets.empty.title": "No assets inventoried yet",
    "assets.empty.description": "Create the first asset or import a bounded JSON batch to build the exposure graph.",
    "assets.empty.action": "Create asset",
    "assets.noResults.title": "No asset matches the filters",
    "assets.noResults.description": "Adjust the filters or clear the search to see the full inventory.",
    "assets.count": "assets",
    "assets.create.title": "Create asset",
    "assets.create.description": "The asset key is stable and idempotent: it identifies the asset across discoveries.",
    "assets.create.name": "Name",
    "assets.create.key": "Asset key",
    "assets.create.keyHint": "Letters, numbers and . _ : / - (max. 200)",
    "assets.create.kind": "Asset kind",
    "assets.create.criticality": "Criticality (1-5)",
    "assets.create.environment": "Environment",
    "assets.create.subtype": "Subtype",
    "assets.create.ips": "IP addresses",
    "assets.create.ipsHint": "Comma separated",
    "assets.create.owner": "Owner",
    "assets.create.zone": "Zone",
    "assets.create.tags": "Tags",
    "assets.create.tagsHint": "Comma separated",
    "assets.create.submit": "Create asset",
    "assets.create.success": "Asset created",
    "assets.create.failed": "Could not create the asset",
    "assets.create.required": "Required",
    "assets.create.invalidKey": "Invalid key format",
    "assets.create.invalidIp": "Invalid IP address",
    "assets.create.invalidCriticality": "Criticality must be between 1 and 5",
    "assets.import.title": "Bulk asset import",
    "assets.import.description": "Paste a JSON array of up to 500 assets. Imports are idempotent on asset_key.",
    "assets.import.json": "Asset JSON",
    "assets.import.placeholder": "[{\"asset_key\": \"...\", \"name\": \"...\", \"kind\": \"host\"}]",
    "assets.import.file": "Load from file",
    "assets.import.submit": "Import assets",
    "assets.import.invalidJson": "The text is not valid JSON",
    "assets.import.invalidShape": "It must be an array of objects or { items: [...] }",
    "assets.import.empty": "Add at least one row",
    "assets.import.tooMany": "Maximum 500 rows per import",
    "assets.import.tooBig": "The file exceeds the 2 MB limit",
    "assets.import.success": "Import completed",
    "assets.import.failed": "Could not import",
    "assets.import.created": "Created",
    "assets.import.updated": "Updated",
    "assets.import.skipped": "Unchanged",
    "assets.import.errors": "Errors",
    "assets.import.total": "Rows processed",
    "assets.import.noErrors": "No validation errors",
    "assets.loadFailed": "Could not load the inventory",
  },
} as const;

export const ASSET_KINDS = ["host", "network", "cloud", "iot", "ot", "identity", "service"] as const;
export const ASSET_ENVIRONMENTS = ["production", "staging", "development", "test"] as const;
export const ASSET_STATUSES = ["active", "inactive", "retired", "quarantined", "unknown"] as const;
export const ASSET_SORTS = ["last_seen", "name", "criticality", "confidence", "created_at"] as const;

const ASSET_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;

export interface AssetDraft {
  name: string;
  asset_key: string;
  kind: string;
  subtype: string;
  criticality: string;
  environment: string;
  ips: string;
  owner: string;
  zone_id: string;
  tags: string;
}

export function emptyAssetDraft(): AssetDraft {
  return {
    name: "",
    asset_key: "",
    kind: "host",
    subtype: "",
    criticality: "3",
    environment: "production",
    ips: "",
    owner: "",
    zone_id: "",
    tags: "",
  };
}

/** Client-side validation mirroring the server contract (server is authoritative). */
export function validateAssetDraft(draft: AssetDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  const name = draft.name.trim();
  if (!name) errors.name = "required";
  else if (name.length > 240) errors.name = "max:240";
  const key = draft.asset_key.trim();
  if (!key) errors.asset_key = "required";
  else if (!ASSET_KEY_RE.test(key)) errors.asset_key = "pattern";
  const criticality = Number(draft.criticality);
  if (!Number.isInteger(criticality) || criticality < 1 || criticality > 5) {
    errors.criticality = "range:1-5";
  }
  if (!ASSET_ENVIRONMENTS.includes(draft.environment as (typeof ASSET_ENVIRONMENTS)[number])) {
    errors.environment = "enum";
  }
  for (const ip of parseCommaList(draft.ips)) {
    if (!isIpAddress(ip)) {
      errors.ip_addresses = "ip";
      break;
    }
  }
  if (draft.owner.trim().length > 200) errors.owner = "max:200";
  if (draft.subtype.trim().length > 60) errors.subtype = "max:60";
  if (parseCommaList(draft.tags).some((tag) => tag.length > 60)) errors.tags = "max:60";
  return errors;
}

/** Convert the draft into the exact AssetCreate payload. */
export function buildAssetPayload(draft: AssetDraft): Record<string, unknown> {
  const owner = draft.owner.trim();
  const subtype = draft.subtype.trim();
  return {
    name: draft.name.trim(),
    asset_key: draft.asset_key.trim(),
    kind: draft.kind,
    subtype: subtype ? subtype : null,
    criticality: Number(draft.criticality),
    environment: draft.environment,
    ip_addresses: parseCommaList(draft.ips),
    owner: owner ? owner : null,
    zone_id: draft.zone_id ? draft.zone_id : null,
    tags: parseCommaList(draft.tags),
  };
}

export type ImportParseResult = { items: Record<string, unknown>[] } | { error: "empty" | "json" | "shape" | "tooMany" };

/** Parse the clipboard/file JSON into bounded object rows. */
export function parseAssetImportText(text: string): ImportParseResult {
  const trimmed = text.trim();
  if (!trimmed) return { error: "empty" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return { error: "json" };
  }
  const rows = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === "object" && Array.isArray((parsed as { items?: unknown }).items)
      ? ((parsed as { items: unknown[] }).items)
      : null;
  if (!rows) return { error: "shape" };
  if (!rows.every((row) => row !== null && typeof row === "object" && !Array.isArray(row))) return { error: "shape" };
  if (rows.length === 0) return { error: "empty" };
  if (rows.length > 500) return { error: "tooMany" };
  return { items: rows as Record<string, unknown>[] };
}

export function AssetsPage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const { can } = useAuth();
  const { push } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const canWrite = can("asset:write");

  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("");
  const [subtype, setSubtype] = useState("");
  const [criticality, setCriticality] = useState("");
  const [environment, setEnvironment] = useState("");
  const [status, setStatus] = useState("");
  const [zoneId, setZoneId] = useState("");
  const [sort, setSort] = useState<(typeof ASSET_SORTS)[number]>("last_seen");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);

  const debouncedSearch = useDebouncedValue(search);
  const debouncedSubtype = useDebouncedValue(subtype, 450);

  const [createOpen, setCreateOpen] = useState(false);
  const [draft, setDraft] = useState<AssetDraft>(emptyAssetDraft);
  const [serverFields, setServerFields] = useState<Record<string, string>>({});
  const [createTouched, setCreateTouched] = useState(false);

  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<AssetImportResult | null>(null);
  const fileInput = useRef<HTMLInputElement | null>(null);

  const zonesQuery = useQuery({
    queryKey: ["assets", "zones"],
    queryFn: () => api.get<Page<Zone>>("/zones", { page: 1, page_size: 200 }),
    staleTime: 120_000,
  });

  const assetsQuery = useQuery({
    queryKey: ["assets", "list", { page, debouncedSearch, kind, subtype: debouncedSubtype, criticality, environment, status, zoneId, sort, order }],
    queryFn: () =>
      api.get<Page<Asset>>("/assets", {
        page,
        page_size: 25,
        q: debouncedSearch || undefined,
        kind: kind || undefined,
        subtype: debouncedSubtype || undefined,
        criticality: criticality || undefined,
        environment: environment || undefined,
        status: status || undefined,
        zone_id: zoneId || undefined,
        sort,
        order,
      }),
  });

  const createMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.post<Asset>("/assets", payload),
    onSuccess: () => {
      push(c("assets.create.success"), "success");
      setCreateOpen(false);
      setDraft(emptyAssetDraft());
      setServerFields({});
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (error) => {
      setServerFields(fieldErrors(error));
      push(`${c("assets.create.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const importMutation = useMutation({
    mutationFn: (items: Record<string, unknown>[]) =>
      api.post<AssetImportResult>("/assets/import", { items, source: "import", confidence: 60 }),
    onSuccess: (result) => {
      setImportResult(result);
      push(`${c("assets.import.success")}: ${result.created} / ${result.updated}`, "success");
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (error) => {
      setImportError(errorMessage(error));
      push(`${c("assets.import.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const rows = assetsQuery.data?.items ?? [];
  const filtersActive = Boolean(debouncedSearch || kind || debouncedSubtype || criticality || environment || status || zoneId);
  const clientErrors = validateAssetDraft(draft);
  const createErrors: Record<string, string> = { ...clientErrors, ...serverFields };
  const showCreateErrors = createTouched || Object.keys(serverFields).length > 0;

  const fieldMessage = (field: string): string | undefined => {
    if (!showCreateErrors) return undefined;
    const code = createErrors[field];
    if (!code) return undefined;
    if (code === "required") return c("assets.create.required");
    if (code === "pattern") return c("assets.create.invalidKey");
    if (code === "ip") return c("assets.create.invalidIp");
    if (code.startsWith("range")) return c("assets.create.invalidCriticality");
    return code;
  };

  const applyFilter = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setPage(1);
  };

  const clearFilters = () => {
    setSearch("");
    setKind("");
    setSubtype("");
    setCriticality("");
    setEnvironment("");
    setStatus("");
    setZoneId("");
    setPage(1);
  };

  const openImport = () => {
    setImportText("");
    setImportError(null);
    setImportResult(null);
    setImportOpen(true);
  };

  const openCreate = () => {
    setDraft(emptyAssetDraft());
    setServerFields({});
    setCreateTouched(false);
    setCreateOpen(true);
  };

  const exportPage = () => {
    if (!rows.length) {
      push(c("assets.exportEmpty"), "info");
      return;
    }
    try {
      downloadCsv(
        `hispanshield-activos-${csvStamp()}-p${page}.csv`,
        ["asset_key", "name", "kind", "subtype", "criticality", "environment", "status", "ip_addresses", "owner", "confidence", "last_seen", "tags"],
        rows.map((asset) => [
          asset.asset_key,
          asset.name,
          asset.kind,
          asset.subtype ?? "",
          asset.criticality,
          asset.environment,
          asset.status,
          asset.ip_addresses.join(";"),
          asset.owner ?? "",
          asset.confidence,
          asset.last_seen,
          asset.tags.join(";"),
        ]),
      );
      push(c("assets.exported"), "success");
    } catch (error) {
      push(`${c("assets.exportFail")}: ${errorMessage(error)}`, "error");
    }
  };

  const zones = zonesQuery.data?.items ?? [];

  const columns: Column<Asset>[] = useMemo(
    () => [
      {
        key: "asset",
        header: c("assets.table.asset"),
        render: (asset) => (
          <div style={{ minWidth: 190 }}>
            <div className="row" style={{ gap: 6 }}>
              <span style={{ color: "var(--text)", fontWeight: 500 }}>{asset.name}</span>
              {asset.is_demo ? <DemoTag /> : null}
            </div>
            <div className="mono" style={{ fontSize: 10, color: "var(--dim)", marginTop: 2 }}>
              {asset.asset_key}
            </div>
          </div>
        ),
      },
      {
        key: "kind",
        header: c("assets.table.kind"),
        width: "132px",
        render: (asset) => (
          <div className="row wrap" style={{ gap: 4 }}>
            <Badge tone="neutral">{c(`assets.kind.${asset.kind}`)}</Badge>
            {asset.subtype ? <span className="tag">{asset.subtype}</span> : null}
          </div>
        ),
      },
      {
        key: "criticality",
        header: c("assets.table.criticality"),
        width: "104px",
        render: (asset) => (
          <div className="row" style={{ gap: 7 }}>
            <CriticalityMeter value={asset.criticality} />
            <span className="mono" style={{ fontSize: 10.5 }}>{asset.criticality}/5</span>
          </div>
        ),
      },
      {
        key: "environment",
        header: c("assets.table.environment"),
        width: "120px",
        render: (asset) => <span style={{ fontSize: 11.5 }}>{c(`assets.environment.${asset.environment}`)}</span>,
      },
      {
        key: "ips",
        header: c("assets.table.ips"),
        width: "150px",
        render: (asset) =>
          asset.ip_addresses.length ? (
            <div className="mono" style={{ fontSize: 10.5 }}>
              {asset.ip_addresses.slice(0, 2).map((ip) => (
                <div key={ip} style={{ color: "var(--text-secondary)" }}>{ip}</div>
              ))}
              {asset.ip_addresses.length > 2 ? <div style={{ color: "var(--dim)" }}>+{asset.ip_addresses.length - 2}</div> : null}
            </div>
          ) : (
            <span className="dim" style={{ fontSize: 11 }}>—</span>
          ),
      },
      {
        key: "owner",
        header: c("assets.table.owner"),
        width: "140px",
        render: (asset) => <span style={{ fontSize: 11.5 }}>{asset.owner ?? "—"}</span>,
      },
      {
        key: "confidence",
        header: c("assets.table.confidence"),
        width: "116px",
        render: (asset) => (
          <div style={{ minWidth: 72 }}>
            <div className="mono" style={{ fontSize: 10.5, marginBottom: 4 }}>{asset.confidence}%</div>
            <ProgressBar value={asset.confidence} tone={asset.confidence >= 80 ? "var(--success)" : asset.confidence >= 50 ? "var(--warning)" : "var(--danger)"} />
          </div>
        ),
      },
      {
        key: "last_seen",
        header: c("assets.table.lastSeen"),
        width: "120px",
        render: (asset) => (
          <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)" }} title={asset.last_seen}>
            {relativeTime(asset.last_seen, lang)}
          </span>
        ),
      },
      {
        key: "vulns",
        header: c("assets.table.vulns"),
        width: "78px",
        align: "right",
        render: (asset) =>
          typeof asset.open_vulnerabilities === "number" ? (
            <Badge tone={asset.open_vulnerabilities > 0 ? "danger" : "success"}>{formatNumber(asset.open_vulnerabilities)}</Badge>
          ) : (
            <span className="dim" style={{ fontSize: 11 }}>—</span>
          ),
      },
      {
        key: "tags",
        header: c("assets.table.tags"),
        width: "150px",
        render: (asset) =>
          asset.tags.length ? (
            <div className="chip-row">
              {asset.tags.slice(0, 3).map((tag) => (
                <span className="tag" key={tag}>{tag}</span>
              ))}
              {asset.tags.length > 3 ? <span className="tag">+{asset.tags.length - 3}</span> : null}
            </div>
          ) : (
            <span className="dim" style={{ fontSize: 11 }}>—</span>
          ),
      },
    ],
    [c, lang],
  );

  if (assetsQuery.isLoading && !assetsQuery.data) return <PageSkeleton />;

  return (
    <div className="animate-in" data-testid="page-assets">
      <PageHeader
        eyebrow={c("assets.eyebrow")}
        title={c("assets.title")}
        subtitle={c("assets.subtitle")}
        actions={
          <>
            <Badge tone="neutral">
              <Layers size={10} aria-hidden="true" /> {formatNumber(assetsQuery.data?.meta.total ?? 0)} {c("assets.count")}
            </Badge>
            <Button icon={RefreshCw} onClick={() => void assetsQuery.refetch()} aria-label={t("common.refresh")} />
            <Button icon={Download} onClick={exportPage} aria-label={c("assets.export")} />
            {canWrite ? (
              <>
                <Button icon={Upload} onClick={openImport} data-testid="open-import">
                  {c("assets.import")}
                </Button>
                <Button
                  variant="primary"
                  icon={Plus}
                  onClick={openCreate}
                  data-testid="open-create"
                >
                  {c("assets.new")}
                </Button>
              </>
            ) : null}
          </>
        }
      />

      <Card
        title={c("assets.title")}
        subtitle={assetsQuery.data ? `${formatNumber(assetsQuery.data.meta.total)} ${c("assets.count")}` : undefined}
        bodyClassName=""
      >
        <FilterBar ariaLabel={t("common.filters")}>
          <SearchInput value={search} onChange={applyFilter(setSearch)} placeholder={c("assets.search")} ariaLabel={c("assets.search")} />
          <Select value={kind} onChange={(event) => applyFilter(setKind)(event.target.value)} aria-label={c("assets.filter.kind")} data-testid="filter-kind">
            <option value="">{c("assets.filter.allKinds")}</option>
            {ASSET_KINDS.map((item) => (
              <option key={item} value={item}>{c(`assets.kind.${item}`)}</option>
            ))}
          </Select>
          <Select
            value={criticality}
            onChange={(event) => applyFilter(setCriticality)(event.target.value)}
            aria-label={c("assets.filter.criticality")}
            data-testid="filter-criticality"
          >
            <option value="">{c("assets.filter.allCriticality")}</option>
            {[5, 4, 3, 2, 1].map((level) => (
              <option key={level} value={level}>{level}/5</option>
            ))}
          </Select>
          <Select
            value={environment}
            onChange={(event) => applyFilter(setEnvironment)(event.target.value)}
            aria-label={c("assets.filter.environment")}
            data-testid="filter-environment"
          >
            <option value="">{c("assets.filter.allEnvironments")}</option>
            {ASSET_ENVIRONMENTS.map((item) => (
              <option key={item} value={item}>{c(`assets.environment.${item}`)}</option>
            ))}
          </Select>
          <Select value={status} onChange={(event) => applyFilter(setStatus)(event.target.value)} aria-label={c("assets.filter.status")} data-testid="filter-status">
            <option value="">{c("assets.filter.allStatuses")}</option>
            {ASSET_STATUSES.map((item) => (
              <option key={item} value={item}>{c(`assets.status.${item}`)}</option>
            ))}
          </Select>
          <Select value={zoneId} onChange={(event) => applyFilter(setZoneId)(event.target.value)} aria-label={c("assets.filter.zone")} data-testid="filter-zone">
            <option value="">{c("assets.filter.allZones")}</option>
            {zones.map((zone) => (
              <option key={zone.id} value={zone.id}>{zone.name}</option>
            ))}
          </Select>
          <input
            className="input"
            style={{ width: "auto", minWidth: 130, height: 30, paddingTop: 0, paddingBottom: 0, fontSize: 11.5 }}
            value={subtype}
            onChange={(event) => applyFilter(setSubtype)(event.target.value)}
            placeholder={c("assets.filter.subtypePlaceholder")}
            aria-label={c("assets.filter.subtype")}
            data-testid="filter-subtype"
          />
          <Select value={sort} onChange={(event) => setSort(event.target.value as (typeof ASSET_SORTS)[number])} aria-label={c("assets.filter.sort")} data-testid="filter-sort">
            {ASSET_SORTS.map((item) => (
              <option key={item} value={item}>{c(`assets.sort.${item}`)}</option>
            ))}
          </Select>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setOrder((value) => (value === "desc" ? "asc" : "desc"));
              setPage(1);
            }}
            aria-label={c("assets.filter.order")}
            icon={order === "desc" ? ChevronDown : ChevronUp}
            data-testid="toggle-order"
          />
          {filtersActive ? (
            <Button size="sm" variant="ghost" onClick={clearFilters} data-testid="clear-filters">
              {c("assets.filter.clear")}
            </Button>
          ) : null}
          <Button size="sm" variant="ghost" icon={Download} onClick={exportPage} data-testid="export-assets">
            {c("assets.export")}
          </Button>
        </FilterBar>

        <div data-testid="table-assets">
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(asset) => asset.id}
            onRowClick={(asset) => navigate(`/assets/${asset.id}`)}
            error={
              assetsQuery.isError ? (
                <ErrorBanner
                  title={c("assets.loadFailed")}
                  message={errorMessage(assetsQuery.error)}
                  onRetry={() => void assetsQuery.refetch()}
                />
              ) : undefined
            }
            empty={
              filtersActive ? (
                <EmptyState
                  icon={ScanSearch}
                  title={c("assets.noResults.title")}
                  description={c("assets.noResults.description")}
                  action={<Button size="sm" variant="primary" onClick={clearFilters}>{c("assets.filter.clear")}</Button>}
                />
              ) : (
                <EmptyState
                  icon={Server}
                  title={c("assets.empty.title")}
                  description={c("assets.empty.description")}
                  action={
                    canWrite ? (
                      <Button size="sm" variant="primary" icon={Plus} onClick={openCreate}>
                        {c("assets.empty.action")}
                      </Button>
                    ) : (
                      <LinkButton to="/integrations" size="sm">{t("nav.integrations")}</LinkButton>
                    )
                  }
                />
              )
            }
          />
        </div>
        <Pagination meta={assetsQuery.data?.meta} onPage={setPage} />
      </Card>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={c("assets.create.title")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={createMutation.isPending}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              loading={createMutation.isPending}
              onClick={() => {
                setCreateTouched(true);
                if (Object.keys(clientErrors).length > 0) return;
                createMutation.mutate(buildAssetPayload(draft));
              }}
              data-testid="submit-create"
            >
              {c("assets.create.submit")}
            </Button>
          </>
        }
      >
        <p className="muted" style={{ fontSize: 12, marginBottom: 14 }}>{c("assets.create.description")}</p>
        <div className="form-grid">
          <Field label={c("assets.create.name")} required htmlFor="asset-name" error={fieldMessage("name")}>
            <Input
              id="asset-name"
              value={draft.name}
              maxLength={240}
              onChange={(event) => setDraft({ ...draft, name: event.target.value })}
              aria-invalid={Boolean(createErrors.name)}
              data-testid="input-asset-name"
            />
          </Field>
          <Field label={c("assets.create.key")} required htmlFor="asset-key" hint={c("assets.create.keyHint")} error={fieldMessage("asset_key")}>
            <Input
              id="asset-key"
              className="mono"
              value={draft.asset_key}
              maxLength={200}
              onChange={(event) => setDraft({ ...draft, asset_key: event.target.value })}
              aria-invalid={Boolean(createErrors.asset_key)}
              data-testid="input-asset-key"
            />
          </Field>
          <Field label={c("assets.create.kind")} required htmlFor="asset-kind">
            <Select id="asset-kind" value={draft.kind} onChange={(event) => setDraft({ ...draft, kind: event.target.value })} data-testid="input-asset-kind">
              {ASSET_KINDS.map((item) => (
                <option key={item} value={item}>{c(`assets.kind.${item}`)}</option>
              ))}
            </Select>
          </Field>
          <Field label={c("assets.create.criticality")} required htmlFor="asset-criticality" error={fieldMessage("criticality")}>
            <Select
              id="asset-criticality"
              value={draft.criticality}
              onChange={(event) => setDraft({ ...draft, criticality: event.target.value })}
              data-testid="input-asset-criticality"
            >
              {[5, 4, 3, 2, 1].map((level) => (
                <option key={level} value={level}>{level}/5</option>
              ))}
            </Select>
          </Field>
          <Field label={c("assets.create.environment")} htmlFor="asset-environment" error={fieldMessage("environment")}>
            <Select id="asset-environment" value={draft.environment} onChange={(event) => setDraft({ ...draft, environment: event.target.value })}>
              {ASSET_ENVIRONMENTS.map((item) => (
                <option key={item} value={item}>{c(`assets.environment.${item}`)}</option>
              ))}
            </Select>
          </Field>
          <Field label={c("assets.create.subtype")} htmlFor="asset-subtype" error={fieldMessage("subtype")}>
            <Input id="asset-subtype" value={draft.subtype} maxLength={60} onChange={(event) => setDraft({ ...draft, subtype: event.target.value })} />
          </Field>
          <Field label={c("assets.create.ips")} htmlFor="asset-ips" hint={c("assets.create.ipsHint")} error={fieldMessage("ip_addresses")}>
            <Input
              id="asset-ips"
              className="mono"
              value={draft.ips}
              onChange={(event) => setDraft({ ...draft, ips: event.target.value })}
              aria-invalid={Boolean(createErrors.ip_addresses)}
              data-testid="input-asset-ips"
            />
          </Field>
          <Field label={c("assets.create.owner")} htmlFor="asset-owner" error={fieldMessage("owner")}>
            <Input id="asset-owner" value={draft.owner} maxLength={200} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} />
          </Field>
          <Field label={c("assets.create.zone")} htmlFor="asset-zone" error={fieldMessage("zone_id")}>
            <Select id="asset-zone" value={draft.zone_id} onChange={(event) => setDraft({ ...draft, zone_id: event.target.value })} data-testid="input-asset-zone">
              <option value="">—</option>
              {zones.map((zone) => (
                <option key={zone.id} value={zone.id}>{zone.name}</option>
              ))}
            </Select>
          </Field>
          <Field label={c("assets.create.tags")} htmlFor="asset-tags" hint={c("assets.create.tagsHint")} error={fieldMessage("tags")}>
            <Input id="asset-tags" value={draft.tags} onChange={(event) => setDraft({ ...draft, tags: event.target.value })} />
          </Field>
        </div>
        {zonesQuery.isError ? (
          <div style={{ marginTop: 12 }}>
            <ErrorBanner compact message={errorMessage(zonesQuery.error)} onRetry={() => void zonesQuery.refetch()} />
          </div>
        ) : null}
        {isApiError(createMutation.error) && createMutation.error.status === 409 ? (
          <div style={{ marginTop: 12 }}>
            <ErrorBanner compact title={c("assets.create.failed")} message={createMutation.error.message} />
          </div>
        ) : null}
      </Modal>

      <Modal
        open={importOpen}
        onClose={() => {
          setImportOpen(false);
          setImportResult(null);
          setImportError(null);
        }}
        title={c("assets.import.title")}
        size="lg"
        footer={
          <>
            <Button
              variant="ghost"
              onClick={() => {
                setImportOpen(false);
                setImportResult(null);
                setImportError(null);
              }}
              disabled={importMutation.isPending}
            >
              {t("common.close")}
            </Button>
            <Button
              variant="primary"
              loading={importMutation.isPending}
              disabled={Boolean(importError) || !importText.trim()}
              onClick={() => {
                const parsed = parseAssetImportText(importText);
                if ("error" in parsed) {
                  setImportError(
                    parsed.error === "empty"
                      ? c("assets.import.empty")
                      : parsed.error === "json"
                        ? c("assets.import.invalidJson")
                        : parsed.error === "tooMany"
                          ? c("assets.import.tooMany")
                          : c("assets.import.invalidShape"),
                  );
                  return;
                }
                setImportError(null);
                importMutation.mutate(parsed.items);
              }}
              data-testid="submit-import"
            >
              {c("assets.import.submit")}
            </Button>
          </>
        }
      >
        <p className="muted" style={{ fontSize: 12, marginBottom: 12 }}>{c("assets.import.description")}</p>
        <Field label={c("assets.import.json")} htmlFor="assets-import-json" error={importError ?? undefined}>
          <Textarea
            id="assets-import-json"
            className="mono"
            style={{ minHeight: 190, fontSize: 11.5 }}
            value={importText}
            placeholder={c("assets.import.placeholder")}
            onChange={(event) => {
              setImportText(event.target.value);
              setImportResult(null);
              setImportError(null);
            }}
            aria-invalid={Boolean(importError)}
            data-testid="import-json"
          />
        </Field>
        <div className="row wrap" style={{ marginTop: 10, gap: 10 }}>
          <input
            ref={fileInput}
            type="file"
            accept="application/json,.json"
            aria-label={c("assets.import.file")}
            className="input"
            style={{ maxWidth: 300 }}
            onChange={async (event) => {
              const file = event.target.files?.[0];
              if (!file) return;
              if (file.size > 2_000_000) {
                setImportError(c("assets.import.tooBig"));
                return;
              }
              const text = await file.text();
              setImportText(text);
              setImportError(null);
              setImportResult(null);
            }}
            data-testid="import-file"
          />
          <span className="dim" style={{ fontSize: 11 }}>{c("assets.import.file")}</span>
        </div>

        {importResult ? (
          <div className="stack" style={{ marginTop: 16 }}>
            <div className="stat-inline">
              <div>
                <span className="label">{c("assets.import.total")}</span>
                <span className="value">{formatNumber(importResult.total)}</span>
              </div>
              <div>
                <span className="label">{c("assets.import.created")}</span>
                <span className="value" style={{ color: "var(--success)" }}>{formatNumber(importResult.created)}</span>
              </div>
              <div>
                <span className="label">{c("assets.import.updated")}</span>
                <span className="value" style={{ color: "var(--accent)" }}>{formatNumber(importResult.updated)}</span>
              </div>
              <div>
                <span className="label">{c("assets.import.skipped")}</span>
                <span className="value">{formatNumber(importResult.skipped)}</span>
              </div>
              <div>
                <span className="label">{c("assets.import.errors")}</span>
                <span className="value" style={{ color: importResult.errors.length ? "var(--danger)" : "var(--success)" }}>
                  {formatNumber(importResult.errors.length)}
                </span>
              </div>
            </div>
            <div>
              <div className="section-label">{c("assets.import.errors")}</div>
              <ImportErrors errors={importResult.errors} emptyLabel={c("assets.import.noErrors")} />
            </div>
          </div>
        ) : importMutation.isPending ? (
          <div style={{ marginTop: 14 }}>
            <TableSkeleton rows={3} />
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

export default AssetsPage;
