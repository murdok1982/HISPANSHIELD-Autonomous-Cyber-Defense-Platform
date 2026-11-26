import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Download,
  FileSearch,
  Fingerprint,
  Link2,
  Lock,
  RefreshCw,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { api, errorMessage, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy, type Lang } from "../lib/i18n";
import { downloadCsv, formatDateTime, formatNumber, formatTime, humanize, relativeTime } from "../lib/format";
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
  PageSkeleton,
  Pagination,
  Select,
  StatusBadge,
  useToast,
  type Column,
} from "../components/ui";
import { CopyButton, MetaRows, PreBlock, hashPrefix } from "../components/features/govern/common";

/* --------------------------------------------------------------- contracts */

interface AuditRecord {
  id: string;
  org_id: string | null;
  actor_type: string;
  actor_id: string | null;
  actor_email: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  request_id: string | null;
  ip_address: string | null;
  payload: Record<string, unknown>;
  hash: string;
  prev_hash: string | null;
  created_at: string;
}

interface ChainResult {
  valid: boolean;
  checked: number;
  head?: string | null;
  broken_at: string | null;
  expected_hash?: string;
  stored_hash?: string;
  reason?: string;
}

interface VerifyResponse {
  organization: ChainResult;
  global_tail: ChainResult;
  verified_at: string;
}

/* -------------------------------------------------------------------- copy */

const COPY: Record<Lang, Record<string, string>> = {
  es: {
    eyebrow: "Gobierno · Auditoría",
    title: "Centro de auditoría",
    subtitle: "Cadena append-only de toda actividad, con evidencia de integridad verificable.",
    appendOnlyTitle: "Append-only y evidencia de manipulación",
    appendOnly:
      "Cada entrada enlaza el hash de la anterior y se sella con SHA-256. La base de datos impide actualizar o borrar registros; cualquier alteración rompe la cadena y queda localizada por su identificador.",
    filters: "Filtros",
    action: "Acción",
    actionHint: "Coincidencia exacta. Ejemplo: connector.create",
    resourceType: "Tipo de recurso",
    resourceHint: "Coincidencia exacta. Ejemplo: connector",
    outcome: "Resultado",
    actor: "Actor",
    actorHint: "Email exacto del actor.",
    all: "Todos",
    clear: "Limpiar filtros",
    applied: "Filtros activos",
    table: "Registro de auditoría",
    timestamp: "Fecha y hora",
    actorColumn: "Actor",
    resource: "Recurso",
    requestId: "Request ID",
    ip: "IP",
    hash: "Hash",
    outcomeColumn: "Resultado",
    details: "Detalle",
    empty: "Sin registros de auditoría",
    emptyHint: "La actividad de la plataforma aparecerá aquí en cuanto se realice la primera operación auditada.",
    emptyFiltered: "Ningún registro coincide con los filtros",
    emptyFilteredHint: "Amplía o limpia los filtros para ver más actividad.",
    loadFailed: "No se pudo cargar la auditoría.",
    noPermission: "No tienes permiso para leer la auditoría.",
    detail: "Entrada de auditoría",
    payload: "Payload redactado",
    payloadNote: "El servidor redacta secretos y datos sensibles antes de devolver el payload. No se muestran valores de credenciales.",
    prevHash: "Hash anterior",
    currentHash: "Hash actual",
    genesis: "Génesis (sin hash anterior)",
    entryId: "ID de entrada",
    organization: "Organización",
    verifyTitle: "Verificación de integridad",
    verifySub: "Recalcula la cadena completa y localiza la primera divergencia.",
    verifyOrg: "Cadena de la organización",
    verifyGlobal: "Cadena global",
    verifyRun: "Verificar ahora",
    verifiedAt: "Verificado",
    valid: "Cadena válida",
    invalid: "Cadena alterada",
    checked: "Entradas comprobadas",
    brokenAt: "Primera divergencia",
    head: "Cabeza de cadena",
    reason: "Motivo",
    expectedHash: "Hash esperado",
    storedHash: "Hash almacenado",
    noVerifyPermission: "Tu rol no puede ejecutar la verificación criptográfica.",
    verifyFailed: "No se pudo verificar la cadena.",
    verifiedOk: "Cadena íntegra verificada",
    verifiedBroken: "Se detectó una divergencia en la cadena",
    export: "Exportar CSV",
    exporting: "Exportando…",
    exportDone: "CSV exportado",
    exportTruncated: "Exportación limitada a 5000 entradas; aplica más filtros para acotar.",
    exportFailed: "No se pudo exportar el CSV.",
    filtersHint: "Los filtros se aplican en el servidor con coincidencia exacta.",
    actionFilter: "Acción exacta",
    resourceFilter: "Recurso exacto",
    close: "Cerrar",
    outcomeSuccess: "success",
    outcomeFailure: "failure",
    outcomePending: "pending",
    rowOpen: "Abrir",
    entryHashPrefix: "Prefijo de hash",
    pageNote: "Ordenado de más reciente a más antiguo.",
    auditPayloadEmpty: "Sin datos adicionales",
  },
  en: {
    eyebrow: "Governance · Audit",
    title: "Audit center",
    subtitle: "Append-only chain of all activity, with verifiable integrity evidence.",
    appendOnlyTitle: "Append-only and tamper evidence",
    appendOnly:
      "Each entry links the previous hash and is sealed with SHA-256. The database rejects updates and deletes; any alteration breaks the chain and is located by identifier.",
    filters: "Filters",
    action: "Action",
    actionHint: "Exact match. Example: connector.create",
    resourceType: "Resource type",
    resourceHint: "Exact match. Example: connector",
    outcome: "Outcome",
    actor: "Actor",
    actorHint: "Exact actor email.",
    all: "All",
    clear: "Clear filters",
    applied: "Active filters",
    table: "Audit trail",
    timestamp: "Timestamp",
    actorColumn: "Actor",
    resource: "Resource",
    requestId: "Request ID",
    ip: "IP",
    hash: "Hash",
    outcomeColumn: "Outcome",
    details: "Detail",
    empty: "No audit records",
    emptyHint: "Platform activity will appear here as soon as the first audited operation occurs.",
    emptyFiltered: "No record matches the filters",
    emptyFilteredHint: "Broaden or clear the filters to see more activity.",
    loadFailed: "Audit data could not be loaded.",
    noPermission: "You do not have permission to read the audit trail.",
    detail: "Audit entry",
    payload: "Redacted payload",
    payloadNote: "The server redacts secrets and sensitive data before returning the payload. Credential values are never shown.",
    prevHash: "Previous hash",
    currentHash: "Current hash",
    genesis: "Genesis (no previous hash)",
    entryId: "Entry ID",
    organization: "Organization",
    verifyTitle: "Integrity verification",
    verifySub: "Recomputes the full chain and locates the first divergence.",
    verifyOrg: "Organization chain",
    verifyGlobal: "Global chain",
    verifyRun: "Verify now",
    verifiedAt: "Verified",
    valid: "Chain valid",
    invalid: "Chain altered",
    checked: "Entries checked",
    brokenAt: "First divergence",
    head: "Chain head",
    reason: "Reason",
    expectedHash: "Expected hash",
    storedHash: "Stored hash",
    noVerifyPermission: "Your role cannot run the cryptographic verification.",
    verifyFailed: "The chain could not be verified.",
    verifiedOk: "Integrity chain verified",
    verifiedBroken: "A divergence was detected in the chain",
    export: "Export CSV",
    exporting: "Exporting…",
    exportDone: "CSV exported",
    exportTruncated: "Export capped at 5000 entries; add filters to narrow it.",
    exportFailed: "The CSV could not be exported.",
    filtersHint: "Filters are applied server-side with exact matching.",
    actionFilter: "Exact action",
    resourceFilter: "Exact resource",
    close: "Close",
    outcomeSuccess: "success",
    outcomeFailure: "failure",
    outcomePending: "pending",
    rowOpen: "Open",
    entryHashPrefix: "Hash prefix",
    pageNote: "Sorted newest first.",
    auditPayloadEmpty: "No additional data",
  },
};

const EXPORT_LIMIT = 5000;

export function AuditPage() {
  const t = usePageCopy(COPY);
  const { lang } = useI18n();
  const { can } = useAuth();
  const toast = useToast();
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [outcome, setOutcome] = useState("");
  const [actor, setActor] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<AuditRecord | null>(null);
  const [exporting, setExporting] = useState(false);

  const canRead = can("audit:read");
  const canVerify = can("audit:verify");

  const filters = {
    action: action.trim() || undefined,
    resource_type: resourceType.trim() || undefined,
    outcome: outcome || undefined,
    actor: actor.trim() || undefined,
  };
  const filtersActive = Boolean(filters.action || filters.resource_type || filters.outcome || filters.actor);

  const auditQuery = useQuery({
    queryKey: ["audit", "records", { action, resourceType, outcome, actor, page }],
    queryFn: () =>
      api.get<Page<AuditRecord>>("/organizations/current/audit", {
        page,
        page_size: 50,
        ...filters,
      }),
    enabled: canRead,
  });

  const verifyQuery = useQuery({
    queryKey: ["audit", "verify"],
    queryFn: () => api.get<VerifyResponse>("/organizations/current/audit/verify"),
    enabled: canVerify,
  });

  const runVerify = async () => {
    const result = await verifyQuery.refetch();
    if (result.data) {
      const ok = result.data.organization.valid && result.data.global_tail.valid;
      toast.push(ok ? t("verifiedOk") : t("verifiedBroken"), ok ? "success" : "error");
    }
  };

  const exportCsv = async () => {
    setExporting(true);
    try {
      const rows: AuditRecord[] = [];
      let currentPage = 1;
      let hasNext = true;
      while (hasNext && rows.length < EXPORT_LIMIT) {
        const result = await api.get<Page<AuditRecord>>("/organizations/current/audit", {
          page: currentPage,
          page_size: 200,
          ...filters,
        });
        rows.push(...result.items);
        hasNext = result.meta.has_next;
        currentPage += 1;
        if (result.items.length === 0) break;
      }
      const limited = rows.length > EXPORT_LIMIT;
      const slice = rows.slice(0, EXPORT_LIMIT);
      downloadCsv(
        `audit-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.csv`,
        ["created_at", "actor", "actor_type", "action", "resource_type", "resource_id", "outcome", "ip_address", "request_id", "hash", "prev_hash"],
        slice.map((row) => [
          row.created_at,
          row.actor_email ?? row.actor_id ?? "",
          row.actor_type,
          row.action,
          row.resource_type,
          row.resource_id ?? "",
          row.outcome,
          row.ip_address ?? "",
          row.request_id ?? "",
          row.hash,
          row.prev_hash ?? "",
        ]),
      );
      toast.push(limited ? t("exportTruncated") : t("exportDone"), limited ? "warning" : "success");
    } catch (error) {
      toast.push(`${t("exportFailed")} ${errorMessage(error)}`, "error");
    } finally {
      setExporting(false);
    }
  };

  const columns: Column<AuditRecord>[] = [
    {
      key: "time",
      header: t("timestamp"),
      width: "150px",
      render: (row) => (
        <div>
          <div className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.created_at, lang)}</div>
          <div className="cell-sub mono">{formatTime(row.created_at, lang)} · {relativeTime(row.created_at, lang)}</div>
        </div>
      ),
    },
    {
      key: "actor",
      header: t("actorColumn"),
      width: "190px",
      render: (row) => (
        <div style={{ minWidth: 0 }}>
          <div className="primary-cell" style={{ fontSize: 11.5 }}>{row.actor_email ?? row.actor_id ?? "—"}</div>
          <div className="cell-sub mono">{row.actor_type}</div>
        </div>
      ),
    },
    {
      key: "action",
      header: t("action"),
      width: "190px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5, color: "var(--accent)" }}>{row.action}</span>,
    },
    {
      key: "resource",
      header: t("resource"),
      width: "180px",
      render: (row) => (
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 11.5 }}>{row.resource_type}</div>
          {row.resource_id ? <div className="cell-sub mono">{row.resource_id.slice(0, 12)}…</div> : null}
        </div>
      ),
    },
    {
      key: "outcome",
      header: t("outcomeColumn"),
      width: "100px",
      render: (row) => <StatusBadge status={row.outcome} />,
    },
    {
      key: "ip",
      header: t("ip"),
      width: "120px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.ip_address ?? "—"}</span>,
    },
    {
      key: "request",
      header: t("requestId"),
      width: "120px",
      render: (row) => <span className="mono" style={{ fontSize: 10 }}>{row.request_id ? row.request_id.slice(0, 12) : "—"}</span>,
    },
    {
      key: "hash",
      header: t("hash"),
      width: "130px",
      render: (row) => <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }} title={row.hash}>{hashPrefix(row.hash)}</span>,
    },
    {
      key: "open",
      header: "",
      width: "80px",
      align: "right",
      render: (row) => (
        <Button size="sm" variant="ghost" onClick={() => setSelected(row)} data-testid="audit-row-open">
          {t("rowOpen")}
        </Button>
      ),
    },
  ];

  if (!canRead) {
    return (
      <div className="animate-in" data-testid="page-audit">
        <PageHeader eyebrow={t("eyebrow")} title={t("title")} subtitle={t("subtitle")} />
        <Card><EmptyState icon={Lock} title={t("noPermission")} /></Card>
      </div>
    );
  }

  return (
    <div className="animate-in" data-testid="page-audit">
      <PageHeader
        eyebrow={t("eyebrow")}
        title={t("title")}
        subtitle={t("subtitle")}
        actions={
          <>
            <Badge tone="accent"><Fingerprint size={11} /> SHA-256</Badge>
            <Button icon={Download} loading={exporting} onClick={() => void exportCsv()} data-testid="audit-export">
              {exporting ? t("exporting") : t("export")}
            </Button>
            <Button variant="ghost" icon={RefreshCw} aria-label={t("common.refresh")} onClick={() => void auditQuery.refetch()} />
          </>
        }
      />

      <div className="notice notice-accent" style={{ marginBottom: 12 }} data-testid="audit-append-only">
        <Link2 size={14} style={{ flex: "0 0 auto" }} />
        <div>
          <strong>{t("appendOnlyTitle")}</strong>
          <div style={{ marginTop: 2, fontSize: 11.5 }}>{t("appendOnly")}</div>
        </div>
      </div>

      <Card
        title={t("verifyTitle")}
        subtitle={t("verifySub")}
        actions={
          canVerify ? (
            <Button size="sm" icon={ShieldCheck} loading={verifyQuery.isFetching} onClick={() => void runVerify()} data-testid="audit-verify-run">
              {t("verifyRun")}
            </Button>
          ) : undefined
        }
      >
        {!canVerify ? (
          <div className="notice">{t("noVerifyPermission")}</div>
        ) : verifyQuery.isError ? (
          <ErrorBanner message={`${t("verifyFailed")} ${errorMessage(verifyQuery.error)}`} onRetry={() => void verifyQuery.refetch()} />
        ) : verifyQuery.isLoading ? (
          <div className="skeleton skeleton-row" />
        ) : verifyQuery.data ? (
          <div className="stack" data-testid="audit-verify-panel">
            <div className="grid-2">
              <div className="card card-pad stack" data-testid="audit-verify-org">
                <div className="row-between">
                  <span className="section-label" style={{ marginBottom: 0 }}>{t("verifyOrg")}</span>
                  <Badge tone={verifyQuery.data.organization.valid ? "success" : "critical"}>
                    {verifyQuery.data.organization.valid ? <ShieldCheck size={11} /> : <ShieldX size={11} />}
                    {verifyQuery.data.organization.valid ? t("valid") : t("invalid")}
                  </Badge>
                </div>
                <MetaRows
                  items={[
                    { label: t("checked"), value: formatNumber(verifyQuery.data.organization.checked) },
                    { label: t("head"), value: <span className="mono" style={{ fontSize: 10 }}>{hashPrefix(verifyQuery.data.organization.head ?? null, 20)}</span> },
                    { label: t("brokenAt"), value: <span className="mono" style={{ fontSize: 10 }}>{verifyQuery.data.organization.broken_at ?? "—"}</span> },
                  ]}
                />
                {!verifyQuery.data.organization.valid ? (
                  <div className="notice notice-danger" style={{ fontSize: 11 }}>
                    <ShieldX size={13} style={{ flex: "0 0 auto" }} />
                    <div className="stack" style={{ gap: 2 }}>
                      <span>{verifyQuery.data.organization.reason ?? t("invalid")}</span>
                      {verifyQuery.data.organization.expected_hash ? <span className="mono" style={{ fontSize: 9.5 }}>{t("expectedHash")}: {verifyQuery.data.organization.expected_hash}</span> : null}
                      {verifyQuery.data.organization.stored_hash ? <span className="mono" style={{ fontSize: 9.5 }}>{t("storedHash")}: {verifyQuery.data.organization.stored_hash}</span> : null}
                    </div>
                  </div>
                ) : null}
              </div>
              <div className="card card-pad stack" data-testid="audit-verify-global">
                <div className="row-between">
                  <span className="section-label" style={{ marginBottom: 0 }}>{t("verifyGlobal")}</span>
                  <Badge tone={verifyQuery.data.global_tail.valid ? "success" : "critical"}>
                    {verifyQuery.data.global_tail.valid ? <ShieldCheck size={11} /> : <ShieldX size={11} />}
                    {verifyQuery.data.global_tail.valid ? t("valid") : t("invalid")}
                  </Badge>
                </div>
                <MetaRows
                  items={[
                    { label: t("checked"), value: formatNumber(verifyQuery.data.global_tail.checked) },
                    { label: t("head"), value: <span className="mono" style={{ fontSize: 10 }}>{hashPrefix(verifyQuery.data.global_tail.head ?? null, 20)}</span> },
                    { label: t("brokenAt"), value: <span className="mono" style={{ fontSize: 10 }}>{verifyQuery.data.global_tail.broken_at ?? "—"}</span> },
                  ]}
                />
                {!verifyQuery.data.global_tail.valid ? (
                  <div className="notice notice-danger" style={{ fontSize: 11 }}>
                    <ShieldX size={13} style={{ flex: "0 0 auto" }} />
                    <div className="stack" style={{ gap: 2 }}>
                      <span>{verifyQuery.data.global_tail.reason ?? t("invalid")}</span>
                      {verifyQuery.data.global_tail.expected_hash ? <span className="mono" style={{ fontSize: 9.5 }}>{t("expectedHash")}: {verifyQuery.data.global_tail.expected_hash}</span> : null}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
            <span className="dim" style={{ fontSize: 11 }}>{t("verifiedAt")}: {formatDateTime(verifyQuery.data.verified_at, lang)}</span>
          </div>
        ) : null}
      </Card>

      <Card
        title={t("table")}
        subtitle={auditQuery.data ? `${formatNumber(auditQuery.data.meta.total)} · ${t("pageNote")}` : t("pageNote")}
        style={{ marginTop: 12 }}
        bodyClassName=""
        footer={<span>{t("filtersHint")}</span>}
      >
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }} data-testid="audit-filters">
          <div className="form-grid">
            <Field label={t("actionFilter")} htmlFor="audit-action" hint={t("actionHint")}>
              <Input
                id="audit-action"
                value={action}
                onChange={(event) => { setAction(event.target.value); setPage(1); }}
                placeholder="connector.create"
                data-testid="audit-action"
              />
            </Field>
            <Field label={t("resourceFilter")} htmlFor="audit-resource" hint={t("resourceHint")}>
              <Input
                id="audit-resource"
                value={resourceType}
                onChange={(event) => { setResourceType(event.target.value); setPage(1); }}
                placeholder="connector"
                data-testid="audit-resource"
              />
            </Field>
            <Field label={t("outcome")} htmlFor="audit-outcome">
              <Select
                id="audit-outcome"
                value={outcome}
                onChange={(event) => { setOutcome(event.target.value); setPage(1); }}
                data-testid="audit-outcome"
              >
                <option value="">{t("all")}</option>
                <option value="success">{t("outcomeSuccess")}</option>
                <option value="failure">{t("outcomeFailure")}</option>
                <option value="pending">{t("outcomePending")}</option>
              </Select>
            </Field>
            <Field label={t("actor")} htmlFor="audit-actor" hint={t("actorHint")}>
              <Input
                id="audit-actor"
                value={actor}
                onChange={(event) => { setActor(event.target.value); setPage(1); }}
                placeholder="analyst@example.eu"
                data-testid="audit-actor"
              />
            </Field>
          </div>
          {filtersActive ? (
            <div className="row wrap" style={{ marginTop: 10 }}>
              <span className="dim" style={{ fontSize: 11 }}>{t("applied")}:</span>
              <div className="chip-row">
                {filters.action ? <span className="tag">action: {filters.action}</span> : null}
                {filters.resource_type ? <span className="tag">resource_type: {filters.resource_type}</span> : null}
                {filters.outcome ? <span className="tag">outcome: {filters.outcome}</span> : null}
                {filters.actor ? <span className="tag">actor: {filters.actor}</span> : null}
              </div>
              <Button size="sm" variant="ghost" onClick={() => { setAction(""); setResourceType(""); setOutcome(""); setActor(""); setPage(1); }}>
                {t("clear")}
              </Button>
            </div>
          ) : null}
        </div>

        {auditQuery.isError ? (
          <div style={{ padding: 16 }}>
            <ErrorBanner message={`${t("loadFailed")} ${errorMessage(auditQuery.error)}`} onRetry={() => void auditQuery.refetch()} />
          </div>
        ) : (
          <div data-testid="audit-table">
            <DataTable
              columns={columns}
              rows={auditQuery.data?.items}
              rowKey={(row) => row.id}
              loading={auditQuery.isLoading}
              onRowClick={setSelected}
              empty={
                <EmptyState
                  icon={FileSearch}
                  title={filtersActive ? t("emptyFiltered") : t("empty")}
                  description={filtersActive ? t("emptyFilteredHint") : t("emptyHint")}
                  action={filtersActive ? <Button size="sm" onClick={() => { setAction(""); setResourceType(""); setOutcome(""); setActor(""); }}>{t("clear")}</Button> : undefined}
                />
              }
            />
            <div style={{ padding: "0 16px 12px" }}>
              <Pagination meta={auditQuery.data?.meta} onPage={setPage} />
            </div>
          </div>
        )}
      </Card>

      <Modal
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={t("detail")}
        size="lg"
        footer={<Button variant="primary" onClick={() => setSelected(null)}>{t("close")}</Button>}
      >
        {selected ? (
          <div className="stack" data-testid="audit-detail">
            <div className="row wrap">
              <StatusBadge status={selected.outcome} />
              <Badge tone="neutral">{selected.action}</Badge>
              <Badge tone="neutral">{selected.resource_type}</Badge>
              <span className="mono" style={{ fontSize: 10, color: "var(--dim)" }}>{selected.id}</span>
            </div>
            <MetaRows
              items={[
                { label: t("timestamp"), value: formatDateTime(selected.created_at, lang) },
                { label: t("actorColumn"), value: selected.actor_email ?? selected.actor_id ?? "—" },
                { label: "actor_type", value: selected.actor_type },
                { label: t("resource"), value: selected.resource_id ?? selected.resource_type },
                { label: t("ip"), value: selected.ip_address ?? "—" },
                { label: t("requestId"), value: selected.request_id ?? "—" },
                { label: t("organization"), value: selected.org_id ?? "—" },
              ]}
            />
            <div>
              <div className="section-label">{t("currentHash")}</div>
              <div className="row" style={{ gap: 6 }}>
                <code className="mono" style={{ fontSize: 10.5, wordBreak: "break-all", flex: 1 }}>{selected.hash}</code>
                <CopyButton value={selected.hash} label={t("currentHash")} />
              </div>
            </div>
            <div>
              <div className="section-label">{t("prevHash")}</div>
              {selected.prev_hash ? (
                <div className="row" style={{ gap: 6 }}>
                  <code className="mono" style={{ fontSize: 10.5, wordBreak: "break-all", flex: 1 }}>{selected.prev_hash}</code>
                  <CopyButton value={selected.prev_hash} label={t("prevHash")} />
                </div>
              ) : (
                <span className="dim" style={{ fontSize: 11 }}>{t("genesis")}</span>
              )}
            </div>
            <div>
              <div className="section-label">{t("payload")}</div>
              <div className="notice" style={{ fontSize: 10.5, marginBottom: 6 }}>{t("payloadNote")}</div>
              {Object.keys(selected.payload ?? {}).length === 0 ? (
                <span className="dim" style={{ fontSize: 11 }}>{t("auditPayloadEmpty")}</span>
              ) : (
                <PreBlock value={selected.payload} />
              )}
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

export default AuditPage;
