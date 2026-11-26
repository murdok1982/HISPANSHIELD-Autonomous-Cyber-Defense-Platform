import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bug,
  ChevronDown,
  ChevronUp,
  Clock,
  Flame,
  RefreshCw,
  ShieldAlert,
  ShieldOff,
  Upload,
} from "lucide-react";
import { api, errorMessage, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatDateTime, formatNumber, formatPercent, humanize } from "../lib/format";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorBanner,
  Field,
  Kpi,
  Modal,
  PageHeader,
  PageSkeleton,
  Pagination,
  ScoreRing,
  SearchInput,
  Select,
  SeverityBadge,
  StatusBadge,
  Tabs,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";
import {
  ConfirmModal,
  CopyButton,
  CriticalityMeter,
  FilterBar,
  ImportErrors,
  SEVERITY_LEVELS,
  useDebouncedValue,
  useToggleSet,
} from "../components/features/detect/shared";
import type {
  Asset,
  CveImportResult,
  EpssImportResult,
  KevImportResult,
  Vulnerability,
  VulnerabilityDetail,
  VulnerabilitySummary,
} from "../components/features/detect/types";

const COPY = {
  es: {
    "vuln.eyebrow": "Exposición · Vulnerabilidades",
    "vuln.title": "Gestión de vulnerabilidades",
    "vuln.subtitle": "Priorización explicable que combina CVSS, EPSS, KEV, exposición y criticidad del activo.",
    "vuln.import": "Importar inteligencia",
    "vuln.kpi.open": "Abiertas",
    "vuln.kpi.critical": "Críticas",
    "vuln.kpi.high": "Altas",
    "vuln.kpi.kev": "Explotadas (KEV)",
    "vuln.kpi.overdue": "SLA vencido",
    "vuln.kpi.mean": "Prioridad media",
    "vuln.kpi.exploitable": "Con exploit conocido",
    "vuln.kpi.total": "Total",
    "vuln.search": "Buscar por CVE, título o descripción…",
    "vuln.filter.severity": "Severidad",
    "vuln.filter.status": "Estado",
    "vuln.filter.kev": "KEV",
    "vuln.filter.asset": "Activo",
    "vuln.filter.sort": "Ordenar por",
    "vuln.filter.allSeverities": "Todas las severidades",
    "vuln.filter.allStatuses": "Todos los estados",
    "vuln.filter.allKev": "KEV: todos",
    "vuln.filter.kevOnly": "Solo KEV",
    "vuln.filter.kevExcluded": "Sin KEV",
    "vuln.filter.allAssets": "Todos los activos",
    "vuln.filter.clear": "Limpiar filtros",
    "vuln.filter.order": "Invertir orden",
    "vuln.sort.priority_score": "Prioridad",
    "vuln.sort.cvss_score": "CVSS",
    "vuln.sort.epss_score": "EPSS",
    "vuln.sort.severity": "Severidad",
    "vuln.sort.due_at": "Vencimiento",
    "vuln.sort.last_seen": "Última observación",
    "vuln.table.priority": "Prioridad",
    "vuln.table.vuln": "CVE / Vulnerabilidad",
    "vuln.table.asset": "Activo",
    "vuln.table.severity": "Severidad",
    "vuln.table.cvss": "CVSS",
    "vuln.table.epss": "EPSS",
    "vuln.table.kev": "KEV",
    "vuln.table.status": "Estado",
    "vuln.table.due": "SLA",
    "vuln.count": "vulnerabilidades",
    "vuln.empty.title": "Sin vulnerabilidades registradas",
    "vuln.empty.description": "Importa un lote de CVEs o aplica el catálogo KEV/EPSS para empezar a priorizar.",
    "vuln.empty.action": "Importar CVEs",
    "vuln.noResults.title": "Ninguna vulnerabilidad coincide",
    "vuln.noResults.description": "Ajusta los filtros o limpia la búsqueda.",
    "vuln.loadFailed": "No se pudieron cargar las vulnerabilidades",
    "vuln.priority.title": "Cómo se prioriza",
    "vuln.priority.body": "La prioridad no es solo CVSS. El motor suma señales ponderadas y explica cada una: una CVE con CVSS medio pero explotada activamente (KEV/EPSS) y sobre un activo crítico expuesto puede superar a una CVE crítica sin explotación conocida.",
    "vuln.priority.factors": "Factores del modelo",
    "vuln.priority.factor.cvss": "CVSS base (30)",
    "vuln.priority.factor.epss": "Probabilidad EPSS (20)",
    "vuln.priority.factor.kev": "Explotación confirmada KEV (15)",
    "vuln.priority.factor.exploitable": "Evidencia de exploit (5)",
    "vuln.priority.factor.criticality": "Criticidad del activo (15)",
    "vuln.priority.factor.environment": "Entorno (6)",
    "vuln.priority.factor.exposure": "Exposición (12)",
    "vuln.priority.factor.threat": "Coincidencia de inteligencia (10)",
    "vuln.priority.more": "Ver desglose",
    "vuln.priority.less": "Ocultar desglose",
    "vuln.priority.noReason": "Sin desglose disponible",
    "vuln.topRisky": "Mayor riesgo",
    "vuln.assetMissing": "Activo no disponible",
    "vuln.assetLookupUnavailable": "Criticidad de activo no disponible",
    "vuln.detail.title": "Detalle de la vulnerabilidad",
    "vuln.detail.loadError": "No se pudo cargar la vulnerabilidad",
    "vuln.detail.description": "Descripción",
    "vuln.detail.noDescription": "Sin descripción registrada",
    "vuln.detail.cvss": "CVSS",
    "vuln.detail.epss": "EPSS",
    "vuln.detail.severity": "Severidad",
    "vuln.detail.exposure": "Exposición",
    "vuln.detail.exploitable": "Explotable",
    "vuln.detail.kev": "CISA KEV",
    "vuln.detail.status": "Estado",
    "vuln.detail.firstSeen": "Primera observación",
    "vuln.detail.lastSeen": "Última observación",
    "vuln.detail.due": "Vencimiento SLA",
    "vuln.detail.source": "Origen",
    "vuln.detail.asset": "Activo afectado",
    "vuln.detail.noAsset": "Sin activo asignado",
    "vuln.detail.remediation": "Remediación",
    "vuln.detail.noRemediation": "Sin plan de remediación registrado",
    "vuln.detail.priority": "Prioridad",
    "vuln.detail.reason": "Desglose de prioridad",
    "vuln.detail.catalog": "Catálogo CVE",
    "vuln.detail.noCatalog": "Sin ficha de catálogo (importa la CVE para enriquecerla)",
    "vuln.detail.cwe": "CWE",
    "vuln.detail.published": "Publicada",
    "vuln.detail.modified": "Modificada",
    "vuln.detail.references": "Referencias",
    "vuln.detail.cpes": "CPEs afectados",
    "vuln.detail.none": "—",
    "vuln.detail.changeStatus": "Cambiar estado",
    "vuln.detail.statusTarget": "Nuevo estado",
    "vuln.detail.applyStatus": "Aplicar estado",
    "vuln.detail.recalculate": "Recalcular prioridad",
    "vuln.detail.recalculated": "Prioridad recalculada",
    "vuln.detail.recalculateFailed": "No se pudo recalcular la prioridad",
    "vuln.detail.recalculateBlocked": "Reabre la vulnerabilidad para recalcular: las aceptadas y falsos positivos quedan excluidas.",
    "vuln.detail.vector": "Vector CVSS",
    "vuln.detail.noTransitions": "Sin transiciones de estado disponibles",
    "vuln.detail.copyAll": "Copiar ficha",
    "vuln.status.open": "Abierta",
    "vuln.status.reopened": "Reabierta",
    "vuln.status.mitigated": "Mitigada",
    "vuln.status.accepted": "Aceptada",
    "vuln.status.false_positive": "Falso positivo",
    "vuln.exposure.public": "Pública",
    "vuln.exposure.dmz": "DMZ",
    "vuln.exposure.internal": "Interna",
    "vuln.confirm.title": "Confirmar cambio de estado",
    "vuln.confirm.description": "El cambio se valida en el servidor según las transiciones permitidas y queda registrado en auditoría. Los estados aceptada y falso positivo excluyen la vulnerabilidad de la priorización.",
    "vuln.confirm.action": "Confirmar cambio",
    "vuln.statusChanged": "Estado actualizado",
    "vuln.statusChangeFailed": "No se pudo cambiar el estado",
    "vuln.import.title": "Importar inteligencia de vulnerabilidades",
    "vuln.import.tab.cve": "CVEs",
    "vuln.import.tab.kev": "KEV",
    "vuln.import.tab.epss": "EPSS",
    "vuln.import.cveHint": "Array JSON de objetos con cve_id y description (máx. 500).",
    "vuln.import.kevHint": "Array JSON de CVE IDs o de entradas CISA KEV con cveID (máx. 500).",
    "vuln.import.epssHint": "CSV con columnas cve,epss[,percentile] o un array JSON de {cve, epss}.",
    "vuln.import.file": "Cargar desde archivo",
    "vuln.import.submit": "Importar",
    "vuln.import.empty": "Añade contenido para importar",
    "vuln.import.invalidJson": "El texto no es JSON válido",
    "vuln.import.invalidShape": "La estructura no coincide con el formato esperado",
    "vuln.import.invalidRow": "Fila no válida",
    "vuln.import.tooMany": "Máximo 500 filas por importación",
    "vuln.import.success": "Importación completada",
    "vuln.import.failed": "No se pudo completar la importación",
    "vuln.import.result": "Resultado",
    "vuln.import.rows": "Filas recibidas",
    "vuln.import.catalogCreated": "Catálogo creado",
    "vuln.import.catalogUpdated": "Catálogo actualizado",
    "vuln.import.vulnsCreated": "Hallazgos creados",
    "vuln.import.vulnsUpdated": "Hallazgos actualizados",
    "vuln.import.catalogMarked": "Entradas KEV marcadas",
    "vuln.import.vulnsMarked": "Hallazgos marcados KEV",
    "vuln.import.unknownCves": "CVEs desconocidas",
    "vuln.import.parsed": "Filas procesadas",
    "vuln.import.errors": "Errores",
    "vuln.import.noErrors": "Sin errores",
    "vuln.import.none": "Sin importación ejecutada",
  },
  en: {
    "vuln.eyebrow": "Exposure · Vulnerabilities",
    "vuln.title": "Vulnerability management",
    "vuln.subtitle": "Explainable prioritisation combining CVSS, EPSS, KEV, exposure and asset criticality.",
    "vuln.import": "Import intelligence",
    "vuln.kpi.open": "Open",
    "vuln.kpi.critical": "Critical",
    "vuln.kpi.high": "High",
    "vuln.kpi.kev": "Known exploited (KEV)",
    "vuln.kpi.overdue": "SLA overdue",
    "vuln.kpi.mean": "Mean priority",
    "vuln.kpi.exploitable": "Known exploit",
    "vuln.kpi.total": "Total",
    "vuln.search": "Search by CVE, title or description…",
    "vuln.filter.severity": "Severity",
    "vuln.filter.status": "Status",
    "vuln.filter.kev": "KEV",
    "vuln.filter.asset": "Asset",
    "vuln.filter.sort": "Sort by",
    "vuln.filter.allSeverities": "All severities",
    "vuln.filter.allStatuses": "All statuses",
    "vuln.filter.allKev": "KEV: all",
    "vuln.filter.kevOnly": "KEV only",
    "vuln.filter.kevExcluded": "Exclude KEV",
    "vuln.filter.allAssets": "All assets",
    "vuln.filter.clear": "Clear filters",
    "vuln.filter.order": "Reverse order",
    "vuln.sort.priority_score": "Priority",
    "vuln.sort.cvss_score": "CVSS",
    "vuln.sort.epss_score": "EPSS",
    "vuln.sort.due_at": "Due date",
    "vuln.sort.last_seen": "Last seen",
    "vuln.sort.severity": "Severity",
    "vuln.table.priority": "Priority",
    "vuln.table.vuln": "CVE / Vulnerability",
    "vuln.table.asset": "Asset",
    "vuln.table.severity": "Severity",
    "vuln.table.cvss": "CVSS",
    "vuln.table.epss": "EPSS",
    "vuln.table.kev": "KEV",
    "vuln.table.status": "Status",
    "vuln.table.due": "SLA",
    "vuln.count": "vulnerabilities",
    "vuln.empty.title": "No vulnerabilities recorded",
    "vuln.empty.description": "Import a CVE batch or apply the KEV/EPSS catalogues to start prioritising.",
    "vuln.empty.action": "Import CVEs",
    "vuln.noResults.title": "No vulnerability matches",
    "vuln.noResults.description": "Adjust the filters or clear the search.",
    "vuln.loadFailed": "Could not load vulnerabilities",
    "vuln.priority.title": "How prioritisation works",
    "vuln.priority.body": "Priority is not CVSS alone. The engine adds weighted signals and explains every one: a medium-CVSS CVE actively exploited (KEV/EPSS) on an exposed critical asset can outrank a critical CVE with no known exploitation.",
    "vuln.priority.factors": "Model factors",
    "vuln.priority.factor.cvss": "CVSS base (30)",
    "vuln.priority.factor.epss": "EPSS probability (20)",
    "vuln.priority.factor.kev": "Confirmed KEV exploitation (15)",
    "vuln.priority.factor.exploitable": "Exploit evidence (5)",
    "vuln.priority.factor.criticality": "Asset criticality (15)",
    "vuln.priority.factor.environment": "Environment (6)",
    "vuln.priority.factor.exposure": "Exposure (12)",
    "vuln.priority.factor.threat": "Threat-intel match (10)",
    "vuln.priority.more": "Show breakdown",
    "vuln.priority.less": "Hide breakdown",
    "vuln.priority.noReason": "No breakdown available",
    "vuln.topRisky": "Highest risk",
    "vuln.assetMissing": "Asset unavailable",
    "vuln.assetLookupUnavailable": "Asset criticality unavailable",
    "vuln.detail.title": "Vulnerability detail",
    "vuln.detail.loadError": "Could not load the vulnerability",
    "vuln.detail.description": "Description",
    "vuln.detail.noDescription": "No description recorded",
    "vuln.detail.cvss": "CVSS",
    "vuln.detail.epss": "EPSS",
    "vuln.detail.severity": "Severity",
    "vuln.detail.exposure": "Exposure",
    "vuln.detail.exploitable": "Exploitable",
    "vuln.detail.kev": "CISA KEV",
    "vuln.detail.status": "Status",
    "vuln.detail.firstSeen": "First seen",
    "vuln.detail.lastSeen": "Last seen",
    "vuln.detail.due": "SLA due date",
    "vuln.detail.source": "Source",
    "vuln.detail.asset": "Affected asset",
    "vuln.detail.noAsset": "No asset assigned",
    "vuln.detail.remediation": "Remediation",
    "vuln.detail.noRemediation": "No remediation plan recorded",
    "vuln.detail.priority": "Priority",
    "vuln.detail.reason": "Priority breakdown",
    "vuln.detail.catalog": "CVE catalogue",
    "vuln.detail.noCatalog": "No catalogue record (import the CVE to enrich it)",
    "vuln.detail.cwe": "CWE",
    "vuln.detail.published": "Published",
    "vuln.detail.modified": "Modified",
    "vuln.detail.references": "References",
    "vuln.detail.cpes": "Affected CPEs",
    "vuln.detail.none": "—",
    "vuln.detail.changeStatus": "Change status",
    "vuln.detail.statusTarget": "New status",
    "vuln.detail.applyStatus": "Apply status",
    "vuln.detail.recalculate": "Recalculate priority",
    "vuln.detail.recalculated": "Priority recalculated",
    "vuln.detail.recalculateFailed": "Could not recalculate the priority",
    "vuln.detail.recalculateBlocked": "Reopen the vulnerability to recalculate: accepted and false-positive rows are excluded.",
    "vuln.detail.vector": "CVSS vector",
    "vuln.detail.noTransitions": "No status transitions available",
    "vuln.detail.copyAll": "Copy record",
    "vuln.status.open": "Open",
    "vuln.status.reopened": "Reopened",
    "vuln.status.mitigated": "Mitigated",
    "vuln.status.accepted": "Accepted",
    "vuln.status.false_positive": "False positive",
    "vuln.exposure.public": "Public",
    "vuln.exposure.dmz": "DMZ",
    "vuln.exposure.internal": "Internal",
    "vuln.confirm.title": "Confirm status change",
    "vuln.confirm.description": "The change is validated server-side against the allowed transitions and recorded in the audit trail. Accepted and false-positive statuses exclude the vulnerability from prioritisation.",
    "vuln.confirm.action": "Confirm change",
    "vuln.statusChanged": "Status updated",
    "vuln.statusChangeFailed": "Could not change the status",
    "vuln.import.title": "Import vulnerability intelligence",
    "vuln.import.tab.cve": "CVEs",
    "vuln.import.tab.kev": "KEV",
    "vuln.import.tab.epss": "EPSS",
    "vuln.import.cveHint": "JSON array of objects with cve_id and description (max. 500).",
    "vuln.import.kevHint": "JSON array of CVE IDs or CISA KEV entries with cveID (max. 500).",
    "vuln.import.epssHint": "CSV with cve,epss[,percentile] columns or a JSON array of {cve, epss}.",
    "vuln.import.file": "Load from file",
    "vuln.import.submit": "Import",
    "vuln.import.empty": "Add content to import",
    "vuln.import.invalidJson": "The text is not valid JSON",
    "vuln.import.invalidShape": "The structure does not match the expected format",
    "vuln.import.invalidRow": "Invalid row",
    "vuln.import.tooMany": "Maximum 500 rows per import",
    "vuln.import.success": "Import completed",
    "vuln.import.failed": "The import could not be completed",
    "vuln.import.result": "Result",
    "vuln.import.rows": "Rows received",
    "vuln.import.catalogCreated": "Catalogue created",
    "vuln.import.catalogUpdated": "Catalogue updated",
    "vuln.import.vulnsCreated": "Findings created",
    "vuln.import.vulnsUpdated": "Findings updated",
    "vuln.import.catalogMarked": "KEV entries marked",
    "vuln.import.vulnsMarked": "Findings marked KEV",
    "vuln.import.unknownCves": "Unknown CVEs",
    "vuln.import.parsed": "Rows parsed",
    "vuln.import.errors": "Errors",
    "vuln.import.noErrors": "No errors",
    "vuln.import.none": "No import executed",
  },
} as const;

const CVE_RE = /^CVE-\d{4}-\d{4,10}$/;

export const VULN_TRANSITIONS: Record<string, string[]> = {
  open: ["mitigated", "accepted", "false_positive", "reopened"],
  reopened: ["open", "mitigated", "accepted", "false_positive"],
  mitigated: ["open", "reopened"],
  accepted: ["open", "reopened"],
  false_positive: ["open", "reopened"],
};

/** Mirror of the server transition matrix, used to only offer valid targets. */
export function allowedStatusTargets(current: string): string[] {
  return VULN_TRANSITIONS[current] ?? [];
}

export function priorityBand(score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 70) return "critical";
  if (score >= 50) return "high";
  if (score >= 30) return "medium";
  return "low";
}

type ParseError = "empty" | "json" | "shape" | "tooMany" | "invalidRow";
type ParseFailure = { error: ParseError; row?: number };
type CveRows = { rows: Record<string, unknown>[] } | ParseFailure;
type KevRows = { cves: string[] } | { rows: Record<string, unknown>[] } | ParseFailure;
type EpssRows = { csv: string } | { rows: Record<string, unknown>[] } | ParseFailure;

function readArray(text: string): unknown[] | ParseError {
  const trimmed = text.trim();
  if (!trimmed) return "empty";
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return "json";
  }
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === "object" && Array.isArray((parsed as { items?: unknown }).items)) {
    return (parsed as { items: unknown[] }).items;
  }
  return "shape";
}

/** CVE import accepts `[{cve_id, description, ...}]` (max. 500). */
export function parseCveImport(text: string): CveRows {
  const parsed = readArray(text);
  if (typeof parsed === "string") return { error: parsed };
  if (parsed.length === 0) return { error: "empty" };
  if (parsed.length > 500) return { error: "tooMany" };
  const rows: Record<string, unknown>[] = [];
  for (let index = 0; index < parsed.length; index += 1) {
    const row = parsed[index];
    if (!row || typeof row !== "object" || Array.isArray(row)) return { error: "invalidRow", row: index };
    const record = row as Record<string, unknown>;
    if (typeof record.cve_id !== "string" || !CVE_RE.test(record.cve_id)) return { error: "invalidRow", row: index };
    if (typeof record.description !== "string" || !record.description.trim()) return { error: "invalidRow", row: index };
    rows.push(record);
  }
  return { rows };
}

/** KEV import accepts CVE strings or CISA KEV entries with `cveID`. */
export function parseKevImport(text: string): KevRows {
  const parsed = readArray(text);
  if (typeof parsed === "string") return { error: parsed };
  if (parsed.length === 0) return { error: "empty" };
  if (parsed.length > 500) return { error: "tooMany" };
  if (parsed.every((item) => typeof item === "string")) {
    const invalid = parsed.findIndex((item) => !CVE_RE.test(item as string));
    if (invalid >= 0) return { error: "invalidRow", row: invalid };
    return { cves: parsed as string[] };
  }
  const rows: Record<string, unknown>[] = [];
  for (let index = 0; index < parsed.length; index += 1) {
    const row = parsed[index];
    if (!row || typeof row !== "object" || Array.isArray(row)) return { error: "invalidRow", row: index };
    const record = row as Record<string, unknown>;
    if (typeof record.cveID !== "string" || !CVE_RE.test(record.cveID)) return { error: "invalidRow", row: index };
    rows.push(record);
  }
  return { rows };
}

/** EPSS import accepts `cve,epss[,percentile]` CSV or JSON `[{cve, epss}]`. */
export function parseEpssImport(text: string): EpssRows {
  const trimmed = text.trim();
  if (!trimmed) return { error: "empty" };
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    const parsed = readArray(trimmed);
    if (typeof parsed === "string") return { error: parsed };
    if (parsed.length === 0) return { error: "empty" };
    if (parsed.length > 500) return { error: "tooMany" };
    const rows: Record<string, unknown>[] = [];
    for (let index = 0; index < parsed.length; index += 1) {
      const row = parsed[index];
      if (!row || typeof row !== "object" || Array.isArray(row)) return { error: "invalidRow", row: index };
      const record = row as Record<string, unknown>;
      if (typeof record.cve !== "string" || !CVE_RE.test(record.cve)) return { error: "invalidRow", row: index };
      if (typeof record.epss !== "number") return { error: "invalidRow", row: index };
      rows.push(record);
    }
    return { rows };
  }
  const lines = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  if (lines.length === 0) return { error: "empty" };
  const hasHeader = ["cve", "cve_id"].includes(lines[0].split(",")[0].trim().toLowerCase());
  const dataLines = hasHeader ? lines.slice(1) : lines;
  if (dataLines.length === 0) return { error: "empty" };
  if (dataLines.length > 500) return { error: "tooMany" };
  for (let index = 0; index < dataLines.length; index += 1) {
    const cells = dataLines[index].split(",").map((cell) => cell.trim());
    if (cells.length < 2 || !CVE_RE.test(cells[0])) return { error: "invalidRow", row: index };
    const epss = Number(cells[1]);
    if (!Number.isFinite(epss) || epss < 0 || epss > 1) return { error: "invalidRow", row: index };
  }
  return { csv: trimmed };
}

const CVE_TEXT_FIELDS = ["cvss_vector", "cwe", "published_at", "modified_at"] as const;
const CVE_NUMBER_FIELDS = ["cvss_score", "epss_score"] as const;
const CVE_LIST_FIELDS = ["references", "cpes", "asset_ids"] as const;

/** Keep only the contract fields: the API rejects unknown keys by design. */
export function toCveItems(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return rows.map((row) => {
    const item: Record<string, unknown> = { cve_id: row.cve_id, description: row.description };
    for (const field of CVE_TEXT_FIELDS) {
      if (typeof row[field] === "string") item[field] = row[field];
    }
    for (const field of CVE_NUMBER_FIELDS) {
      if (typeof row[field] === "number") item[field] = row[field];
    }
    if (typeof row.kev === "boolean") item.kev = row.kev;
    for (const field of CVE_LIST_FIELDS) {
      if (Array.isArray(row[field])) item[field] = row[field];
    }
    return item;
  });
}

export function toEpssItems(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return rows.map((row) => {
    const item: Record<string, unknown> = { cve: row.cve, epss: row.epss };
    if (typeof row.percentile === "number") item.percentile = row.percentile;
    return item;
  });
}

type ImportTab = "cve" | "kev" | "epss";
type ImportOutcome =
  | { kind: "cve"; data: CveImportResult }
  | { kind: "kev"; data: KevImportResult }
  | { kind: "epss"; data: EpssImportResult };

export function VulnerabilitiesPage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const canWrite = can("vuln:write");
  const canImport = can("vuln:import");
  const canReadAssets = can("asset:read");

  const assetFilter = params.get("asset") ?? "";
  const vulnParam = params.get("vuln");

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [kev, setKev] = useState("");
  const [sort, setSort] = useState("priority_score");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const debouncedSearch = useDebouncedValue(search);

  const [selectedId, setSelectedId] = useState<string | null>(vulnParam);
  const [statusTarget, setStatusTarget] = useState<string | null>(null);
  const [pendingStatus, setPendingStatus] = useState<string | null>(null);
  const expanded = useToggleSet();

  const [importOpen, setImportOpen] = useState(false);
  const [importTab, setImportTab] = useState<ImportTab>("cve");
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [importOutcome, setImportOutcome] = useState<ImportOutcome | null>(null);

  useEffect(() => {
    setSelectedId(vulnParam);
    setStatusTarget(null);
    setPendingStatus(null);
  }, [vulnParam]);

  const summaryQuery = useQuery({
    queryKey: ["vulnerabilities", "summary"],
    queryFn: () => api.get<VulnerabilitySummary>("/vulnerabilities/summary"),
  });

  const listQuery = useQuery({
    queryKey: ["vulnerabilities", "list", { page, search: debouncedSearch, severity, status, kev, assetFilter, sort, order }],
    queryFn: () =>
      api.get<Page<Vulnerability>>("/vulnerabilities", {
        page,
        page_size: 25,
        q: debouncedSearch || undefined,
        severity: severity || undefined,
        status: status || undefined,
        kev: kev === "" ? undefined : kev === "true",
        asset_id: assetFilter || undefined,
        sort,
        order,
      }),
  });

  const detailQuery = useQuery({
    queryKey: ["vulnerabilities", "detail", selectedId],
    queryFn: () => api.get<VulnerabilityDetail>(`/vulnerabilities/${selectedId}`),
    enabled: selectedId !== null,
  });

  const assetsQuery = useQuery({
    queryKey: ["assets", "vulnerability-lookup"],
    queryFn: () => api.get<Page<Asset>>("/assets", { page: 1, page_size: 200, sort: "criticality", order: "desc" }),
    enabled: canReadAssets,
    staleTime: 60_000,
  });

  const changeStatus = useMutation({
    mutationFn: ({ id, next }: { id: string; next: string }) =>
      api.patch<Vulnerability>(`/vulnerabilities/${id}`, { status: next }),
    onSuccess: () => {
      push(c("vuln.statusChanged"), "success");
      setPendingStatus(null);
      setStatusTarget(null);
      void queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
    },
    onError: (error) => push(`${c("vuln.statusChangeFailed")}: ${errorMessage(error)}`, "error"),
  });

  const recalculate = useMutation({
    mutationFn: (id: string) => api.post<Vulnerability>(`/vulnerabilities/${id}/recalculate`),
    onSuccess: () => {
      push(c("vuln.detail.recalculated"), "success");
      void queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
    },
    onError: (error) => push(`${c("vuln.detail.recalculateFailed")}: ${errorMessage(error)}`, "error"),
  });

  const importMutation = useMutation({
    mutationFn: ({ tab, payload }: { tab: ImportTab; payload: Record<string, unknown> }) =>
      api.post<CveImportResult | KevImportResult | EpssImportResult>(`/vulnerabilities/import/${tab}`, payload),
    onSuccess: (data, variables) => {
      if (variables.tab === "cve") setImportOutcome({ kind: "cve", data: data as CveImportResult });
      else if (variables.tab === "kev") setImportOutcome({ kind: "kev", data: data as KevImportResult });
      else setImportOutcome({ kind: "epss", data: data as EpssImportResult });
      push(c("vuln.import.success"), "success");
      void queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
    },
    onError: (error) => {
      setImportError(errorMessage(error));
      push(`${c("vuln.import.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  if (listQuery.isLoading && !listQuery.data) return <PageSkeleton />;

  const summary = summaryQuery.data;
  const rows = listQuery.data?.items ?? [];
  const assets = assetsQuery.data?.items ?? [];
  const assetById = new Map(assets.map((asset) => [asset.id, asset]));
  const filtersActive = Boolean(debouncedSearch || severity || status || kev || assetFilter);
  const detail = detailQuery.data ?? null;

  const applyFilter = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setPage(1);
  };

  const clearFilters = () => {
    setSearch("");
    setSeverity("");
    setStatus("");
    setKev("");
    setPage(1);
    if (assetFilter) {
      const next = new URLSearchParams(params);
      next.delete("asset");
      next.delete("vuln");
      setParams(next, { replace: true });
    }
  };

  const openDetail = (id: string) => {
    setSelectedId(id);
    setStatusTarget(null);
    setPendingStatus(null);
    const next = new URLSearchParams(params);
    next.set("vuln", id);
    setParams(next, { replace: true });
  };

  const closeDetail = () => {
    setSelectedId(null);
    setStatusTarget(null);
    setPendingStatus(null);
    if (params.has("vuln")) {
      const next = new URLSearchParams(params);
      next.delete("vuln");
      setParams(next, { replace: true });
    }
  };

  const changeAssetFilter = (nextAsset: string) => {
    const next = new URLSearchParams(params);
    next.delete("vuln");
    if (nextAsset) next.set("asset", nextAsset);
    else next.delete("asset");
    setParams(next, { replace: true });
    setPage(1);
  };

  const priorityColumns = (row: Vulnerability) => {
    const band = priorityBand(row.priority_score);
    const tone = band === "critical" ? "critical" : band === "high" ? "danger" : band === "medium" ? "warning" : "success";
    return (
      <div style={{ minWidth: 132 }}>
        <div className="row" style={{ gap: 6 }}>
          <span title={row.priority_reason ?? undefined}>
            <Badge tone={tone} className="mono">{row.priority_score.toFixed(1)}</Badge>
          </span>
          <button
            type="button"
            className="icon-btn"
            style={{ width: 22, height: 22 }}
            onClick={(event) => {
              event.stopPropagation();
              expanded.toggle(row.id);
            }}
            aria-expanded={expanded.has(row.id)}
            aria-label={expanded.has(row.id) ? c("vuln.priority.less") : c("vuln.priority.more")}
            title={expanded.has(row.id) ? c("vuln.priority.less") : c("vuln.priority.more")}
          >
            {expanded.has(row.id) ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>
        </div>
        {expanded.has(row.id) ? (
          <p className="mono" style={{ fontSize: 9.5, color: "var(--dim)", marginTop: 6, whiteSpace: "normal", lineHeight: 1.5 }}>
            {row.priority_reason ?? c("vuln.priority.noReason")}
          </p>
        ) : (
          <span className="dim" style={{ fontSize: 9.5 }}>{c("vuln.priority.more")}</span>
        )}
      </div>
    );
  };

  const columns: Column<Vulnerability>[] = [
    { key: "priority", header: c("vuln.table.priority"), width: "170px", render: priorityColumns },
    {
      key: "vuln",
      header: c("vuln.table.vuln"),
      render: (row) => (
        <div style={{ minWidth: 210 }}>
          <div className="row" style={{ gap: 6 }}>
            <span className="mono" style={{ color: "var(--accent)", fontSize: 10.5 }}>{row.cve_id ?? "—"}</span>
            {row.kev ? <Badge tone="critical">KEV</Badge> : null}
            {row.exploitable ? <Badge tone="warning">EXPLOIT</Badge> : null}
          </div>
          <div style={{ color: "var(--text)", marginTop: 2 }}>{row.title}</div>
          <div className="mono" style={{ fontSize: 9.5, color: "var(--dim)", marginTop: 2 }}>{row.source}</div>
        </div>
      ),
    },
    {
      key: "asset",
      header: c("vuln.table.asset"),
      width: "160px",
      render: (row) => {
        if (!row.asset_id) return <span className="dim" style={{ fontSize: 11 }}>—</span>;
        const asset = assetById.get(row.asset_id);
        return (
          <div style={{ minWidth: 120 }}>
            <Link
              to={`/assets/${row.asset_id}`}
              onClick={(event) => event.stopPropagation()}
              style={{ fontSize: 11.5, color: "var(--text-secondary)" }}
            >
              {asset?.name ?? `${row.asset_id.slice(0, 8)}…`}
            </Link>
            <div className="row" style={{ gap: 6, marginTop: 3 }}>
              {asset ? <CriticalityMeter value={asset.criticality} /> : <span className="dim" style={{ fontSize: 9.5 }}>—</span>}
            </div>
          </div>
        );
      },
    },
    { key: "severity", header: c("vuln.table.severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "cvss",
      header: c("vuln.table.cvss"),
      width: "70px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.cvss_score?.toFixed(1) ?? "—"}</span>,
    },
    {
      key: "epss",
      header: c("vuln.table.epss"),
      width: "76px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{row.epss_score !== null ? formatPercent(row.epss_score * 100, 1) : "—"}</span>,
    },
    {
      key: "kev",
      header: c("vuln.table.kev"),
      width: "64px",
      render: (row) => (row.kev ? <Badge tone="danger">KEV</Badge> : <span className="dim">—</span>),
    },
    {
      key: "status",
      header: c("vuln.table.status"),
      width: "124px",
      render: (row) => <StatusBadge status={row.status} label={copyOr(c, `vuln.status.${row.status}`, humanize(row.status))} />,
    },
    {
      key: "due",
      header: c("vuln.table.due"),
      width: "112px",
      render: (row) => {
        if (!row.due_at) return <span className="dim" style={{ fontSize: 11 }}>—</span>;
        const overdue = new Date(row.due_at).getTime() < Date.now();
        return (
          <span className="mono" style={{ fontSize: 10.5, color: overdue ? "var(--danger)" : "var(--muted)" }}>
            {formatDateTime(row.due_at, lang)}
          </span>
        );
      },
    },
  ];

  const statusOptions = detail ? allowedStatusTargets(detail.status) : [];

  return (
    <div className="animate-in" data-testid="page-vulnerabilities">
      <PageHeader
        eyebrow={c("vuln.eyebrow")}
        title={c("vuln.title")}
        subtitle={c("vuln.subtitle")}
        actions={
          <>
            <Button icon={RefreshCw} onClick={() => void listQuery.refetch()} aria-label={t("common.refresh")} />
            {canImport ? (
              <Button
                variant="primary"
                icon={Upload}
                onClick={() => {
                  setImportOpen(true);
                  setImportOutcome(null);
                  setImportError(null);
                  setImportText("");
                }}
                data-testid="open-import"
              >
                {c("vuln.import")}
              </Button>
            ) : null}
          </>
        }
      />

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi
          label={c("vuln.kpi.open")}
          value={summary ? formatNumber((summary.by_status.open ?? 0) + (summary.by_status.reopened ?? 0)) : "—"}
          icon={ShieldAlert}
          tone="danger"
          footer={
            <span>
              {formatNumber(summary?.by_status.reopened ?? 0)} {c("vuln.status.reopened").toLowerCase()} ·{" "}
              {formatNumber(summary?.total ?? 0)} {c("vuln.kpi.total").toLowerCase()}
            </span>
          }
        />
        <Kpi
          label={c("vuln.kpi.critical")}
          value={summary ? formatNumber(summary.by_severity.critical ?? 0) : "—"}
          icon={Flame}
          tone="danger"
          footer={<span>{formatNumber(summary?.exploitable ?? 0)} {c("vuln.kpi.exploitable").toLowerCase()}</span>}
        />
        <Kpi
          label={c("vuln.kpi.high")}
          value={summary ? formatNumber(summary.by_severity.high ?? 0) : "—"}
          icon={Bug}
          tone="warning"
          footer={<span>{summary ? `${c("vuln.kpi.mean")}: ${summary.mean_priority.toFixed(1)}` : "—"}</span>}
        />
        <Kpi
          label={c("vuln.kpi.kev")}
          value={summary ? formatNumber(summary.kev) : "—"}
          icon={ShieldOff}
          tone="danger"
          footer={<span>{t("overview.knownExploited")}</span>}
        />
      </div>

      <div className="notice notice-warning" style={{ marginBottom: 12 }}>
        <Clock size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
        <span>
          <b>{c("vuln.kpi.overdue")}: {formatNumber(summary?.overdue ?? 0)}</b> ·{" "}
          {c("vuln.kpi.mean")}: <span className="mono">{summary ? summary.mean_priority.toFixed(1) : "—"}</span> ·{" "}
          {summary ? `${formatNumber(summary.total)} ${c("vuln.count")}` : "—"}
        </span>
      </div>

      {summaryQuery.isError ? (
        <div style={{ marginBottom: 12 }}>
          <ErrorBanner compact message={errorMessage(summaryQuery.error)} onRetry={() => void summaryQuery.refetch()} />
        </div>
      ) : null}

      <div className="split-main">
        <Card
          title={c("vuln.title")}
          subtitle={listQuery.data ? `${formatNumber(listQuery.data.meta.total)} ${c("vuln.count")}` : undefined}
          bodyClassName=""
        >
          <FilterBar ariaLabel={t("common.filters")}>
            <SearchInput value={search} onChange={applyFilter(setSearch)} placeholder={c("vuln.search")} ariaLabel={c("vuln.search")} />
            <Select value={severity} onChange={(event) => applyFilter(setSeverity)(event.target.value)} aria-label={c("vuln.filter.severity")} data-testid="filter-severity">
              <option value="">{c("vuln.filter.allSeverities")}</option>
              {SEVERITY_LEVELS.map((level) => (
                <option key={level.id} value={level.value}>{t(`common.${level.value}`)}</option>
              ))}
            </Select>
            <Select value={status} onChange={(event) => applyFilter(setStatus)(event.target.value)} aria-label={c("vuln.filter.status")} data-testid="filter-status">
              <option value="">{c("vuln.filter.allStatuses")}</option>
              {["open", "reopened", "mitigated", "accepted", "false_positive"].map((value) => (
                <option key={value} value={value}>{copyOr(c, `vuln.status.${value}`, humanize(value))}</option>
              ))}
            </Select>
            <Select value={kev} onChange={(event) => applyFilter(setKev)(event.target.value)} aria-label={c("vuln.filter.kev")} data-testid="filter-kev">
              <option value="">{c("vuln.filter.allKev")}</option>
              <option value="true">{c("vuln.filter.kevOnly")}</option>
              <option value="false">{c("vuln.filter.kevExcluded")}</option>
            </Select>
            <Select
              value={assetFilter}
              onChange={(event) => changeAssetFilter(event.target.value)}
              aria-label={c("vuln.filter.asset")}
              data-testid="filter-asset"
            >
              <option value="">{c("vuln.filter.allAssets")}</option>
              {assets.map((asset) => (
                <option key={asset.id} value={asset.id}>{asset.name}</option>
              ))}
            </Select>
            <Select value={sort} onChange={(event) => setSort(event.target.value)} aria-label={c("vuln.filter.sort")} data-testid="filter-sort">
              {["priority_score", "cvss_score", "epss_score", "severity", "due_at", "last_seen"].map((value) => (
                <option key={value} value={value}>{c(`vuln.sort.${value}`)}</option>
              ))}
            </Select>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setOrder((value) => (value === "desc" ? "asc" : "desc"));
                setPage(1);
              }}
              aria-label={c("vuln.filter.order")}
              icon={order === "desc" ? ChevronDown : ChevronUp}
              data-testid="toggle-order"
            />
            {filtersActive ? (
              <Button size="sm" variant="ghost" onClick={clearFilters} data-testid="clear-filters">
                {c("vuln.filter.clear")}
              </Button>
            ) : null}
            {assetFilter ? (
              <Badge tone="accent">{assetById.get(assetFilter)?.name ?? assetFilter.slice(0, 8)}</Badge>
            ) : null}
            {assetsQuery.isError ? (
              <Badge tone="neutral">{c("vuln.assetLookupUnavailable")}</Badge>
            ) : null}
          </FilterBar>

          <div data-testid="table-vulnerabilities">
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(row) => row.id}
              onRowClick={(row) => openDetail(row.id)}
              error={
                listQuery.isError ? (
                  <ErrorBanner
                    title={c("vuln.loadFailed")}
                    message={errorMessage(listQuery.error)}
                    onRetry={() => void listQuery.refetch()}
                  />
                ) : undefined
              }
              empty={
                filtersActive ? (
                  <EmptyState
                    icon={Bug}
                    title={c("vuln.noResults.title")}
                    description={c("vuln.noResults.description")}
                    action={<Button size="sm" variant="primary" onClick={clearFilters}>{c("vuln.filter.clear")}</Button>}
                  />
                ) : (
                  <EmptyState
                    icon={ShieldAlert}
                    title={c("vuln.empty.title")}
                    description={c("vuln.empty.description")}
                    action={
                      canImport ? (
                        <Button size="sm" variant="primary" icon={Upload} onClick={() => setImportOpen(true)}>
                          {c("vuln.empty.action")}
                        </Button>
                      ) : undefined
                    }
                  />
                )
              }
            />
          </div>
          <Pagination meta={listQuery.data?.meta} onPage={setPage} />
        </Card>

        <div className="stack">
          <Card title={c("vuln.priority.title")}>
            <p style={{ fontSize: 12, color: "var(--muted)" }}>{c("vuln.priority.body")}</p>
            <div className="divider" />
            <div className="section-label">{c("vuln.priority.factors")}</div>
            <div className="metric-list">
              {[
                "cvss",
                "epss",
                "kev",
                "exploitable",
                "criticality",
                "environment",
                "exposure",
                "threat",
              ].map((factor) => (
                <div className="metric-row" key={factor}>
                  <span className="metric-label">{c(`vuln.priority.factor.${factor}`)}</span>
                </div>
              ))}
            </div>
          </Card>

          <Card title={c("vuln.topRisky")} subtitle={c("vuln.table.priority")}>
            {summary && summary.top_risky.length ? (
              <div>
                {summary.top_risky.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className="list-item"
                    style={{ width: "100%", background: "transparent", border: 0, textAlign: "left", color: "inherit" }}
                    onClick={() => openDetail(item.id)}
                  >
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div className="mono" style={{ fontSize: 9.5, color: "var(--accent)" }}>{item.cve_id ?? "—"}</div>
                      <div className="item-title" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {item.title}
                      </div>
                      <div className="item-sub">
                        {item.asset_name ?? c("vuln.assetMissing")} · {copyOr(c, `vuln.status.${item.status}`, humanize(item.status))}
                      </div>
                    </div>
                    <div className="item-side">
                      <Badge tone={priorityBand(item.priority_score) === "critical" ? "critical" : "danger"}>
                        {item.priority_score.toFixed(1)}
                      </Badge>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <EmptyState icon={ShieldAlert} title={c("vuln.empty.title")} />
            )}
          </Card>
        </div>
      </div>

      <Modal
        open={selectedId !== null}
        onClose={closeDetail}
        title={c("vuln.detail.title")}
        size="lg"
        footer={detail ? <CopyButton text={JSON.stringify(detail, null, 2)} label={c("vuln.detail.copyAll")} /> : undefined}
      >
        {detailQuery.isLoading ? (
          <p className="muted" style={{ fontSize: 12 }}>{t("common.loading")}</p>
        ) : detailQuery.isError ? (
          <ErrorBanner
            title={c("vuln.detail.loadError")}
            message={errorMessage(detailQuery.error)}
            onRetry={() => void detailQuery.refetch()}
          />
        ) : detail ? (
          <div className="stack">
            <div className="row wrap" style={{ gap: 6 }}>
              <SeverityBadge severity={detail.severity} />
              <StatusBadge status={detail.status} label={copyOr(c, `vuln.status.${detail.status}`, humanize(detail.status))} />
              {detail.kev ? <Badge tone="critical">KEV</Badge> : null}
              {detail.exploitable ? <Badge tone="warning">EXPLOIT</Badge> : null}
              <span className="mono" style={{ fontSize: 10, color: "var(--dim)", marginLeft: "auto" }}>{detail.id}</span>
            </div>
            <div>
              <div className="mono" style={{ fontSize: 11, color: "var(--accent)" }}>{detail.cve_id ?? "—"}</div>
              <h3 style={{ fontSize: 15, marginTop: 2 }}>{detail.title}</h3>
            </div>

            <div className="grid-2">
              <div className="metric-list">
                <div className="metric-row"><span className="metric-label">{c("vuln.detail.cvss")}</span><span className="metric-value mono">{detail.cvss_score?.toFixed(1) ?? "—"}</span></div>
                <div className="metric-row"><span className="metric-label">{c("vuln.detail.vector")}</span><span className="metric-value mono" style={{ fontSize: 10 }}>{detail.cvss_vector ?? "—"}</span></div>
                <div className="metric-row"><span className="metric-label">{c("vuln.detail.epss")}</span><span className="metric-value mono">{detail.epss_score !== null ? formatPercent(detail.epss_score * 100, 2) : "—"}</span></div>
                <div className="metric-row"><span className="metric-label">{c("vuln.detail.exposure")}</span><span className="metric-value">{copyOr(c, `vuln.exposure.${detail.exposure}`, humanize(detail.exposure))}</span></div>
                <div className="metric-row"><span className="metric-label">{c("vuln.detail.source")}</span><span className="metric-value">{detail.source}</span></div>
                <div className="metric-row"><span className="metric-label">{c("vuln.detail.firstSeen")}</span><span className="metric-value mono">{formatDateTime(detail.first_seen, lang)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("vuln.detail.lastSeen")}</span><span className="metric-value mono">{formatDateTime(detail.last_seen, lang)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("vuln.detail.due")}</span><span className="metric-value mono">{detail.due_at ? formatDateTime(detail.due_at, lang) : "—"}</span></div>
                <div className="metric-row">
                  <span className="metric-label">{c("vuln.detail.asset")}</span>
                  <span className="metric-value">
                    {detail.asset ? (
                      <Link to={`/assets/${detail.asset.id}`} style={{ fontSize: 11.5 }}>{detail.asset.name}</Link>
                    ) : (
                      c("vuln.detail.noAsset")
                    )}
                  </span>
                </div>
              </div>
              <div className="row" style={{ gap: 16, alignItems: "flex-start" }}>
                <ScoreRing score={Math.round(detail.priority_score)} size={120} label={c("vuln.detail.priority")} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="section-label">{c("vuln.detail.reason")}</div>
                  <p className="mono" style={{ fontSize: 10, color: "var(--muted)", lineHeight: 1.6, wordBreak: "break-word" }}>
                    {detail.priority_reason ?? c("vuln.priority.noReason")}
                  </p>
                </div>
              </div>
            </div>

            <div>
              <div className="section-label">{c("vuln.detail.description")}</div>
              <p style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
                {detail.description ?? detail.catalog?.description ?? c("vuln.detail.noDescription")}
              </p>
            </div>

            <div>
              <div className="section-label">{c("vuln.detail.remediation")}</div>
              <p style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
                {detail.remediation ?? c("vuln.detail.noRemediation")}
              </p>
            </div>

            <div>
              <div className="section-label">{c("vuln.detail.catalog")}</div>
              {detail.catalog ? (
                <div className="stack">
                  <div className="stat-inline">
                    <div>
                      <span className="label">{c("vuln.detail.cwe")}</span>
                      <span className="value" style={{ fontSize: 14 }}>{detail.catalog.cwe ?? "—"}</span>
                    </div>
                    <div>
                      <span className="label">{c("vuln.detail.published")}</span>
                      <span className="value" style={{ fontSize: 12 }}>{detail.catalog.published_at ? formatDateTime(detail.catalog.published_at, lang) : "—"}</span>
                    </div>
                    <div>
                      <span className="label">{c("vuln.detail.modified")}</span>
                      <span className="value" style={{ fontSize: 12 }}>{detail.catalog.modified_at ? formatDateTime(detail.catalog.modified_at, lang) : "—"}</span>
                    </div>
                  </div>
                  <div>
                    <div className="section-label">{c("vuln.detail.references")}</div>
                    {detail.catalog.references.length ? (
                      <div className="chip-row">
                        {detail.catalog.references.slice(0, 10).map((reference) =>
                          /^https?:\/\//i.test(reference) ? (
                            <a key={reference} className="tag" href={reference} target="_blank" rel="noreferrer noopener">
                              {reference.replace(/^https?:\/\//i, "").slice(0, 48)}
                            </a>
                          ) : (
                            <span className="tag" key={reference}>{reference.slice(0, 48)}</span>
                          ),
                        )}
                      </div>
                    ) : (
                      <span className="dim" style={{ fontSize: 11 }}>{c("vuln.detail.none")}</span>
                    )}
                  </div>
                  <div>
                    <div className="section-label">{c("vuln.detail.cpes")}</div>
                    {detail.catalog.cpes.length ? (
                      <div className="chip-row">
                        {detail.catalog.cpes.slice(0, 12).map((cpe) => (
                          <span className="tag" key={cpe}>{cpe}</span>
                        ))}
                      </div>
                    ) : (
                      <span className="dim" style={{ fontSize: 11 }}>{c("vuln.detail.none")}</span>
                    )}
                  </div>
                </div>
              ) : (
                <p className="dim" style={{ fontSize: 11.5 }}>{c("vuln.detail.noCatalog")}</p>
              )}
            </div>

            {canWrite ? (
              <div className="notice" style={{ display: "block" }}>
                <div className="row-between" style={{ gap: 10, flexWrap: "wrap" }}>
                  <div>
                    <div className="section-label" style={{ marginBottom: 4 }}>{c("vuln.detail.changeStatus")}</div>
                    <div className="row wrap" style={{ gap: 8 }}>
                      <Select
                        value={statusTarget ?? ""}
                        onChange={(event) => setStatusTarget(event.target.value || null)}
                        aria-label={c("vuln.detail.statusTarget")}
                        style={{ maxWidth: 190 }}
                        data-testid="vuln-status-target"
                      >
                        <option value="">{c("vuln.detail.statusTarget")}</option>
                        {statusOptions.map((value) => (
                          <option key={value} value={value}>{copyOr(c, `vuln.status.${value}`, humanize(value))}</option>
                        ))}
                      </Select>
                      <Button
                        variant="primary"
                        disabled={!statusTarget || statusTarget === detail.status}
                        onClick={() => {
                          if (statusTarget) setPendingStatus(statusTarget);
                        }}
                        data-testid="submit-status-change"
                      >
                        {c("vuln.detail.applyStatus")}
                      </Button>
                    </div>
                  </div>
                  <div>
                    <div className="section-label" style={{ marginBottom: 4 }}>{c("vuln.detail.priority")}</div>
                    <Button
                      icon={RefreshCw}
                      loading={recalculate.isPending}
                      disabled={detail.status === "accepted" || detail.status === "false_positive"}
                      title={
                        detail.status === "accepted" || detail.status === "false_positive"
                          ? c("vuln.detail.recalculateBlocked")
                          : c("vuln.detail.recalculate")
                      }
                      onClick={() => recalculate.mutate(detail.id)}
                      data-testid="recalculate-priority"
                    >
                      {c("vuln.detail.recalculate")}
                    </Button>
                  </div>
                </div>
                {statusOptions.length === 0 ? (
                  <p className="dim" style={{ fontSize: 11, marginTop: 6 }}>{c("vuln.detail.noTransitions")}</p>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : null}
      </Modal>

      <ConfirmModal
        open={pendingStatus !== null}
        onClose={() => setPendingStatus(null)}
        title={c("vuln.confirm.title")}
        description={c("vuln.confirm.description")}
        confirmLabel={c("vuln.confirm.action")}
        loading={changeStatus.isPending}
        danger={pendingStatus === "accepted" || pendingStatus === "false_positive"}
        onConfirm={() => {
          if (detail && pendingStatus) changeStatus.mutate({ id: detail.id, next: pendingStatus });
        }}
      >
        {detail && pendingStatus ? (
          <div className="metric-list">
            <div className="metric-row"><span className="metric-label">{c("vuln.detail.status")}</span><span className="metric-value">{copyOr(c, `vuln.status.${detail.status}`, humanize(detail.status))}</span></div>
            <div className="metric-row"><span className="metric-label">{c("vuln.detail.statusTarget")}</span><span className="metric-value">{copyOr(c, `vuln.status.${pendingStatus}`, humanize(pendingStatus))}</span></div>
          </div>
        ) : null}
      </ConfirmModal>

      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title={c("vuln.import.title")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setImportOpen(false)} disabled={importMutation.isPending}>
              {t("common.close")}
            </Button>
            <Button
              variant="primary"
              loading={importMutation.isPending}
              disabled={!importText.trim()}
              onClick={() => {
                setImportOutcome(null);
                if (importTab === "cve") {
                  const parsed = parseCveImport(importText);
                  if ("error" in parsed) {
                    setImportError(parseErrorMessage(parsed));
                    return;
                  }
                  setImportError(null);
                  importMutation.mutate({ tab: "cve", payload: { items: toCveItems(parsed.rows) } });
                  return;
                }
                if (importTab === "kev") {
                  const parsed = parseKevImport(importText);
                  if ("error" in parsed) {
                    setImportError(parseErrorMessage(parsed));
                    return;
                  }
                  setImportError(null);
                  importMutation.mutate({
                    tab: "kev",
                    payload: "cves" in parsed ? { cves: parsed.cves } : { vulnerabilities: parsed.rows },
                  });
                  return;
                }
                const parsed = parseEpssImport(importText);
                if ("error" in parsed) {
                  setImportError(parseErrorMessage(parsed));
                  return;
                }
                setImportError(null);
                importMutation.mutate({
                  tab: "epss",
                  payload: "csv" in parsed ? { csv: parsed.csv } : { items: toEpssItems(parsed.rows) },
                });
              }}
              data-testid="submit-import"
            >
              {c("vuln.import.submit")}
            </Button>
          </>
        }
      >
        <Tabs
          items={[
            { key: "cve" as ImportTab, label: c("vuln.import.tab.cve") },
            { key: "kev" as ImportTab, label: c("vuln.import.tab.kev") },
            { key: "epss" as ImportTab, label: c("vuln.import.tab.epss") },
          ]}
          value={importTab}
          onChange={(value) => {
            setImportTab(value);
            setImportText("");
            setImportError(null);
            setImportOutcome(null);
          }}
          ariaLabel={c("vuln.import.title")}
        />
        <div style={{ marginTop: 12 }}>
          <p className="muted" style={{ fontSize: 11.5, marginBottom: 10 }}>
            {importTab === "cve" ? c("vuln.import.cveHint") : importTab === "kev" ? c("vuln.import.kevHint") : c("vuln.import.epssHint")}
          </p>
          <Field label={c(`vuln.import.tab.${importTab}`)} htmlFor="vuln-import-text" error={importError ?? undefined}>
            <Textarea
              id="vuln-import-text"
              className="mono"
              style={{ minHeight: 190, fontSize: 11.5 }}
              value={importText}
              onChange={(event) => {
                setImportText(event.target.value);
                setImportError(null);
                setImportOutcome(null);
              }}
              aria-invalid={Boolean(importError)}
              data-testid="import-text"
            />
          </Field>
          <div className="row wrap" style={{ marginTop: 10, gap: 10 }}>
            <input
              type="file"
              accept=".json,.csv,application/json,text/csv"
              aria-label={c("vuln.import.file")}
              className="input"
              style={{ maxWidth: 300 }}
              onChange={async (event) => {
                const file = event.target.files?.[0];
                if (!file) return;
                if (file.size > 2_000_000) {
                  setImportError(c("vuln.import.tooMany"));
                  return;
                }
                const text = await file.text();
                setImportText(text);
                setImportError(null);
                setImportOutcome(null);
              }}
              data-testid="import-file"
            />
            <span className="dim" style={{ fontSize: 11 }}>{c("vuln.import.file")}</span>
          </div>

          {importOutcome ? (
            <div className="stack" style={{ marginTop: 16 }}>
              <div className="section-label">{c("vuln.import.result")}</div>
              <ImportOutcomeView outcome={importOutcome} />
            </div>
          ) : importMutation.isPending ? (
            <p className="muted" style={{ fontSize: 12, marginTop: 14 }}>{t("common.loading")}</p>
          ) : (
            <p className="dim" style={{ fontSize: 11.5, marginTop: 14 }}>{c("vuln.import.none")}</p>
          )}
        </div>
      </Modal>
    </div>
  );

  function parseErrorMessage(parsed: { error: string; row?: number }): string {
    if (parsed.error === "empty") return c("vuln.import.empty");
    if (parsed.error === "json") return c("vuln.import.invalidJson");
    if (parsed.error === "tooMany") return c("vuln.import.tooMany");
    if (parsed.error === "invalidRow") {
      return `${c("vuln.import.invalidRow")} ${(parsed.row ?? 0) + 1}`;
    }
    return c("vuln.import.invalidShape");
  }

  function ImportOutcomeView({ outcome }: { outcome: ImportOutcome }) {
    if (outcome.kind === "cve") {
      return (
        <div className="stack">
          <div className="stat-inline">
            <div><span className="label">{c("vuln.import.catalogCreated")}</span><span className="value">{formatNumber(outcome.data.catalog_created)}</span></div>
            <div><span className="label">{c("vuln.import.catalogUpdated")}</span><span className="value">{formatNumber(outcome.data.catalog_updated)}</span></div>
            <div><span className="label">{c("vuln.import.vulnsCreated")}</span><span className="value">{formatNumber(outcome.data.vulnerabilities_created)}</span></div>
            <div><span className="label">{c("vuln.import.vulnsUpdated")}</span><span className="value">{formatNumber(outcome.data.vulnerabilities_updated)}</span></div>
          </div>
          <div>
            <div className="section-label">{c("vuln.import.errors")}</div>
            <ImportErrors errors={outcome.data.errors} emptyLabel={c("vuln.import.noErrors")} />
          </div>
        </div>
      );
    }
    if (outcome.kind === "kev") {
      return (
        <div className="stack">
          <div className="stat-inline">
            <div><span className="label">{c("vuln.import.catalogCreated")}</span><span className="value">{formatNumber(outcome.data.catalog_created)}</span></div>
            <div><span className="label">{c("vuln.import.catalogMarked")}</span><span className="value">{formatNumber(outcome.data.catalog_marked)}</span></div>
            <div><span className="label">{c("vuln.import.vulnsMarked")}</span><span className="value">{formatNumber(outcome.data.vulnerabilities_marked)}</span></div>
            <div><span className="label">{c("vuln.import.unknownCves")}</span><span className="value" style={{ color: outcome.data.unknown_cves.length ? "var(--warning)" : "var(--success)" }}>{formatNumber(outcome.data.unknown_cves.length)}</span></div>
          </div>
          {outcome.data.unknown_cves.length ? (
            <div>
              <div className="section-label">{c("vuln.import.unknownCves")}</div>
              <div className="chip-row">
                {outcome.data.unknown_cves.slice(0, 40).map((cve) => (
                  <span className="tag" key={cve}>{cve}</span>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      );
    }
    return (
      <div className="stack">
        <div className="stat-inline">
          <div><span className="label">{c("vuln.import.parsed")}</span><span className="value">{formatNumber(outcome.data.parsed)}</span></div>
          <div><span className="label">{c("vuln.import.catalogUpdated")}</span><span className="value">{formatNumber(outcome.data.catalog_updated)}</span></div>
          <div><span className="label">{c("vuln.import.vulnsUpdated")}</span><span className="value">{formatNumber(outcome.data.vulnerabilities_updated)}</span></div>
        </div>
        <div>
          <div className="section-label">{c("vuln.import.errors")}</div>
          <ImportErrors errors={outcome.data.errors} emptyLabel={c("vuln.import.noErrors")} />
        </div>
      </div>
    );
  }
}

function copyOr(copy: (key: string) => string, key: string, fallback: string): string {
  const translated = copy(key);
  return translated === key ? fallback : translated;
}

export default VulnerabilitiesPage;
