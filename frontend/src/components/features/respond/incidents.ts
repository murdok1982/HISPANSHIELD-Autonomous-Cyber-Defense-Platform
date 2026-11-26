/**
 * Shared incident-response domain types and pure helpers.
 *
 * The lifecycle mirror in this module is intentionally identical to
 * `backend/app/modules/incidents/service.py`; the server remains authoritative
 * and the UI only disables transitions the API would reject.
 */

export const INCIDENT_STATUSES = [
  "new",
  "triage",
  "investigating",
  "contained",
  "eradicated",
  "recovered",
  "closed",
] as const;

export const OPEN_STATUSES = ["new", "triage", "investigating", "contained", "eradicated", "recovered"] as const;

export const INCIDENT_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

export const ALLOWED_TRANSITIONS: Record<string, readonly string[]> = {
  new: ["triage"],
  triage: ["investigating"],
  investigating: ["contained"],
  contained: ["eradicated"],
  eradicated: ["recovered"],
  recovered: ["closed"],
  closed: [],
};

export const TRANSITIONS_REQUIRING_REASON: Record<string, boolean> = {
  contained: true,
  closed: true,
};

export const CLOSE_OUT_MIN_LENGTH = 10;

export interface Incident {
  id: string;
  ref: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  priority: number;
  assignee_id: string | null;
  commander_id: string | null;
  detected_at: string;
  contained_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  sla_due_at: string | null;
  mitre: string[];
  affected_asset_ids: string[];
  root_cause: string | null;
  lessons_learned: string | null;
  is_demo: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface TimelineEntry {
  id: string;
  incident_id: string;
  at: string;
  kind: string;
  actor: string | null;
  summary: string;
  detail: Record<string, unknown>;
}

export interface EvidenceRecord {
  id: string;
  incident_id: string | null;
  kind: string;
  title: string;
  description: string | null;
  sha256: string;
  content_type: string;
  size_bytes: number;
  collected_by: string | null;
  collected_at: string;
  sealed: boolean;
  chain_of_custody: Record<string, unknown>[];
}

export interface AlertLink {
  id: string;
  title: string;
  severity: string;
  status: string;
  count: number;
  first_seen: string;
  last_seen: string;
  mitre: string[];
}

export interface RemediationLink {
  id: string;
  action_type: string;
  target_type: string;
  target_id: string;
  status: string;
  risk_level: string;
  execution_id: string | null;
  executed_at: string | null;
  verified_at: string | null;
  rollback_status: string | null;
}

export interface AffectedAsset {
  id: string;
  name: string;
  kind: string;
  criticality: number;
  environment: string;
  status: string;
  ip_addresses: string[];
}

export interface IncidentDetailData extends Incident {
  timeline: TimelineEntry[];
  evidence: EvidenceRecord[];
  alerts: AlertLink[];
  remediations: RemediationLink[];
  assets: AffectedAsset[];
}

export interface IncidentMetrics {
  open_total: number;
  open_by_severity: Record<string, number>;
  closed_total: number;
  total: number;
  mttd_seconds: number | null;
  mttr_seconds: number | null;
  computed_at: string;
}

export interface OrganizationMember {
  id: string;
  user_id: string;
  email: string;
  full_name: string;
  role: string;
  status: string;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface AssetOption {
  id: string;
  name: string;
  kind: string;
  criticality: number;
  environment: string;
  ip_addresses: string[];
}

export type SlaState = "none" | "ok" | "at_risk" | "breached";

export function allowedTransitions(status: string): string[] {
  return [...(ALLOWED_TRANSITIONS[status] ?? [])];
}

export function isTransitionAllowed(from: string, to: string): boolean {
  return (ALLOWED_TRANSITIONS[from] ?? []).includes(to);
}

export function transitionNeedsReason(target: string): boolean {
  return TRANSITIONS_REQUIRING_REASON[target] === true;
}

export function transitionNeedsCloseOut(target: string): boolean {
  return target === "closed";
}

export function isOpenStatus(status: string): boolean {
  return status !== "closed";
}

/**
 * Remaining minutes until the SLA deadline. Returns null when no deadline is
 * recorded and negative values when the deadline has already passed.
 */
export function slaRemainingMinutes(dueAt: string | null | undefined, now: number = Date.now()): number | null {
  if (!dueAt) return null;
  const due = new Date(dueAt).getTime();
  if (Number.isNaN(due)) return null;
  return Math.round((due - now) / 60_000);
}

/** Classify an SLA deadline. Anything inside the 2h window is "at risk". */
export function slaState(dueAt: string | null | undefined, now: number = Date.now(), atRiskMinutes = 120): SlaState {
  const remaining = slaRemainingMinutes(dueAt, now);
  if (remaining === null) return "none";
  if (remaining < 0) return "breached";
  if (remaining <= atRiskMinutes) return "at_risk";
  return "ok";
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}

export function incidentAgeMinutes(detectedAt: string, now: number = Date.now()): number | null {
  const detected = new Date(detectedAt).getTime();
  if (Number.isNaN(detected)) return null;
  return Math.max(0, Math.round((now - detected) / 60_000));
}

export function shortSha(sha: string | null | undefined): string {
  if (!sha) return "—";
  return sha.length > 16 ? `${sha.slice(0, 12)}…${sha.slice(-4)}` : sha;
}

export function parseJsonObject(text: string): { value?: Record<string, unknown>; error?: string } {
  if (!text.trim()) return { value: {} };
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { error: "Se esperaba un objeto JSON" };
    }
    return { value: parsed as Record<string, unknown> };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "JSON inválido" };
  }
}

export function stringifyDefinition(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "{}";
  }
}
