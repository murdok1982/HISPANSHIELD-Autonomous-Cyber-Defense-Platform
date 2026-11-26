/**
 * API contracts for the detection & exposure screens.
 *
 * Field names mirror the FastAPI/Pydantic response schemas (snake_case).
 * Optional fields are only the ones the server may omit for auxiliary
 * enrichment; core entities stay required so TypeScript catches drift.
 */
import type { Page, PageMeta } from "../../../lib/api";

export type { Page, PageMeta };

/* ------------------------------------------------------------------ events */

export interface SecurityEvent {
  id: number;
  event_uid: string;
  org_id?: string;
  source_id: string | null;
  occurred_at: string;
  received_at: string;
  class_uid: number;
  class_name: string;
  category_uid: number;
  activity_id: number | null;
  severity_id: number;
  status_id: number | null;
  message: string;
  raw_format: string;
  schema_version: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  user_name: string | null;
  host_name: string | null;
  process_name: string | null;
  file_hash_sha256: string | null;
  url: string | null;
  domain: string | null;
  ioc_matches: Record<string, unknown>[];
  mitre_techniques: string[];
  is_demo?: boolean;
}

export interface SecurityEventDetail extends SecurityEvent {
  raw: Record<string, unknown>;
  normalized: Record<string, unknown>;
  dedupe_key: string | null;
  source_connector: string | null;
}

export interface EventStats {
  generated_at: string;
  window_hours: number;
  total: number;
  by_severity: Record<string, number>;
  by_class: { class_uid: number; class_name: string; count: number }[];
  top_sources: { source_id: string | null; name: string; count: number }[];
  top_hosts: { host_name: string; count: number }[];
  timeline: { timestamp: string; count: number }[];
}

export interface IngestSource {
  id: string;
  org_id?: string;
  name: string;
  kind: string;
  parser: string;
  enabled: boolean;
  connector_id: string | null;
  config: Record<string, unknown>;
  last_event_at: string | null;
  event_count: number;
  created_at: string;
  updated_at: string;
  has_token: boolean;
  has_hmac_secret: boolean;
}

/* ------------------------------------------------------------------ assets */

export interface Zone {
  id: string;
  name: string;
  kind: string;
  purdue_level: number | null;
  description: string | null;
  parent_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetRef {
  id: string;
  asset_key: string;
  name: string;
  kind: string;
  criticality: number;
  environment: string;
  zone_id: string | null;
}

export interface Asset {
  id: string;
  asset_key: string;
  name: string;
  kind: string;
  subtype: string | null;
  criticality: number;
  environment: string;
  status: string;
  ip_addresses: string[];
  mac_addresses: string[];
  hostnames: string[];
  os_name: string | null;
  vendor: string | null;
  model: string | null;
  firmware: string | null;
  serial_number: string | null;
  location: string | null;
  owner: string | null;
  discovery_source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  last_scanned_at: string | null;
  zone_id: string | null;
  tags: string[];
  metadata: Record<string, unknown>;
  is_demo: boolean;
  created_at: string;
  updated_at: string;
  /** Enriched by some deployments; absent otherwise. Never fabricated. */
  open_vulnerabilities?: number;
}

export interface AssetIdentity {
  id: string;
  asset_id: string;
  kind: string;
  value: string;
  confidence: number;
  created_at: string;
}

export interface Relationship {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  kind: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  metadata: Record<string, unknown>;
  direction: string;
  counterpart: AssetRef | null;
}

export interface AssetIoT {
  protocols: string[];
  connectivity: string | null;
  edge_gateway_id: string | null;
  firmware_version: string | null;
  last_telemetry_at: string | null;
  security_posture: Record<string, unknown>;
}

export interface AssetOT {
  protocols: string[];
  zone_id: string | null;
  safety_critical: boolean;
  passive_only: boolean;
  controller_model: string | null;
  firmware_version: string | null;
  last_telemetry_at: string | null;
  baseline: Record<string, unknown>;
}

export interface AssetVulnSummary {
  total: number;
  open: number;
  reopened: number;
  kev: number;
  by_severity: Record<string, number>;
}

export interface AssetDetail extends Asset {
  identities: AssetIdentity[];
  relationships: Relationship[];
  iot: AssetIoT | null;
  ot: AssetOT | null;
  vulnerability_summary: AssetVulnSummary;
}

export interface GraphNode {
  id: string;
  asset_key: string;
  name: string;
  kind: string;
  criticality: number;
  environment: string;
  zone_id: string | null;
}

export interface GraphEdge {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  kind: string;
  confidence: number;
}

export interface AssetGraph {
  root_id: string;
  depth: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AssetImportRowError {
  row: number;
  asset_key: string | null;
  message: string;
}

export interface AssetImportResult {
  total: number;
  created: number;
  updated: number;
  skipped: number;
  errors: AssetImportRowError[];
}

/* ------------------------------------------------------------ vulnerabilities */

export interface AssetVulnerability {
  id: string;
  asset_id: string | null;
  cve_id: string | null;
  title: string;
  severity: string;
  status: string;
  cvss_score: number | null;
  epss_score: number | null;
  kev: boolean;
  exploitable: boolean;
  exposure: string;
  priority_score: number;
  priority_reason: string | null;
  source: string;
  first_seen: string;
  last_seen: string;
  due_at: string | null;
  remediation: string | null;
}

export interface Vulnerability extends AssetVulnerability {
  description: string | null;
  cvss_vector: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface CveCatalog {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  epss_score: number | null;
  kev: boolean;
  published_at: string | null;
  modified_at: string | null;
  references: string[];
  cpes: string[];
  cwe: string | null;
  updated_at: string;
}

export interface VulnerabilityDetail extends Vulnerability {
  asset: AssetRef | null;
  catalog: CveCatalog | null;
}

export interface VulnTopRisky {
  id: string;
  title: string;
  cve_id: string | null;
  severity: string;
  status: string;
  priority_score: number;
  asset_id: string | null;
  asset_name: string | null;
}

export interface VulnerabilitySummary {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  kev: number;
  exploitable: number;
  overdue: number;
  mean_priority: number;
  top_risky: VulnTopRisky[];
}

export interface ImportRowError {
  row: number;
  identifier: string | null;
  message: string;
}

export interface CveImportResult {
  catalog_created: number;
  catalog_updated: number;
  vulnerabilities_created: number;
  vulnerabilities_updated: number;
  errors: ImportRowError[];
}

export interface KevImportResult {
  catalog_created: number;
  catalog_marked: number;
  vulnerabilities_marked: number;
  unknown_cves: string[];
}

export interface EpssImportResult {
  parsed: number;
  catalog_updated: number;
  vulnerabilities_updated: number;
  errors: ImportRowError[];
}

/* ------------------------------------------------------------ attack surface */

export interface Finding {
  id: string;
  asset_id: string | null;
  kind: string;
  title: string;
  severity: string;
  status: string;
  evidence: string | null;
  source: string;
  first_seen: string;
  last_seen: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface FindingSummary {
  total: number;
  by_severity: Record<string, number>;
  by_kind: Record<string, number>;
  by_status: Record<string, number>;
}

export interface AnalyzeResult {
  scanned_assets: number;
  created: number;
  updated: number;
  by_kind: Record<string, number>;
}

export interface DiscoveryJob {
  id: string;
  name: string;
  mode: string;
  scope_cidrs: string[];
  status: string;
  authorized_by: string | null;
  authorization_reference: string | null;
  authorized_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  summary: Record<string, unknown>;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface DiscoveryRunResult {
  job: DiscoveryJob;
  summary: Record<string, unknown>;
}

/* -------------------------------------------------------------- threat intel */

export interface Indicator {
  id: string;
  org_id: string | null;
  indicator_type: string;
  value: string;
  confidence: number;
  severity: string;
  source: string;
  description: string | null;
  tags: string[];
  actor_id: string | null;
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
  active: boolean;
  created_at: string;
  updated_at: string;
  is_demo?: boolean;
}

export interface ThreatActor {
  id: string;
  org_id: string | null;
  name: string;
  aliases: string[];
  mitre_id: string | null;
  description: string | null;
  sophistication: string;
  motivation: string;
  country: string | null;
  techniques: string[];
  created_at: string;
  updated_at: string;
}

export interface ThreatActorDetail extends ThreatActor {
  indicator_count: number;
}

export interface IntelFeed {
  id: string;
  org_id: string;
  name: string;
  kind: string;
  connector_id: string | null;
  enabled: boolean;
  schedule_minutes: number;
  last_sync_at: string | null;
  status: string;
  last_error: string | null;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface IntelImportError {
  row: number | null;
  field: string | null;
  message: string;
}

export interface IntelImportResult {
  created: number;
  updated: number;
  skipped: number;
  errors: IntelImportError[];
  total_received: number;
}

export interface FeedSyncResult {
  feed_id: string;
  status: string;
  objects_read: number;
  created: number;
  updated: number;
  skipped: number;
  errors: IntelImportError[];
  last_sync_at: string | null;
}

export interface IntelSummary {
  generated_at: string;
  indicators: {
    total: number;
    active: number;
    expired: number;
    inactive: number;
    by_type: Record<string, number>;
    by_severity: Record<string, number>;
  };
  actors: { total: number };
  feeds: {
    total: number;
    by_status: Record<string, number>;
    enabled: number;
    stale: { id: string; name: string; last_sync_at: string | null }[];
  };
  mitre: { catalog_size: number; covered_count: number; coverage_percent: number };
  data_quality: string;
}

export interface EnrichmentMatch {
  indicator_id: string;
  indicator_type: string;
  value: string;
  confidence: number;
  severity: string;
  source: string;
  active: boolean;
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
  actor_id: string | null;
  scope: string;
}

export interface EnrichmentTechnique {
  id: string;
  name: string;
  tactics: string[];
  description: string;
}

export interface EnrichmentActor {
  id: string;
  name: string;
  aliases: string[];
  mitre_id: string | null;
  techniques?: string[];
}

export interface EnrichmentEvent {
  event_id: string;
  event_uid: string;
  occurred_at: string;
  severity_id: number;
  message: string;
}

export interface Enrichment {
  value: string;
  type: string | null;
  verdict: "malicious" | "suspicious" | "unknown";
  confidence: number;
  matches: EnrichmentMatch[];
  evidence: EnrichmentMatch[];
  matched?: boolean;
  actors: EnrichmentActor[];
  actor: EnrichmentActor | null;
  techniques: EnrichmentTechnique[];
  events?: EnrichmentEvent[];
  reason?: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  description: string;
  event_count?: number;
  indicator_count?: number;
  actor_count?: number;
}

export interface MitreCoverage {
  catalog_size: number;
  covered_count: number;
  coverage_percent: number;
  techniques: MitreTechnique[];
  uncovered: MitreTechnique[];
}

export interface MitreTechniqueResponse {
  catalog_size: number;
  count: number;
  items: MitreTechnique[];
  filters: { tactic: string | null; q: string | null };
}
