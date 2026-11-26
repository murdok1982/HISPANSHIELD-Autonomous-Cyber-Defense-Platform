import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Boxes,
  Cable,
  Factory,
  GitBranch,
  KeyRound,
  Lock,
  Network,
  Pencil,
  Plus,
  Radio,
  RefreshCw,
  Router,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  Waves,
  Zap,
} from "lucide-react";
import { ApiError, api, errorMessage, withQuery, type Page } from "../lib/api";
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
  Kpi,
  LinkButton,
  Modal,
  PageHeader,
  PageSkeleton,
  Pagination,
  ProgressBar,
  SearchInput,
  Select,
  StatusBadge,
  Tabs,
  TableSkeleton,
  Textarea,
  useToast,
  type Column,
} from "../components/ui";
import { CopyField } from "../components/features/protect/common";
import { formatPorts, groupProtocols, splitTokens } from "../components/features/protect/protocols";

/* ------------------------------------------------------------------ types */

interface AssetRef {
  id: string;
  asset_key: string;
  name: string;
  kind: string;
  criticality: number;
  environment: string;
  zone_id: string | null;
}

interface IoTDevice {
  asset_id: string;
  asset: AssetRef;
  protocols: string[];
  connectivity: string | null;
  edge_gateway_id: string | null;
  firmware_version: string | null;
  last_telemetry_at: string | null;
  security_posture: Record<string, unknown>;
  risk_flags: string[];
}

interface IoTSummary {
  total_devices: number;
  stale_devices: number;
  without_protocols: number;
  by_connectivity: Record<string, number>;
  by_protocol: Record<string, number>;
  by_support_level: Record<string, number>;
  risk_flag_counts: Record<string, number>;
}

interface IoTProtocol {
  name: string;
  family: string;
  default_ports: number[];
  read_only_default: boolean;
  security_notes: string;
  support_level: string;
}

interface OTDevice {
  asset_id: string;
  asset: AssetRef;
  zone_id: string | null;
  zone_name: string | null;
  protocols: string[];
  safety_critical: boolean;
  passive_only: boolean;
  controller_model: string | null;
  firmware_version: string | null;
  last_telemetry_at: string | null;
  baseline: Record<string, unknown>;
  risk_flags: string[];
}

interface OTProtocol {
  name: string;
  family: string;
  default_ports: number[];
  safety_class: string;
  support_level: string;
  passive_only_default: boolean;
  security_notes: string;
  active_operations_denied: string[];
}

interface OTZonePosture {
  zone_id: string;
  name: string;
  kind: string;
  purdue_level: number | null;
  devices: number;
  safety_critical: number;
}

interface OTPosture {
  ot_devices_total: number;
  ot_devices_zoned: number;
  unzoned_devices: number;
  safety_critical_devices: number;
  monitored_devices: number;
  unmonitored_devices: number;
  zones_total: number;
  conduits_total: number;
  purdue_documented_zones: number;
  zone_coverage_pct: number;
  conduit_coverage_pct: number;
  posture_level: string;
  iec62443: Record<string, unknown>;
  zone_breakdown: OTZonePosture[];
}

interface Zone {
  id: string;
  name: string;
  kind: string;
  purdue_level: number | null;
  description: string | null;
  parent_id: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface AssetRow {
  id: string;
  asset_key: string;
  name: string;
  kind: string;
  criticality: number;
  zone_id: string | null;
  status: string;
}

interface EdgeGateway {
  id: string;
  org_id: string;
  name: string;
  fingerprint: string;
  status: string;
  version: string | null;
  last_seen_at: string | null;
  enrolled_at: string | null;
  revoked_at: string | null;
  certificate_serial: string | null;
  config: Record<string, unknown>;
  buffer_stats: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface GatewayEvent {
  id: string;
  gateway_id: string;
  kind: string;
  sequence: number;
  signature_valid: boolean;
  accepted: boolean;
  rejection_reason: string | null;
  processed_count: number;
  payload: Record<string, unknown>;
  received_at: string;
}

interface EnrollmentToken {
  gateway_id: string;
  token: string;
  expires_at: string;
  expires_in_seconds: number;
}

interface RotateKeyResult {
  gateway_id: string;
  shared_key: string;
  key_id: string;
  rotated_at: string;
}

type TabKey = "overview" | "iot" | "ot" | "zones" | "gateways" | "protocols";

/* ------------------------------------------------------------------- copy */

const copy = {
  es: {
    "eyebrow": "Protección · IoT / OT",
    "title": "Seguridad IoT y OT",
    "subtitle":
      "Inventario IoT/OT, zonas y conductos IEC 62443, pasarelas edge y registro de protocolos con monitorización estrictamente pasiva.",
    "refreshed": "Actualizado",
    "tab.overview": "Resumen",
    "tab.iot": "Inventario IoT",
    "tab.ot": "Inventario OT",
    "tab.zones": "Zonas",
    "tab.gateways": "Pasarelas edge",
    "tab.protocols": "Protocolos",
    "safetyTitle": "Monitorización pasiva únicamente",
    "safetyBody":
      "HISPANSHIELD no realiza escaneos activos, no escribe en controladores ni reinicia equipos. La telemetría OT/IoT se limita a observación pasiva y aprendizaje de línea base. No existe ninguna acción de control expuesta en esta interfaz.",
    "safetyNoWrite": "Sin escrituras de control · sin escaneo activo · sin reinicio de dispositivos",
    "iotDevices": "Dispositivos IoT",
    "iotHint": "Activos con perfil IoT, protocolos y conectividad registrados.",
    "otDevices": "Dispositivos OT",
    "otHint": "Activos industriales con zona, flags de seguridad y línea base pasiva.",
    "unzoned": "Sin zona IEC 62443",
    "unzonedHint": "Activos OT que aún no pertenecen a ninguna zona declarada.",
    "safetyCritical": "Críticos de seguridad",
    "safetyCriticalHint": "Equipos marcados como safety-critical por el operador.",
    "monitored": "Monitorizados",
    "monitoredHint": "Dispositivos OT con telemetría pasiva reciente dentro de la ventana de frescura.",
    "unmonitored": "Sin monitorizar",
    "zoneCoverage": "Cobertura de zonas",
    "conduitCoverage": "Cobertura de conductos",
    "postureLevel": "Nivel de postura",
    "posture.aligned": "Alineada",
    "posture.partial": "Parcial",
    "posture.initial": "Inicial",
    "iecTitle": "Postura IEC 62443",
    "iecHint": "Zonas y conductos declarados, cobertura de activos y controles de monitorización.",
    "zonesDocumented": "Zonas documentadas",
    "zonesTotal": "Zonas totales",
    "conduitsTotal": "Conductos",
    "purdueDocumented": "Con niveles Purdue",
    "unzonedDevices": "Dispositivos sin zona",
    "unmonitoredDevices": "Dispositivos sin monitorizar",
    "commControl": "Control de comunicación declarado",
    "purdueModel": "Modelo Purdue documentado",
    "monitoringPct": "Cobertura de monitorización",
    "authorizedDevices": "Dispositivos autorizados",
    "yes": "Sí",
    "no": "No",
    "zoneBreakdown": "Desglose por zona",
    "zone": "Zona",
    "kind": "Tipo",
    "purdue": "Purdue",
    "devices": "Dispositivos",
    "iotRiskFlags": "Riesgos IoT detectados",
    "iotRiskHint": "Recuento de flags de riesgo calculados por el servidor sobre el inventario IoT.",
    "iotByConnectivity": "IoT por conectividad",
    "iotByProtocol": "IoT por protocolo",
    "noRiskFlags": "Sin flags de riesgo activos",
    "noRiskFlagsHint": "El inventario IoT no presenta señales de riesgo en este momento.",
    "staleDevices": "Dispositivos obsoletos",
    "withoutProtocols": "Sin protocolos",
    "inventory": "Inventario",
    "filterSearch": "Buscar por nombre o clave",
    "filterConnectivity": "Conectividad",
    "allConnectivity": "Toda conectividad",
    "filterProtocol": "Protocolo",
    "allProtocols": "Todos los protocolos",
    "filterZone": "Zona",
    "allZones": "Todas las zonas",
    "filterSafety": "Criticidad de seguridad",
    "allSafety": "Todos",
    "safetyOnly": "Solo safety-critical",
    "nonSafety": "Solo no críticos",
    "clearFilters": "Limpiar filtros",
    "noIot": "Sin dispositivos IoT inventariados",
    "noIotHint": "Registra un dispositivo pasivo para empezar a construir el inventario.",
    "noIotResults": "Ningún dispositivo coincide con los filtros",
    "noIotResultsHint": "Ajusta la búsqueda o limpia los filtros.",
    "noOt": "Sin dispositivos OT inventariados",
    "noOtHint": "Registra un equipo industrial; la monitorización seguirá siendo pasiva.",
    "noOtResults": "Ningún equipo OT coincide con los filtros",
    "noOtResultsHint": "Ajusta la búsqueda o limpia los filtros.",
    "createIot": "Registrar IoT",
    "createOt": "Registrar OT",
    "edit": "Editar",
    "delete": "Eliminar",
    "save": "Guardar",
    "cancel": "Cancelar",
    "name": "Nombre",
    "assetKey": "Clave de activo",
    "assetKeyHint": "Identificador único estable, p. ej. sensor-hvac-01.",
    "criticality": "Criticidad (1–5)",
    "ipAddresses": "Direcciones IP",
    "ipHint": "Separadas por comas. Se validan en el servidor.",
    "vendor": "Fabricante",
    "model": "Modelo",
    "firmware": "Firmware",
    "connectivity": "Conectividad",
    "connectivityHint": "Wi-Fi, Ethernet, celular, LoRaWAN…",
    "protocols": "Protocolos",
    "protocolsHint": "Selecciona solo protocolos del registro oficial.",
    "edgeGateway": "Pasarela edge",
    "noGateway": "Sin pasarela",
    "zoneNone": "Sin zona",
    "controllerModel": "Modelo de controlador",
    "safetyCriticalFlag": "Safety-critical",
    "passiveOnly": "Solo pasivo",
    "passiveLocked": "La monitorización pasiva es obligatoria en OT y no puede desactivarse.",
    "baseline": "Línea base",
    "samples": "Muestras",
    "anomalies": "Anomalías",
    "lastTelemetry": "Última telemetría",
    "never": "Nunca",
    "riskFlags": "Riesgos",
    "actions": "Acciones",
    "status": "Estado",
    "open": "Abrir",
    "deleteIotTitle": "Eliminar dispositivo IoT",
    "deleteIotBody": "Se eliminará el activo y su perfil IoT del inventario. Esta acción queda auditada y no afecta a la telemetría ya almacenada en eventos.",
    "deleteConfirm": "Eliminar definitivamente",
    "zoneAssets": "Activos de la zona",
    "zoneAssetsHint": "Activos cuyo zone_id apunta a la zona seleccionada.",
    "selectZone": "Selecciona una zona",
    "selectZoneHint": "Elige una zona de la tabla para ver sus activos asignados.",
    "noZoneAssets": "Sin activos asignados a esta zona",
    "zonesTabHint": "Zonas y conductos IEC 62443 con nivel Purdue documentado.",
    "createZone": "Crear zona",
    "zoneName": "Nombre de la zona",
    "zoneKind": "Tipo",
    "zoneType.zone": "Zona",
    "zoneType.conduit": "Conducto",
    "purdueLevel": "Nivel Purdue",
    "purdueNone": "Sin nivel",
    "description": "Descripción",
    "updated": "Actualizado",
    "noZones": "Sin zonas ni conductos declarados",
    "noZonesHint": "Declara zonas para asignar activos OT y medir la cobertura IEC 62443.",
    "editZone": "Editar zona",
    "deleteZone": "Eliminar zona",
    "deleteZoneBody": "La zona se eliminará. Si tiene activos, dispositivos o zonas hijas, debes indicar una zona de reasignación.",
    "reassignTo": "Reasignar referencias a",
    "reassignNone": "Sin reasignación",
    "deleteZoneConfirm": "Eliminar zona",
    "gatewaysTabHint": "Pasarelas edge con almacenamiento y reenvío, heartbeat y configuración firmada.",
    "createToken": "Generar token de alta",
    "gateway": "Pasarela",
    "fingerprint": "Huella",
    "version": "Versión",
    "lastSeen": "Último heartbeat",
    "freshness": "Frescura",
    "fresh": "Reciente",
    "stale": "Obsoleto",
    "unknownFreshness": "Desconocida",
    "events": "Eventos",
    "configure": "Configurar",
    "revoke": "Revocar",
    "rotateKey": "Rotar clave",
    "noGateways": "Sin pasarelas edge registradas",
    "noGatewaysHint": "Genera un token de alta y despliega una pasarela para ingerir telemetría offline.",
    "offlineTitle": "Almacenamiento y reenvío offline",
    "offlineBody":
      "Las pasarelas bufferean telemetría firmada cuando no hay conectividad y la reenvían al recuperarla. La configuración remota está limitada por lista blanca: una pasarela no puede cambiar la política central, la autonomía ni los permisos.",
    "enrollTitle": "Token de alta de un solo uso",
    "enrollBody": "Copia el token ahora. Caduca y solo puede usarse una vez; no se volverá a mostrar.",
    "expiresIn": "Caduca en",
    "expiresAt": "Caduca",
    "token": "Token",
    "gatewayId": "ID de pasarela",
    "close": "Cerrar",
    "rotateTitle": "Nueva clave HMAC",
    "rotateBody": "La clave se muestra una única vez. Actualiza la pasarela inmediatamente: la clave anterior deja de ser válida.",
    "sharedKey": "Clave compartida",
    "keyId": "ID de clave",
    "revokeTitle": "Revocar pasarela",
    "revokeBody": "La pasarela dejará de autenticar heartbeats y telemetría. Sus eventos históricos se conservan y la acción queda auditada.",
    "revokeConfirm": "Revocar pasarela",
    "configTitle": "Configuración operativa",
    "configHint": "Solo se permiten claves de la lista blanca del servidor.",
    "bufferMax": "Máx. eventos en buffer",
    "batchSize": "Tamaño de lote",
    "flushInterval": "Intervalo de vaciado (s)",
    "heartbeatInterval": "Intervalo de heartbeat (s)",
    "logLevel": "Nivel de log",
    "collectors": "Colectores",
    "collectorsHint": "Identificadores separados por comas.",
    "tags": "Etiquetas",
    "storeForward": "Almacenamiento y reenvío",
    "allowRemoteConfig": "Permitir configuración remota",
    "gatewayEvents": "Eventos de la pasarela",
    "gatewayEventsHint": "Lotes recibidos con validez de firma y resultado de procesamiento.",
    "selectGateway": "Selecciona una pasarela",
    "selectGatewayHint": "Elige una pasarela para inspeccionar sus lotes de telemetría.",
    "noEvents": "Sin lotes de telemetría recibidos",
    "noEventsHint": "La pasarela enviará lotes firmados en su próximo ciclo de sincronización.",
    "sequence": "Secuencia",
    "signature": "Firma",
    "valid": "Válida",
    "invalid": "Inválida",
    "accepted": "Aceptado",
    "rejected": "Rechazado",
    "processed": "Procesados",
    "received": "Recibido",
    "reason": "Motivo",
    "iotRegistry": "Registro de protocolos IoT",
    "otRegistry": "Registro de protocolos OT",
    "registryHint": "Los protocolos se agrupan por familia (IoT) o clase de seguridad (OT). Todos son de solo lectura.",
    "readOnly": "Solo lectura",
    "support": "Soporte",
    "support.full": "Completo",
    "support.observe": "Observación",
    "ports": "Puertos",
    "family": "Familia",
    "safetyClass": "Clase de seguridad",
    "deniedOps": "Operaciones denegadas",
    "securityNotes": "Notas de seguridad",
    "noProtocols": "Registro de protocolos vacío",
    "loadingProtocols": "Cargando registro de protocolos…",
    "overviewHint": "Resumen derivado de /iot/summary y /ot/posture; no se estiman métricas.",
    "permissionReadOnly": "Tu rol no permite modificar el inventario (asset:write).",
    "permissionEdge": "Tu rol no permite administrar pasarelas (edge:write).",
    "permissionEdgeHint": "La lectura de pasarelas requiere el permiso edge:read. Solicita acceso a un administrador de la organización.",
    "formCreateIot": "Registrar dispositivo IoT",
    "formEditIot": "Editar dispositivo IoT",
    "formCreateOt": "Registrar dispositivo OT",
    "formEditOt": "Editar dispositivo OT",
    "formZone": "Zona / conducto",
    "formGatewayConfig": "Configuración de pasarela",
    "formRequired": "Revisa los campos marcados.",
    "saveIot": "Guardar IoT",
    "saveOt": "Guardar OT",
    "saveZone": "Guardar zona",
    "saveConfig": "Aplicar configuración",
    "createSuccess": "Dispositivo registrado",
    "updateSuccess": "Cambios guardados",
    "deleteSuccess": "Dispositivo eliminado",
    "zoneCreateSuccess": "Zona creada",
    "zoneUpdateSuccess": "Zona actualizada",
    "zoneDeleteSuccess": "Zona eliminada",
    "tokenSuccess": "Token generado",
    "rotateSuccess": "Clave rotada",
    "revokeSuccess": "Pasarela revocada",
    "configSuccess": "Configuración aplicada",
    "operationFailed": "La operación falló",
    "zoneRefsError": "La zona tiene referencias. Indica una zona de reasignación.",
    "all": "Todos",
    "deviceFallback": "Dispositivo",
    "lastUpdated": "Última evaluación",
    "goAssets": "Ver activos",
    "editIn": "Inventario",
  },
  en: {
    "eyebrow": "Protect · IoT / OT",
    "title": "IoT and OT security",
    "subtitle":
      "IoT/OT inventory, IEC 62443 zones and conduits, edge gateways and protocol registry with strictly passive monitoring.",
    "refreshed": "Updated",
    "tab.overview": "Overview",
    "tab.iot": "IoT inventory",
    "tab.ot": "OT inventory",
    "tab.zones": "Zones",
    "tab.gateways": "Edge gateways",
    "tab.protocols": "Protocols",
    "safetyTitle": "Passive monitoring only",
    "safetyBody":
      "HISPANSHIELD performs no active scans, never writes to controllers and never reboots equipment. OT/IoT telemetry is limited to passive observation and baseline learning. No control action is exposed in this interface.",
    "safetyNoWrite": "No control writes · no active scanning · no device reboots",
    "iotDevices": "IoT devices",
    "iotHint": "Assets with an IoT profile, protocols and connectivity recorded.",
    "otDevices": "OT devices",
    "otHint": "Industrial assets with a zone, safety flags and a passive baseline.",
    "unzoned": "Without IEC 62443 zone",
    "unzonedHint": "OT assets not yet assigned to a declared zone.",
    "safetyCritical": "Safety-critical",
    "safetyCriticalHint": "Equipment marked safety-critical by the operator.",
    "monitored": "Monitored",
    "monitoredHint": "OT devices with recent passive telemetry inside the freshness window.",
    "unmonitored": "Unmonitored",
    "zoneCoverage": "Zone coverage",
    "conduitCoverage": "Conduit coverage",
    "postureLevel": "Posture level",
    "posture.aligned": "Aligned",
    "posture.partial": "Partial",
    "posture.initial": "Initial",
    "iecTitle": "IEC 62443 posture",
    "iecHint": "Declared zones and conduits, asset coverage and monitoring controls.",
    "zonesDocumented": "Documented zones",
    "zonesTotal": "Total zones",
    "conduitsTotal": "Conduits",
    "purdueDocumented": "With Purdue levels",
    "unzonedDevices": "Devices without a zone",
    "unmonitoredDevices": "Unmonitored devices",
    "commControl": "Declared communication control",
    "purdueModel": "Documented Purdue model",
    "monitoringPct": "Monitoring coverage",
    "authorizedDevices": "Authorized devices",
    "yes": "Yes",
    "no": "No",
    "zoneBreakdown": "Zone breakdown",
    "zone": "Zone",
    "kind": "Type",
    "purdue": "Purdue",
    "devices": "Devices",
    "iotRiskFlags": "Detected IoT risks",
    "iotRiskHint": "Risk flag counts computed server-side over the IoT inventory.",
    "iotByConnectivity": "IoT by connectivity",
    "iotByProtocol": "IoT by protocol",
    "noRiskFlags": "No active risk flags",
    "noRiskFlagsHint": "The IoT inventory shows no risk signals at this time.",
    "staleDevices": "Stale devices",
    "withoutProtocols": "Without protocols",
    "inventory": "Inventory",
    "filterSearch": "Search by name or key",
    "filterConnectivity": "Connectivity",
    "allConnectivity": "All connectivity",
    "filterProtocol": "Protocol",
    "allProtocols": "All protocols",
    "filterZone": "Zone",
    "allZones": "All zones",
    "filterSafety": "Safety criticality",
    "allSafety": "All",
    "safetyOnly": "Safety-critical only",
    "nonSafety": "Non-critical only",
    "clearFilters": "Clear filters",
    "noIot": "No IoT devices inventoried",
    "noIotHint": "Register a passive device to start building the inventory.",
    "noIotResults": "No device matches the filters",
    "noIotResultsHint": "Adjust the search or clear the filters.",
    "noOt": "No OT devices inventoried",
    "noOtHint": "Register industrial equipment; monitoring remains passive.",
    "noOtResults": "No OT device matches the filters",
    "noOtResultsHint": "Adjust the search or clear the filters.",
    "createIot": "Register IoT",
    "createOt": "Register OT",
    "edit": "Edit",
    "delete": "Delete",
    "save": "Save",
    "cancel": "Cancel",
    "name": "Name",
    "assetKey": "Asset key",
    "assetKeyHint": "Stable unique identifier, e.g. sensor-hvac-01.",
    "criticality": "Criticality (1–5)",
    "ipAddresses": "IP addresses",
    "ipHint": "Comma separated. Validated server-side.",
    "vendor": "Vendor",
    "model": "Model",
    "firmware": "Firmware",
    "connectivity": "Connectivity",
    "connectivityHint": "Wi-Fi, Ethernet, cellular, LoRaWAN…",
    "protocols": "Protocols",
    "protocolsHint": "Select only protocols from the official registry.",
    "edgeGateway": "Edge gateway",
    "noGateway": "No gateway",
    "zoneNone": "No zone",
    "controllerModel": "Controller model",
    "safetyCriticalFlag": "Safety-critical",
    "passiveOnly": "Passive only",
    "passiveLocked": "Passive monitoring is mandatory for OT and cannot be disabled.",
    "baseline": "Baseline",
    "samples": "Samples",
    "anomalies": "Anomalies",
    "lastTelemetry": "Last telemetry",
    "never": "Never",
    "riskFlags": "Risks",
    "actions": "Actions",
    "status": "Status",
    "open": "Open",
    "deleteIotTitle": "Delete IoT device",
    "deleteIotBody": "The asset and its IoT profile will be removed from the inventory. The action is audited and does not affect telemetry already stored in events.",
    "deleteConfirm": "Delete permanently",
    "zoneAssets": "Zone assets",
    "zoneAssetsHint": "Assets whose zone_id points to the selected zone.",
    "selectZone": "Select a zone",
    "selectZoneHint": "Pick a zone in the table to view its assigned assets.",
    "noZoneAssets": "No assets assigned to this zone",
    "zonesTabHint": "IEC 62443 zones and conduits with a documented Purdue level.",
    "createZone": "Create zone",
    "zoneName": "Zone name",
    "zoneKind": "Type",
    "zoneType.zone": "Zone",
    "zoneType.conduit": "Conduit",
    "purdueLevel": "Purdue level",
    "purdueNone": "No level",
    "description": "Description",
    "updated": "Updated",
    "noZones": "No zones or conduits declared",
    "noZonesHint": "Declare zones to assign OT assets and measure IEC 62443 coverage.",
    "editZone": "Edit zone",
    "deleteZone": "Delete zone",
    "deleteZoneBody": "The zone will be deleted. If it has assets, devices or child zones, you must choose a reassignment zone.",
    "reassignTo": "Reassign references to",
    "reassignNone": "No reassignment",
    "deleteZoneConfirm": "Delete zone",
    "gatewaysTabHint": "Edge gateways with store-and-forward, heartbeat and signed configuration.",
    "createToken": "Generate enrollment token",
    "gateway": "Gateway",
    "fingerprint": "Fingerprint",
    "version": "Version",
    "lastSeen": "Last heartbeat",
    "freshness": "Freshness",
    "fresh": "Fresh",
    "stale": "Stale",
    "unknownFreshness": "Unknown",
    "events": "Events",
    "configure": "Configure",
    "revoke": "Revoke",
    "rotateKey": "Rotate key",
    "noGateways": "No edge gateways registered",
    "noGatewaysHint": "Generate an enrollment token and deploy a gateway to ingest offline telemetry.",
    "offlineTitle": "Offline store-and-forward",
    "offlineBody":
      "Gateways buffer signed telemetry while offline and forward it once connectivity returns. Remote configuration is allow-listed: a gateway cannot change central policy, autonomy or permissions.",
    "enrollTitle": "One-time enrollment token",
    "enrollBody": "Copy the token now. It expires and can only be used once; it will not be shown again.",
    "expiresIn": "Expires in",
    "expiresAt": "Expires",
    "token": "Token",
    "gatewayId": "Gateway ID",
    "close": "Close",
    "rotateTitle": "New HMAC key",
    "rotateBody": "The key is shown only once. Update the gateway immediately: the previous key stops being valid.",
    "sharedKey": "Shared key",
    "keyId": "Key ID",
    "revokeTitle": "Revoke gateway",
    "revokeBody": "The gateway will stop authenticating heartbeats and telemetry. Historical events are retained and the action is audited.",
    "revokeConfirm": "Revoke gateway",
    "configTitle": "Operational configuration",
    "configHint": "Only keys on the server allow-list are accepted.",
    "bufferMax": "Max buffered events",
    "batchSize": "Batch size",
    "flushInterval": "Flush interval (s)",
    "heartbeatInterval": "Heartbeat interval (s)",
    "logLevel": "Log level",
    "collectors": "Collectors",
    "collectorsHint": "Comma separated identifiers.",
    "tags": "Tags",
    "storeForward": "Store and forward",
    "allowRemoteConfig": "Allow remote configuration",
    "gatewayEvents": "Gateway events",
    "gatewayEventsHint": "Received batches with signature validity and processing outcome.",
    "selectGateway": "Select a gateway",
    "selectGatewayHint": "Pick a gateway to inspect its telemetry batches.",
    "noEvents": "No telemetry batches received",
    "noEventsHint": "The gateway will send signed batches on its next sync cycle.",
    "sequence": "Sequence",
    "signature": "Signature",
    "valid": "Valid",
    "invalid": "Invalid",
    "accepted": "Accepted",
    "rejected": "Rejected",
    "processed": "Processed",
    "received": "Received",
    "reason": "Reason",
    "iotRegistry": "IoT protocol registry",
    "otRegistry": "OT protocol registry",
    "registryHint": "Protocols are grouped by family (IoT) or safety class (OT). All are read-only.",
    "readOnly": "Read-only",
    "support": "Support",
    "support.full": "Full",
    "support.observe": "Observe",
    "ports": "Ports",
    "family": "Family",
    "safetyClass": "Safety class",
    "deniedOps": "Denied operations",
    "securityNotes": "Security notes",
    "noProtocols": "Protocol registry is empty",
    "loadingProtocols": "Loading protocol registry…",
    "overviewHint": "Summary derived from /iot/summary and /ot/posture; no metrics are estimated.",
    "permissionReadOnly": "Your role cannot modify the inventory (asset:write).",
    "permissionEdge": "Your role cannot manage gateways (edge:write).",
    "permissionEdgeHint": "Reading gateways requires the edge:read permission. Ask an organization administrator for access.",
    "formCreateIot": "Register IoT device",
    "formEditIot": "Edit IoT device",
    "formCreateOt": "Register OT device",
    "formEditOt": "Edit OT device",
    "formZone": "Zone / conduit",
    "formGatewayConfig": "Gateway configuration",
    "formRequired": "Review the highlighted fields.",
    "saveIot": "Save IoT",
    "saveOt": "Save OT",
    "saveZone": "Save zone",
    "saveConfig": "Apply configuration",
    "createSuccess": "Device registered",
    "updateSuccess": "Changes saved",
    "deleteSuccess": "Device deleted",
    "zoneCreateSuccess": "Zone created",
    "zoneUpdateSuccess": "Zone updated",
    "zoneDeleteSuccess": "Zone deleted",
    "tokenSuccess": "Token generated",
    "rotateSuccess": "Key rotated",
    "revokeSuccess": "Gateway revoked",
    "configSuccess": "Configuration applied",
    "operationFailed": "The operation failed",
    "zoneRefsError": "The zone still has references. Provide a reassignment zone.",
    "all": "All",
    "deviceFallback": "Device",
    "lastUpdated": "Last assessment",
    "goAssets": "View assets",
    "editIn": "Inventory",
  },
};

const EMPTY_META = { page: 1, pages: 1, total: 0, page_size: 25, has_next: false };

function apiFieldErrors(error: unknown): Record<string, string> {
  if (!(error instanceof ApiError)) return {};
  const map: Record<string, string> = {};
  for (const detail of error.details) {
    if (detail?.field) map[detail.field] = detail.message;
  }
  return map;
}

function fieldError(map: Record<string, string>, name: string): string | undefined {
  return map[name] ?? map[`body.${name}`] ?? map[`body.${name}.${name}`];
}

function baselineNumber(baseline: Record<string, unknown>, key: string): number {
  const value = baseline[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function freshness(lastSeen: string | null): "fresh" | "stale" | "unknown" {
  if (!lastSeen) return "unknown";
  const diff = Date.now() - new Date(lastSeen).getTime();
  if (Number.isNaN(diff)) return "unknown";
  return diff > 15 * 60_000 ? "stale" : "fresh";
}

/* ------------------------------------------------------------------ forms */

interface FormShellProps {
  open: boolean;
  title: string;
  onClose: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  loading: boolean;
  error: string | null;
  submitLabel: string;
  cancelLabel: string;
  children: ReactNode;
  submitTestId: string;
  size?: "md" | "lg";
}

function FormShell({ open, title, onClose, onSubmit, loading, error, submitLabel, cancelLabel, children, submitTestId, size }: FormShellProps) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      size={size ?? "lg"}
      footer={
        <>
          <Button type="button" onClick={onClose} disabled={loading}>{cancelLabel}</Button>
          <Button type="submit" form="entity-form" variant="primary" loading={loading} data-testid={submitTestId}>
            {submitLabel}
          </Button>
        </>
      }
    >
      <form id="entity-form" onSubmit={onSubmit} className="stack">
        {error ? <ErrorBanner compact message={error} /> : null}
        {children}
      </form>
    </Modal>
  );
}

function IoTFormModal({
  initial,
  zones,
  gateways,
  protocolOptions,
  loading,
  error,
  fieldErrors,
  onClose,
  onSubmit,
}: {
  initial: IoTDevice | null;
  zones: Zone[];
  gateways: EdgeGateway[];
  protocolOptions: string[];
  loading: boolean;
  error: string | null;
  fieldErrors: Record<string, string>;
  onClose: () => void;
  onSubmit: (payload: Record<string, unknown>) => void;
}) {
  const c = usePageCopy(copy);
  const [name, setName] = useState(initial?.asset.name ?? "");
  const [assetKey, setAssetKey] = useState(initial?.asset.asset_key ?? "");
  const [criticality, setCriticality] = useState(String(initial?.asset.criticality ?? 3));
  const [ips, setIps] = useState("");
  const [vendor, setVendor] = useState("");
  const [model, setModel] = useState("");
  const [firmware, setFirmware] = useState(initial?.firmware_version ?? "");
  const [connectivity, setConnectivity] = useState(initial?.connectivity ?? "");
  const [zoneId, setZoneId] = useState(initial?.asset.zone_id ?? "");
  const [gatewayId, setGatewayId] = useState(initial?.edge_gateway_id ?? "");
  const [protocols, setProtocols] = useState<string[]>(initial?.protocols ?? []);

  const toggleProtocol = (protocol: string) => {
    setProtocols((current) => (current.includes(protocol) ? current.filter((item) => item !== protocol) : [...current, protocol]));
  };

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const base: Record<string, unknown> = {
      name: name.trim(),
      criticality: Number(criticality),
      firmware: firmware.trim() || null,
      firmware_version: firmware.trim() || null,
      connectivity: connectivity.trim() || null,
      zone_id: zoneId || null,
      edge_gateway_id: gatewayId || null,
      protocols,
    };
    if (initial) {
      onSubmit(base);
    } else {
      onSubmit({
        ...base,
        asset_key: assetKey.trim(),
        kind: "iot",
        ip_addresses: splitTokens(ips),
        vendor: vendor.trim() || null,
        model: model.trim() || null,
        discovery_source: "manual",
      });
    }
  };

  return (
    <FormShell
      open
      title={initial ? c("formEditIot") : c("formCreateIot")}
      onClose={onClose}
      onSubmit={submit}
      loading={loading}
      error={error}
      submitLabel={c("saveIot")}
      cancelLabel={c("cancel")}
      submitTestId="submit-iot"
    >
      <div className="form-grid" data-testid="iot-form">
        <Field label={c("name")} required htmlFor="iot-name" error={fieldError(fieldErrors, "name")}>
          <Input id="iot-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={240} />
        </Field>
        <Field label={c("assetKey")} required htmlFor="iot-key" hint={c("assetKeyHint")} error={fieldError(fieldErrors, "asset_key")}>
          <Input id="iot-key" value={assetKey} onChange={(event) => setAssetKey(event.target.value)} required disabled={Boolean(initial)} maxLength={200} pattern="^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$" />
        </Field>
        <Field label={c("criticality")} htmlFor="iot-criticality" error={fieldError(fieldErrors, "criticality")}>
          <Select id="iot-criticality" value={criticality} onChange={(event) => setCriticality(event.target.value)}>
            {[1, 2, 3, 4, 5].map((level) => <option value={level} key={level}>{level}</option>)}
          </Select>
        </Field>
        <Field label={c("connectivity")} htmlFor="iot-connectivity" hint={c("connectivityHint")} error={fieldError(fieldErrors, "connectivity")}>
          <Input id="iot-connectivity" value={connectivity} onChange={(event) => setConnectivity(event.target.value)} maxLength={80} />
        </Field>
        {!initial ? (
          <>
            <Field label={c("ipAddresses")} htmlFor="iot-ips" hint={c("ipHint")} error={fieldError(fieldErrors, "ip_addresses")}>
              <Input id="iot-ips" value={ips} onChange={(event) => setIps(event.target.value)} placeholder="10.0.4.11, 10.0.4.12" />
            </Field>
            <Field label={c("firmware")} htmlFor="iot-firmware" error={fieldError(fieldErrors, "firmware_version")}>
              <Input id="iot-firmware" value={firmware} onChange={(event) => setFirmware(event.target.value)} maxLength={120} />
            </Field>
            <Field label={c("vendor")} htmlFor="iot-vendor" error={fieldError(fieldErrors, "vendor")}>
              <Input id="iot-vendor" value={vendor} onChange={(event) => setVendor(event.target.value)} maxLength={160} />
            </Field>
            <Field label={c("model")} htmlFor="iot-model" error={fieldError(fieldErrors, "model")}>
              <Input id="iot-model" value={model} onChange={(event) => setModel(event.target.value)} maxLength={160} />
            </Field>
          </>
        ) : (
          <Field label={c("firmware")} htmlFor="iot-firmware" error={fieldError(fieldErrors, "firmware_version")}>
            <Input id="iot-firmware" value={firmware} onChange={(event) => setFirmware(event.target.value)} maxLength={120} />
          </Field>
        )}
        <Field label={c("zone")} htmlFor="iot-zone" error={fieldError(fieldErrors, "zone_id")}>
          <Select id="iot-zone" value={zoneId} onChange={(event) => setZoneId(event.target.value)}>
            <option value="">{c("zoneNone")}</option>
            {zones.map((zone) => <option value={zone.id} key={zone.id}>{zone.name}</option>)}
          </Select>
        </Field>
        <Field label={c("edgeGateway")} htmlFor="iot-gateway" error={fieldError(fieldErrors, "edge_gateway_id")}>
          <Select id="iot-gateway" value={gatewayId} onChange={(event) => setGatewayId(event.target.value)}>
            <option value="">{c("noGateway")}</option>
            {gateways.map((gateway) => <option value={gateway.id} key={gateway.id}>{gateway.name}</option>)}
          </Select>
        </Field>
        <div className="span-2">
          <Field label={c("protocols")} hint={c("protocolsHint")} error={fieldError(fieldErrors, "protocols")}>
            {protocolOptions.length === 0 ? (
              <span className="dim" style={{ fontSize: 11.5 }}>{c("loadingProtocols")}</span>
            ) : (
              <div className="chip-row" style={{ gap: 10 }}>
                {protocolOptions.map((protocol) => (
                  <label className="checkbox" key={protocol}>
                    <input
                      type="checkbox"
                      checked={protocols.includes(protocol)}
                      onChange={() => toggleProtocol(protocol)}
                    />
                    {protocol}
                  </label>
                ))}
              </div>
            )}
          </Field>
        </div>
      </div>
    </FormShell>
  );
}

function OTFormModal({
  initial,
  zones,
  protocolOptions,
  loading,
  error,
  fieldErrors,
  onClose,
  onSubmit,
}: {
  initial: OTDevice | null;
  zones: Zone[];
  protocolOptions: string[];
  loading: boolean;
  error: string | null;
  fieldErrors: Record<string, string>;
  onClose: () => void;
  onSubmit: (payload: Record<string, unknown>) => void;
}) {
  const c = usePageCopy(copy);
  const [name, setName] = useState(initial?.asset.name ?? "");
  const [assetKey, setAssetKey] = useState(initial?.asset.asset_key ?? "");
  const [criticality, setCriticality] = useState(String(initial?.asset.criticality ?? 3));
  const [ips, setIps] = useState("");
  const [vendor, setVendor] = useState("");
  const [model, setModel] = useState("");
  const [controllerModel, setControllerModel] = useState(initial?.controller_model ?? "");
  const [firmware, setFirmware] = useState(initial?.firmware_version ?? "");
  const [zoneId, setZoneId] = useState(initial?.zone_id ?? initial?.asset.zone_id ?? "");
  const [safetyCritical, setSafetyCritical] = useState(initial?.safety_critical ?? true);
  const [protocols, setProtocols] = useState<string[]>(initial?.protocols ?? []);

  const toggleProtocol = (protocol: string) => {
    setProtocols((current) => (current.includes(protocol) ? current.filter((item) => item !== protocol) : [...current, protocol]));
  };

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (initial) {
      onSubmit({
        zone_id: zoneId || null,
        protocols,
        safety_critical: safetyCritical,
        controller_model: controllerModel.trim() || null,
        firmware_version: firmware.trim() || null,
      });
      return;
    }
    onSubmit({
      name: name.trim(),
      asset_key: assetKey.trim(),
      kind: "ot",
      criticality: Number(criticality),
      ip_addresses: splitTokens(ips),
      vendor: vendor.trim() || null,
      model: model.trim() || null,
      zone_id: zoneId || null,
      protocols,
      safety_critical: safetyCritical,
      passive_only: true,
      controller_model: controllerModel.trim() || null,
      firmware_version: firmware.trim() || null,
      discovery_source: "manual",
    });
  };

  return (
    <FormShell
      open
      title={initial ? c("formEditOt") : c("formCreateOt")}
      onClose={onClose}
      onSubmit={submit}
      loading={loading}
      error={error}
      submitLabel={c("saveOt")}
      cancelLabel={c("cancel")}
      submitTestId="submit-ot"
    >
      <div className="notice notice-warning" style={{ marginBottom: 2 }}>
        <Lock size={13} style={{ flex: "0 0 auto" }} aria-hidden="true" />
        <span>{c("passiveLocked")}</span>
      </div>
      <div className="form-grid" data-testid="ot-form">
        <Field label={c("name")} required htmlFor="ot-name" error={fieldError(fieldErrors, "name")}>
          <Input id="ot-name" value={name} onChange={(event) => setName(event.target.value)} required disabled={Boolean(initial)} maxLength={240} />
        </Field>
        <Field label={c("assetKey")} required htmlFor="ot-key" hint={c("assetKeyHint")} error={fieldError(fieldErrors, "asset_key")}>
          <Input id="ot-key" value={assetKey} onChange={(event) => setAssetKey(event.target.value)} required disabled={Boolean(initial)} maxLength={200} pattern="^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$" />
        </Field>
        <Field label={c("criticality")} htmlFor="ot-criticality" error={fieldError(fieldErrors, "criticality")}>
          <Select id="ot-criticality" value={criticality} onChange={(event) => setCriticality(event.target.value)} disabled={Boolean(initial)}>
            {[1, 2, 3, 4, 5].map((level) => <option value={level} key={level}>{level}</option>)}
          </Select>
        </Field>
        <Field label={c("zone")} htmlFor="ot-zone" error={fieldError(fieldErrors, "zone_id")}>
          <Select id="ot-zone" value={zoneId} onChange={(event) => setZoneId(event.target.value)}>
            <option value="">{c("zoneNone")}</option>
            {zones.map((zone) => <option value={zone.id} key={zone.id}>{zone.name}</option>)}
          </Select>
        </Field>
        {!initial ? (
          <>
            <Field label={c("ipAddresses")} htmlFor="ot-ips" hint={c("ipHint")} error={fieldError(fieldErrors, "ip_addresses")}>
              <Input id="ot-ips" value={ips} onChange={(event) => setIps(event.target.value)} placeholder="192.168.10.5" />
            </Field>
            <Field label={c("firmware")} htmlFor="ot-firmware" error={fieldError(fieldErrors, "firmware_version")}>
              <Input id="ot-firmware" value={firmware} onChange={(event) => setFirmware(event.target.value)} maxLength={120} />
            </Field>
            <Field label={c("vendor")} htmlFor="ot-vendor" error={fieldError(fieldErrors, "vendor")}>
              <Input id="ot-vendor" value={vendor} onChange={(event) => setVendor(event.target.value)} maxLength={160} />
            </Field>
            <Field label={c("model")} htmlFor="ot-model" error={fieldError(fieldErrors, "model")}>
              <Input id="ot-model" value={model} onChange={(event) => setModel(event.target.value)} maxLength={160} />
            </Field>
          </>
        ) : (
          <Field label={c("firmware")} htmlFor="ot-firmware" error={fieldError(fieldErrors, "firmware_version")}>
            <Input id="ot-firmware" value={firmware} onChange={(event) => setFirmware(event.target.value)} maxLength={120} />
          </Field>
        )}
        <Field label={c("controllerModel")} htmlFor="ot-controller" error={fieldError(fieldErrors, "controller_model")}>
          <Input id="ot-controller" value={controllerModel} onChange={(event) => setControllerModel(event.target.value)} maxLength={160} />
        </Field>
        <div className="span-2">
          <Field label={c("protocols")} hint={c("protocolsHint")} error={fieldError(fieldErrors, "protocols")}>
            {protocolOptions.length === 0 ? (
              <span className="dim" style={{ fontSize: 11.5 }}>{c("loadingProtocols")}</span>
            ) : (
              <div className="chip-row" style={{ gap: 10 }}>
                {protocolOptions.map((protocol) => (
                  <label className="checkbox" key={protocol}>
                    <input
                      type="checkbox"
                      checked={protocols.includes(protocol)}
                      onChange={() => toggleProtocol(protocol)}
                    />
                    {protocol}
                  </label>
                ))}
              </div>
            )}
          </Field>
        </div>
        <div className="span-2">
          <label className="checkbox">
            <input type="checkbox" checked={safetyCritical} onChange={(event) => setSafetyCritical(event.target.checked)} />
            {c("safetyCriticalFlag")}
          </label>
          <div className="dim" style={{ fontSize: 10.5, marginTop: 4 }}>{c("passiveOnly")}: {c("yes")} · {c("passiveLocked")}</div>
        </div>
      </div>
    </FormShell>
  );
}

function ZoneFormModal({
  initial,
  loading,
  error,
  fieldErrors,
  onClose,
  onSubmit,
}: {
  initial: Zone | null;
  loading: boolean;
  error: string | null;
  fieldErrors: Record<string, string>;
  onClose: () => void;
  onSubmit: (payload: Record<string, unknown>) => void;
}) {
  const c = usePageCopy(copy);
  const [name, setName] = useState(initial?.name ?? "");
  const [kind, setKind] = useState(initial?.kind ?? "zone");
  const [purdue, setPurdue] = useState(initial?.purdue_level === null || initial?.purdue_level === undefined ? "" : String(initial.purdue_level));
  const [description, setDescription] = useState(initial?.description ?? "");

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const payload: Record<string, unknown> = {
      name: name.trim(),
      kind,
      purdue_level: purdue === "" ? null : Number(purdue),
      description: description.trim() || null,
    };
    onSubmit(payload);
  };

  return (
    <FormShell
      open
      title={c("formZone")}
      onClose={onClose}
      onSubmit={submit}
      loading={loading}
      error={error}
      submitLabel={c("saveZone")}
      cancelLabel={c("cancel")}
      submitTestId="submit-zone"
    >
      <div className="form-grid" data-testid="zone-form">
        <Field label={c("zoneName")} required htmlFor="zone-name" error={fieldError(fieldErrors, "name")}>
          <Input id="zone-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={120} />
        </Field>
        <Field label={c("zoneKind")} htmlFor="zone-kind" error={fieldError(fieldErrors, "kind")}>
          <Select id="zone-kind" value={kind} onChange={(event) => setKind(event.target.value)}>
            <option value="zone">{c("zoneType.zone")}</option>
            <option value="conduit">{c("zoneType.conduit")}</option>
          </Select>
        </Field>
        <Field label={c("purdueLevel")} htmlFor="zone-purdue" error={fieldError(fieldErrors, "purdue_level")}>
          <Select id="zone-purdue" value={purdue} onChange={(event) => setPurdue(event.target.value)}>
            <option value="">{c("purdueNone")}</option>
            {[0, 1, 2, 3, 4, 5].map((level) => <option value={level} key={level}>{level}</option>)}
          </Select>
        </Field>
        <div className="span-2">
          <Field label={c("description")} htmlFor="zone-description" error={fieldError(fieldErrors, "description")}>
            <Textarea id="zone-description" value={description} onChange={(event) => setDescription(event.target.value)} maxLength={2000} />
          </Field>
        </div>
      </div>
    </FormShell>
  );
}

function GatewayConfigModal({
  gateway,
  loading,
  error,
  fieldErrors,
  onClose,
  onSubmit,
}: {
  gateway: EdgeGateway;
  loading: boolean;
  error: string | null;
  fieldErrors: Record<string, string>;
  onClose: () => void;
  onSubmit: (payload: Record<string, unknown>) => void;
}) {
  const c = usePageCopy(copy);
  const config = gateway.config ?? {};
  const asString = (value: unknown) => (typeof value === "number" || typeof value === "string" ? String(value) : "");
  const asBool = (value: unknown, fallback: boolean) => (typeof value === "boolean" ? value : fallback);
  const asList = (value: unknown) => (Array.isArray(value) ? value.filter((item): item is string => typeof item === "string").join(", ") : "");

  const [bufferMax, setBufferMax] = useState(asString(config.buffer_max_events));
  const [batchSize, setBatchSize] = useState(asString(config.batch_size));
  const [flushInterval, setFlushInterval] = useState(asString(config.flush_interval_seconds));
  const [heartbeatInterval, setHeartbeatInterval] = useState(asString(config.heartbeat_interval_seconds));
  const [logLevel, setLogLevel] = useState(typeof config.log_level === "string" ? config.log_level : "");
  const [collectors, setCollectors] = useState(asList(config.collectors));
  const [tags, setTags] = useState(asList(config.tags));
  const [storeForward, setStoreForward] = useState(asBool(config.store_forward, true));
  const [allowRemote, setAllowRemote] = useState(asBool(config.allow_remote_config, false));

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const payload: Record<string, unknown> = {
      store_forward: storeForward,
      allow_remote_config: allowRemote,
    };
    if (bufferMax) payload.buffer_max_events = Number(bufferMax);
    if (batchSize) payload.batch_size = Number(batchSize);
    if (flushInterval) payload.flush_interval_seconds = Number(flushInterval);
    if (heartbeatInterval) payload.heartbeat_interval_seconds = Number(heartbeatInterval);
    if (logLevel) payload.log_level = logLevel;
    const collectorList = splitTokens(collectors);
    payload.collectors = collectorList;
    const tagList = splitTokens(tags);
    payload.tags = tagList;
    onSubmit(payload);
  };

  return (
    <FormShell
      open
      title={`${c("formGatewayConfig")} · ${gateway.name}`}
      onClose={onClose}
      onSubmit={submit}
      loading={loading}
      error={error}
      submitLabel={c("saveConfig")}
      cancelLabel={c("cancel")}
      submitTestId="submit-gateway-config"
    >
      <div className="notice" style={{ marginBottom: 2 }}>
        <ShieldCheck size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} aria-hidden="true" />
        <span>{c("configHint")}</span>
      </div>
      <div className="form-grid" data-testid="gateway-config-form">
        <Field label={c("bufferMax")} htmlFor="gw-buffer" error={fieldError(fieldErrors, "buffer_max_events")}>
          <Input id="gw-buffer" type="number" min={100} max={1_000_000} value={bufferMax} onChange={(event) => setBufferMax(event.target.value)} />
        </Field>
        <Field label={c("batchSize")} htmlFor="gw-batch" error={fieldError(fieldErrors, "batch_size")}>
          <Input id="gw-batch" type="number" min={1} max={1000} value={batchSize} onChange={(event) => setBatchSize(event.target.value)} />
        </Field>
        <Field label={c("flushInterval")} htmlFor="gw-flush" error={fieldError(fieldErrors, "flush_interval_seconds")}>
          <Input id="gw-flush" type="number" min={5} max={3600} value={flushInterval} onChange={(event) => setFlushInterval(event.target.value)} />
        </Field>
        <Field label={c("heartbeatInterval")} htmlFor="gw-heartbeat" error={fieldError(fieldErrors, "heartbeat_interval_seconds")}>
          <Input id="gw-heartbeat" type="number" min={15} max={3600} value={heartbeatInterval} onChange={(event) => setHeartbeatInterval(event.target.value)} />
        </Field>
        <Field label={c("logLevel")} htmlFor="gw-log" error={fieldError(fieldErrors, "log_level")}>
          <Select id="gw-log" value={logLevel} onChange={(event) => setLogLevel(event.target.value)}>
            <option value="">—</option>
            {["debug", "info", "warning", "error"].map((level) => <option value={level} key={level}>{level}</option>)}
          </Select>
        </Field>
        <Field label={c("collectors")} htmlFor="gw-collectors" hint={c("collectorsHint")} error={fieldError(fieldErrors, "collectors")}>
          <Input id="gw-collectors" value={collectors} onChange={(event) => setCollectors(event.target.value)} placeholder="netflow, suricata" />
        </Field>
        <div className="span-2">
          <Field label={c("tags")} htmlFor="gw-tags" error={fieldError(fieldErrors, "tags")}>
            <Input id="gw-tags" value={tags} onChange={(event) => setTags(event.target.value)} placeholder="plant-a, dmz" />
          </Field>
        </div>
        <label className="checkbox">
          <input type="checkbox" checked={storeForward} onChange={(event) => setStoreForward(event.target.checked)} />
          {c("storeForward")}
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={allowRemote} onChange={(event) => setAllowRemote(event.target.checked)} />
          {c("allowRemoteConfig")}
        </label>
      </div>
    </FormShell>
  );
}

/* -------------------------------------------------------------------- page */

export function IotOtPage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(copy);
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();

  const canWriteAssets = can("asset:write");
  const canReadEdge = can("edge:read");
  const canWriteEdge = can("edge:write");

  const [tab, setTab] = useState<TabKey>("overview");

  const [iotQ, setIotQ] = useState("");
  const [iotPage, setIotPage] = useState(1);
  const [iotConnectivity, setIotConnectivity] = useState("");
  const [iotProtocol, setIotProtocol] = useState("");
  const [iotEditing, setIotEditing] = useState<IoTDevice | null>(null);
  const [iotCreateOpen, setIotCreateOpen] = useState(false);
  const [deletingIot, setDeletingIot] = useState<IoTDevice | null>(null);

  const [otQ, setOtQ] = useState("");
  const [otPage, setOtPage] = useState(1);
  const [otZone, setOtZone] = useState("");
  const [otSafety, setOtSafety] = useState("");
  const [otEditing, setOtEditing] = useState<OTDevice | null>(null);
  const [otCreateOpen, setOtCreateOpen] = useState(false);

  const [zoneKind, setZoneKind] = useState("");
  const [zoneQ, setZoneQ] = useState("");
  const [zonePage, setZonePage] = useState(1);
  const [selectedZoneId, setSelectedZoneId] = useState<string | null>(null);
  const [zoneAssetsPage, setZoneAssetsPage] = useState(1);
  const [zoneEditing, setZoneEditing] = useState<Zone | null>(null);
  const [zoneCreateOpen, setZoneCreateOpen] = useState(false);
  const [deletingZone, setDeletingZone] = useState<Zone | null>(null);
  const [reassignTo, setReassignTo] = useState("");

  const [gatewayQ, setGatewayQ] = useState("");
  const [gatewayStatus, setGatewayStatus] = useState("");
  const [gatewayPage, setGatewayPage] = useState(1);
  const [selectedGatewayId, setSelectedGatewayId] = useState<string | null>(null);
  const [gatewayEventsPage, setGatewayEventsPage] = useState(1);
  const [configuringGateway, setConfiguringGateway] = useState<EdgeGateway | null>(null);
  const [revokingGateway, setRevokingGateway] = useState<EdgeGateway | null>(null);
  const [rotation, setRotation] = useState<RotateKeyResult | null>(null);
  const [enrollment, setEnrollment] = useState<EnrollmentToken | null>(null);

  const iotSummaryQuery = useQuery({
    queryKey: ["iot", "summary"],
    queryFn: () => api.get<IoTSummary>("/iot/summary"),
  });
  const otPostureQuery = useQuery({
    queryKey: ["ot", "posture"],
    queryFn: () => api.get<OTPosture>("/ot/posture"),
  });
  const iotProtocolsQuery = useQuery({
    queryKey: ["iot", "protocols"],
    queryFn: () => api.get<IoTProtocol[]>("/iot/protocols"),
  });
  const otProtocolsQuery = useQuery({
    queryKey: ["ot", "protocols"],
    queryFn: () => api.get<OTProtocol[]>("/ot/protocols"),
  });

  const iotDevicesQuery = useQuery({
    queryKey: ["iot", "devices", { iotQ, iotPage, iotConnectivity, iotProtocol }],
    queryFn: () =>
      api.get<Page<IoTDevice>>("/iot/devices", {
        q: iotQ,
        page: iotPage,
        page_size: 25,
        connectivity: iotConnectivity,
        protocol: iotProtocol,
      }),
  });

  const otDevicesQuery = useQuery({
    queryKey: ["ot", "devices", { otQ, otPage, otZone, otSafety }],
    queryFn: () =>
      api.get<Page<OTDevice>>("/ot/devices", {
        q: otQ,
        page: otPage,
        page_size: 25,
        zone_id: otZone,
        safety_critical: otSafety === "" ? undefined : otSafety === "true",
      }),
  });

  const zonesQuery = useQuery({
    queryKey: ["assets", "zones", { zoneKind, zoneQ, zonePage }],
    queryFn: () => api.get<Page<Zone>>("/assets/zones", { kind: zoneKind, q: zoneQ, page: zonePage, page_size: 200 }),
  });

  const zoneAssetsQuery = useQuery({
    queryKey: ["assets", "zone", selectedZoneId, zoneAssetsPage],
    queryFn: () => api.get<Page<AssetRow>>(`/assets/zones/${selectedZoneId}/assets`, { page: zoneAssetsPage, page_size: 25 }),
    enabled: Boolean(selectedZoneId),
  });

  const gatewaysQuery = useQuery({
    queryKey: ["edge", "gateways", { gatewayQ, gatewayStatus, gatewayPage }],
    queryFn: () =>
      api.get<Page<EdgeGateway>>("/edge/gateways", {
        q: gatewayQ,
        status: gatewayStatus,
        page: gatewayPage,
        page_size: 25,
      }),
    enabled: canReadEdge,
  });

  const gatewayEventsQuery = useQuery({
    queryKey: ["edge", "events", selectedGatewayId, gatewayEventsPage],
    queryFn: () => api.get<Page<GatewayEvent>>(`/edge/gateways/${selectedGatewayId}/events`, { page: gatewayEventsPage, page_size: 25 }),
    enabled: canReadEdge && Boolean(selectedGatewayId),
  });

  const zones = zonesQuery.data?.items ?? [];
  const gateways = gatewaysQuery.data?.items ?? [];
  const iotProtocolOptions = (iotProtocolsQuery.data ?? []).map((item) => item.name);
  const otProtocolOptions = (otProtocolsQuery.data ?? []).map((item) => item.name);
  const selectedGateway = gateways.find((item) => item.id === selectedGatewayId) ?? null;
  const selectedZone = zones.find((item) => item.id === selectedZoneId) ?? null;

  const invalidateInventory = () => {
    void queryClient.invalidateQueries({ queryKey: ["iot"] });
    void queryClient.invalidateQueries({ queryKey: ["ot"] });
    void queryClient.invalidateQueries({ queryKey: ["assets", "zones"] });
    void queryClient.invalidateQueries({ queryKey: ["assets", "zone"] });
  };

  const invalidateGateways = () => {
    void queryClient.invalidateQueries({ queryKey: ["edge", "gateways"] });
    void queryClient.invalidateQueries({ queryKey: ["edge", "events"] });
  };

  const iotMutation = useMutation({
    mutationFn: ({ payload, editing }: { payload: Record<string, unknown>; editing: IoTDevice | null }) =>
      editing ? api.patch<IoTDevice>(`/iot/devices/${editing.asset_id}`, payload) : api.post<IoTDevice>("/iot/devices", payload),
    onSuccess: (_result, variables) => {
      invalidateInventory();
      toast.push(variables.editing ? c("updateSuccess") : c("createSuccess"), "success");
      setIotEditing(null);
      setIotCreateOpen(false);
    },
    onError: (error) => toast.push(`${c("operationFailed")}: ${errorMessage(error)}`, "error"),
  });

  const iotDeleteMutation = useMutation({
    mutationFn: (device: IoTDevice) => api.delete(`/iot/devices/${device.asset_id}`),
    onSuccess: () => {
      invalidateInventory();
      toast.push(c("deleteSuccess"), "success");
      setDeletingIot(null);
    },
    onError: (error) => toast.push(`${c("operationFailed")}: ${errorMessage(error)}`, "error"),
  });

  const otMutation = useMutation({
    mutationFn: ({ payload, editing }: { payload: Record<string, unknown>; editing: OTDevice | null }) =>
      editing ? api.patch<OTDevice>(`/ot/devices/${editing.asset_id}`, payload) : api.post<OTDevice>("/ot/devices", payload),
    onSuccess: (_result, variables) => {
      invalidateInventory();
      toast.push(variables.editing ? c("updateSuccess") : c("createSuccess"), "success");
      setOtEditing(null);
      setOtCreateOpen(false);
    },
    onError: (error) => toast.push(`${c("operationFailed")}: ${errorMessage(error)}`, "error"),
  });

  const zoneMutation = useMutation({
    mutationFn: ({ payload, editing }: { payload: Record<string, unknown>; editing: Zone | null }) =>
      editing ? api.patch<Zone>(`/assets/zones/${editing.id}`, payload) : api.post<Zone>("/assets/zones", payload),
    onSuccess: (_result, variables) => {
      invalidateInventory();
      toast.push(variables.editing ? c("zoneUpdateSuccess") : c("zoneCreateSuccess"), "success");
      setZoneEditing(null);
      setZoneCreateOpen(false);
    },
    onError: (error) => toast.push(`${c("operationFailed")}: ${errorMessage(error)}`, "error"),
  });

  const zoneDeleteMutation = useMutation({
    mutationFn: ({ zone, reassign }: { zone: Zone; reassign: string }) =>
      api.delete(withQuery(`/assets/zones/${zone.id}`, { reassign_to: reassign || undefined })),
    onSuccess: () => {
      invalidateInventory();
      toast.push(c("zoneDeleteSuccess"), "success");
      setDeletingZone(null);
      setReassignTo("");
      if (deletingZone && selectedZoneId === deletingZone.id) setSelectedZoneId(null);
    },
    onError: (error) => toast.push(`${c("operationFailed")}: ${errorMessage(error)}`, "error"),
  });

  const tokenMutation = useMutation({
    mutationFn: () => api.post<EnrollmentToken>("/edge/gateways/enroll-token"),
    onSuccess: (result) => {
      setEnrollment(result);
      invalidateGateways();
      toast.push(c("tokenSuccess"), "success");
    },
    onError: (error) => toast.push(`${c("operationFailed")}: ${errorMessage(error)}`, "error"),
  });

  const rotateMutation = useMutation({
    mutationFn: (gateway: EdgeGateway) => api.post<RotateKeyResult>(`/edge/gateways/${gateway.id}/rotate-key`),
    onSuccess: (result) => {
      setRotation(result);
      invalidateGateways();
      toast.push(c("rotateSuccess"), "success");
    },
    onError: (error) => toast.push(`${c("operationFailed")}: ${errorMessage(error)}`, "error"),
  });

  const revokeMutation = useMutation({
    mutationFn: (gateway: EdgeGateway) => api.post<EdgeGateway>(`/edge/gateways/${gateway.id}/revoke`),
    onSuccess: () => {
      invalidateGateways();
      toast.push(c("revokeSuccess"), "success");
      setRevokingGateway(null);
    },
    onError: (error) => toast.push(`${c("operationFailed")}: ${errorMessage(error)}`, "error"),
  });

  const configMutation = useMutation({
    mutationFn: ({ gateway, payload }: { gateway: EdgeGateway; payload: Record<string, unknown> }) =>
      api.patch<EdgeGateway>(`/edge/gateways/${gateway.id}`, payload),
    onSuccess: () => {
      invalidateGateways();
      toast.push(c("configSuccess"), "success");
      setConfiguringGateway(null);
    },
    onError: (error) => toast.push(`${c("operationFailed")}: ${errorMessage(error)}`, "error"),
  });

  if (iotSummaryQuery.isLoading || otPostureQuery.isLoading || zonesQuery.isLoading || gatewaysQuery.isLoading) {
    return <PageSkeleton />;
  }
  if (iotSummaryQuery.isError || otPostureQuery.isError || !iotSummaryQuery.data || !otPostureQuery.data) {
    return (
      <div data-testid="page-iot-ot">
        <PageHeader eyebrow={c("eyebrow")} title={c("title")} subtitle={c("subtitle")} />
        <ErrorBanner
          message={t("errors.retryHint")}
          onRetry={() => {
            void iotSummaryQuery.refetch();
            void otPostureQuery.refetch();
          }}
        />
      </div>
    );
  }

  const iotSummary = iotSummaryQuery.data;
  const otPosture = otPostureQuery.data;
  const zoneMeta = zonesQuery.data?.meta ?? EMPTY_META;
  const gatewayMeta = gatewaysQuery.data?.meta ?? EMPTY_META;

  const tabs: { key: TabKey; label: string; count?: number }[] = [
    { key: "overview", label: c("tab.overview") },
    { key: "iot", label: c("tab.iot"), count: iotSummary.total_devices },
    { key: "ot", label: c("tab.ot"), count: otPosture.ot_devices_total },
    { key: "zones", label: c("tab.zones"), count: zoneMeta.total },
    { key: "gateways", label: c("tab.gateways"), count: gatewayMeta.total },
    { key: "protocols", label: c("tab.protocols") },
  ];

  /* --------------------------------------------------------- columns */

  const iotColumns: Column<IoTDevice>[] = [
    {
      key: "name",
      header: c("name"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.asset.name}</div>
          <div className="mono" style={{ fontSize: 10, color: "var(--dim)", marginTop: 2 }}>{row.asset.asset_key}</div>
        </div>
      ),
    },
    {
      key: "connectivity",
      header: c("connectivity"),
      width: "130px",
      render: (row) => (row.connectivity ? <span className="tag">{row.connectivity}</span> : <span className="dim">—</span>),
    },
    {
      key: "protocols",
      header: c("protocols"),
      width: "200px",
      render: (row) => (
        <div className="chip-row">
          {row.protocols.length ? row.protocols.slice(0, 3).map((protocol) => <span className="tag" key={protocol}>{protocol}</span>) : <span className="dim">—</span>}
          {row.protocols.length > 3 ? <span className="tag">+{row.protocols.length - 3}</span> : null}
        </div>
      ),
    },
    {
      key: "risk",
      header: c("riskFlags"),
      width: "180px",
      render: (row) =>
        row.risk_flags.length ? (
          <div className="chip-row">
            {row.risk_flags.slice(0, 2).map((flag) => <span className="tag" key={flag} style={{ color: "var(--warning)" }}>{humanize(flag)}</span>)}
            {row.risk_flags.length > 2 ? <span className="tag">+{row.risk_flags.length - 2}</span> : null}
          </div>
        ) : (
          <span className="dim">—</span>
        ),
    },
    {
      key: "telemetry",
      header: c("lastTelemetry"),
      width: "140px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)" }}>
          {row.last_telemetry_at ? relativeTime(row.last_telemetry_at, lang) : c("never")}
        </span>
      ),
    },
    {
      key: "actions",
      header: c("actions"),
      width: "150px",
      render: (row) =>
        canWriteAssets ? (
          <div className="row" style={{ gap: 6 }}>
            <Button size="sm" variant="ghost" icon={Pencil} onClick={() => setIotEditing(row)} aria-label={c("edit")} />
            <Button size="sm" variant="ghost" icon={Trash2} onClick={() => setDeletingIot(row)} aria-label={c("delete")} />
          </div>
        ) : (
          <span className="dim" style={{ fontSize: 10.5 }}>{c("permissionReadOnly")}</span>
        ),
    },
  ];

  const otColumns: Column<OTDevice>[] = [
    {
      key: "name",
      header: c("name"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.asset.name}</div>
          <div className="mono" style={{ fontSize: 10, color: "var(--dim)", marginTop: 2 }}>{row.asset.asset_key}</div>
        </div>
      ),
    },
    {
      key: "zone",
      header: c("zone"),
      width: "160px",
      render: (row) =>
        row.zone_name ? (
          <div>
            <div style={{ color: "var(--text-secondary)" }}>{row.zone_name}</div>
            <div className="cell-sub">{c("purdue")}: {zones.find((zone) => zone.id === row.zone_id)?.purdue_level ?? "—"}</div>
          </div>
        ) : (
          <Badge tone="warning">{c("unzoned")}</Badge>
        ),
    },
    {
      key: "protocols",
      header: c("protocols"),
      width: "190px",
      render: (row) => (
        <div className="chip-row">
          {row.protocols.length ? row.protocols.slice(0, 3).map((protocol) => <span className="tag" key={protocol}>{protocol}</span>) : <span className="dim">—</span>}
          {row.protocols.length > 3 ? <span className="tag">+{row.protocols.length - 3}</span> : null}
        </div>
      ),
    },
    {
      key: "flags",
      header: c("safetyCritical"),
      width: "170px",
      render: (row) => (
        <div className="row wrap" style={{ gap: 5 }}>
          {row.safety_critical ? <Badge tone="warning">{c("safetyCriticalFlag")}</Badge> : null}
          <Badge tone="success">{c("passiveOnly")}</Badge>
        </div>
      ),
    },
    {
      key: "baseline",
      header: c("baseline"),
      width: "150px",
      render: (row) => (
        <div className="mono" style={{ fontSize: 10.5 }}>
          {c("samples")}: {formatNumber(baselineNumber(row.baseline, "samples"))}
          <div style={{ color: baselineNumber(row.baseline, "anomalies") ? "var(--warning)" : "var(--dim)" }}>
            {c("anomalies")}: {formatNumber(baselineNumber(row.baseline, "anomalies"))}
          </div>
        </div>
      ),
    },
    {
      key: "telemetry",
      header: c("lastTelemetry"),
      width: "130px",
      render: (row) => (
        <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)" }}>
          {row.last_telemetry_at ? relativeTime(row.last_telemetry_at, lang) : c("never")}
        </span>
      ),
    },
    {
      key: "actions",
      header: c("actions"),
      width: "96px",
      render: (row) =>
        canWriteAssets ? (
          <Button size="sm" variant="ghost" icon={Pencil} onClick={() => setOtEditing(row)} aria-label={c("edit")} />
        ) : (
          <span className="dim" style={{ fontSize: 10.5 }}>—</span>
        ),
    },
  ];

  const zoneColumns: Column<Zone>[] = [
    {
      key: "name",
      header: c("zoneName"),
      render: (row) => (
        <div style={{ minWidth: 190 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.name}</div>
          <div className="cell-sub">{row.description ?? "—"}</div>
        </div>
      ),
    },
    { key: "kind", header: c("kind"), width: "110px", render: (row) => <Badge tone={row.kind === "conduit" ? "accent" : "neutral"}>{c(`zoneType.${row.kind}`)}</Badge> },
    { key: "purdue", header: c("purdue"), width: "90px", align: "center", render: (row) => <span className="mono">{row.purdue_level ?? "—"}</span> },
    {
      key: "updated",
      header: c("updated"),
      width: "140px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5, color: "var(--muted)" }}>{relativeTime(row.updated_at, lang)}</span>,
    },
    {
      key: "actions",
      header: c("actions"),
      width: "210px",
      render: (row) => (
        <div className="row wrap" style={{ gap: 6 }}>
          <Button size="sm" variant="ghost" onClick={() => { setSelectedZoneId(row.id); setZoneAssetsPage(1); }} aria-label={c("zoneAssets")}>
            {c("zoneAssets")}
          </Button>
          {canWriteAssets ? (
            <>
              <Button size="sm" variant="ghost" icon={Pencil} onClick={() => setZoneEditing(row)} aria-label={c("editZone")} />
              <Button size="sm" variant="ghost" icon={Trash2} onClick={() => { setDeletingZone(row); setReassignTo(""); }} aria-label={c("deleteZone")} />
            </>
          ) : null}
        </div>
      ),
    },
  ];

  const gatewayColumns: Column<EdgeGateway>[] = [
    {
      key: "name",
      header: c("gateway"),
      render: (row) => (
        <div style={{ minWidth: 200 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.name}</div>
          <div className="mono" style={{ fontSize: 10, color: "var(--dim)", marginTop: 2 }}>{row.fingerprint}</div>
        </div>
      ),
    },
    { key: "status", header: c("status"), width: "110px", render: (row) => <StatusBadge status={row.status} /> },
    { key: "version", header: c("version"), width: "96px", render: (row) => <span className="mono">{row.version ?? "—"}</span> },
    {
      key: "freshness",
      header: c("freshness"),
      width: "130px",
      render: (row) => {
        const state = freshness(row.last_seen_at);
        const tone = state === "fresh" ? "success" : state === "stale" ? "warning" : "neutral";
        const label = state === "fresh" ? c("fresh") : state === "stale" ? c("stale") : c("unknownFreshness");
        return (
          <div>
            <Badge tone={tone}>{label}</Badge>
            <div className="mono" style={{ fontSize: 10, color: "var(--dim)", marginTop: 3 }}>
              {row.last_seen_at ? relativeTime(row.last_seen_at, lang) : "—"}
            </div>
          </div>
        );
      },
    },
    {
      key: "actions",
      header: c("actions"),
      width: "300px",
      render: (row) => {
        const revoked = row.status === "revoked";
        return (
          <div className="row wrap" style={{ gap: 6 }}>
            <Button size="sm" variant="ghost" icon={Activity} onClick={() => { setSelectedGatewayId(row.id); setGatewayEventsPage(1); }}>
              {c("events")}
            </Button>
            {canWriteEdge ? (
              <>
                <Button size="sm" variant="ghost" icon={Router} disabled={revoked} onClick={() => setConfiguringGateway(row)}>
                  {c("configure")}
                </Button>
                <Button size="sm" variant="ghost" icon={KeyRound} disabled={revoked} onClick={() => rotateMutation.mutate(row)}>
                  {c("rotateKey")}
                </Button>
                <Button size="sm" variant="ghost" icon={ShieldAlert} disabled={revoked} onClick={() => setRevokingGateway(row)}>
                  {c("revoke")}
                </Button>
              </>
            ) : null}
          </div>
        );
      },
    },
  ];

  const gatewayEventColumns: Column<GatewayEvent>[] = [
    { key: "sequence", header: c("sequence"), width: "90px", align: "right", render: (row) => <span className="mono">{formatNumber(row.sequence)}</span> },
    { key: "kind", header: c("kind"), width: "100px", render: (row) => <span className="tag">{row.kind}</span> },
    {
      key: "signature",
      header: c("signature"),
      width: "110px",
      render: (row) => <Badge tone={row.signature_valid ? "success" : "danger"}>{row.signature_valid ? c("valid") : c("invalid")}</Badge>,
    },
    {
      key: "accepted",
      header: c("accepted"),
      width: "120px",
      render: (row) => <Badge tone={row.accepted ? "success" : "warning"}>{row.accepted ? c("accepted") : c("rejected")}</Badge>,
    },
    {
      key: "processed",
      header: c("processed"),
      width: "96px",
      align: "right",
      render: (row) => <span className="mono">{formatNumber(row.processed_count)}</span>,
    },
    {
      key: "reason",
      header: c("reason"),
      width: "160px",
      render: (row) => <span className="dim" style={{ fontSize: 11 }}>{row.rejection_reason ?? "—"}</span>,
    },
    {
      key: "received",
      header: c("received"),
      width: "130px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{formatDateTime(row.received_at, lang)}</span>,
    },
  ];

  const iotProtocolColumns: Column<IoTProtocol>[] = [
    { key: "name", header: c("name"), render: (row) => <span style={{ color: "var(--text)", fontWeight: 500 }}>{row.name}</span> },
    { key: "ports", header: c("ports"), width: "120px", render: (row) => <span className="mono">{formatPorts(row.default_ports)}</span> },
    { key: "family", header: c("family"), width: "120px", render: (row) => <span className="tag">{row.family}</span> },
    { key: "readOnly", header: c("readOnly"), width: "110px", render: (row) => <Badge tone={row.read_only_default ? "success" : "danger"}>{row.read_only_default ? c("yes") : c("no")}</Badge> },
    { key: "support", header: c("support"), width: "120px", render: (row) => <Badge tone="neutral">{c(`support.${row.support_level}`)}</Badge> },
    {
      key: "notes",
      header: c("securityNotes"),
      render: (row) => <span className="muted" style={{ fontSize: 11.5 }}>{row.security_notes}</span>,
    },
  ];

  const otProtocolColumns: Column<OTProtocol>[] = [
    { key: "name", header: c("name"), render: (row) => <span style={{ color: "var(--text)", fontWeight: 500 }}>{row.name}</span> },
    { key: "ports", header: c("ports"), width: "120px", render: (row) => <span className="mono">{formatPorts(row.default_ports)}</span> },
    { key: "safety", header: c("safetyClass"), width: "150px", render: (row) => <Badge tone={row.safety_class === "safety_critical" ? "critical" : row.safety_class === "process_critical" ? "danger" : "warning"}>{humanize(row.safety_class)}</Badge> },
    { key: "passive", header: c("readOnly"), width: "110px", render: (row) => <Badge tone={row.passive_only_default ? "success" : "danger"}>{row.passive_only_default ? c("yes") : c("no")}</Badge> },
    { key: "support", header: c("support"), width: "120px", render: (row) => <Badge tone="neutral">{c(`support.${row.support_level}`)}</Badge> },
    {
      key: "denied",
      header: c("deniedOps"),
      width: "220px",
      render: (row) => (
        <div className="chip-row">
          {row.active_operations_denied.slice(0, 4).map((operation) => <span className="tag" key={operation}>{operation}</span>)}
          {row.active_operations_denied.length > 4 ? <span className="tag">+{row.active_operations_denied.length - 4}</span> : null}
        </div>
      ),
    },
    {
      key: "notes",
      header: c("securityNotes"),
      render: (row) => <span className="muted" style={{ fontSize: 11.5 }}>{row.security_notes}</span>,
    },
  ];

  /* --------------------------------------------------------- overview */

  const riskFlagEntries = Object.entries(iotSummary.risk_flag_counts);
  const connectivityEntries = Object.entries(iotSummary.by_connectivity);
  const protocolCountEntries = Object.entries(iotSummary.by_protocol);

  const overview = (
    <div className="stack" data-testid="iotot-overview">
      <div className="kpi-grid">
        <Kpi
          label={c("iotDevices")}
          value={formatNumber(iotSummary.total_devices)}
          icon={Radio}
          tone="accent"
          footer={<span>{formatNumber(iotSummary.stale_devices)} {c("staleDevices").toLowerCase()} · {formatNumber(iotSummary.without_protocols)} {c("withoutProtocols").toLowerCase()}</span>}
        />
        <Kpi
          label={c("otDevices")}
          value={formatNumber(otPosture.ot_devices_total)}
          icon={Factory}
          tone="accent"
          footer={<span>{formatNumber(otPosture.ot_devices_zoned)}/{formatNumber(otPosture.ot_devices_total)} {c("zonesDocumented").toLowerCase()}</span>}
        />
        <Kpi
          label={c("unzoned")}
          value={formatNumber(otPosture.unzoned_devices)}
          icon={GitBranch}
          tone={otPosture.unzoned_devices ? "warning" : "success"}
          footer={<span>{c("unzonedHint")}</span>}
        />
        <Kpi
          label={c("safetyCritical")}
          value={formatNumber(otPosture.safety_critical_devices)}
          icon={AlertTriangle}
          tone={otPosture.safety_critical_devices ? "danger" : "success"}
          footer={<span>{formatNumber(otPosture.unmonitored_devices)} {c("unmonitoredDevices").toLowerCase()}</span>}
        />
      </div>

      <div className="split-main">
        <Card title={c("iecTitle")} subtitle={c("iecHint")} actions={<Badge tone={otPosture.posture_level === "aligned" ? "success" : otPosture.posture_level === "partial" ? "warning" : "danger"}>{c(`posture.${otPosture.posture_level}`)}</Badge>}>
          <div className="row wrap" style={{ gap: 22, alignItems: "flex-start" }}>
            <div style={{ flex: "1 1 260px", minWidth: 230 }}>
              <div className="section-label">{c("zoneCoverage")}</div>
              <div className="row-between" style={{ marginBottom: 5 }}>
                <span className="mono" style={{ fontSize: 12 }}>{otPosture.zone_coverage_pct.toFixed(1)}%</span>
                <span className="dim" style={{ fontSize: 10.5 }}>{formatNumber(otPosture.ot_devices_zoned)}/{formatNumber(otPosture.ot_devices_total)}</span>
              </div>
              <ProgressBar value={otPosture.zone_coverage_pct} tone="var(--accent)" />
              <div className="section-label" style={{ marginTop: 14 }}>{c("conduitCoverage")}</div>
              <div className="row-between" style={{ marginBottom: 5 }}>
                <span className="mono" style={{ fontSize: 12 }}>{otPosture.conduit_coverage_pct.toFixed(1)}%</span>
                <span className="dim" style={{ fontSize: 10.5 }}>{formatNumber(otPosture.conduits_total)} {c("conduitsTotal").toLowerCase()}</span>
              </div>
              <ProgressBar value={otPosture.conduit_coverage_pct} tone="var(--accent)" />
              <div className="section-label" style={{ marginTop: 14 }}>{c("monitoringPct")}</div>
              <div className="row-between" style={{ marginBottom: 5 }}>
                <span className="mono" style={{ fontSize: 12 }}>{formatNumber(otPosture.monitored_devices)}/{formatNumber(otPosture.ot_devices_total)}</span>
                <span className="dim" style={{ fontSize: 10.5 }}>{c("monitoredHint")}</span>
              </div>
              <ProgressBar
                value={otPosture.ot_devices_total ? (otPosture.monitored_devices / otPosture.ot_devices_total) * 100 : 0}
                tone={otPosture.unmonitored_devices ? "var(--warning)" : "var(--success)"}
              />
            </div>
            <div style={{ flex: "1 1 280px", minWidth: 240 }}>
              <div className="metric-list">
                <div className="metric-row"><span className="metric-label">{c("zonesTotal")}</span><span className="metric-value">{formatNumber(otPosture.zones_total)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("conduitsTotal")}</span><span className="metric-value">{formatNumber(otPosture.conduits_total)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("purdueDocumented")}</span><span className="metric-value">{formatNumber(otPosture.purdue_documented_zones)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("unzonedDevices")}</span><span className="metric-value" style={{ color: otPosture.unzoned_devices ? "var(--warning)" : "var(--success)" }}>{formatNumber(otPosture.unzoned_devices)}</span></div>
                <div className="metric-row"><span className="metric-label">{c("commControl")}</span><span className="metric-value">{otPosture.iec62443.sr_3_1_communication_control ? c("yes") : c("no")}</span></div>
                <div className="metric-row"><span className="metric-label">{c("purdueModel")}</span><span className="metric-value">{otPosture.iec62443.purdue_model_documented ? c("yes") : c("no")}</span></div>
                <div className="metric-row"><span className="metric-label">{c("authorizedDevices")}</span><span className="metric-value">{formatNumber(Number(otPosture.iec62443.sr_2_1_authorized_devices ?? 0))}</span></div>
              </div>
            </div>
          </div>
        </Card>

        <div className="stack">
          <Card title={c("iotRiskFlags")} subtitle={c("iotRiskHint")}>
            {riskFlagEntries.length === 0 ? (
              <EmptyState icon={ShieldCheck} title={c("noRiskFlags")} description={c("noRiskFlagsHint")} />
            ) : (
              <div className="metric-list">
                {riskFlagEntries.map(([flag, count]) => (
                  <div className="metric-row" key={flag}>
                    <span className="metric-label"><AlertTriangle size={13} style={{ color: "var(--warning)" }} aria-hidden="true" /> {humanize(flag)}</span>
                    <span className="metric-value" style={{ color: "var(--warning)" }}>{formatNumber(count)}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title={c("iotByConnectivity")}>
            {connectivityEntries.length === 0 ? (
              <EmptyState icon={Waves} title={t("common.noData")} />
            ) : (
              <div className="metric-list">
                {connectivityEntries.map(([key, count]) => (
                  <div className="metric-row" key={key}>
                    <span className="metric-label"><Cable size={13} aria-hidden="true" /> {humanize(key)}</span>
                    <span className="metric-value">{formatNumber(count)}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title={c("iotByProtocol")}>
            {protocolCountEntries.length === 0 ? (
              <EmptyState icon={Network} title={t("common.noData")} />
            ) : (
              <div className="metric-list">
                {protocolCountEntries.slice(0, 8).map(([key, count]) => (
                  <div className="metric-row" key={key}>
                    <span className="metric-label"><Radio size={13} aria-hidden="true" /> {key}</span>
                    <span className="metric-value">{formatNumber(count)}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      <Card title={c("zoneBreakdown")} bodyClassName="">
        <div data-testid="ot-zone-breakdown">
          <DataTable
            columns={[
              { key: "name", header: c("zone"), render: (row: OTZonePosture) => <span style={{ color: "var(--text)" }}>{row.name}</span> },
              { key: "kind", header: c("kind"), width: "110px", render: (row: OTZonePosture) => <Badge tone={row.kind === "conduit" ? "accent" : "neutral"}>{c(`zoneType.${row.kind}`)}</Badge> },
              { key: "purdue", header: c("purdue"), width: "90px", align: "center", render: (row: OTZonePosture) => <span className="mono">{row.purdue_level ?? "—"}</span> },
              { key: "devices", header: c("devices"), width: "110px", align: "right", render: (row: OTZonePosture) => <span className="mono">{formatNumber(row.devices)}</span> },
              { key: "safety", header: c("safetyCritical"), width: "150px", align: "right", render: (row: OTZonePosture) => <span className="mono" style={{ color: row.safety_critical ? "var(--danger)" : "var(--dim)" }}>{formatNumber(row.safety_critical)}</span> },
            ]}
            rows={otPosture.zone_breakdown}
            rowKey={(row) => row.zone_id}
            empty={<EmptyState icon={GitBranch} title={c("noZones")} description={c("noZonesHint")} action={canWriteAssets ? <Button size="sm" variant="primary" icon={Plus} onClick={() => setZoneCreateOpen(true)}>{c("createZone")}</Button> : undefined} />}
          />
        </div>
      </Card>
    </div>
  );

  /* -------------------------------------------------------------- iot */

  const iotTab = (
    <Card
      title={c("inventory")}
      subtitle={c("iotHint")}
      bodyClassName=""
      actions={
        canWriteAssets ? (
          <Button size="sm" variant="primary" icon={Plus} onClick={() => setIotCreateOpen(true)} data-testid="create-iot-device">
            {c("createIot")}
          </Button>
        ) : (
          <Badge tone="warning">{c("permissionReadOnly")}</Badge>
        )
      }
      footer={<Pagination meta={iotDevicesQuery.data?.meta} onPage={setIotPage} />}
    >
      <div className="filters-bar" data-testid="iot-filters">
        <SearchInput
          value={iotQ}
          onChange={(value) => { setIotQ(value); setIotPage(1); }}
          placeholder={c("filterSearch")}
          ariaLabel={c("filterSearch")}
        />
        <Input
          value={iotConnectivity}
          onChange={(event) => { setIotConnectivity(event.target.value); setIotPage(1); }}
          placeholder={c("filterConnectivity")}
          aria-label={c("filterConnectivity")}
          style={{ width: 150 }}
          data-testid="iot-filter-connectivity"
        />
        <Select
          value={iotProtocol}
          onChange={(event) => { setIotProtocol(event.target.value); setIotPage(1); }}
          aria-label={c("filterProtocol")}
          data-testid="iot-filter-protocol"
        >
          <option value="">{c("allProtocols")}</option>
          {iotProtocolOptions.map((protocol) => <option value={protocol} key={protocol}>{protocol}</option>)}
        </Select>
        {iotQ || iotConnectivity || iotProtocol ? (
          <Button size="sm" variant="ghost" onClick={() => { setIotQ(""); setIotConnectivity(""); setIotProtocol(""); setIotPage(1); }}>
            {c("clearFilters")}
          </Button>
        ) : null}
      </div>
      {iotDevicesQuery.isError ? (
        <div style={{ padding: 12 }}>
          <ErrorBanner message={errorMessage(iotDevicesQuery.error)} onRetry={() => void iotDevicesQuery.refetch()} compact />
        </div>
      ) : (
        <div data-testid="iot-devices-table">
          <DataTable
            columns={iotColumns}
            rows={iotDevicesQuery.data?.items}
            rowKey={(row) => row.asset_id}
            loading={iotDevicesQuery.isLoading}
            empty={
              iotQ || iotConnectivity || iotProtocol ? (
                <EmptyState icon={Radio} title={c("noIotResults")} description={c("noIotResultsHint")} action={<Button size="sm" onClick={() => { setIotQ(""); setIotConnectivity(""); setIotProtocol(""); }}>{c("clearFilters")}</Button>} />
              ) : (
                <EmptyState
                  icon={Radio}
                  title={c("noIot")}
                  description={c("noIotHint")}
                  action={canWriteAssets ? <Button size="sm" variant="primary" icon={Plus} onClick={() => setIotCreateOpen(true)}>{c("createIot")}</Button> : undefined}
                />
              )
            }
          />
        </div>
      )}
    </Card>
  );

  /* --------------------------------------------------------------- ot */

  const otTab = (
    <Card
      title={c("inventory")}
      subtitle={c("otHint")}
      bodyClassName=""
      actions={
        canWriteAssets ? (
          <Button size="sm" variant="primary" icon={Plus} onClick={() => setOtCreateOpen(true)} data-testid="create-ot-device">
            {c("createOt")}
          </Button>
        ) : (
          <Badge tone="warning">{c("permissionReadOnly")}</Badge>
        )
      }
      footer={<Pagination meta={otDevicesQuery.data?.meta} onPage={setOtPage} />}
    >
      <div className="filters-bar" data-testid="ot-filters">
        <SearchInput
          value={otQ}
          onChange={(value) => { setOtQ(value); setOtPage(1); }}
          placeholder={c("filterSearch")}
          ariaLabel={c("filterSearch")}
        />
        <Select
          value={otZone}
          onChange={(event) => { setOtZone(event.target.value); setOtPage(1); }}
          aria-label={c("filterZone")}
          data-testid="ot-filter-zone"
        >
          <option value="">{c("allZones")}</option>
          {zones.map((zone) => <option value={zone.id} key={zone.id}>{zone.name}</option>)}
        </Select>
        <Select
          value={otSafety}
          onChange={(event) => { setOtSafety(event.target.value); setOtPage(1); }}
          aria-label={c("filterSafety")}
          data-testid="ot-filter-safety"
        >
          <option value="">{c("allSafety")}</option>
          <option value="true">{c("safetyOnly")}</option>
          <option value="false">{c("nonSafety")}</option>
        </Select>
        {otQ || otZone || otSafety ? (
          <Button size="sm" variant="ghost" onClick={() => { setOtQ(""); setOtZone(""); setOtSafety(""); setOtPage(1); }}>
            {c("clearFilters")}
          </Button>
        ) : null}
      </div>
      {otDevicesQuery.isError ? (
        <div style={{ padding: 12 }}>
          <ErrorBanner message={errorMessage(otDevicesQuery.error)} onRetry={() => void otDevicesQuery.refetch()} compact />
        </div>
      ) : (
        <div data-testid="ot-devices-table">
          <DataTable
            columns={otColumns}
            rows={otDevicesQuery.data?.items}
            rowKey={(row) => row.asset_id}
            loading={otDevicesQuery.isLoading}
            empty={
              otQ || otZone || otSafety ? (
                <EmptyState icon={Factory} title={c("noOtResults")} description={c("noOtResultsHint")} action={<Button size="sm" onClick={() => { setOtQ(""); setOtZone(""); setOtSafety(""); }}>{c("clearFilters")}</Button>} />
              ) : (
                <EmptyState
                  icon={Factory}
                  title={c("noOt")}
                  description={c("noOtHint")}
                  action={canWriteAssets ? <Button size="sm" variant="primary" icon={Plus} onClick={() => setOtCreateOpen(true)}>{c("createOt")}</Button> : undefined}
                />
              )
            }
          />
        </div>
      )}
    </Card>
  );

  /* ------------------------------------------------------------ zones */

  const zonesTab = (
    <div className="stack">
      <Card
        title={c("tab.zones")}
        subtitle={c("zonesTabHint")}
        bodyClassName=""
        actions={
          canWriteAssets ? (
            <Button size="sm" variant="primary" icon={Plus} onClick={() => setZoneCreateOpen(true)} data-testid="create-zone">
              {c("createZone")}
            </Button>
          ) : (
            <Badge tone="warning">{c("permissionReadOnly")}</Badge>
          )
        }
        footer={<Pagination meta={zonesQuery.data?.meta} onPage={setZonePage} />}
      >
        <div className="filters-bar" data-testid="zone-filters">
          <SearchInput
            value={zoneQ}
            onChange={(value) => { setZoneQ(value); setZonePage(1); }}
            placeholder={c("filterSearch")}
            ariaLabel={c("filterSearch")}
          />
          <Select
            value={zoneKind}
            onChange={(event) => { setZoneKind(event.target.value); setZonePage(1); }}
            aria-label={c("zoneKind")}
            data-testid="zone-filter-kind"
          >
            <option value="">{c("all")}</option>
            <option value="zone">{c("zoneType.zone")}</option>
            <option value="conduit">{c("zoneType.conduit")}</option>
          </Select>
          {zoneQ || zoneKind ? (
            <Button size="sm" variant="ghost" onClick={() => { setZoneQ(""); setZoneKind(""); setZonePage(1); }}>
              {c("clearFilters")}
            </Button>
          ) : null}
        </div>
        {zonesQuery.isError ? (
          <div style={{ padding: 12 }}>
            <ErrorBanner message={errorMessage(zonesQuery.error)} onRetry={() => void zonesQuery.refetch()} compact />
          </div>
        ) : (
          <div data-testid="zones-table">
            <DataTable
              columns={zoneColumns}
              rows={zones}
              rowKey={(row) => row.id}
              loading={zonesQuery.isLoading}
              empty={<EmptyState icon={GitBranch} title={c("noZones")} description={c("noZonesHint")} action={canWriteAssets ? <Button size="sm" variant="primary" icon={Plus} onClick={() => setZoneCreateOpen(true)}>{c("createZone")}</Button> : undefined} />}
            />
          </div>
        )}
      </Card>

      <Card
        title={selectedZone ? `${c("zoneAssets")} · ${selectedZone.name}` : c("zoneAssets")}
        subtitle={c("zoneAssetsHint")}
        bodyClassName=""
        footer={selectedZoneId ? <Pagination meta={zoneAssetsQuery.data?.meta} onPage={setZoneAssetsPage} /> : undefined}
        actions={selectedZone?.purdue_level !== undefined && selectedZone?.purdue_level !== null ? <Badge tone="neutral">Purdue {selectedZone.purdue_level}</Badge> : undefined}
      >
        {!selectedZoneId ? (
          <EmptyState icon={Boxes} title={c("selectZone")} description={c("selectZoneHint")} />
        ) : zoneAssetsQuery.isError ? (
          <div style={{ padding: 12 }}>
            <ErrorBanner message={errorMessage(zoneAssetsQuery.error)} onRetry={() => void zoneAssetsQuery.refetch()} compact />
          </div>
        ) : (
          <div data-testid="zone-assets-table">
            <DataTable
              columns={[
                { key: "name", header: c("name"), render: (row: AssetRow) => <div><div style={{ color: "var(--text)" }}>{row.name}</div><div className="cell-sub mono">{row.asset_key}</div></div> },
                { key: "kind", header: c("kind"), width: "110px", render: (row: AssetRow) => <span className="tag">{row.kind}</span> },
                { key: "criticality", header: c("criticality"), width: "110px", align: "center", render: (row: AssetRow) => <Badge tone={row.criticality >= 4 ? "danger" : "neutral"}>{row.criticality}</Badge> },
                { key: "status", header: c("status"), width: "120px", render: (row: AssetRow) => <StatusBadge status={row.status} /> },
                { key: "open", header: c("actions"), width: "100px", render: (row: AssetRow) => <LinkButton to={`/assets/${row.id}`} size="sm" variant="ghost">{c("open")}</LinkButton> },
              ]}
              rows={zoneAssetsQuery.data?.items}
              rowKey={(row) => row.id}
              loading={zoneAssetsQuery.isLoading}
              empty={<EmptyState icon={Boxes} title={c("noZoneAssets")} description={c("selectZoneHint")} />}
            />
          </div>
        )}
      </Card>
    </div>
  );

  /* --------------------------------------------------------- gateways */

  const gatewaysTab = !canReadEdge ? (
    <Card title={c("tab.gateways")} subtitle={c("gatewaysTabHint")}>
      <EmptyState icon={Lock} title={c("permissionEdge")} description={c("permissionEdgeHint")} />
    </Card>
  ) : (
    <div className="stack">
      <div className="notice notice-accent">
        <Router size={15} style={{ flex: "0 0 auto" }} aria-hidden="true" />
        <div>
          <strong>{c("offlineTitle")}</strong>
          <div style={{ marginTop: 3 }}>{c("offlineBody")}</div>
        </div>
      </div>

      <Card
        title={c("tab.gateways")}
        subtitle={c("gatewaysTabHint")}
        bodyClassName=""
        actions={
          canWriteEdge ? (
            <Button size="sm" variant="primary" icon={KeyRound} onClick={() => tokenMutation.mutate()} loading={tokenMutation.isPending} data-testid="enroll-token">
              {c("createToken")}
            </Button>
          ) : (
            <Badge tone="warning">{c("permissionEdge")}</Badge>
          )
        }
        footer={<Pagination meta={gatewaysQuery.data?.meta} onPage={setGatewayPage} />}
      >
        <div className="filters-bar" data-testid="gateway-filters">
          <SearchInput
            value={gatewayQ}
            onChange={(value) => { setGatewayQ(value); setGatewayPage(1); }}
            placeholder={c("filterSearch")}
            ariaLabel={c("filterSearch")}
          />
          <Select
            value={gatewayStatus}
            onChange={(event) => { setGatewayStatus(event.target.value); setGatewayPage(1); }}
            aria-label={c("status")}
            data-testid="gateway-filter-status"
          >
            <option value="">{c("all")}</option>
            <option value="active">active</option>
            <option value="degraded">degraded</option>
            <option value="revoked">revoked</option>
            <option value="pending">pending</option>
          </Select>
        </div>
        {gatewaysQuery.isError ? (
          <div style={{ padding: 12 }}>
            <ErrorBanner message={errorMessage(gatewaysQuery.error)} onRetry={() => void gatewaysQuery.refetch()} compact />
          </div>
        ) : (
          <div data-testid="gateways-table">
            <DataTable
              columns={gatewayColumns}
              rows={gateways}
              rowKey={(row) => row.id}
              loading={gatewaysQuery.isLoading}
              empty={<EmptyState icon={Router} title={c("noGateways")} description={c("noGatewaysHint")} action={canWriteEdge ? <Button size="sm" variant="primary" icon={KeyRound} onClick={() => tokenMutation.mutate()}>{c("createToken")}</Button> : undefined} />}
            />
          </div>
        )}
      </Card>

      <Card
        title={selectedGateway ? `${c("gatewayEvents")} · ${selectedGateway.name}` : c("gatewayEvents")}
        subtitle={c("gatewayEventsHint")}
        bodyClassName=""
        footer={selectedGatewayId ? <Pagination meta={gatewayEventsQuery.data?.meta} onPage={setGatewayEventsPage} /> : undefined}
      >
        {!selectedGatewayId ? (
          <EmptyState icon={Activity} title={c("selectGateway")} description={c("selectGatewayHint")} />
        ) : gatewayEventsQuery.isError ? (
          <div style={{ padding: 12 }}>
            <ErrorBanner message={errorMessage(gatewayEventsQuery.error)} onRetry={() => void gatewayEventsQuery.refetch()} compact />
          </div>
        ) : (
          <div data-testid="gateway-events-table">
            <DataTable
              columns={gatewayEventColumns}
              rows={gatewayEventsQuery.data?.items}
              rowKey={(row) => row.id}
              loading={gatewayEventsQuery.isLoading}
              empty={<EmptyState icon={Activity} title={c("noEvents")} description={c("noEventsHint")} />}
            />
          </div>
        )}
      </Card>
    </div>
  );

  /* -------------------------------------------------------- protocols */

  const protocolsTab = (
    <div className="stack" data-testid="protocols-registry">
      <div className="notice">
        <ShieldCheck size={14} style={{ flex: "0 0 auto", color: "var(--accent)" }} aria-hidden="true" />
        <span>{c("registryHint")} {c("safetyNoWrite")}.</span>
      </div>

      <div className="split-main">
        <Card title={c("iotRegistry")} actions={<Badge tone="accent">{formatNumber(iotProtocolsQuery.data?.length ?? 0)}</Badge>}>
          {iotProtocolsQuery.isLoading ? (
            <TableSkeleton rows={5} />
          ) : iotProtocolsQuery.isError ? (
            <ErrorBanner compact message={errorMessage(iotProtocolsQuery.error)} onRetry={() => void iotProtocolsQuery.refetch()} />
          ) : (iotProtocolsQuery.data ?? []).length === 0 ? (
            <EmptyState icon={Radio} title={c("noProtocols")} />
          ) : (
            <div className="stack" data-testid="iot-protocols">
              {groupProtocols(iotProtocolsQuery.data ?? [], (item) => item.family).map((group) => (
                <Card key={group.key} title={humanize(group.key)} subtitle={`${formatNumber(group.items.length)} ${c("protocols").toLowerCase()}`} bodyClassName="">
                  <DataTable columns={iotProtocolColumns} rows={group.items} rowKey={(row) => row.name} />
                </Card>
              ))}
            </div>
          )}
        </Card>

        <Card title={c("otRegistry")} actions={<Badge tone="warning">{formatNumber(otProtocolsQuery.data?.length ?? 0)}</Badge>}>
          {otProtocolsQuery.isLoading ? (
            <TableSkeleton rows={5} />
          ) : otProtocolsQuery.isError ? (
            <ErrorBanner compact message={errorMessage(otProtocolsQuery.error)} onRetry={() => void otProtocolsQuery.refetch()} />
          ) : (otProtocolsQuery.data ?? []).length === 0 ? (
            <EmptyState icon={Factory} title={c("noProtocols")} />
          ) : (
            <div className="stack" data-testid="ot-protocols">
              {groupProtocols(otProtocolsQuery.data ?? [], (item) => item.safety_class).map((group) => (
                <Card key={group.key} title={humanize(group.key)} subtitle={`${formatNumber(group.items.length)} ${c("protocols").toLowerCase()}`} bodyClassName="">
                  <DataTable columns={otProtocolColumns} rows={group.items} rowKey={(row) => row.name} />
                </Card>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );

  const iotMutationError = iotMutation.isError ? errorMessage(iotMutation.error) : null;
  const otMutationError = otMutation.isError ? errorMessage(otMutation.error) : null;
  const zoneMutationError = zoneMutation.isError ? errorMessage(zoneMutation.error) : null;
  const configMutationError = configMutation.isError ? errorMessage(configMutation.error) : null;

  return (
    <div className="animate-in" data-testid="page-iot-ot">
      <PageHeader
        eyebrow={c("eyebrow")}
        title={c("title")}
        subtitle={c("subtitle")}
        actions={
          <>
            <span className="mono hide-mobile" style={{ fontSize: 10, color: "var(--dim)" }}>
              {c("refreshed")}{" "}
              {iotSummaryQuery.dataUpdatedAt ? formatDateTime(new Date(iotSummaryQuery.dataUpdatedAt).toISOString(), lang) : "—"}
            </span>
            <Button
              icon={RefreshCw}
              onClick={() => {
                void iotSummaryQuery.refetch();
                void otPostureQuery.refetch();
                void iotDevicesQuery.refetch();
                void otDevicesQuery.refetch();
                void zonesQuery.refetch();
                void gatewaysQuery.refetch();
                if (selectedGatewayId) void gatewayEventsQuery.refetch();
              }}
              aria-label={t("common.refresh")}
              data-testid="refresh-iot-ot"
            />
            <LinkButton to="/assets" icon={Boxes}>{c("goAssets")}</LinkButton>
          </>
        }
      />

      <div className="notice notice-warning" style={{ marginBottom: 12 }} role="status" data-testid="ot-safety-banner">
        <Lock size={15} style={{ flex: "0 0 auto" }} aria-hidden="true" />
        <div>
          <strong>{c("safetyTitle")}</strong>
          <div style={{ marginTop: 3 }}>{c("safetyBody")}</div>
          <div className="mono" style={{ fontSize: 10, marginTop: 5, letterSpacing: "0.04em" }}>{c("safetyNoWrite")}</div>
        </div>
      </div>

      <div style={{ marginBottom: 12 }} data-testid="iotot-tabs">
        <Tabs items={tabs} value={tab} onChange={setTab} ariaLabel={c("title")} />
      </div>

      {tab === "overview" ? overview : null}
      {tab === "iot" ? iotTab : null}
      {tab === "ot" ? otTab : null}
      {tab === "zones" ? zonesTab : null}
      {tab === "gateways" ? gatewaysTab : null}
      {tab === "protocols" ? protocolsTab : null}

      <div className="notice" style={{ fontSize: 11, marginTop: 12 }}>
        <ShieldAlert size={14} style={{ flex: "0 0 auto", color: "var(--warning)" }} aria-hidden="true" />
        <span>
          {c("overviewHint")} · {t("common.lastUpdated", { time: relativeTime(new Date().toISOString(), lang) })}
        </span>
      </div>

      {/* ------------------------------------------------------------ modals */}

      {iotCreateOpen || iotEditing ? (
        <IoTFormModal
          initial={iotEditing}
          zones={zones}
          gateways={gateways}
          protocolOptions={iotProtocolOptions}
          loading={iotMutation.isPending}
          error={iotMutationError}
          fieldErrors={apiFieldErrors(iotMutation.error)}
          onClose={() => { setIotCreateOpen(false); setIotEditing(null); iotMutation.reset(); }}
          onSubmit={(payload) => iotMutation.mutate({ payload, editing: iotEditing })}
        />
      ) : null}

      {otCreateOpen || otEditing ? (
        <OTFormModal
          initial={otEditing}
          zones={zones}
          protocolOptions={otProtocolOptions}
          loading={otMutation.isPending}
          error={otMutationError}
          fieldErrors={apiFieldErrors(otMutation.error)}
          onClose={() => { setOtCreateOpen(false); setOtEditing(null); otMutation.reset(); }}
          onSubmit={(payload) => otMutation.mutate({ payload, editing: otEditing })}
        />
      ) : null}

      {zoneCreateOpen || zoneEditing ? (
        <ZoneFormModal
          initial={zoneEditing}
          loading={zoneMutation.isPending}
          error={zoneMutationError}
          fieldErrors={apiFieldErrors(zoneMutation.error)}
          onClose={() => { setZoneCreateOpen(false); setZoneEditing(null); zoneMutation.reset(); }}
          onSubmit={(payload) => zoneMutation.mutate({ payload, editing: zoneEditing })}
        />
      ) : null}

      <Modal
        open={Boolean(deletingIot)}
        onClose={() => setDeletingIot(null)}
        title={c("deleteIotTitle")}
        footer={
          <>
            <Button onClick={() => setDeletingIot(null)}>{c("cancel")}</Button>
            <Button
              variant="danger"
              loading={iotDeleteMutation.isPending}
              onClick={() => { if (deletingIot) iotDeleteMutation.mutate(deletingIot); }}
              data-testid="confirm-delete-iot"
            >
              {c("deleteConfirm")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <p style={{ fontSize: 12.5 }}>{c("deleteIotBody")}</p>
          <div className="notice notice-danger">
            <AlertTriangle size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
            <span>{deletingIot?.asset.name ?? deletingIot?.asset.asset_key ?? c("deviceFallback")}</span>
          </div>
        </div>
      </Modal>

      <Modal
        open={Boolean(deletingZone)}
        onClose={() => { setDeletingZone(null); setReassignTo(""); }}
        title={c("deleteZone")}
        footer={
          <>
            <Button onClick={() => { setDeletingZone(null); setReassignTo(""); }}>{c("cancel")}</Button>
            <Button
              variant="danger"
              loading={zoneDeleteMutation.isPending}
              onClick={() => { if (deletingZone) zoneDeleteMutation.mutate({ zone: deletingZone, reassign: reassignTo }); }}
              data-testid="confirm-delete-zone"
            >
              {c("deleteZoneConfirm")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <p style={{ fontSize: 12.5 }}>{c("deleteZoneBody")}</p>
          <Field label={c("reassignTo")} htmlFor="zone-reassign" hint={c("zoneRefsError")}>
            <Select id="zone-reassign" value={reassignTo} onChange={(event) => setReassignTo(event.target.value)}>
              <option value="">{c("reassignNone")}</option>
              {zones.filter((zone) => zone.id !== deletingZone?.id).map((zone) => <option value={zone.id} key={zone.id}>{zone.name}</option>)}
            </Select>
          </Field>
          <div className="notice notice-danger">
            <AlertTriangle size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
            <span>{deletingZone?.name ?? "—"}</span>
          </div>
        </div>
      </Modal>

      <Modal
        open={Boolean(enrollment)}
        onClose={() => setEnrollment(null)}
        title={c("enrollTitle")}
        footer={<Button variant="primary" onClick={() => setEnrollment(null)}>{c("close")}</Button>}
      >
        {enrollment ? (
          <div className="stack" data-testid="enrollment-token">
            <div className="notice notice-warning">
              <KeyRound size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
              <span>{c("enrollBody")}</span>
            </div>
            <CopyField label={c("token")} value={enrollment.token} />
            <div className="metric-list">
              <div className="metric-row"><span className="metric-label">{c("gatewayId")}</span><span className="metric-value mono">{enrollment.gateway_id}</span></div>
              <div className="metric-row"><span className="metric-label">{c("expiresIn")}</span><span className="metric-value">{formatNumber(enrollment.expires_in_seconds)} s</span></div>
              <div className="metric-row"><span className="metric-label">{c("expiresAt")}</span><span className="metric-value">{formatDateTime(enrollment.expires_at, lang)}</span></div>
            </div>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={Boolean(rotation)}
        onClose={() => setRotation(null)}
        title={c("rotateTitle")}
        footer={<Button variant="primary" onClick={() => setRotation(null)}>{c("close")}</Button>}
      >
        {rotation ? (
          <div className="stack" data-testid="rotated-key">
            <div className="notice notice-warning">
              <ShieldAlert size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
              <span>{c("rotateBody")}</span>
            </div>
            <CopyField label={c("sharedKey")} value={rotation.shared_key} />
            <div className="metric-list">
              <div className="metric-row"><span className="metric-label">{c("keyId")}</span><span className="metric-value mono">{rotation.key_id}</span></div>
              <div className="metric-row"><span className="metric-label">{c("refreshed")}</span><span className="metric-value">{formatDateTime(rotation.rotated_at, lang)}</span></div>
            </div>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={Boolean(revokingGateway)}
        onClose={() => setRevokingGateway(null)}
        title={c("revokeTitle")}
        footer={
          <>
            <Button onClick={() => setRevokingGateway(null)}>{c("cancel")}</Button>
            <Button
              variant="danger"
              loading={revokeMutation.isPending}
              onClick={() => { if (revokingGateway) revokeMutation.mutate(revokingGateway); }}
              data-testid="confirm-revoke-gateway"
            >
              {c("revokeConfirm")}
            </Button>
          </>
        }
      >
        <div className="stack">
          <p style={{ fontSize: 12.5 }}>{c("revokeBody")}</p>
          <div className="notice notice-danger">
            <ShieldAlert size={14} style={{ flex: "0 0 auto" }} aria-hidden="true" />
            <span>{revokingGateway?.name} · {revokingGateway?.fingerprint}</span>
          </div>
        </div>
      </Modal>

      {configuringGateway ? (
        <GatewayConfigModal
          gateway={configuringGateway}
          loading={configMutation.isPending}
          error={configMutationError}
          fieldErrors={apiFieldErrors(configMutation.error)}
          onClose={() => { setConfiguringGateway(null); configMutation.reset(); }}
          onSubmit={(payload) => configMutation.mutate({ gateway: configuringGateway, payload })}
        />
      ) : null}

      <div className="notice" style={{ fontSize: 10.5, marginTop: 12 }}>
        <Zap size={13} style={{ flex: "0 0 auto", color: "var(--accent)" }} aria-hidden="true" />
        <span>
          {c("safetyNoWrite")} · {c("passiveLocked")} · {c("safetyCriticalFlag")}: {c("safetyCriticalHint")}
        </span>
      </div>
    </div>
  );
}

export default IotOtPage;
