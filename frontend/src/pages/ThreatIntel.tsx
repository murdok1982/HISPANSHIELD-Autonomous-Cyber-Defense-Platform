import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Crosshair,
  Filter,
  Fingerprint,
  Plus,
  Power,
  Radar,
  RefreshCw,
  Rss,
  ShieldOff,
  SquarePen,
  Swords,
  Target,
  Trash2,
  Upload,
  Users,
} from "lucide-react";
import { api, apiRequest, errorMessage, type Page } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, usePageCopy } from "../lib/i18n";
import { formatDateTime, formatNumber, formatPercent, humanize, relativeTime } from "../lib/format";
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
  Pagination,
  ProgressBar,
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
  FilterBar,
  ImportErrors,
  TagList,
  fieldErrors,
  useDebouncedValue,
} from "../components/features/detect/shared";
import type {
  Enrichment,
  FeedSyncResult,
  IntelFeed,
  IntelImportResult,
  IntelSummary,
  Indicator,
  MitreCoverage,
  MitreTechnique,
  MitreTechniqueResponse,
  ThreatActor,
  ThreatActorDetail,
} from "../components/features/detect/types";

const COPY = {
  es: {
    "ti.eyebrow": "Detección · Inteligencia",
    "ti.title": "Inteligencia de amenazas",
    "ti.subtitle": "Indicadores, actores, fuentes y cobertura ATT&CK con enriquecimiento explicable y sin datos inventados.",
    "ti.kpi.active": "Indicadores activos",
    "ti.kpi.total": "Indicadores totales",
    "ti.kpi.actors": "Actores",
    "ti.kpi.coverage": "Cobertura ATT&CK",
    "ti.kpi.expired": "Expirados",
    "ti.tab.indicators": "Indicadores",
    "ti.tab.actors": "Actores",
    "ti.tab.feeds": "Fuentes",
    "ti.tab.mitre": "MITRE ATT&CK",
    "ti.ind.search": "Buscar por valor…",
    "ti.ind.filter.type": "Tipo",
    "ti.ind.filter.severity": "Severidad",
    "ti.ind.filter.source": "Origen",
    "ti.ind.filter.active": "Estado",
    "ti.ind.filter.allTypes": "Todos los tipos",
    "ti.ind.filter.allSeverities": "Todas las severidades",
    "ti.ind.filter.allSources": "Todos los orígenes",
    "ti.ind.filter.allActive": "Activos e inactivos",
    "ti.ind.filter.activeOnly": "Solo activos",
    "ti.ind.filter.inactiveOnly": "Solo inactivos",
    "ti.ind.sourcePlaceholder": "Filtrar origen",
    "ti.ind.new": "Nuevo indicador",
    "ti.ind.newShort": "Nuevo",
    "ti.ind.import": "Importar",
    "ti.ind.count": "indicadores",
    "ti.ind.col.indicator": "Indicador",
    "ti.ind.col.severity": "Severidad",
    "ti.ind.col.confidence": "Confianza",
    "ti.ind.col.source": "Origen",
    "ti.ind.col.actor": "Actor",
    "ti.ind.col.lastSeen": "Última vez",
    "ti.ind.col.status": "Estado",
    "ti.ind.col.actions": "Acciones",
    "ti.ind.global": "GLOBAL",
    "ti.ind.edit": "Editar indicador",
    "ti.ind.deactivate": "Desactivar indicador",
    "ti.ind.deactivateTitle": "Desactivar indicador",
    "ti.ind.deactivateDescription": "El indicador deja de aplicarse a la correlación y al enriquecimiento. La fila se conserva para auditoría; puedes reactivarla editándola.",
    "ti.ind.deactivated": "Indicador desactivado",
    "ti.ind.deactivateFailed": "No se pudo desactivar el indicador",
    "ti.ind.empty.title": "Aún no hay indicadores",
    "ti.ind.empty.description": "Crea un indicador o importa un bundle STIX/CSV para activar la correlación.",
    "ti.ind.empty.action": "Importar indicadores",
    "ti.ind.noResults.title": "Ningún indicador coincide",
    "ti.ind.noResults.description": "Ajusta los filtros o limpia la búsqueda.",
    "ti.ind.clear": "Limpiar filtros",
    "ti.ind.loadFailed": "No se pudieron cargar los indicadores",
    "ti.ind.status.active": "Activo",
    "ti.ind.status.inactive": "Inactivo",
    "ti.ind.editor.createTitle": "Nuevo indicador",
    "ti.ind.editor.editTitle": "Editar indicador",
    "ti.ind.editor.type": "Tipo",
    "ti.ind.editor.value": "Valor",
    "ti.ind.editor.confidence": "Confianza (0-100)",
    "ti.ind.editor.severity": "Severidad",
    "ti.ind.editor.source": "Origen",
    "ti.ind.editor.description": "Descripción",
    "ti.ind.editor.tags": "Etiquetas",
    "ti.ind.editor.tagsHint": "Separadas por comas (máx. 20)",
    "ti.ind.editor.actor": "Actor asociado",
    "ti.ind.editor.actorNone": "Sin actor",
    "ti.ind.editor.active": "Activo",
    "ti.ind.editor.submitCreate": "Crear indicador",
    "ti.ind.editor.submitSave": "Guardar cambios",
    "ti.ind.editor.created": "Indicador creado",
    "ti.ind.editor.updated": "Indicador actualizado",
    "ti.ind.editor.failed": "No se pudo guardar el indicador",
    "ti.ind.editor.required": "Obligatorio",
    "ti.ind.editor.invalidConfidence": "La confianza debe estar entre 0 y 100",
    "ti.ind.import.title": "Importar indicadores",
    "ti.ind.import.description": "El bundle STIX 2.1 y el CSV se validan por fila en el servidor; los errores no descartan el lote completo.",
    "ti.ind.import.tab.stix": "Bundle STIX",
    "ti.ind.import.tab.csv": "CSV",
    "ti.ind.import.stixHint": "Objeto JSON STIX 2.1 con type=bundle.",
    "ti.ind.import.csvHint": "CSV con columnas type,value[,severity,confidence,source,description,tags].",
    "ti.ind.import.file": "Cargar desde archivo",
    "ti.ind.import.submit": "Importar",
    "ti.ind.import.invalidJson": "El texto no es JSON válido",
    "ti.ind.import.invalidBundle": "El bundle debe ser un objeto JSON STIX",
    "ti.ind.import.empty": "Añade contenido para importar",
    "ti.ind.import.tooBig": "El archivo supera el límite de 5 MB",
    "ti.ind.import.success": "Importación completada",
    "ti.ind.import.failed": "No se pudo completar la importación",
    "ti.ind.import.result": "Resultado",
    "ti.ind.import.created": "Creados",
    "ti.ind.import.updated": "Actualizados",
    "ti.ind.import.skipped": "Omitidos",
    "ti.ind.import.received": "Recibidos",
    "ti.ind.import.errors": "Errores",
    "ti.ind.import.noErrors": "Sin errores",
    "ti.ind.import.none": "Sin importación ejecutada",
    "ti.enrich.title": "Enriquecimiento",
    "ti.enrich.subtitle": "Comprueba un valor contra la inteligencia activa de la organización y global.",
    "ti.enrich.value": "Valor",
    "ti.enrich.placeholder": "IP, dominio, URL, hash o email",
    "ti.enrich.type": "Tipo",
    "ti.enrich.auto": "Detección automática",
    "ti.enrich.submit": "Comprobar",
    "ti.enrich.verdict.malicious": "Malicioso",
    "ti.enrich.verdict.suspicious": "Sospechoso",
    "ti.enrich.verdict.unknown": "Desconocido",
    "ti.enrich.unknown": "Valor desconocido",
    "ti.enrich.unknownHint": "No hay coincidencias con indicadores activos. Esto no certifica que el valor sea benigno.",
    "ti.enrich.confidence": "Confianza",
    "ti.enrich.actor": "Actor atribuido",
    "ti.enrich.reason": "Motivo",
    "ti.enrich.evidence": "Evidencia",
    "ti.enrich.matches": "coincidencias",
    "ti.enrich.none": "Sin coincidencias",
    "ti.enrich.techniques": "Técnicas observadas",
    "ti.enrich.events": "Eventos operativos relacionados",
    "ti.enrich.error": "No se pudo enriquecer el valor",
    "ti.enrich.scope.global": "Global",
    "ti.enrich.scope.organization": "Organización",
    "ti.actors.search": "Buscar por nombre o alias…",
    "ti.actors.new": "Nuevo actor",
    "ti.actors.count": "actores",
    "ti.actors.col.name": "Actor",
    "ti.actors.col.mitre": "ID MITRE",
    "ti.actors.col.country": "País",
    "ti.actors.col.sophistication": "Sofisticación",
    "ti.actors.col.motivation": "Motivación",
    "ti.actors.col.techniques": "Técnicas",
    "ti.actors.col.actions": "Acciones",
    "ti.actors.empty": "Sin actores registrados",
    "ti.actors.emptyHint": "Crea un actor para atribuir indicadores y contextualizar campañas.",
    "ti.actors.loadFailed": "No se pudieron cargar los actores",
    "ti.actors.detail.title": "Detalle del actor",
    "ti.actors.detail.indicators": "Indicadores atribuidos",
    "ti.actors.detail.aliases": "Alias",
    "ti.actors.detail.description": "Descripción",
    "ti.actors.detail.none": "Sin datos",
    "ti.actors.edit": "Editar actor",
    "ti.actors.delete": "Eliminar actor",
    "ti.actors.deleteTitle": "Eliminar actor",
    "ti.actors.deleteDescription": "El actor se elimina del catálogo y los indicadores quedan sin atribución. La operación queda auditada.",
    "ti.actors.deleteConfirm": "Eliminar",
    "ti.actors.deleted": "Actor eliminado",
    "ti.actors.deleteFailed": "No se pudo eliminar el actor",
    "ti.actors.editor.createTitle": "Nuevo actor",
    "ti.actors.editor.editTitle": "Editar actor",
    "ti.actors.editor.name": "Nombre",
    "ti.actors.editor.mitre": "ID MITRE",
    "ti.actors.editor.mitreHint": "Formato G1234, S1234 o T1234",
    "ti.actors.editor.aliases": "Alias",
    "ti.actors.editor.aliasesHint": "Separados por comas",
    "ti.actors.editor.description": "Descripción",
    "ti.actors.editor.sophistication": "Sofisticación",
    "ti.actors.editor.motivation": "Motivación",
    "ti.actors.editor.country": "País",
    "ti.actors.editor.techniques": "Técnicas ATT&CK",
    "ti.actors.editor.techniquesHint": "IDs separados por comas (p. ej. T1566, T1059.001)",
    "ti.actors.editor.submitCreate": "Crear actor",
    "ti.actors.editor.submitSave": "Guardar cambios",
    "ti.actors.editor.created": "Actor creado",
    "ti.actors.editor.updated": "Actor actualizado",
    "ti.actors.editor.failed": "No se pudo guardar el actor",
    "ti.actors.editor.required": "Obligatorio",
    "ti.actors.editor.invalidMitre": "ID MITRE no válido",
    "ti.actors.editor.invalidTechnique": "Técnica no válida",
    "ti.feeds.new": "Nueva fuente",
    "ti.feeds.count": "fuentes",
    "ti.feeds.col.name": "Fuente",
    "ti.feeds.col.kind": "Tipo",
    "ti.feeds.col.enabled": "Activa",
    "ti.feeds.col.schedule": "Intervalo",
    "ti.feeds.col.status": "Estado",
    "ti.feeds.col.lastSync": "Última sincronización",
    "ti.feeds.col.lastError": "Último error",
    "ti.feeds.col.actions": "Acciones",
    "ti.feeds.empty": "Sin fuentes configuradas",
    "ti.feeds.emptyHint": "Conecta MISP, OpenCTI, TAXII, STIX o CSV para alimentar la inteligencia.",
    "ti.feeds.loadFailed": "No se pudieron cargar las fuentes",
    "ti.feeds.sync": "Sincronizar",
    "ti.feeds.synced": "Sincronización completada",
    "ti.feeds.syncFailed": "No se pudo sincronizar la fuente",
    "ti.feeds.objectsRead": "objetos leídos",
    "ti.feeds.enabledOk": "Fuente activada",
    "ti.feeds.disabledOk": "Fuente desactivada",
    "ti.feeds.toggleFailed": "No se pudo cambiar el estado de la fuente",
    "ti.feeds.status.idle": "Sin sincronizar",
    "ti.feeds.status.success": "Correcta",
    "ti.feeds.status.error": "Error",
    "ti.feeds.lastErrorNone": "—",
    "ti.feeds.minutes": "min",
    "ti.feeds.create.title": "Nueva fuente de inteligencia",
    "ti.feeds.create.name": "Nombre",
    "ti.feeds.create.kind": "Tipo de fuente",
    "ti.feeds.create.schedule": "Intervalo (min)",
    "ti.feeds.create.scheduleHint": "Entre 5 y 1440 minutos",
    "ti.feeds.create.enabled": "Activa",
    "ti.feeds.create.config": "Configuración",
    "ti.feeds.create.configHint": "Objeto JSON con claves admitidas (url, token, headers…)",
    "ti.feeds.create.configInvalid": "La configuración debe ser un objeto JSON",
    "ti.feeds.create.submit": "Crear fuente",
    "ti.feeds.create.created": "Fuente creada",
    "ti.feeds.create.failed": "No se pudo crear la fuente",
    "ti.mitre.coverage": "Cobertura ATT&CK",
    "ti.mitre.coverageHint": "Técnicas observadas en eventos, indicadores y actores de la organización.",
    "ti.mitre.covered": "Técnicas cubiertas",
    "ti.mitre.catalog": "Catálogo",
    "ti.mitre.percent": "Cobertura",
    "ti.mitre.coveredTable": "Técnicas observadas",
    "ti.mitre.catalogTable": "Catálogo de técnicas",
    "ti.mitre.col.id": "ID",
    "ti.mitre.col.name": "Técnica",
    "ti.mitre.col.tactics": "Tácticas",
    "ti.mitre.col.events": "Eventos",
    "ti.mitre.col.indicators": "Indicadores",
    "ti.mitre.col.actors": "Actores",
    "ti.mitre.col.description": "Descripción",
    "ti.mitre.search": "Buscar técnica por ID, nombre o descripción…",
    "ti.mitre.tactic": "Táctica",
    "ti.mitre.allTactics": "Todas las tácticas",
    "ti.mitre.empty": "Sin técnicas observadas",
    "ti.mitre.emptyHint": "La cobertura se calcula a partir de telemetría, indicadores y actores reales.",
    "ti.mitre.loadFailed": "No se pudo cargar la cobertura ATT&CK",
    "ti.mitre.techniquesFailed": "No se pudo cargar el catálogo de técnicas",
    "ti.mitre.uncovered": "sin observaciones",
    "ti.mitre.count": "técnicas",
  },
  en: {
    "ti.eyebrow": "Detection · Intelligence",
    "ti.title": "Threat intelligence",
    "ti.subtitle": "Indicators, actors, feeds and ATT&CK coverage with explainable enrichment and no fabricated data.",
    "ti.kpi.active": "Active indicators",
    "ti.kpi.total": "Total indicators",
    "ti.kpi.actors": "Actors",
    "ti.kpi.coverage": "ATT&CK coverage",
    "ti.kpi.expired": "Expired",
    "ti.tab.indicators": "Indicators",
    "ti.tab.actors": "Actors",
    "ti.tab.feeds": "Feeds",
    "ti.tab.mitre": "MITRE ATT&CK",
    "ti.ind.search": "Search by value…",
    "ti.ind.filter.type": "Type",
    "ti.ind.filter.severity": "Severity",
    "ti.ind.filter.source": "Source",
    "ti.ind.filter.active": "Status",
    "ti.ind.filter.allTypes": "All types",
    "ti.ind.filter.allSeverities": "All severities",
    "ti.ind.filter.allSources": "All sources",
    "ti.ind.filter.allActive": "Active and inactive",
    "ti.ind.filter.activeOnly": "Active only",
    "ti.ind.filter.inactiveOnly": "Inactive only",
    "ti.ind.sourcePlaceholder": "Filter source",
    "ti.ind.new": "New indicator",
    "ti.ind.newShort": "New",
    "ti.ind.import": "Import",
    "ti.ind.count": "indicators",
    "ti.ind.col.indicator": "Indicator",
    "ti.ind.col.severity": "Severity",
    "ti.ind.col.confidence": "Confidence",
    "ti.ind.col.source": "Source",
    "ti.ind.col.actor": "Actor",
    "ti.ind.col.lastSeen": "Last seen",
    "ti.ind.col.status": "Status",
    "ti.ind.col.actions": "Actions",
    "ti.ind.global": "GLOBAL",
    "ti.ind.edit": "Edit indicator",
    "ti.ind.deactivate": "Deactivate indicator",
    "ti.ind.deactivateTitle": "Deactivate indicator",
    "ti.ind.deactivateDescription": "The indicator stops applying to correlation and enrichment. The row is kept for audit; you can reactivate it by editing.",
    "ti.ind.deactivated": "Indicator deactivated",
    "ti.ind.deactivateFailed": "Could not deactivate the indicator",
    "ti.ind.empty.title": "No indicators yet",
    "ti.ind.empty.description": "Create an indicator or import a STIX/CSV bundle to activate correlation.",
    "ti.ind.empty.action": "Import indicators",
    "ti.ind.noResults.title": "No indicator matches",
    "ti.ind.noResults.description": "Adjust the filters or clear the search.",
    "ti.ind.clear": "Clear filters",
    "ti.ind.loadFailed": "Could not load indicators",
    "ti.ind.status.active": "Active",
    "ti.ind.status.inactive": "Inactive",
    "ti.ind.editor.createTitle": "New indicator",
    "ti.ind.editor.editTitle": "Edit indicator",
    "ti.ind.editor.type": "Type",
    "ti.ind.editor.value": "Value",
    "ti.ind.editor.confidence": "Confidence (0-100)",
    "ti.ind.editor.severity": "Severity",
    "ti.ind.editor.source": "Source",
    "ti.ind.editor.description": "Description",
    "ti.ind.editor.tags": "Tags",
    "ti.ind.editor.tagsHint": "Comma separated (max. 20)",
    "ti.ind.editor.actor": "Associated actor",
    "ti.ind.editor.actorNone": "No actor",
    "ti.ind.editor.active": "Active",
    "ti.ind.editor.submitCreate": "Create indicator",
    "ti.ind.editor.submitSave": "Save changes",
    "ti.ind.editor.created": "Indicator created",
    "ti.ind.editor.updated": "Indicator updated",
    "ti.ind.editor.failed": "Could not save the indicator",
    "ti.ind.editor.required": "Required",
    "ti.ind.editor.invalidConfidence": "Confidence must be between 0 and 100",
    "ti.ind.import.title": "Import indicators",
    "ti.ind.import.description": "STIX 2.1 bundles and CSV are validated row by row server-side; errors do not discard the whole batch.",
    "ti.ind.import.tab.stix": "STIX bundle",
    "ti.ind.import.tab.csv": "CSV",
    "ti.ind.import.stixHint": "STIX 2.1 JSON object with type=bundle.",
    "ti.ind.import.csvHint": "CSV with columns type,value[,severity,confidence,source,description,tags].",
    "ti.ind.import.file": "Load from file",
    "ti.ind.import.submit": "Import",
    "ti.ind.import.invalidJson": "The text is not valid JSON",
    "ti.ind.import.invalidBundle": "The bundle must be a STIX JSON object",
    "ti.ind.import.empty": "Add content to import",
    "ti.ind.import.tooBig": "The file exceeds the 5 MB limit",
    "ti.ind.import.success": "Import completed",
    "ti.ind.import.failed": "The import could not be completed",
    "ti.ind.import.result": "Result",
    "ti.ind.import.created": "Created",
    "ti.ind.import.updated": "Updated",
    "ti.ind.import.skipped": "Skipped",
    "ti.ind.import.received": "Received",
    "ti.ind.import.errors": "Errors",
    "ti.ind.import.noErrors": "No errors",
    "ti.ind.import.none": "No import executed",
    "ti.enrich.title": "Enrichment",
    "ti.enrich.subtitle": "Check a value against the organization and global active intelligence.",
    "ti.enrich.value": "Value",
    "ti.enrich.placeholder": "IP, domain, URL, hash or email",
    "ti.enrich.type": "Type",
    "ti.enrich.auto": "Automatic detection",
    "ti.enrich.submit": "Check",
    "ti.enrich.verdict.malicious": "Malicious",
    "ti.enrich.verdict.suspicious": "Suspicious",
    "ti.enrich.verdict.unknown": "Unknown",
    "ti.enrich.unknown": "Unknown value",
    "ti.enrich.unknownHint": "No matches against active indicators. This does not certify the value is benign.",
    "ti.enrich.confidence": "Confidence",
    "ti.enrich.actor": "Attributed actor",
    "ti.enrich.reason": "Reason",
    "ti.enrich.evidence": "Evidence",
    "ti.enrich.matches": "matches",
    "ti.enrich.none": "No matches",
    "ti.enrich.techniques": "Observed techniques",
    "ti.enrich.events": "Related operational events",
    "ti.enrich.error": "Could not enrich the value",
    "ti.enrich.scope.global": "Global",
    "ti.enrich.scope.organization": "Organization",
    "ti.actors.search": "Search by name or alias…",
    "ti.actors.new": "New actor",
    "ti.actors.count": "actors",
    "ti.actors.col.name": "Actor",
    "ti.actors.col.mitre": "MITRE ID",
    "ti.actors.col.country": "Country",
    "ti.actors.col.sophistication": "Sophistication",
    "ti.actors.col.motivation": "Motivation",
    "ti.actors.col.techniques": "Techniques",
    "ti.actors.col.actions": "Actions",
    "ti.actors.empty": "No actors registered",
    "ti.actors.emptyHint": "Create an actor to attribute indicators and contextualize campaigns.",
    "ti.actors.loadFailed": "Could not load actors",
    "ti.actors.detail.title": "Actor detail",
    "ti.actors.detail.indicators": "Attributed indicators",
    "ti.actors.detail.aliases": "Aliases",
    "ti.actors.detail.description": "Description",
    "ti.actors.detail.none": "No data",
    "ti.actors.edit": "Edit actor",
    "ti.actors.delete": "Delete actor",
    "ti.actors.deleteTitle": "Delete actor",
    "ti.actors.deleteDescription": "The actor is removed from the catalogue and indicators lose attribution. The action is audited.",
    "ti.actors.deleteConfirm": "Delete",
    "ti.actors.deleted": "Actor deleted",
    "ti.actors.deleteFailed": "Could not delete the actor",
    "ti.actors.editor.createTitle": "New actor",
    "ti.actors.editor.editTitle": "Edit actor",
    "ti.actors.editor.name": "Name",
    "ti.actors.editor.mitre": "MITRE ID",
    "ti.actors.editor.mitreHint": "Format G1234, S1234 or T1234",
    "ti.actors.editor.aliases": "Aliases",
    "ti.actors.editor.aliasesHint": "Comma separated",
    "ti.actors.editor.description": "Description",
    "ti.actors.editor.sophistication": "Sophistication",
    "ti.actors.editor.motivation": "Motivation",
    "ti.actors.editor.country": "Country",
    "ti.actors.editor.techniques": "ATT&CK techniques",
    "ti.actors.editor.techniquesHint": "Comma separated IDs (e.g. T1566, T1059.001)",
    "ti.actors.editor.submitCreate": "Create actor",
    "ti.actors.editor.submitSave": "Save changes",
    "ti.actors.editor.created": "Actor created",
    "ti.actors.editor.updated": "Actor updated",
    "ti.actors.editor.failed": "Could not save the actor",
    "ti.actors.editor.required": "Required",
    "ti.actors.editor.invalidMitre": "Invalid MITRE ID",
    "ti.actors.editor.invalidTechnique": "Invalid technique",
    "ti.feeds.new": "New feed",
    "ti.feeds.count": "feeds",
    "ti.feeds.col.name": "Feed",
    "ti.feeds.col.kind": "Kind",
    "ti.feeds.col.enabled": "Enabled",
    "ti.feeds.col.schedule": "Interval",
    "ti.feeds.col.status": "Status",
    "ti.feeds.col.lastSync": "Last sync",
    "ti.feeds.col.lastError": "Last error",
    "ti.feeds.col.actions": "Actions",
    "ti.feeds.empty": "No feeds configured",
    "ti.feeds.emptyHint": "Connect MISP, OpenCTI, TAXII, STIX or CSV to feed intelligence.",
    "ti.feeds.loadFailed": "Could not load feeds",
    "ti.feeds.sync": "Sync",
    "ti.feeds.synced": "Synchronization completed",
    "ti.feeds.syncFailed": "Could not synchronize the feed",
    "ti.feeds.objectsRead": "objects read",
    "ti.feeds.enabledOk": "Feed enabled",
    "ti.feeds.disabledOk": "Feed disabled",
    "ti.feeds.toggleFailed": "Could not change the feed state",
    "ti.feeds.status.idle": "Never synced",
    "ti.feeds.status.success": "Success",
    "ti.feeds.status.error": "Error",
    "ti.feeds.lastErrorNone": "—",
    "ti.feeds.minutes": "min",
    "ti.feeds.create.title": "New intelligence feed",
    "ti.feeds.create.name": "Name",
    "ti.feeds.create.kind": "Feed kind",
    "ti.feeds.create.schedule": "Interval (min)",
    "ti.feeds.create.scheduleHint": "Between 5 and 1440 minutes",
    "ti.feeds.create.enabled": "Enabled",
    "ti.feeds.create.config": "Configuration",
    "ti.feeds.create.configHint": "JSON object with supported keys (url, token, headers…)",
    "ti.feeds.create.configInvalid": "Configuration must be a JSON object",
    "ti.feeds.create.submit": "Create feed",
    "ti.feeds.create.created": "Feed created",
    "ti.feeds.create.failed": "Could not create the feed",
    "ti.mitre.coverage": "ATT&CK coverage",
    "ti.mitre.coverageHint": "Techniques observed in the organization's events, indicators and actors.",
    "ti.mitre.covered": "Covered techniques",
    "ti.mitre.catalog": "Catalogue",
    "ti.mitre.percent": "Coverage",
    "ti.mitre.coveredTable": "Observed techniques",
    "ti.mitre.catalogTable": "Technique catalogue",
    "ti.mitre.col.id": "ID",
    "ti.mitre.col.name": "Technique",
    "ti.mitre.col.tactics": "Tactics",
    "ti.mitre.col.events": "Events",
    "ti.mitre.col.indicators": "Indicators",
    "ti.mitre.col.actors": "Actors",
    "ti.mitre.col.description": "Description",
    "ti.mitre.search": "Search techniques by ID, name or description…",
    "ti.mitre.tactic": "Tactic",
    "ti.mitre.allTactics": "All tactics",
    "ti.mitre.empty": "No observed techniques",
    "ti.mitre.emptyHint": "Coverage is computed from real telemetry, indicators and actors.",
    "ti.mitre.loadFailed": "Could not load ATT&CK coverage",
    "ti.mitre.techniquesFailed": "Could not load the technique catalogue",
    "ti.mitre.uncovered": "unobserved",
    "ti.mitre.count": "techniques",
  },
} as const;

const INDICATOR_TYPES = ["ip", "domain", "url", "sha256", "sha1", "md5", "email"] as const;
const INDICATOR_SEVERITIES = ["low", "medium", "high", "critical"] as const;
const FEED_KINDS = ["misp", "opencti", "taxii", "csv", "stix"] as const;
const MITRE_ID_RE = /^[GST]\d{4}$/;
const TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;

type TabKey = "indicators" | "actors" | "feeds" | "mitre";

function copyOr(copy: (key: string) => string, key: string, fallback: string): string {
  const translated = copy(key);
  return translated === key ? fallback : translated;
}

export function ThreatIntelPage() {
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const [tab, setTab] = useState<TabKey>("indicators");

  const summaryQuery = useQuery({
    queryKey: ["threat-intel", "summary"],
    queryFn: () => api.get<IntelSummary>("/threat-intel/summary"),
  });

  const summary = summaryQuery.data;

  return (
    <div className="animate-in" data-testid="page-threat-intel">
      <PageHeader
        eyebrow={c("ti.eyebrow")}
        title={c("ti.title")}
        subtitle={c("ti.subtitle")}
        actions={
          <Button icon={RefreshCw} onClick={() => void summaryQuery.refetch()} aria-label={t("common.refresh")} data-testid="refresh-threat-intel" />
        }
      />

      <div className="kpi-grid" style={{ marginBottom: 12 }}>
        <Kpi
          label={c("ti.kpi.active")}
          value={summary ? formatNumber(summary.indicators.active) : "—"}
          icon={Radar}
          tone="success"
          footer={<span>{formatNumber(summary?.indicators.expired ?? 0)} {c("ti.kpi.expired").toLowerCase()}</span>}
        />
        <Kpi
          label={c("ti.kpi.total")}
          value={summary ? formatNumber(summary.indicators.total) : "—"}
          icon={Fingerprint}
          tone="accent"
          footer={<span>{formatNumber(Object.keys(summary?.indicators.by_type ?? {}).length)} {lang === "es" ? "tipos" : "types"}</span>}
        />
        <Kpi
          label={c("ti.kpi.actors")}
          value={summary ? formatNumber(summary.actors.total) : "—"}
          icon={Users}
          tone="warning"
          footer={<span>{formatNumber(summary?.feeds.total ?? 0)} {c("ti.feeds.count")}</span>}
        />
        <Kpi
          label={c("ti.kpi.coverage")}
          value={summary ? formatPercent(summary.mitre.coverage_percent, 1) : "—"}
          icon={Target}
          tone="accent"
          footer={<span>{formatNumber(summary?.mitre.covered_count ?? 0)} / {formatNumber(summary?.mitre.catalog_size ?? 0)}</span>}
        />
      </div>

      {summaryQuery.isError ? (
        <div style={{ marginBottom: 12 }}>
          <ErrorBanner compact message={errorMessage(summaryQuery.error)} onRetry={() => void summaryQuery.refetch()} />
        </div>
      ) : null}

      <div style={{ marginBottom: 12 }}>
        <Tabs
          items={[
            { key: "indicators" as TabKey, label: c("ti.tab.indicators"), count: summary?.indicators.total },
            { key: "actors" as TabKey, label: c("ti.tab.actors"), count: summary?.actors.total },
            { key: "feeds" as TabKey, label: c("ti.tab.feeds"), count: summary?.feeds.total },
            { key: "mitre" as TabKey, label: c("ti.tab.mitre"), count: summary?.mitre.covered_count },
          ]}
          value={tab}
          onChange={setTab}
          ariaLabel={c("ti.title")}
        />
      </div>

      {tab === "indicators" ? <IndicatorsPanel /> : null}
      {tab === "actors" ? <ActorsPanel /> : null}
      {tab === "feeds" ? <FeedsPanel /> : null}
      {tab === "mitre" ? <MitrePanel /> : null}
    </div>
  );
}

/* ------------------------------------------------------------------ indicators */

function IndicatorsPanel() {
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const canWrite = can("ti:write");

  const [search, setSearch] = useState("");
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [active, setActive] = useState("");
  const [page, setPage] = useState(1);
  const debouncedSearch = useDebouncedValue(search);
  const debouncedSource = useDebouncedValue(source, 450);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<Indicator | null>(null);
  const [draft, setDraft] = useState({
    indicator_type: "ip",
    value: "",
    confidence: "50",
    severity: "medium",
    source: "manual",
    description: "",
    tags: "",
    actor_id: "",
    active: true,
  });
  const [editorErrors, setEditorErrors] = useState<Record<string, string>>({});

  const [importOpen, setImportOpen] = useState(false);
  const [importTab, setImportTab] = useState<"stix" | "csv">("stix");
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<IntelImportResult | null>(null);

  const [deactivateTarget, setDeactivateTarget] = useState<Indicator | null>(null);

  const [enrichValue, setEnrichValue] = useState("");
  const [enrichType, setEnrichType] = useState("auto");
  const [enrichSubmitted, setEnrichSubmitted] = useState<{ value: string; type: string } | null>(null);
  const [enrichAttempt, setEnrichAttempt] = useState(0);

  const listQuery = useQuery({
    queryKey: ["threat-intel", "indicators", { page, search: debouncedSearch, type, severity, source: debouncedSource, active }],
    queryFn: () =>
      api.get<Page<Indicator>>("/threat-intel/indicators", {
        page,
        page_size: 20,
        q: debouncedSearch || undefined,
        type: type || undefined,
        severity: severity || undefined,
        source: debouncedSource || undefined,
        active: active === "" ? undefined : active === "true",
      }),
  });

  const actorsQuery = useQuery({
    queryKey: ["threat-intel", "actors", "options"],
    queryFn: () => api.get<Page<ThreatActor>>("/threat-intel/actors", { page: 1, page_size: 100 }),
    staleTime: 60_000,
  });

  const enrichQuery = useQuery({
    queryKey: ["threat-intel", "enrich", enrichSubmitted, enrichAttempt],
    queryFn: () =>
      api.get<Enrichment>("/threat-intel/enrich", {
        value: enrichSubmitted?.value,
        type: enrichSubmitted && enrichSubmitted.type !== "auto" ? enrichSubmitted.type : undefined,
      }),
    enabled: enrichSubmitted !== null,
  });

  const createIndicator = useMutation({
    mutationFn: () =>
      api.post<Indicator>("/threat-intel/indicators", {
        indicator_type: draft.indicator_type,
        value: draft.value.trim(),
        confidence: Number(draft.confidence),
        severity: draft.severity,
        source: draft.source.trim() || "manual",
        description: draft.description.trim() || null,
        tags: draft.tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        actor_id: draft.actor_id || null,
        active: draft.active,
      }),
    onSuccess: () => {
      push(c("ti.ind.editor.created"), "success");
      setEditorOpen(false);
      setEditorErrors({});
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => {
      setEditorErrors(fieldErrors(error));
      push(`${c("ti.ind.editor.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const updateIndicator = useMutation({
    mutationFn: (indicator: Indicator) =>
      api.patch<Indicator>(`/threat-intel/indicators/${indicator.id}`, {
        confidence: Number(draft.confidence),
        severity: draft.severity,
        source: draft.source.trim() || "manual",
        description: draft.description.trim() || null,
        tags: draft.tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        actor_id: draft.actor_id || null,
        active: draft.active,
      }),
    onSuccess: () => {
      push(c("ti.ind.editor.updated"), "success");
      setEditorOpen(false);
      setEditorErrors({});
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => {
      setEditorErrors(fieldErrors(error));
      push(`${c("ti.ind.editor.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const deactivate = useMutation({
    mutationFn: (id: string) => api.post<{ id: string; active: boolean; message: string }>(`/threat-intel/indicators/${id}/deactivate`),
    onSuccess: () => {
      push(c("ti.ind.deactivated"), "success");
      setDeactivateTarget(null);
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => push(`${c("ti.ind.deactivateFailed")}: ${errorMessage(error)}`, "error"),
  });

  const importIndicators = useMutation({
    mutationFn: async () => {
      if (importTab === "stix") {
        return api.post<IntelImportResult>("/threat-intel/indicators/import", { bundle: JSON.parse(importText) as Record<string, unknown> });
      }
      return api.post<IntelImportResult>("/threat-intel/indicators/import/csv", { csv: importText });
    },
    onSuccess: (result) => {
      setImportResult(result);
      push(`${c("ti.ind.import.success")}: ${result.created} / ${result.updated}`, "success");
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => {
      setImportError(errorMessage(error));
      push(`${c("ti.ind.import.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const rows = listQuery.data?.items ?? [];
  const actors = actorsQuery.data?.items ?? [];
  const actorById = new Map(actors.map((actor) => [actor.id, actor]));
  const filtersActive = Boolean(debouncedSearch || type || severity || debouncedSource || active);

  const applyFilter = (setter: (value: string) => void) => (value: string) => {
    setter(value);
    setPage(1);
  };

  const clearFilters = () => {
    setSearch("");
    setType("");
    setSeverity("");
    setSource("");
    setActive("");
    setPage(1);
  };

  const openCreate = () => {
    setEditing(null);
    setDraft({
      indicator_type: "ip",
      value: "",
      confidence: "50",
      severity: "medium",
      source: "manual",
      description: "",
      tags: "",
      actor_id: "",
      active: true,
    });
    setEditorErrors({});
    setEditorOpen(true);
  };

  const openEdit = (indicator: Indicator) => {
    setEditing(indicator);
    setDraft({
      indicator_type: indicator.indicator_type,
      value: indicator.value,
      confidence: String(indicator.confidence),
      severity: indicator.severity,
      source: indicator.source,
      description: indicator.description ?? "",
      tags: indicator.tags.join(", "),
      actor_id: indicator.actor_id ?? "",
      active: indicator.active,
    });
    setEditorErrors({});
    setEditorOpen(true);
  };

  const columns: Column<Indicator>[] = [
    {
      key: "indicator",
      header: c("ti.ind.col.indicator"),
      render: (row) => (
        <div style={{ minWidth: 210 }}>
          <div className="row wrap" style={{ gap: 4 }}>
            <span className="tag">{row.indicator_type}</span>
            <span
              className="mono"
              title={row.value}
              style={{ fontSize: 11, color: "var(--text)", maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
            >
              {row.value}
            </span>
          </div>
          <div className="row wrap" style={{ gap: 4, marginTop: 4 }}>
            {row.org_id === null ? <Badge tone="accent">{c("ti.ind.global")}</Badge> : null}
            {row.is_demo || row.source.toLowerCase() === "demo" || row.tags.some((tag) => tag.toLowerCase() === "demo") ? (
              <Badge tone="amber">DEMO</Badge>
            ) : null}
            {row.tags.slice(0, 3).map((tag) => (
              <span className="tag" key={tag}>{tag}</span>
            ))}
          </div>
        </div>
      ),
    },
    { key: "severity", header: c("ti.ind.col.severity"), width: "104px", render: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "confidence",
      header: c("ti.ind.col.confidence"),
      width: "118px",
      render: (row) => (
        <div style={{ minWidth: 70 }}>
          <div className="mono" style={{ fontSize: 10.5, marginBottom: 4 }}>{row.confidence}%</div>
          <ProgressBar value={row.confidence} tone={row.confidence >= 70 ? "var(--danger)" : row.confidence >= 40 ? "var(--warning)" : "var(--accent)"} />
        </div>
      ),
    },
    {
      key: "source",
      header: c("ti.ind.col.source"),
      width: "120px",
      render: (row) => <span style={{ fontSize: 11 }}>{row.source}</span>,
    },
    {
      key: "actor",
      header: c("ti.ind.col.actor"),
      width: "140px",
      render: (row) => {
        const actor = row.actor_id ? actorById.get(row.actor_id) : null;
        return actor ? (
          <span style={{ fontSize: 11.5 }}>{actor.name}</span>
        ) : (
          <span className="dim" style={{ fontSize: 11 }}>—</span>
        );
      },
    },
    {
      key: "last_seen",
      header: c("ti.ind.col.lastSeen"),
      width: "118px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }} title={row.last_seen}>{relativeTime(row.last_seen, lang)}</span>,
    },
    {
      key: "status",
      header: c("ti.ind.col.status"),
      width: "100px",
      render: (row) => (
        <StatusBadge status={row.active ? "active" : "disabled"} label={row.active ? c("ti.ind.status.active") : c("ti.ind.status.inactive")} />
      ),
    },
    {
      key: "actions",
      header: c("ti.ind.col.actions"),
      width: "96px",
      align: "right",
      render: (row) =>
        canWrite ? (
          <div className="row" style={{ gap: 2, justifyContent: "flex-end" }}>
            <Button
              size="sm"
              variant="ghost"
              icon={SquarePen}
              aria-label={c("ti.ind.edit")}
              title={c("ti.ind.edit")}
              onClick={() => openEdit(row)}
            />
            <Button
              size="sm"
              variant="ghost"
              icon={ShieldOff}
              aria-label={c("ti.ind.deactivate")}
              title={c("ti.ind.deactivate")}
              disabled={!row.active}
              onClick={() => setDeactivateTarget(row)}
            />
          </div>
        ) : null,
    },
  ];

  return (
    <div className="split-main">
      <Card
        title={c("ti.tab.indicators")}
        subtitle={listQuery.data ? `${formatNumber(listQuery.data.meta.total)} ${c("ti.ind.count")}` : undefined}
        actions={
          canWrite ? (
            <>
              <Button
                size="sm"
                icon={Upload}
                aria-label={c("ti.ind.import")}
                title={c("ti.ind.import")}
                onClick={() => {
                  setImportText("");
                  setImportError(null);
                  setImportResult(null);
                  setImportOpen(true);
                }}
                data-testid="open-indicator-import"
              />
              <Button size="sm" variant="primary" icon={Plus} onClick={openCreate} data-testid="open-indicator-create">
                {c("ti.ind.newShort")}
              </Button>
            </>
          ) : undefined
        }
        bodyClassName=""
      >
        <FilterBar ariaLabel={t("common.filters")}>
          <SearchInput value={search} onChange={applyFilter(setSearch)} placeholder={c("ti.ind.search")} ariaLabel={c("ti.ind.search")} />
          <Select value={type} onChange={(event) => applyFilter(setType)(event.target.value)} aria-label={c("ti.ind.filter.type")} data-testid="filter-type">
            <option value="">{c("ti.ind.filter.allTypes")}</option>
            {INDICATOR_TYPES.map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </Select>
          <Select
            value={severity}
            onChange={(event) => applyFilter(setSeverity)(event.target.value)}
            aria-label={c("ti.ind.filter.severity")}
            data-testid="filter-severity"
          >
            <option value="">{c("ti.ind.filter.allSeverities")}</option>
            {INDICATOR_SEVERITIES.map((value) => (
              <option key={value} value={value}>{t(`common.${value}`)}</option>
            ))}
          </Select>
          <input
            className="input"
            style={{ width: "auto", minWidth: 130, height: 30, paddingTop: 0, paddingBottom: 0, fontSize: 11.5 }}
            value={source}
            onChange={(event) => applyFilter(setSource)(event.target.value)}
            placeholder={c("ti.ind.sourcePlaceholder")}
            aria-label={c("ti.ind.filter.source")}
            data-testid="filter-source"
          />
          <Select value={active} onChange={(event) => applyFilter(setActive)(event.target.value)} aria-label={c("ti.ind.filter.active")} data-testid="filter-active">
            <option value="">{c("ti.ind.filter.allActive")}</option>
            <option value="true">{c("ti.ind.filter.activeOnly")}</option>
            <option value="false">{c("ti.ind.filter.inactiveOnly")}</option>
          </Select>
          {filtersActive ? (
            <Button size="sm" variant="ghost" onClick={clearFilters} data-testid="clear-filters">
              {c("ti.ind.clear")}
            </Button>
          ) : null}
        </FilterBar>

        <div data-testid="table-indicators">
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(row) => row.id}
            loading={listQuery.isLoading}
            error={
              listQuery.isError ? (
                <ErrorBanner
                  title={c("ti.ind.loadFailed")}
                  message={errorMessage(listQuery.error)}
                  onRetry={() => void listQuery.refetch()}
                />
              ) : undefined
            }
            empty={
              filtersActive ? (
                <EmptyState
                  icon={Filter}
                  title={c("ti.ind.noResults.title")}
                  description={c("ti.ind.noResults.description")}
                  action={<Button size="sm" variant="primary" onClick={clearFilters}>{c("ti.ind.clear")}</Button>}
                />
              ) : (
                <EmptyState
                  icon={Crosshair}
                  title={c("ti.ind.empty.title")}
                  description={c("ti.ind.empty.description")}
                  action={
                    canWrite ? (
                      <Button size="sm" variant="primary" icon={Upload} onClick={() => setImportOpen(true)}>
                        {c("ti.ind.empty.action")}
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

      <Card title={c("ti.enrich.title")}>
        <div className="stack">
          <p className="muted" style={{ fontSize: 11.5 }}>{c("ti.enrich.subtitle")}</p>
          <Field label={c("ti.enrich.value")} htmlFor="enrich-value" required>
            <Input
              id="enrich-value"
              className="mono"
              value={enrichValue}
              placeholder={c("ti.enrich.placeholder")}
              onChange={(event) => setEnrichValue(event.target.value)}
              data-testid="enrich-value"
            />
          </Field>
          <div className="row wrap" style={{ gap: 8 }}>
            <Select
              value={enrichType}
              onChange={(event) => setEnrichType(event.target.value)}
              aria-label={c("ti.enrich.type")}
              style={{ maxWidth: 180 }}
              data-testid="enrich-type"
            >
              <option value="auto">{c("ti.enrich.auto")}</option>
              {INDICATOR_TYPES.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </Select>
            <Button
              variant="primary"
              icon={Crosshair}
              disabled={!enrichValue.trim()}
              loading={enrichQuery.isFetching}
              onClick={() => {
                setEnrichSubmitted({ value: enrichValue.trim(), type: enrichType });
                setEnrichAttempt((value) => value + 1);
              }}
              data-testid="enrich-submit"
            >
              {c("ti.enrich.submit")}
            </Button>
          </div>

          {enrichQuery.isError ? (
            <ErrorBanner
              compact
              title={c("ti.enrich.error")}
              message={errorMessage(enrichQuery.error)}
              onRetry={() => void enrichQuery.refetch()}
            />
          ) : enrichQuery.data ? (
            <EnrichmentView data={enrichQuery.data} />
          ) : (
            <p className="dim" style={{ fontSize: 11.5 }}>{c("ti.enrich.unknownHint")}</p>
          )}
        </div>
      </Card>

      <Modal
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        title={editing ? c("ti.ind.editor.editTitle") : c("ti.ind.editor.createTitle")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditorOpen(false)} disabled={createIndicator.isPending || updateIndicator.isPending}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              loading={createIndicator.isPending || updateIndicator.isPending}
              onClick={() => {
                const errors: Record<string, string> = {};
                if (!editing && !draft.value.trim()) errors.value = c("ti.ind.editor.required");
                const confidence = Number(draft.confidence);
                if (!Number.isFinite(confidence) || confidence < 0 || confidence > 100) {
                  errors.confidence = c("ti.ind.editor.invalidConfidence");
                }
                setEditorErrors(errors);
                if (Object.keys(errors).length) return;
                if (editing) updateIndicator.mutate(editing);
                else createIndicator.mutate();
              }}
              data-testid="submit-indicator"
            >
              {editing ? c("ti.ind.editor.submitSave") : c("ti.ind.editor.submitCreate")}
            </Button>
          </>
        }
      >
        <div className="form-grid">
          <Field label={c("ti.ind.editor.type")} htmlFor="indicator-type" required error={editorErrors.indicator_type}>
            <Select
              id="indicator-type"
              value={draft.indicator_type}
              disabled={Boolean(editing)}
              onChange={(event) => setDraft({ ...draft, indicator_type: event.target.value })}
              data-testid="input-indicator-type"
            >
              {INDICATOR_TYPES.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </Select>
          </Field>
          <Field label={c("ti.ind.editor.value")} htmlFor="indicator-value" required error={editorErrors.value}>
            <Input
              id="indicator-value"
              className="mono"
              value={draft.value}
              maxLength={500}
              disabled={Boolean(editing)}
              onChange={(event) => setDraft({ ...draft, value: event.target.value })}
              aria-invalid={Boolean(editorErrors.value)}
              data-testid="input-indicator-value"
            />
          </Field>
          <Field label={c("ti.ind.editor.confidence")} htmlFor="indicator-confidence" error={editorErrors.confidence}>
            <Input
              id="indicator-confidence"
              type="number"
              min={0}
              max={100}
              value={draft.confidence}
              onChange={(event) => setDraft({ ...draft, confidence: event.target.value })}
            />
          </Field>
          <Field label={c("ti.ind.editor.severity")} htmlFor="indicator-severity">
            <Select id="indicator-severity" value={draft.severity} onChange={(event) => setDraft({ ...draft, severity: event.target.value })}>
              {INDICATOR_SEVERITIES.map((value) => (
                <option key={value} value={value}>{t(`common.${value}`)}</option>
              ))}
            </Select>
          </Field>
          <Field label={c("ti.ind.editor.source")} htmlFor="indicator-source" error={editorErrors.source}>
            <Input
              id="indicator-source"
              value={draft.source}
              maxLength={120}
              onChange={(event) => setDraft({ ...draft, source: event.target.value })}
            />
          </Field>
          <Field label={c("ti.ind.editor.actor")} htmlFor="indicator-actor">
            <Select id="indicator-actor" value={draft.actor_id} onChange={(event) => setDraft({ ...draft, actor_id: event.target.value })}>
              <option value="">{c("ti.ind.editor.actorNone")}</option>
              {actors.map((actor) => (
                <option key={actor.id} value={actor.id}>{actor.name}</option>
              ))}
            </Select>
          </Field>
          <div className="span-2">
            <Field label={c("ti.ind.editor.tags")} htmlFor="indicator-tags" hint={c("ti.ind.editor.tagsHint")} error={editorErrors.tags}>
              <Input
                id="indicator-tags"
                value={draft.tags}
                onChange={(event) => setDraft({ ...draft, tags: event.target.value })}
              />
            </Field>
          </div>
          <div className="span-2">
            <Field label={c("ti.ind.editor.description")} htmlFor="indicator-description" error={editorErrors.description}>
              <Textarea
                id="indicator-description"
                value={draft.description}
                maxLength={2000}
                style={{ minHeight: 80 }}
                onChange={(event) => setDraft({ ...draft, description: event.target.value })}
              />
            </Field>
          </div>
          <label className="checkbox span-2">
            <input type="checkbox" checked={draft.active} onChange={(event) => setDraft({ ...draft, active: event.target.checked })} />
            {c("ti.ind.editor.active")}
          </label>
        </div>
      </Modal>

      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title={c("ti.ind.import.title")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setImportOpen(false)} disabled={importIndicators.isPending}>
              {t("common.close")}
            </Button>
            <Button
              variant="primary"
              loading={importIndicators.isPending}
              disabled={!importText.trim()}
              onClick={() => {
                setImportResult(null);
                if (!importText.trim()) {
                  setImportError(c("ti.ind.import.empty"));
                  return;
                }
                if (importTab === "stix") {
                  try {
                    const parsed = JSON.parse(importText) as unknown;
                    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
                      setImportError(c("ti.ind.import.invalidBundle"));
                      return;
                    }
                  } catch {
                    setImportError(c("ti.ind.import.invalidJson"));
                    return;
                  }
                }
                setImportError(null);
                importIndicators.mutate();
              }}
              data-testid="submit-indicator-import"
            >
              {c("ti.ind.import.submit")}
            </Button>
          </>
        }
      >
        <p className="muted" style={{ fontSize: 12, marginBottom: 12 }}>{c("ti.ind.import.description")}</p>
        <Tabs
          items={[
            { key: "stix" as const, label: c("ti.ind.import.tab.stix") },
            { key: "csv" as const, label: c("ti.ind.import.tab.csv") },
          ]}
          value={importTab}
          onChange={(value) => {
            setImportTab(value);
            setImportText("");
            setImportError(null);
            setImportResult(null);
          }}
          ariaLabel={c("ti.ind.import.title")}
        />
        <div style={{ marginTop: 12 }}>
          <p className="muted" style={{ fontSize: 11.5, marginBottom: 10 }}>
            {importTab === "stix" ? c("ti.ind.import.stixHint") : c("ti.ind.import.csvHint")}
          </p>
          <Field label={importTab === "stix" ? c("ti.ind.import.tab.stix") : c("ti.ind.import.tab.csv")} htmlFor="ti-import-text" error={importError ?? undefined}>
            <Textarea
              id="ti-import-text"
              className="mono"
              style={{ minHeight: 200, fontSize: 11.5 }}
              value={importText}
              onChange={(event) => {
                setImportText(event.target.value);
                setImportError(null);
                setImportResult(null);
              }}
              aria-invalid={Boolean(importError)}
              data-testid="indicator-import-text"
            />
          </Field>
          <div className="row wrap" style={{ marginTop: 10, gap: 10 }}>
            <input
              type="file"
              accept={importTab === "stix" ? ".json,application/json" : ".csv,text/csv"}
              aria-label={c("ti.ind.import.file")}
              className="input"
              style={{ maxWidth: 300 }}
              onChange={async (event) => {
                const file = event.target.files?.[0];
                if (!file) return;
                if (file.size > 5_000_000) {
                  setImportError(c("ti.ind.import.tooBig"));
                  return;
                }
                setImportText(await file.text());
                setImportError(null);
                setImportResult(null);
              }}
              data-testid="indicator-import-file"
            />
            <span className="dim" style={{ fontSize: 11 }}>{c("ti.ind.import.file")}</span>
          </div>

          {importResult ? (
            <div className="stack" style={{ marginTop: 16 }}>
              <div className="section-label">{c("ti.ind.import.result")}</div>
              <div className="stat-inline">
                <div><span className="label">{c("ti.ind.import.received")}</span><span className="value">{formatNumber(importResult.total_received)}</span></div>
                <div><span className="label">{c("ti.ind.import.created")}</span><span className="value" style={{ color: "var(--success)" }}>{formatNumber(importResult.created)}</span></div>
                <div><span className="label">{c("ti.ind.import.updated")}</span><span className="value" style={{ color: "var(--accent)" }}>{formatNumber(importResult.updated)}</span></div>
                <div><span className="label">{c("ti.ind.import.skipped")}</span><span className="value">{formatNumber(importResult.skipped)}</span></div>
              </div>
              <div>
                <div className="section-label">{c("ti.ind.import.errors")}</div>
                <ImportErrors errors={importResult.errors} emptyLabel={c("ti.ind.import.noErrors")} />
              </div>
            </div>
          ) : importIndicators.isPending ? (
            <p className="muted" style={{ fontSize: 12, marginTop: 14 }}>{t("common.loading")}</p>
          ) : (
            <p className="dim" style={{ fontSize: 11.5, marginTop: 14 }}>{c("ti.ind.import.none")}</p>
          )}
        </div>
      </Modal>

      <ConfirmModal
        open={deactivateTarget !== null}
        onClose={() => setDeactivateTarget(null)}
        title={c("ti.ind.deactivateTitle")}
        description={c("ti.ind.deactivateDescription")}
        confirmLabel={c("ti.ind.deactivate")}
        loading={deactivate.isPending}
        danger
        onConfirm={() => {
          if (deactivateTarget) deactivate.mutate(deactivateTarget.id);
        }}
      >
        {deactivateTarget ? (
          <div className="metric-list">
            <div className="metric-row"><span className="metric-label">{deactivateTarget.indicator_type}</span><span className="metric-value mono">{deactivateTarget.value}</span></div>
            <div className="metric-row"><span className="metric-label">{c("ti.ind.col.confidence")}</span><span className="metric-value">{deactivateTarget.confidence}%</span></div>
          </div>
        ) : null}
      </ConfirmModal>
    </div>
  );
}

function EnrichmentView({ data }: { data: Enrichment }) {
  const { c, lang } = useCopy();
  const verdictTone = data.verdict === "malicious" ? "critical" : data.verdict === "suspicious" ? "warning" : "neutral";
  const verdictLabel = data.verdict === "malicious" ? c("ti.enrich.verdict.malicious") : data.verdict === "suspicious" ? c("ti.enrich.verdict.suspicious") : c("ti.enrich.verdict.unknown");

  if (data.verdict === "unknown" || data.matches.length === 0) {
    return (
      <div className="stack">
        <div className="row wrap" style={{ gap: 6 }}>
          <Badge tone="neutral">{verdictLabel}</Badge>
          <span className="mono" style={{ fontSize: 10.5, color: "var(--dim)" }}>{data.type ?? "—"} · {data.value}</span>
        </div>
        <div>
          <div className="row-between" style={{ fontSize: 11.5, marginBottom: 4 }}>
            <span className="muted">{c("ti.enrich.confidence")}</span>
            <span className="mono">0%</span>
          </div>
          <ProgressBar value={0} />
        </div>
        <div className="notice notice-accent" style={{ display: "block" }}>{c("ti.enrich.unknownHint")}</div>
        <span className="dim" style={{ fontSize: 11.5 }}>{c("ti.enrich.none")}</span>
      </div>
    );
  }

  return (
    <div className="stack">
      <div className="row wrap" style={{ gap: 6 }}>
        <Badge tone={verdictTone}>{verdictLabel}</Badge>
        <Badge tone="neutral">{data.type ?? "—"}</Badge>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--text-secondary)", wordBreak: "break-all" }}>{data.value}</span>
      </div>
      <div>
        <div className="row-between" style={{ fontSize: 11.5, marginBottom: 4 }}>
          <span className="muted">{c("ti.enrich.confidence")}</span>
          <span className="mono">{data.confidence}%</span>
        </div>
        <ProgressBar value={data.confidence} tone={data.confidence >= 70 ? "var(--danger)" : "var(--warning)"} />
      </div>
      {data.reason ? (
        <div>
          <div className="section-label">{c("ti.enrich.reason")}</div>
          <p style={{ fontSize: 11.5, color: "var(--text-secondary)" }}>{data.reason}</p>
        </div>
      ) : null}
      {data.actor ? (
        <div>
          <div className="section-label">{c("ti.enrich.actor")}</div>
          <div className="row wrap" style={{ gap: 6 }}>
            <span style={{ fontSize: 12 }}>{data.actor.name}</span>
            {data.actor.mitre_id ? <span className="tag">{data.actor.mitre_id}</span> : null}
          </div>
        </div>
      ) : null}
      {data.techniques.length ? (
        <div>
          <div className="section-label">{c("ti.enrich.techniques")}</div>
          <div className="chip-row">
            {data.techniques.slice(0, 10).map((technique) => (
              <span className="tag" key={technique.id}>{technique.id} · {technique.name}</span>
            ))}
          </div>
        </div>
      ) : null}
      <div>
        <div className="row-between">
          <div className="section-label" style={{ marginBottom: 0 }}>{c("ti.enrich.evidence")} ({data.matches.length} {c("ti.enrich.matches")})</div>
          <CopyButton text={JSON.stringify(data, null, 2)} />
        </div>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>IOC</th>
                <th>{c("ti.ind.col.source")}</th>
                <th>{c("ti.enrich.confidence")}</th>
                <th>{c("ti.ind.col.lastSeen")}</th>
              </tr>
            </thead>
            <tbody>
              {data.evidence.slice(0, 20).map((item) => (
                <tr key={item.indicator_id}>
                  <td>
                    <div className="mono" style={{ fontSize: 10.5, wordBreak: "break-all" }}>{item.value}</div>
                    <div className="row wrap" style={{ gap: 4, marginTop: 3 }}>
                      <span className="tag">{item.indicator_type}</span>
                      <Badge tone={item.scope === "global" ? "accent" : "neutral"}>
                        {item.scope === "global" ? c("ti.enrich.scope.global") : c("ti.enrich.scope.organization")}
                      </Badge>
                    </div>
                  </td>
                  <td style={{ fontSize: 11 }}>{item.source}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{item.confidence}%</td>
                  <td className="mono" style={{ fontSize: 10.5 }}>{relativeTime(item.last_seen, lang)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {data.events && data.events.length ? (
        <div>
          <div className="section-label">{c("ti.enrich.events")}</div>
          <div className="metric-list">
            {data.events.slice(0, 8).map((event) => (
              <div className="metric-row" key={event.event_id}>
                <span className="metric-label" style={{ color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {event.message}
                </span>
                <span className="metric-value mono" style={{ fontSize: 10 }}>{formatDateTime(event.occurred_at, lang)}</span>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 8 }}>
            <LinkButton to="/monitoring" size="sm">{lang === "es" ? "Abrir monitorización" : "Open monitoring"}</LinkButton>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function useCopy() {
  const { lang } = useI18n();
  const copy = usePageCopy(COPY);
  return { c: copy, lang };
}

/* ---------------------------------------------------------------------- actors */

interface ActorDraft {
  name: string;
  mitre_id: string;
  aliases: string;
  description: string;
  sophistication: string;
  motivation: string;
  country: string;
  techniques: string;
}

function emptyActor(): ActorDraft {
  return {
    name: "",
    mitre_id: "",
    aliases: "",
    description: "",
    sophistication: "unknown",
    motivation: "unknown",
    country: "",
    techniques: "",
  };
}

function ActorsPanel() {
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const canWrite = can("ti:write");

  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const debouncedSearch = useDebouncedValue(search);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<ThreatActor | null>(null);
  const [draft, setDraft] = useState<ActorDraft>(emptyActor);
  const [editorErrors, setEditorErrors] = useState<Record<string, string>>({});
  const [deleteTarget, setDeleteTarget] = useState<ThreatActor | null>(null);

  const listQuery = useQuery({
    queryKey: ["threat-intel", "actors", { page, search: debouncedSearch }],
    queryFn: () => api.get<Page<ThreatActor>>("/threat-intel/actors", { page, page_size: 20, q: debouncedSearch || undefined }),
  });

  const detailQuery = useQuery({
    queryKey: ["threat-intel", "actors", "detail", selectedId],
    queryFn: () => api.get<ThreatActorDetail>(`/threat-intel/actors/${selectedId}`),
    enabled: selectedId !== null,
  });

  const createActor = useMutation({
    mutationFn: () =>
      api.post<ThreatActor>("/threat-intel/actors", {
        name: draft.name.trim(),
        mitre_id: draft.mitre_id.trim() || null,
        aliases: draft.aliases.split(",").map((value) => value.trim()).filter(Boolean),
        description: draft.description.trim() || null,
        sophistication: draft.sophistication.trim() || "unknown",
        motivation: draft.motivation.trim() || "unknown",
        country: draft.country.trim() || null,
        techniques: draft.techniques.split(",").map((value) => value.trim().toUpperCase()).filter(Boolean),
      }),
    onSuccess: () => {
      push(c("ti.actors.editor.created"), "success");
      setEditorOpen(false);
      setEditorErrors({});
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => {
      setEditorErrors(fieldErrors(error));
      push(`${c("ti.actors.editor.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const updateActor = useMutation({
    mutationFn: (actor: ThreatActor) =>
      api.patch<ThreatActor>(`/threat-intel/actors/${actor.id}`, {
        name: draft.name.trim(),
        mitre_id: draft.mitre_id.trim() || null,
        aliases: draft.aliases.split(",").map((value) => value.trim()).filter(Boolean),
        description: draft.description.trim() || null,
        sophistication: draft.sophistication.trim() || "unknown",
        motivation: draft.motivation.trim() || "unknown",
        country: draft.country.trim() || null,
        techniques: draft.techniques.split(",").map((value) => value.trim().toUpperCase()).filter(Boolean),
      }),
    onSuccess: () => {
      push(c("ti.actors.editor.updated"), "success");
      setEditorOpen(false);
      setEditorErrors({});
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => {
      setEditorErrors(fieldErrors(error));
      push(`${c("ti.actors.editor.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const deleteActor = useMutation({
    mutationFn: (id: string) => api.delete<void>(`/threat-intel/actors/${id}`),
    onSuccess: () => {
      push(c("ti.actors.deleted"), "success");
      setDeleteTarget(null);
      setSelectedId(null);
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => push(`${c("ti.actors.deleteFailed")}: ${errorMessage(error)}`, "error"),
  });

  const rows = listQuery.data?.items ?? [];

  const openCreate = () => {
    setEditing(null);
    setDraft(emptyActor());
    setEditorErrors({});
    setEditorOpen(true);
  };

  const openEdit = (actor: ThreatActor) => {
    setEditing(actor);
    setDraft({
      name: actor.name,
      mitre_id: actor.mitre_id ?? "",
      aliases: actor.aliases.join(", "),
      description: actor.description ?? "",
      sophistication: actor.sophistication,
      motivation: actor.motivation,
      country: actor.country ?? "",
      techniques: actor.techniques.join(", "),
    });
    setEditorErrors({});
    setEditorOpen(true);
  };

  const columns: Column<ThreatActor>[] = [
    {
      key: "name",
      header: c("ti.actors.col.name"),
      render: (row) => (
        <div style={{ minWidth: 180 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.name}</div>
          {row.aliases.length ? (
            <div style={{ fontSize: 10.5, color: "var(--dim)", marginTop: 2 }}>{row.aliases.slice(0, 3).join(", ")}</div>
          ) : null}
        </div>
      ),
    },
    {
      key: "mitre",
      header: c("ti.actors.col.mitre"),
      width: "110px",
      render: (row) => (row.mitre_id ? <span className="tag">{row.mitre_id}</span> : <span className="dim">—</span>),
    },
    {
      key: "country",
      header: c("ti.actors.col.country"),
      width: "100px",
      render: (row) => <span style={{ fontSize: 11.5 }}>{row.country ?? "—"}</span>,
    },
    {
      key: "sophistication",
      header: c("ti.actors.col.sophistication"),
      width: "130px",
      render: (row) => <span className="tag">{humanize(row.sophistication)}</span>,
    },
    {
      key: "motivation",
      header: c("ti.actors.col.motivation"),
      width: "130px",
      render: (row) => <span style={{ fontSize: 11.5 }}>{humanize(row.motivation)}</span>,
    },
    {
      key: "techniques",
      header: c("ti.actors.col.techniques"),
      width: "150px",
      render: (row) =>
        row.techniques.length ? (
          <div className="chip-row">
            {row.techniques.slice(0, 3).map((technique) => (
              <span className="tag" key={technique}>{technique}</span>
            ))}
            {row.techniques.length > 3 ? <span className="tag">+{row.techniques.length - 3}</span> : null}
          </div>
        ) : (
          <span className="dim" style={{ fontSize: 11 }}>—</span>
        ),
    },
    {
      key: "actions",
      header: c("ti.actors.col.actions"),
      width: "112px",
      align: "right",
      render: (row) => (
        <div className="row" style={{ gap: 2, justifyContent: "flex-end" }}>
          <Button
            size="sm"
            variant="ghost"
            icon={SquarePen}
            aria-label={c("ti.actors.edit")}
            onClick={(event) => {
              event.stopPropagation();
              openEdit(row);
            }}
            disabled={!canWrite}
          />
          <Button
            size="sm"
            variant="ghost"
            icon={Trash2}
            aria-label={c("ti.actors.delete")}
            onClick={(event) => {
              event.stopPropagation();
              setDeleteTarget(row);
            }}
            disabled={!canWrite}
          />
        </div>
      ),
    },
  ];

  return (
    <Card
      title={c("ti.tab.actors")}
      subtitle={listQuery.data ? `${formatNumber(listQuery.data.meta.total)} ${c("ti.actors.count")}` : undefined}
      actions={
        canWrite ? (
          <Button size="sm" variant="primary" icon={Plus} onClick={openCreate} data-testid="open-actor-create">
            {c("ti.actors.new")}
          </Button>
        ) : undefined
      }
      bodyClassName=""
    >
      <FilterBar ariaLabel={t("common.filters")}>
        <SearchInput
          value={search}
          onChange={(value) => {
            setSearch(value);
            setPage(1);
          }}
          placeholder={c("ti.actors.search")}
          ariaLabel={c("ti.actors.search")}
        />
      </FilterBar>
      <div data-testid="table-actors">
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(row) => row.id}
          loading={listQuery.isLoading}
          onRowClick={(row) => setSelectedId(row.id)}
          error={
            listQuery.isError ? (
              <ErrorBanner title={c("ti.actors.loadFailed")} message={errorMessage(listQuery.error)} onRetry={() => void listQuery.refetch()} />
            ) : undefined
          }
          empty={
            <EmptyState
              icon={Users}
              title={c("ti.actors.empty")}
              description={c("ti.actors.emptyHint")}
              action={
                canWrite ? (
                  <Button size="sm" variant="primary" icon={Plus} onClick={openCreate}>{c("ti.actors.new")}</Button>
                ) : undefined
              }
            />
          }
        />
      </div>
      <Pagination meta={listQuery.data?.meta} onPage={setPage} />

      <Modal
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        title={c("ti.actors.detail.title")}
        size="lg"
        footer={
          detailQuery.data ? (
            <div className="row wrap" style={{ gap: 8 }}>
              <Button
                icon={SquarePen}
                onClick={() => {
                  const actor = detailQuery.data;
                  if (!actor) return;
                  setSelectedId(null);
                  openEdit(actor);
                }}
                disabled={!canWrite}
              >
                {c("ti.actors.edit")}
              </Button>
              <Button variant="danger" icon={Trash2} onClick={() => setDeleteTarget(detailQuery.data)} disabled={!canWrite}>
                {c("ti.actors.delete")}
              </Button>
            </div>
          ) : undefined
        }
      >
        {detailQuery.isLoading ? (
          <p className="muted" style={{ fontSize: 12 }}>{t("common.loading")}</p>
        ) : detailQuery.isError ? (
          <ErrorBanner message={errorMessage(detailQuery.error)} onRetry={() => void detailQuery.refetch()} />
        ) : detailQuery.data ? (
          <div className="stack">
            <div className="row wrap" style={{ gap: 6 }}>
              <h3 style={{ fontSize: 15 }}>{detailQuery.data.name}</h3>
              {detailQuery.data.mitre_id ? <span className="tag">{detailQuery.data.mitre_id}</span> : null}
              <span className="tag">{humanize(detailQuery.data.sophistication)}</span>
              <span className="tag">{humanize(detailQuery.data.motivation)}</span>
              {detailQuery.data.country ? <span className="tag">{detailQuery.data.country}</span> : null}
            </div>
            <div className="stat-inline">
              <div>
                <span className="label">{c("ti.actors.detail.indicators")}</span>
                <span className="value">{formatNumber(detailQuery.data.indicator_count)}</span>
              </div>
              <div>
                <span className="label">{c("ti.actors.col.techniques")}</span>
                <span className="value">{formatNumber(detailQuery.data.techniques.length)}</span>
              </div>
              <div>
                <span className="label">{t("common.updated")}</span>
                <span className="value" style={{ fontSize: 12 }}>{formatDateTime(detailQuery.data.updated_at, lang)}</span>
              </div>
            </div>
            <div>
              <div className="section-label">{c("ti.actors.detail.aliases")}</div>
              <TagList tags={detailQuery.data.aliases} emptyLabel={c("ti.actors.detail.none")} />
            </div>
            <div>
              <div className="section-label">{c("ti.actors.detail.description")}</div>
              <p style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
                {detailQuery.data.description ?? c("ti.actors.detail.none")}
              </p>
            </div>
            <div>
              <div className="section-label">{c("ti.actors.col.techniques")}</div>
              <TagList tags={detailQuery.data.techniques} emptyLabel={c("ti.actors.detail.none")} />
            </div>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        title={editing ? c("ti.actors.editor.editTitle") : c("ti.actors.editor.createTitle")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditorOpen(false)} disabled={createActor.isPending || updateActor.isPending}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              loading={createActor.isPending || updateActor.isPending}
              onClick={() => {
                const errors: Record<string, string> = {};
                if (!draft.name.trim()) errors.name = c("ti.actors.editor.required");
                if (draft.mitre_id.trim() && !MITRE_ID_RE.test(draft.mitre_id.trim())) errors.mitre_id = c("ti.actors.editor.invalidMitre");
                const techniques = draft.techniques.split(",").map((value) => value.trim().toUpperCase()).filter(Boolean);
                if (techniques.some((value) => !TECHNIQUE_RE.test(value))) errors.techniques = c("ti.actors.editor.invalidTechnique");
                setEditorErrors(errors);
                if (Object.keys(errors).length) return;
                if (editing) updateActor.mutate(editing);
                else createActor.mutate();
              }}
              data-testid="submit-actor"
            >
              {editing ? c("ti.actors.editor.submitSave") : c("ti.actors.editor.submitCreate")}
            </Button>
          </>
        }
      >
        <div className="form-grid">
          <Field label={c("ti.actors.editor.name")} htmlFor="actor-name" required error={editorErrors.name}>
            <Input id="actor-name" value={draft.name} maxLength={200} onChange={(event) => setDraft({ ...draft, name: event.target.value })} data-testid="input-actor-name" />
          </Field>
          <Field label={c("ti.actors.editor.mitre")} htmlFor="actor-mitre" hint={c("ti.actors.editor.mitreHint")} error={editorErrors.mitre_id}>
            <Input id="actor-mitre" className="mono" value={draft.mitre_id} maxLength={5} onChange={(event) => setDraft({ ...draft, mitre_id: event.target.value })} />
          </Field>
          <Field label={c("ti.actors.editor.aliases")} htmlFor="actor-aliases" hint={c("ti.actors.editor.aliasesHint")} error={editorErrors.aliases}>
            <Input id="actor-aliases" value={draft.aliases} onChange={(event) => setDraft({ ...draft, aliases: event.target.value })} />
          </Field>
          <Field label={c("ti.actors.editor.country")} htmlFor="actor-country" error={editorErrors.country}>
            <Input id="actor-country" value={draft.country} maxLength={80} onChange={(event) => setDraft({ ...draft, country: event.target.value })} />
          </Field>
          <Field label={c("ti.actors.editor.sophistication")} htmlFor="actor-sophistication">
            <Input id="actor-sophistication" value={draft.sophistication} maxLength={40} onChange={(event) => setDraft({ ...draft, sophistication: event.target.value })} />
          </Field>
          <Field label={c("ti.actors.editor.motivation")} htmlFor="actor-motivation">
            <Input id="actor-motivation" value={draft.motivation} maxLength={80} onChange={(event) => setDraft({ ...draft, motivation: event.target.value })} />
          </Field>
          <div className="span-2">
            <Field label={c("ti.actors.editor.techniques")} htmlFor="actor-techniques" hint={c("ti.actors.editor.techniquesHint")} error={editorErrors.techniques}>
              <Input
                id="actor-techniques"
                className="mono"
                value={draft.techniques}
                onChange={(event) => setDraft({ ...draft, techniques: event.target.value })}
                aria-invalid={Boolean(editorErrors.techniques)}
              />
            </Field>
          </div>
          <div className="span-2">
            <Field label={c("ti.actors.editor.description")} htmlFor="actor-description" error={editorErrors.description}>
              <Textarea
                id="actor-description"
                value={draft.description}
                maxLength={4000}
                style={{ minHeight: 90 }}
                onChange={(event) => setDraft({ ...draft, description: event.target.value })}
              />
            </Field>
          </div>
        </div>
      </Modal>

      <ConfirmModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title={c("ti.actors.deleteTitle")}
        description={c("ti.actors.deleteDescription")}
        confirmLabel={c("ti.actors.deleteConfirm")}
        loading={deleteActor.isPending}
        danger
        onConfirm={() => {
          if (deleteTarget) deleteActor.mutate(deleteTarget.id);
        }}
      >
        {deleteTarget ? (
          <div className="metric-list">
            <div className="metric-row"><span className="metric-label">{c("ti.actors.col.name")}</span><span className="metric-value">{deleteTarget.name}</span></div>
            {deleteTarget.mitre_id ? (
              <div className="metric-row"><span className="metric-label">{c("ti.actors.col.mitre")}</span><span className="metric-value mono">{deleteTarget.mitre_id}</span></div>
            ) : null}
          </div>
        ) : null}
      </ConfirmModal>
    </Card>
  );
}

/* ----------------------------------------------------------------------- feeds */

function FeedsPanel() {
  const { t, lang } = useI18n();
  const c = usePageCopy(COPY);
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const canWrite = can("ti:write");
  const canSync = can("ti:sync");

  const [enabled, setEnabled] = useState("");
  const [status, setStatus] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [draft, setDraft] = useState({ name: "", kind: "misp", schedule: "60", enabled: true, config: "{\n  \"url\": \"\"\n}" });
  const [draftErrors, setDraftErrors] = useState<Record<string, string>>({});
  const [syncTarget, setSyncTarget] = useState<IntelFeed | null>(null);

  const listQuery = useQuery({
    queryKey: ["threat-intel", "feeds", { enabled, status }],
    queryFn: () =>
      api.get<Page<IntelFeed>>("/threat-intel/feeds", {
        page: 1,
        page_size: 50,
        enabled: enabled === "" ? undefined : enabled === "true",
        status: status || undefined,
      }),
  });

  const createFeed = useMutation({
    mutationFn: () =>
      api.post<IntelFeed>("/threat-intel/feeds", {
        name: draft.name.trim(),
        kind: draft.kind,
        enabled: draft.enabled,
        schedule_minutes: Number(draft.schedule),
        config: JSON.parse(draft.config || "{}") as Record<string, unknown>,
      }),
    onSuccess: () => {
      push(c("ti.feeds.create.created"), "success");
      setCreateOpen(false);
      setDraft({ name: "", kind: "misp", schedule: "60", enabled: true, config: "{\n  \"url\": \"\"\n}" });
      setDraftErrors({});
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => {
      setDraftErrors(fieldErrors(error));
      push(`${c("ti.feeds.create.failed")}: ${errorMessage(error)}`, "error");
    },
  });

  const syncFeed = useMutation({
    mutationFn: (feed: IntelFeed) =>
      apiRequest<FeedSyncResult>(`/threat-intel/feeds/${feed.id}/sync`, { method: "POST", timeoutMs: 120_000 }),
    onSuccess: (result) => {
      push(`${c("ti.feeds.synced")} · ${result.objects_read} ${c("ti.feeds.objectsRead")} · +${result.created} / ~${result.updated}`, "success");
      setSyncTarget(null);
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => push(`${c("ti.feeds.syncFailed")}: ${errorMessage(error)}`, "error"),
  });

  const toggleFeed = useMutation({
    mutationFn: (feed: IntelFeed) => api.patch<IntelFeed>(`/threat-intel/feeds/${feed.id}`, { enabled: !feed.enabled }),
    onSuccess: (feed) => {
      push(feed.enabled ? c("ti.feeds.enabledOk") : c("ti.feeds.disabledOk"), "success");
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (error) => push(`${c("ti.feeds.toggleFailed")}: ${errorMessage(error)}`, "error"),
  });

  const rows = listQuery.data?.items ?? [];

  const columns: Column<IntelFeed>[] = [
    {
      key: "name",
      header: c("ti.feeds.col.name"),
      render: (row) => (
        <div style={{ minWidth: 170 }}>
          <div style={{ color: "var(--text)", fontWeight: 500 }}>{row.name}</div>
          <div className="mono" style={{ fontSize: 9.5, color: "var(--dim)" }}>{row.id.slice(0, 8)}…</div>
        </div>
      ),
    },
    { key: "kind", header: c("ti.feeds.col.kind"), width: "96px", render: (row) => <span className="tag">{row.kind}</span> },
    {
      key: "enabled",
      header: c("ti.feeds.col.enabled"),
      width: "92px",
      render: (row) => (
        <StatusBadge status={row.enabled ? "active" : "disabled"} label={row.enabled ? t("common.active") : t("common.inactive")} />
      ),
    },
    {
      key: "schedule",
      header: c("ti.feeds.col.schedule"),
      width: "96px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.schedule_minutes} {c("ti.feeds.minutes")}</span>,
    },
    {
      key: "status",
      header: c("ti.feeds.col.status"),
      width: "116px",
      render: (row) => (
        <Badge tone={row.status === "success" ? "success" : row.status === "error" ? "danger" : "neutral"}>
          {copyOr(c, `ti.feeds.status.${row.status}`, humanize(row.status))}
        </Badge>
      ),
    },
    {
      key: "last_sync",
      header: c("ti.feeds.col.lastSync"),
      width: "134px",
      render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.last_sync_at ? relativeTime(row.last_sync_at, lang) : "—"}</span>,
    },
    {
      key: "last_error",
      header: c("ti.feeds.col.lastError"),
      render: (row) => (
        <span
          style={{ fontSize: 10.5, color: row.last_error ? "var(--danger)" : "var(--dim)", overflowWrap: "anywhere" }}
          title={row.last_error ?? undefined}
        >
          {row.last_error ? (row.last_error.length > 90 ? `${row.last_error.slice(0, 89)}…` : row.last_error) : c("ti.feeds.lastErrorNone")}
        </span>
      ),
    },
    {
      key: "actions",
      header: c("ti.feeds.col.actions"),
      width: "140px",
      align: "right",
      render: (row) => (
        <div className="row" style={{ gap: 4, justifyContent: "flex-end" }}>
          <Button
            size="sm"
            variant="ghost"
            icon={RefreshCw}
            aria-label={c("ti.feeds.sync")}
            disabled={!canSync || !row.enabled}
            title={!row.enabled ? t("common.inactive") : c("ti.feeds.sync")}
            onClick={() => setSyncTarget(row)}
            data-testid={`sync-feed-${row.id}`}
          >
            {c("ti.feeds.sync")}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={Power}
            aria-label={row.enabled ? t("common.inactive") : t("common.active")}
            disabled={!canWrite}
            onClick={() => toggleFeed.mutate(row)}
            data-testid={`toggle-feed-${row.id}`}
          />
        </div>
      ),
    },
  ];

  return (
    <Card
      title={c("ti.tab.feeds")}
      subtitle={listQuery.data ? `${formatNumber(listQuery.data.meta.total)} ${c("ti.feeds.count")}` : undefined}
      actions={
        canWrite ? (
          <Button size="sm" variant="primary" icon={Plus} onClick={() => setCreateOpen(true)} data-testid="open-feed-create">
            {c("ti.feeds.new")}
          </Button>
        ) : undefined
      }
      bodyClassName=""
    >
      <FilterBar ariaLabel={t("common.filters")}>
        <Select value={enabled} onChange={(event) => setEnabled(event.target.value)} aria-label={c("ti.feeds.col.enabled")} data-testid="filter-enabled">
          <option value="">{c("ti.ind.filter.allActive")}</option>
          <option value="true">{c("ti.ind.filter.activeOnly")}</option>
          <option value="false">{c("ti.ind.filter.inactiveOnly")}</option>
        </Select>
        <Select value={status} onChange={(event) => setStatus(event.target.value)} aria-label={c("ti.feeds.col.status")} data-testid="filter-feed-status">
          <option value="">{c("ti.feeds.col.status")}</option>
          {["idle", "success", "error"].map((value) => (
            <option key={value} value={value}>{copyOr(c, `ti.feeds.status.${value}`, humanize(value))}</option>
          ))}
        </Select>
        <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => void listQuery.refetch()}>
          {t("common.refresh")}
        </Button>
      </FilterBar>
      <div data-testid="table-feeds">
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(row) => row.id}
          loading={listQuery.isLoading}
          error={
            listQuery.isError ? (
              <ErrorBanner title={c("ti.feeds.loadFailed")} message={errorMessage(listQuery.error)} onRetry={() => void listQuery.refetch()} />
            ) : undefined
          }
          empty={
            <EmptyState
              icon={Rss}
              title={c("ti.feeds.empty")}
              description={c("ti.feeds.emptyHint")}
              action={
                canWrite ? (
                  <Button size="sm" variant="primary" icon={Plus} onClick={() => setCreateOpen(true)}>{c("ti.feeds.new")}</Button>
                ) : undefined
              }
            />
          }
        />
      </div>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={c("ti.feeds.create.title")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={createFeed.isPending}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              loading={createFeed.isPending}
              onClick={() => {
                const errors: Record<string, string> = {};
                if (!draft.name.trim()) errors.name = c("ti.actors.editor.required");
                const schedule = Number(draft.schedule);
                if (!Number.isInteger(schedule) || schedule < 5 || schedule > 1440) errors.schedule_minutes = c("ti.feeds.create.scheduleHint");
                let config: unknown;
                try {
                  config = JSON.parse(draft.config || "{}");
                } catch {
                  errors.config = c("ti.feeds.create.configInvalid");
                }
                if (config !== undefined && (typeof config !== "object" || config === null || Array.isArray(config))) {
                  errors.config = c("ti.feeds.create.configInvalid");
                }
                setDraftErrors(errors);
                if (Object.keys(errors).length) return;
                createFeed.mutate();
              }}
              data-testid="submit-feed"
            >
              {c("ti.feeds.create.submit")}
            </Button>
          </>
        }
      >
        <div className="form-grid">
          <Field label={c("ti.feeds.create.name")} htmlFor="feed-name" required error={draftErrors.name}>
            <Input id="feed-name" value={draft.name} maxLength={160} onChange={(event) => setDraft({ ...draft, name: event.target.value })} data-testid="input-feed-name" />
          </Field>
          <Field label={c("ti.feeds.create.kind")} htmlFor="feed-kind" required>
            <Select id="feed-kind" value={draft.kind} onChange={(event) => setDraft({ ...draft, kind: event.target.value })} data-testid="input-feed-kind">
              {FEED_KINDS.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </Select>
          </Field>
          <Field label={c("ti.feeds.create.schedule")} htmlFor="feed-schedule" hint={c("ti.feeds.create.scheduleHint")} error={draftErrors.schedule_minutes}>
            <Input
              id="feed-schedule"
              type="number"
              min={5}
              max={1440}
              value={draft.schedule}
              onChange={(event) => setDraft({ ...draft, schedule: event.target.value })}
            />
          </Field>
          <label className="checkbox">
            <input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} />
            {c("ti.feeds.create.enabled")}
          </label>
          <div className="span-2">
            <Field label={c("ti.feeds.create.config")} htmlFor="feed-config" hint={c("ti.feeds.create.configHint")} error={draftErrors.config ?? draftErrors["config.url"]}>
              <Textarea
                id="feed-config"
                className="mono"
                style={{ minHeight: 130, fontSize: 11.5 }}
                value={draft.config}
                onChange={(event) => setDraft({ ...draft, config: event.target.value })}
                aria-invalid={Boolean(draftErrors.config)}
                data-testid="input-feed-config"
              />
            </Field>
          </div>
        </div>
      </Modal>

      <ConfirmModal
        open={syncTarget !== null}
        onClose={() => setSyncTarget(null)}
        title={c("ti.feeds.sync")}
        description={
          lang === "es"
            ? "La sincronización realiza una petición saliente a la URL configurada de la fuente. El origen y las credenciales se validan en el servidor."
            : "Synchronization performs an outbound request to the configured feed URL. Origin and credentials are validated server-side."
        }
        confirmLabel={c("ti.feeds.sync")}
        loading={syncFeed.isPending}
        onConfirm={() => {
          if (syncTarget) syncFeed.mutate(syncTarget);
        }}
      >
        {syncTarget ? (
          <div className="metric-list">
            <div className="metric-row"><span className="metric-label">{c("ti.feeds.col.name")}</span><span className="metric-value">{syncTarget.name}</span></div>
            <div className="metric-row"><span className="metric-label">{c("ti.feeds.col.kind")}</span><span className="metric-value mono">{syncTarget.kind}</span></div>
            <div className="metric-row"><span className="metric-label">{c("ti.feeds.col.lastSync")}</span><span className="metric-value">{syncTarget.last_sync_at ? formatDateTime(syncTarget.last_sync_at, lang) : "—"}</span></div>
          </div>
        ) : null}
      </ConfirmModal>
    </Card>
  );
}

/* ----------------------------------------------------------------------- mitre */

function MitrePanel() {
  const { t } = useI18n();
  const c = usePageCopy(COPY);
  const [search, setSearch] = useState("");
  const [tactic, setTactic] = useState("");
  const debouncedSearch = useDebouncedValue(search);

  const coverageQuery = useQuery({
    queryKey: ["threat-intel", "mitre", "coverage"],
    queryFn: () => api.get<MitreCoverage>("/threat-intel/mitre/coverage"),
  });

  const techniquesQuery = useQuery({
    queryKey: ["threat-intel", "mitre", "techniques", { tactic, search: debouncedSearch }],
    queryFn: () =>
      api.get<MitreTechniqueResponse>("/threat-intel/mitre/techniques", {
        tactic: tactic || undefined,
        q: debouncedSearch || undefined,
      }),
  });

  const coverage = coverageQuery.data;
  const tactics = Array.from(
    new Set((coverage?.techniques ?? []).flatMap((technique) => technique.tactics)),
  ).sort();

  const coveredColumns: Column<MitreTechnique>[] = [
    { key: "id", header: c("ti.mitre.col.id"), width: "96px", render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.id}</span> },
    {
      key: "name",
      header: c("ti.mitre.col.name"),
      render: (row) => <span style={{ fontSize: 11.5 }}>{row.name}</span>,
    },
    {
      key: "tactics",
      header: c("ti.mitre.col.tactics"),
      width: "180px",
      render: (row) => (
        <div className="chip-row">
          {row.tactics.slice(0, 3).map((item) => (
            <span className="tag" key={item}>{item}</span>
          ))}
        </div>
      ),
    },
    {
      key: "events",
      header: c("ti.mitre.col.events"),
      width: "80px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{formatNumber(row.event_count ?? 0)}</span>,
    },
    {
      key: "indicators",
      header: c("ti.mitre.col.indicators"),
      width: "96px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{formatNumber(row.indicator_count ?? 0)}</span>,
    },
    {
      key: "actors",
      header: c("ti.mitre.col.actors"),
      width: "80px",
      align: "right",
      render: (row) => <span className="mono" style={{ fontSize: 11 }}>{formatNumber(row.actor_count ?? 0)}</span>,
    },
  ];

  const catalogueColumns: Column<MitreTechnique>[] = [
    { key: "id", header: c("ti.mitre.col.id"), width: "96px", render: (row) => <span className="mono" style={{ fontSize: 10.5 }}>{row.id}</span> },
    {
      key: "name",
      header: c("ti.mitre.col.name"),
      render: (row) => <span style={{ fontSize: 11.5 }}>{row.name}</span>,
    },
    {
      key: "tactics",
      header: c("ti.mitre.col.tactics"),
      width: "180px",
      render: (row) => (
        <div className="chip-row">
          {row.tactics.slice(0, 3).map((item) => (
            <span className="tag" key={item}>{item}</span>
          ))}
        </div>
      ),
    },
    {
      key: "description",
      header: c("ti.mitre.col.description"),
      render: (row) => (
        <span style={{ fontSize: 11, color: "var(--muted)" }}>
          {row.description.length > 170 ? `${row.description.slice(0, 169)}…` : row.description || "—"}
        </span>
      ),
    },
  ];

  return (
    <div className="stack">
      <Card
        title={c("ti.mitre.coverage")}
        actions={<Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => void coverageQuery.refetch()}>{t("common.refresh")}</Button>}
      >
        <p className="muted" style={{ fontSize: 11.5, marginBottom: 10 }}>{c("ti.mitre.coverageHint")}</p>
        {coverageQuery.isLoading ? (
          <p className="muted" style={{ fontSize: 12 }}>{t("common.loading")}</p>
        ) : coverageQuery.isError ? (
          <ErrorBanner
            title={c("ti.mitre.loadFailed")}
            message={errorMessage(coverageQuery.error)}
            onRetry={() => void coverageQuery.refetch()}
          />
        ) : coverage ? (
          <div className="grid-2">
            <div>
              <div className="row-between" style={{ marginBottom: 6 }}>
                <span className="muted" style={{ fontSize: 11.5 }}>{c("ti.mitre.percent")}</span>
                <span className="mono" style={{ fontSize: 12 }}>{formatPercent(coverage.coverage_percent, 1)}</span>
              </div>
              <ProgressBar value={coverage.coverage_percent} tone="var(--accent)" />
              <div className="stat-inline" style={{ marginTop: 14 }}>
                <div>
                  <span className="label">{c("ti.mitre.covered")}</span>
                  <span className="value">{formatNumber(coverage.covered_count)}</span>
                </div>
                <div>
                  <span className="label">{c("ti.mitre.catalog")}</span>
                  <span className="value">{formatNumber(coverage.catalog_size)}</span>
                </div>
                <div>
                  <span className="label">{c("ti.mitre.uncovered")}</span>
                  <span className="value">{formatNumber(coverage.uncovered.length)}</span>
                </div>
              </div>
            </div>
            <div>
              <div className="section-label">{c("ti.mitre.col.tactics")}</div>
              <div className="chip-row">
                {tactics.length ? (
                  tactics.slice(0, 14).map((item) => (
                    <span className="tag" key={item}>{item}</span>
                  ))
                ) : (
                  <span className="dim" style={{ fontSize: 11 }}>{c("ti.mitre.empty")}</span>
                )}
              </div>
            </div>
          </div>
        ) : null}
      </Card>

      <Card title={c("ti.mitre.coveredTable")} subtitle={`${formatNumber(coverage?.covered_count ?? 0)} ${c("ti.mitre.count")}`} bodyClassName="">
        <div data-testid="table-mitre-covered">
          <DataTable
            columns={coveredColumns}
            rows={coverage?.techniques}
            rowKey={(row) => row.id}
            loading={coverageQuery.isLoading}
            empty={<EmptyState icon={Swords} title={c("ti.mitre.empty")} description={c("ti.mitre.emptyHint")} />}
          />
        </div>
      </Card>

      <Card
        title={c("ti.mitre.catalogTable")}
        subtitle={techniquesQuery.data ? `${formatNumber(techniquesQuery.data.count)} / ${formatNumber(techniquesQuery.data.catalog_size)}` : undefined}
        bodyClassName=""
      >
        <FilterBar ariaLabel={t("common.filters")}>
          <SearchInput value={search} onChange={setSearch} placeholder={c("ti.mitre.search")} ariaLabel={c("ti.mitre.search")} />
          <Select value={tactic} onChange={(event) => setTactic(event.target.value)} aria-label={c("ti.mitre.tactic")} data-testid="filter-tactic">
            <option value="">{c("ti.mitre.allTactics")}</option>
            {tactics.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </Select>
        </FilterBar>
        <div data-testid="table-mitre-techniques">
          <DataTable
            columns={catalogueColumns}
            rows={techniquesQuery.data?.items}
            rowKey={(row) => row.id}
            loading={techniquesQuery.isLoading}
            error={
              techniquesQuery.isError ? (
                <ErrorBanner
                  title={c("ti.mitre.techniquesFailed")}
                  message={errorMessage(techniquesQuery.error)}
                  onRetry={() => void techniquesQuery.refetch()}
                />
              ) : undefined
            }
            empty={<EmptyState icon={Swords} title={c("ti.mitre.empty")} description={c("ti.mitre.emptyHint")} />}
          />
        </div>
      </Card>
    </div>
  );
}

export default ThreatIntelPage;
