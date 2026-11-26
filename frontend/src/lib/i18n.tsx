import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type Lang = "es" | "en";

type Dictionary = Record<string, string>;

const es: Dictionary = {
  "nav.group.command": "Mando",
  "nav.group.detect": "Detección",
  "nav.group.expose": "Superficie",
  "nav.group.protect": "Protección",
  "nav.group.govern": "Gobierno",
  "nav.group.admin": "Administración",
  "nav.executive": "Visión ejecutiva",
  "nav.soc": "Centro de mando SOC",
  "nav.monitoring": "Monitorización en vivo",
  "nav.incidents": "Gestión de incidentes",
  "nav.threatIntel": "Inteligencia de amenazas",
  "nav.siem": "SIEM",
  "nav.assets": "Inteligencia de activos",
  "nav.attackSurface": "Superficie de ataque",
  "nav.vulnerabilities": "Vulnerabilidades",
  "nav.soar": "SOAR",
  "nav.agents": "Control de agentes IA",
  "nav.iotOt": "Seguridad IoT/OT",
  "nav.network": "Seguridad de red",
  "nav.cloud": "Seguridad cloud",
  "nav.identity": "Seguridad de identidad",
  "nav.forensics": "Análisis forense",
  "nav.compliance": "Cumplimiento",
  "nav.audit": "Centro de auditoría",
  "nav.integrations": "Integraciones",
  "nav.playbooks": "Diseñador de playbooks",
  "nav.models": "Gestión de modelos",
  "nav.organizations": "Organizaciones",
  "nav.admin": "Administración del sistema",

  "common.search": "Buscar en la plataforma…",
  "common.searchShort": "Buscar",
  "common.retry": "Reintentar",
  "common.refresh": "Actualizar",
  "common.save": "Guardar",
  "common.cancel": "Cancelar",
  "common.create": "Crear",
  "common.edit": "Editar",
  "common.delete": "Eliminar",
  "common.close": "Cerrar",
  "common.confirm": "Confirmar",
  "common.loading": "Cargando…",
  "common.error": "No se pudo completar la operación",
  "common.noData": "Sin datos",
  "common.showing": "Mostrando {from}–{to} de {total}",
  "common.page": "Página {page} de {pages}",
  "common.previous": "Anterior",
  "common.next": "Siguiente",
  "common.filters": "Filtros",
  "common.all": "Todos",
  "common.actions": "Acciones",
  "common.details": "Detalle",
  "common.status": "Estado",
  "common.severity": "Severidad",
  "common.created": "Creado",
  "common.updated": "Actualizado",
  "common.source": "Origen",
  "common.owner": "Responsable",
  "common.type": "Tipo",
  "common.time": "Hora",
  "common.signOut": "Cerrar sesión",
  "common.profile": "Perfil",
  "common.settings": "Ajustes",
  "common.language": "Idioma",
  "common.theme": "Tema",
  "common.light": "Claro",
  "common.dark": "Oscuro",
  "common.killSwitch": "Kill switch",
  "common.autonomy": "Autonomía",
  "common.demoData": "Datos de demostración",
  "common.operational": "Entorno operativo",
  "common.notifications": "Notificaciones",
  "common.noNotifications": "Sin notificaciones",
  "common.critical": "Crítica",
  "common.high": "Alta",
  "common.medium": "Media",
  "common.low": "Baja",
  "common.info": "Informativa",
  "common.open": "Abierta",
  "common.closed": "Cerrada",
  "common.active": "Activo",
  "common.inactive": "Inactivo",
  "common.healthy": "Saludable",
  "common.degraded": "Degradado",
  "common.unhealthy": "No saludable",
  "common.unknown": "Desconocido",
  "common.recommended": "Recomendado",
  "common.export": "Exportar",
  "common.download": "Descargar",
  "common.copy": "Copiar",
  "common.copied": "Copiado",
  "common.required": "Obligatorio",
  "common.optional": "Opcional",
  "common.permissionDenied": "No tienes permisos para esta acción",
  "common.seeAll": "Ver todo",
  "common.lastUpdated": "Actualizado {time}",
  "common.na": "—",
  "common.yes": "Sí",
  "common.no": "No",

  "auth.title": "Acceso al centro de mando",
  "auth.subtitle": "Autenticación reforzada para operadores autorizados de ciberdefensa.",
  "auth.email": "Correo corporativo",
  "auth.password": "Contraseña",
  "auth.signIn": "Acceder",
  "auth.signingIn": "Verificando…",
  "auth.mfaTitle": "Verificación en dos pasos",
  "auth.mfaSubtitle": "Introduce el código de 6 dígitos de tu aplicación TOTP.",
  "auth.mfaCode": "Código de verificación",
  "auth.verify": "Verificar",
  "auth.back": "Volver",
  "auth.failed": "No se pudo iniciar sesión",
  "auth.invalidCode": "Código inválido o caducado",
  "auth.securityNotice":
    "Sistema de uso restringido. Toda actividad se registra en una cadena de auditoría inmutable. El acceso no autorizado está prohibido y puede ser perseguido legalmente.",
  "auth.euHosting": "Alojamiento europeo · IA local · Zero Trust",
  "auth.restricted": "ACCESO RESTRINGIDO",
  "auth.sessionExpired": "Tu sesión ha caducado. Vuelve a autenticarte.",

  "overview.title": "Visión ejecutiva",
  "overview.subtitle": "Riesgo consolidado, postura defensiva y actividad operativa de la organización.",
  "overview.riskScore": "Índice de riesgo",
  "overview.openIncidents": "Incidentes abiertos",
  "overview.openAlerts": "Alertas abiertas",
  "overview.openVulns": "Vulnerabilidades abiertas",
  "overview.events24h": "Eventos (24 h)",
  "overview.mttr": "MTTR",
  "overview.knownExploited": "Explotadas conocidas",
  "overview.activeIndicators": "Indicadores activos",
  "overview.incidentTrend": "Tendencia de incidentes",
  "overview.eventVolume": "Volumen de eventos",
  "overview.severitySplit": "Distribución por severidad",
  "overview.connectorHealth": "Salud de integraciones",
  "overview.recentIncidents": "Incidentes recientes",
  "overview.topAssets": "Activos con más exposición",
  "overview.riskFactors": "Factores de riesgo",
  "overview.autonomyLevel": "Nivel de autonomía",
  "overview.noIncidents": "No hay incidentes registrados",
  "overview.noIncidentsHint": "Cuando se detecte actividad adversaria aparecerá aquí con su trazabilidad completa.",
  "overview.emptyEvents": "Sin eventos en la ventana temporal",
  "overview.goToSoc": "Ir al SOC",
  "overview.generateReport": "Generar informe",
  "overview.ages": "Antigüedad",
  "overview.notEnoughData": "Datos insuficientes para calcular la tendencia",

  "soc.title": "Centro de mando SOC",
  "soc.subtitle": "Triaje, correlación y respuesta en tiempo real sobre la telemetría normalizada.",
  "soc.eventRate": "Eventos por minuto",
  "soc.eventsLastHour": "Última hora",
  "soc.liveFeed": "Flujo de eventos en vivo",
  "soc.newAlerts": "Alertas nuevas",
  "soc.activeIncidents": "Incidentes activos",
  "soc.noAlerts": "Sin alertas nuevas",
  "soc.noAlertsHint": "Las reglas de detección no han generado alertas en esta ventana.",
  "soc.noEvents": "Esperando telemetría",
  "soc.noEventsHint": "Conecta una fuente de ingesta o envía eventos para activar el flujo en vivo.",
  "soc.sources": "Fuentes de ingesta",
  "soc.ruleCoverage": "Cobertura de reglas",
  "soc.recentActivity": "Actividad reciente",
  "soc.triage": "Triar",
  "soc.pause": "Pausar",
  "soc.resume": "Reanudar",

  "errors.network": "No se pudo contactar con el servidor",
  "errors.forbidden": "Permisos insuficientes",
  "errors.notFound": "Recurso no encontrado",
  "errors.timeout": "Tiempo de espera agotado",
  "errors.unexpected": "Error inesperado",
  "errors.retryHint": "Vuelve a intentarlo. Si persiste, revisa el estado de las integraciones.",
  "errors.loadFailed": "No se pudieron cargar los datos",
  "errors.emptyTitle": "Aún no hay datos",
  "errors.insufficientData": "Datos insuficientes",
  "page.notFound": "Página no encontrada",
  "page.notFoundHint": "La ruta solicitada no existe o ha sido movida.",
  "page.backHome": "Volver al panel",
};

const en: Dictionary = {
  "nav.group.command": "Command",
  "nav.group.detect": "Detect",
  "nav.group.expose": "Exposure",
  "nav.group.protect": "Protect",
  "nav.group.govern": "Govern",
  "nav.group.admin": "Administration",
  "nav.executive": "Executive overview",
  "nav.soc": "SOC command center",
  "nav.monitoring": "Live threat monitoring",
  "nav.incidents": "Incident management",
  "nav.threatIntel": "Threat intelligence",
  "nav.siem": "SIEM",
  "nav.assets": "Asset intelligence",
  "nav.attackSurface": "Attack surface",
  "nav.vulnerabilities": "Vulnerability management",
  "nav.soar": "SOAR",
  "nav.agents": "AI agent control",
  "nav.iotOt": "IoT/OT security",
  "nav.network": "Network security",
  "nav.cloud": "Cloud security",
  "nav.identity": "Identity security",
  "nav.forensics": "Forensics",
  "nav.compliance": "Compliance",
  "nav.audit": "Audit center",
  "nav.integrations": "Integrations",
  "nav.playbooks": "Playbook designer",
  "nav.models": "Model management",
  "nav.organizations": "Organizations",
  "nav.admin": "System administration",

  "common.search": "Search the platform…",
  "common.searchShort": "Search",
  "common.retry": "Retry",
  "common.refresh": "Refresh",
  "common.save": "Save",
  "common.cancel": "Cancel",
  "common.create": "Create",
  "common.edit": "Edit",
  "common.delete": "Delete",
  "common.close": "Close",
  "common.confirm": "Confirm",
  "common.loading": "Loading…",
  "common.error": "The operation could not be completed",
  "common.noData": "No data",
  "common.showing": "Showing {from}–{to} of {total}",
  "common.page": "Page {page} of {pages}",
  "common.previous": "Previous",
  "common.next": "Next",
  "common.filters": "Filters",
  "common.all": "All",
  "common.actions": "Actions",
  "common.details": "Details",
  "common.status": "Status",
  "common.severity": "Severity",
  "common.created": "Created",
  "common.updated": "Updated",
  "common.source": "Source",
  "common.owner": "Owner",
  "common.type": "Type",
  "common.time": "Time",
  "common.signOut": "Sign out",
  "common.profile": "Profile",
  "common.settings": "Settings",
  "common.language": "Language",
  "common.theme": "Theme",
  "common.light": "Light",
  "common.dark": "Dark",
  "common.killSwitch": "Kill switch",
  "common.autonomy": "Autonomy",
  "common.demoData": "Demonstration data",
  "common.operational": "Operational environment",
  "common.notifications": "Notifications",
  "common.noNotifications": "No notifications",
  "common.critical": "Critical",
  "common.high": "High",
  "common.medium": "Medium",
  "common.low": "Low",
  "common.info": "Informational",
  "common.open": "Open",
  "common.closed": "Closed",
  "common.active": "Active",
  "common.inactive": "Inactive",
  "common.healthy": "Healthy",
  "common.degraded": "Degraded",
  "common.unhealthy": "Unhealthy",
  "common.unknown": "Unknown",
  "common.recommended": "Recommended",
  "common.export": "Export",
  "common.download": "Download",
  "common.copy": "Copy",
  "common.copied": "Copied",
  "common.required": "Required",
  "common.optional": "Optional",
  "common.permissionDenied": "You do not have permission for this action",
  "common.seeAll": "See all",
  "common.lastUpdated": "Updated {time}",
  "common.na": "—",
  "common.yes": "Yes",
  "common.no": "No",

  "auth.title": "Command center access",
  "auth.subtitle": "Hardened authentication for authorized cyber defence operators.",
  "auth.email": "Corporate email",
  "auth.password": "Password",
  "auth.signIn": "Sign in",
  "auth.signingIn": "Verifying…",
  "auth.mfaTitle": "Two-step verification",
  "auth.mfaSubtitle": "Enter the 6-digit code from your TOTP application.",
  "auth.mfaCode": "Verification code",
  "auth.verify": "Verify",
  "auth.back": "Back",
  "auth.failed": "Sign-in failed",
  "auth.invalidCode": "Invalid or expired code",
  "auth.securityNotice":
    "Restricted-use system. All activity is recorded in an immutable audit chain. Unauthorized access is prohibited and may be prosecuted.",
  "auth.euHosting": "European hosting · Local AI · Zero Trust",
  "auth.restricted": "RESTRICTED ACCESS",
  "auth.sessionExpired": "Your session has expired. Please authenticate again.",

  "overview.title": "Executive overview",
  "overview.subtitle": "Consolidated risk, defensive posture and operational activity for the organization.",
  "overview.riskScore": "Risk index",
  "overview.openIncidents": "Open incidents",
  "overview.openAlerts": "Open alerts",
  "overview.openVulns": "Open vulnerabilities",
  "overview.events24h": "Events (24 h)",
  "overview.mttr": "MTTR",
  "overview.knownExploited": "Known exploited",
  "overview.activeIndicators": "Active indicators",
  "overview.incidentTrend": "Incident trend",
  "overview.eventVolume": "Event volume",
  "overview.severitySplit": "Severity distribution",
  "overview.connectorHealth": "Integration health",
  "overview.recentIncidents": "Recent incidents",
  "overview.topAssets": "Most exposed assets",
  "overview.riskFactors": "Risk factors",
  "overview.autonomyLevel": "Autonomy level",
  "overview.noIncidents": "No incidents recorded",
  "overview.noIncidentsHint": "Adversary activity will appear here with full traceability.",
  "overview.emptyEvents": "No events in the time window",
  "overview.goToSoc": "Go to SOC",
  "overview.generateReport": "Generate report",
  "overview.ages": "Age",
  "overview.notEnoughData": "Not enough data to compute the trend",

  "soc.title": "SOC command center",
  "soc.subtitle": "Real-time triage, correlation and response over normalized telemetry.",
  "soc.eventRate": "Events per minute",
  "soc.eventsLastHour": "Last hour",
  "soc.liveFeed": "Live event feed",
  "soc.newAlerts": "New alerts",
  "soc.activeIncidents": "Active incidents",
  "soc.noAlerts": "No new alerts",
  "soc.noAlertsHint": "Detection rules have not produced alerts in this window.",
  "soc.noEvents": "Awaiting telemetry",
  "soc.noEventsHint": "Connect an ingestion source or submit events to activate the live feed.",
  "soc.sources": "Ingestion sources",
  "soc.ruleCoverage": "Rule coverage",
  "soc.recentActivity": "Recent activity",
  "soc.triage": "Triage",
  "soc.pause": "Pause",
  "soc.resume": "Resume",

  "errors.network": "Unable to reach the server",
  "errors.forbidden": "Insufficient permissions",
  "errors.notFound": "Resource not found",
  "errors.timeout": "Request timed out",
  "errors.unexpected": "Unexpected error",
  "errors.retryHint": "Try again. If it persists, review integration health.",
  "errors.loadFailed": "Could not load the data",
  "errors.emptyTitle": "No data yet",
  "errors.insufficientData": "Insufficient data",
  "page.notFound": "Page not found",
  "page.notFoundHint": "The requested route does not exist or has moved.",
  "page.backHome": "Back to dashboard",
};

const dictionaries: Record<Lang, Dictionary> = { es, en };

interface I18nContextValue {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (key: string, params?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

const LANG_KEY = "hs.lang";

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    try {
      const stored = window.localStorage.getItem(LANG_KEY);
      if (stored === "es" || stored === "en") return stored;
    } catch {
      /* ignore */
    }
    return navigator.language.toLowerCase().startsWith("en") ? "en" : "es";
  });

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  const setLang = useCallback((next: Lang) => {
    setLangState(next);
    try {
      window.localStorage.setItem(LANG_KEY, next);
    } catch {
      /* ignore */
    }
  }, []);

  const t = useCallback(
    (key: string, params?: Record<string, string | number>) => {
      let value = dictionaries[lang][key] ?? dictionaries.en[key] ?? key;
      if (params) {
        for (const [name, replacement] of Object.entries(params)) {
          value = value.replaceAll(`{${name}}`, String(replacement));
        }
      }
      return value;
    },
    [lang],
  );

  const value = useMemo(() => ({ lang, setLang, t }), [lang, setLang, t]);
  return createElement(I18nContext.Provider, { value }, children);
}

export function useI18n(): I18nContextValue {
  const context = useContext(I18nContext);
  if (!context) throw new Error("useI18n must be used inside I18nProvider");
  return context;
}

/**
 * Page-local dictionaries keep translations close to the screen and avoid a
 * single merge-conflict-prone catalogue. Missing keys fall back to the global
 * dictionary and then to the provided key.
 */
export function usePageCopy<T extends Record<Lang, Dictionary>>(copy: T): (key: string) => string {
  const { lang } = useI18n();
  return useCallback((key: string) => copy[lang][key] ?? copy.en[key] ?? key, [copy, lang]);
}

export function severityKey(severity: string): string {
  const normalized = severity.toLowerCase();
  if (["critical", "critica", "crítica"].includes(normalized)) return "common.critical";
  if (["high", "alta", "alto"].includes(normalized)) return "common.high";
  if (["medium", "media", "medio", "moderate"].includes(normalized)) return "common.medium";
  if (["low", "baja", "bajo"].includes(normalized)) return "common.low";
  return "common.info";
}
