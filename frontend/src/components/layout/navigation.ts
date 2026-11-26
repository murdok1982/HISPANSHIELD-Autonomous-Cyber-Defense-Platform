import type { LucideIcon } from "lucide-react";
import {
  Activity,
  BookOpenCheck,
  Bot,
  Building2,
  Cloud,
  Crosshair,
  Cpu,
  Database,
  Factory,
  Fingerprint,
  LayoutDashboard,
  Microscope,
  Network,
  PlugZap,
  Radar,
  Scale,
  ScanSearch,
  ScrollText,
  Settings,
  ShieldAlert,
  Siren,
  Workflow,
} from "lucide-react";

export interface NavItem {
  key: string;
  path: string;
  labelKey: string;
  icon: LucideIcon;
  permission: string;
  badgeKey?: "incidents" | "alerts";
}

export interface NavGroup {
  key: string;
  labelKey: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    key: "command",
    labelKey: "nav.group.command",
    items: [
      { key: "executive", path: "/", labelKey: "nav.executive", icon: LayoutDashboard, permission: "org:read" },
      { key: "soc", path: "/soc", labelKey: "nav.soc", icon: Radar, permission: "event:read" },
      { key: "monitoring", path: "/monitoring", labelKey: "nav.monitoring", icon: Activity, permission: "event:read" },
    ],
  },
  {
    key: "detect",
    labelKey: "nav.group.detect",
    items: [
      { key: "incidents", path: "/incidents", labelKey: "nav.incidents", icon: Siren, permission: "incident:read" },
      { key: "threat-intel", path: "/threat-intel", labelKey: "nav.threatIntel", icon: Crosshair, permission: "ti:read" },
      { key: "siem", path: "/siem", labelKey: "nav.siem", icon: Database, permission: "event:read" },
    ],
  },
  {
    key: "expose",
    labelKey: "nav.group.expose",
    items: [
      { key: "assets", path: "/assets", labelKey: "nav.assets", icon: ScanSearch, permission: "asset:read" },
      { key: "attack-surface", path: "/attack-surface", labelKey: "nav.attackSurface", icon: ShieldAlert, permission: "attack_surface:read" },
      { key: "vulnerabilities", path: "/vulnerabilities", labelKey: "nav.vulnerabilities", icon: Fingerprint, permission: "vuln:read" },
    ],
  },
  {
    key: "protect",
    labelKey: "nav.group.protect",
    items: [
      { key: "soar", path: "/soar", labelKey: "nav.soar", icon: Workflow, permission: "playbook:read" },
      { key: "playbooks", path: "/playbook-designer", labelKey: "nav.playbooks", icon: BookOpenCheck, permission: "playbook:read" },
      { key: "agents", path: "/agents", labelKey: "nav.agents", icon: Bot, permission: "ai:read" },
      { key: "iot-ot", path: "/iot-ot", labelKey: "nav.iotOt", icon: Factory, permission: "asset:read" },
      { key: "network", path: "/network", labelKey: "nav.network", icon: Network, permission: "asset:read" },
      { key: "cloud", path: "/cloud", labelKey: "nav.cloud", icon: Cloud, permission: "asset:read" },
      { key: "identity", path: "/identity", labelKey: "nav.identity", icon: Cpu, permission: "asset:read" },
    ],
  },
  {
    key: "govern",
    labelKey: "nav.group.govern",
    items: [
      { key: "forensics", path: "/forensics", labelKey: "nav.forensics", icon: Microscope, permission: "incident:read" },
      { key: "compliance", path: "/compliance", labelKey: "nav.compliance", icon: Scale, permission: "compliance:read" },
      { key: "audit", path: "/audit", labelKey: "nav.audit", icon: ScrollText, permission: "audit:read" },
    ],
  },
  {
    key: "admin",
    labelKey: "nav.group.admin",
    items: [
      { key: "integrations", path: "/integrations", labelKey: "nav.integrations", icon: PlugZap, permission: "connector:read" },
      { key: "models", path: "/models", labelKey: "nav.models", icon: Bot, permission: "ai:read" },
      { key: "organizations", path: "/organizations", labelKey: "nav.organizations", icon: Building2, permission: "org:read" },
      { key: "admin", path: "/admin", labelKey: "nav.admin", icon: Settings, permission: "org:read" },
    ],
  },
];

export const ALL_NAV_ITEMS = NAV_GROUPS.flatMap((group) => group.items);
