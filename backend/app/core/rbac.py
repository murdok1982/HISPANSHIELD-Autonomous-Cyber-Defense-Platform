"""Role-based access control catalogue.

Roles are static and auditable; per-object constraints are evaluated by the ABAC
policy engine (`app.services.policy_engine`). A user's effective permissions are
computed from the membership role only — never from client-supplied claims.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

ROLE_LABELS: dict[str, str] = {
    "platform_admin": "Platform administrator",
    "org_admin": "Organization administrator",
    "soc_manager": "SOC manager",
    "soc_analyst": "SOC analyst",
    "incident_responder": "Incident responder",
    "threat_analyst": "Threat intelligence analyst",
    "vulnerability_manager": "Vulnerability manager",
    "compliance_officer": "Compliance officer",
    "auditor": "Read-only auditor",
    "viewer": "Viewer",
}

READ_ONLY = {
    "org:read",
    "user:read",
    "asset:read",
    "vuln:read",
    "attack_surface:read",
    "event:read",
    "alert:read",
    "incident:read",
    "ti:read",
    "playbook:read",
    "connector:read",
    "ai:read",
    "compliance:read",
    "report:read",
    "policy:read",
    "audit:read",
    "edge:read",
    "mcp:read",
    "defence:read",
}

_ORG_ADMIN_MODULES = (
    "org",
    "user",
    "asset",
    "vuln",
    "attack_surface",
    "event",
    "alert",
    "incident",
    "ti",
    "playbook",
    "connector",
    "ai",
    "compliance",
    "report",
    "policy",
    "audit",
    "edge",
    "mcp",
    "defence",
    "autonomy",
    "killswitch",
    "approval",
    "apikey",
    "notification",
    "settings",
)

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "platform_admin": {"*"},
    "org_admin": {f"{module}:*" for module in _ORG_ADMIN_MODULES},
    "soc_manager": {
        *READ_ONLY,
        "alert:write",
        "incident:write",
        "incident:close",
        "vuln:write",
        "ti:write",
        "playbook:write",
        "playbook:execute",
        "playbook:approve",
        "connector:write",
        "connector:execute",
        "defence:propose",
        "defence:approve",
        "autonomy:read",
        "autonomy:write",
        "killswitch:operate",
        "approval:read",
        "approval:decide",
        "event:ingest",
        "ai:use",
        "ai:admin",
        "report:generate",
        "user:read",
        "edge:write",
        "mcp:write",
    },
    "soc_analyst": {
        *READ_ONLY,
        "alert:write",
        "incident:write",
        "vuln:write",
        "ti:write",
        "playbook:execute",
        "defence:propose",
        "event:ingest",
        "ai:use",
        "report:generate",
        "approval:read",
        "notification:read",
    },
    "incident_responder": {
        *READ_ONLY,
        "alert:write",
        "incident:write",
        "incident:close",
        "playbook:execute",
        "connector:execute",
        "defence:propose",
        "defence:execute",
        "approval:read",
        "ai:use",
        "event:ingest",
        "report:read",
        "notification:read",
    },
    "threat_analyst": {
        *READ_ONLY,
        "ti:write",
        "ti:sync",
        "alert:write",
        "ai:use",
        "report:generate",
        "notification:read",
    },
    "vulnerability_manager": {
        *READ_ONLY,
        "asset:write",
        "vuln:write",
        "vuln:import",
        "attack_surface:write",
        "report:generate",
        "notification:read",
    },
    "compliance_officer": {
        *READ_ONLY,
        "compliance:write",
        "compliance:assess",
        "report:generate",
        "notification:read",
    },
    "auditor": {*READ_ONLY, "audit:verify", "notification:read"},
    "viewer": {*READ_ONLY, "notification:read"},
}

ALL_PERMISSIONS: list[dict[str, str]] = [
    {"key": "org:read", "description": "View organization profile and settings"},
    {"key": "org:write", "description": "Modify organization profile and settings"},
    {"key": "user:read", "description": "List members and roles"},
    {"key": "user:manage", "description": "Invite, modify and deactivate members"},
    {"key": "apikey:manage", "description": "Create and revoke API tokens"},
    {"key": "asset:read", "description": "Read asset inventory and relationships"},
    {"key": "asset:write", "description": "Create, update and delete assets"},
    {"key": "vuln:read", "description": "Read vulnerabilities and prioritisation"},
    {"key": "vuln:write", "description": "Update vulnerability lifecycle"},
    {"key": "vuln:import", "description": "Import CVE/KEV/EPSS intelligence"},
    {"key": "attack_surface:read", "description": "Read attack surface findings"},
    {"key": "attack_surface:write", "description": "Run authorized discovery and manage findings"},
    {"key": "event:read", "description": "Search normalized security events"},
    {"key": "event:ingest", "description": "Submit events to the ingestion API"},
    {"key": "alert:read", "description": "Read alerts"},
    {"key": "alert:write", "description": "Triage, assign and close alerts"},
    {"key": "incident:read", "description": "Read incidents, timelines and evidence"},
    {"key": "incident:write", "description": "Create and update incidents"},
    {"key": "incident:close", "description": "Close incidents with lessons learned"},
    {"key": "ti:read", "description": "Read threat intelligence"},
    {"key": "ti:write", "description": "Manage indicators, actors and feeds"},
    {"key": "ti:sync", "description": "Synchronize external intelligence feeds"},
    {"key": "playbook:read", "description": "Read playbooks and executions"},
    {"key": "playbook:write", "description": "Author and publish playbooks"},
    {"key": "playbook:execute", "description": "Execute published playbooks"},
    {"key": "playbook:approve", "description": "Approve playbook executions requiring authorization"},
    {"key": "connector:read", "description": "Read connector registry and health"},
    {"key": "connector:write", "description": "Configure connectors and credentials"},
    {"key": "connector:execute", "description": "Invoke connector read/write operations"},
    {"key": "defence:read", "description": "Read remediations and autonomy decisions"},
    {"key": "defence:propose", "description": "Propose defensive actions"},
    {"key": "defence:execute", "description": "Execute authorized defensive actions"},
    {"key": "defence:approve", "description": "Approve A3/A4 defensive actions"},
    {"key": "autonomy:read", "description": "Read autonomy policies"},
    {"key": "autonomy:write", "description": "Edit autonomy policies"},
    {"key": "killswitch:operate", "description": "Engage or release kill switches"},
    {"key": "approval:read", "description": "Read approval requests"},
    {"key": "approval:decide", "description": "Approve or reject requests"},
    {"key": "ai:read", "description": "Read model registry and usage"},
    {"key": "ai:use", "description": "Invoke AI reasoning and agents"},
    {"key": "ai:admin", "description": "Manage providers, models and knowledge base"},
    {"key": "mcp:read", "description": "Read MCP servers and tools"},
    {"key": "mcp:write", "description": "Register and approve MCP capabilities"},
    {"key": "mcp:execute", "description": "Execute approved MCP tools"},
    {"key": "compliance:read", "description": "Read frameworks and assessments"},
    {"key": "compliance:write", "description": "Manage frameworks, controls and evidence links"},
    {"key": "compliance:assess", "description": "Create and complete assessments"},
    {"key": "report:read", "description": "Read generated reports"},
    {"key": "report:generate", "description": "Generate technical, executive and regulatory reports"},
    {"key": "policy:read", "description": "Read access and retention policies"},
    {"key": "policy:write", "description": "Edit policies"},
    {"key": "audit:read", "description": "Read the append-only audit trail"},
    {"key": "audit:verify", "description": "Verify audit hash-chain integrity"},
    {"key": "edge:read", "description": "Read edge gateways"},
    {"key": "edge:write", "description": "Enroll, configure and revoke gateways"},
    {"key": "settings:write", "description": "Modify platform settings"},
    {"key": "notification:read", "description": "Read notifications"},
]


def has_permission(role: str, permission: str) -> bool:
    granted = ROLE_PERMISSIONS.get(role)
    if not granted:
        return False
    if "*" in granted:
        return True
    for pattern in granted:
        if fnmatchcase(permission, pattern):
            return True
    return permission in granted


def effective_permissions(role: str) -> list[str]:
    granted = ROLE_PERMISSIONS.get(role, set())
    if "*" in granted:
        role_perms = {p["key"] for p in ALL_PERMISSIONS}
        return sorted(role_perms | {"*"})
    result: set[str] = set()
    for permission in (p["key"] for p in ALL_PERMISSIONS):
        if has_permission(role, permission):
            result.add(permission)
    return sorted(result)
