"""Canonical catalogue of defensive actions.

The catalogue is code-owned and immutable at runtime: no model or agent can
invent an action. Each entry declares the minimum autonomy level, risk,
reversibility, target type and connector capability required.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ActionDefinition:
    key: str
    label: str
    description: str
    min_level: str
    risk: str  # low | medium | high | critical
    reversible: bool
    target_type: str  # endpoint | ip | identity | session | incident | asset | organization | integration
    capability: str | None  # connector capability; None for internal actions
    internal: bool = False
    approval_required: bool = False
    ot_allowed: bool = False


ACTIONS: dict[str, ActionDefinition] = {
    "investigation.enrich": ActionDefinition(
        key="investigation.enrich",
        label="Enrich investigation context",
        description="Correlate events, assets and threat intelligence for an incident.",
        min_level="A1",
        risk="low",
        reversible=True,
        target_type="incident",
        capability=None,
        internal=True,
    ),
    "evidence.collect": ActionDefinition(
        key="evidence.collect",
        label="Collect forensic evidence",
        description="Capture and seal evidence with a SHA-256 chain of custody.",
        min_level="A1",
        risk="low",
        reversible=True,
        target_type="incident",
        capability=None,
        internal=True,
    ),
    "incident.open": ActionDefinition(
        key="incident.open",
        label="Open an incident",
        description="Create an incident from an alert or investigation.",
        min_level="A1",
        risk="low",
        reversible=True,
        target_type="incident",
        capability=None,
        internal=True,
    ),
    "notify.webhook": ActionDefinition(
        key="notify.webhook",
        label="Notify an external channel",
        description="Send a signed notification to an approved webhook.",
        min_level="A1",
        risk="low",
        reversible=False,
        target_type="integration",
        capability="notify_webhook",
    ),
    "session.revoke": ActionDefinition(
        key="session.revoke",
        label="Revoke identity sessions",
        description="Revoke active sessions for a compromised identity.",
        min_level="A2",
        risk="medium",
        reversible=True,
        target_type="identity",
        capability="revoke_sessions",
    ),
    "endpoint.isolate": ActionDefinition(
        key="endpoint.isolate",
        label="Isolate endpoint",
        description="Network-isolate a managed endpoint while preserving management connectivity.",
        min_level="A3",
        risk="high",
        reversible=True,
        target_type="endpoint",
        capability="isolate_endpoint",
        approval_required=True,
    ),
    "endpoint.unisolate": ActionDefinition(
        key="endpoint.unisolate",
        label="Release endpoint isolation",
        description="Reverse an endpoint isolation authorized by this platform.",
        min_level="A3",
        risk="medium",
        reversible=True,
        target_type="endpoint",
        capability="unisolate_endpoint",
    ),
    "identity.disable": ActionDefinition(
        key="identity.disable",
        label="Disable identity",
        description="Disable a compromised account in the identity provider.",
        min_level="A3",
        risk="high",
        reversible=True,
        target_type="identity",
        capability="disable_user",
        approval_required=True,
    ),
    "identity.enable": ActionDefinition(
        key="identity.enable",
        label="Re-enable identity",
        description="Reverse a platform-authorized identity disable.",
        min_level="A3",
        risk="medium",
        reversible=True,
        target_type="identity",
        capability="enable_user",
    ),
    "ip.block": ActionDefinition(
        key="ip.block",
        label="Block network indicator",
        description="Add a defensive deny entry for an indicator on a managed firewall.",
        min_level="A3",
        risk="medium",
        reversible=True,
        target_type="ip",
        capability="block_ip",
        approval_required=True,
    ),
    "ip.unblock": ActionDefinition(
        key="ip.unblock",
        label="Unblock network indicator",
        description="Remove a deny entry previously authorized by this platform.",
        min_level="A3",
        risk="medium",
        reversible=True,
        target_type="ip",
        capability="unblock_ip",
    ),
    "configuration.restore": ActionDefinition(
        key="configuration.restore",
        label="Restore known-good configuration",
        description="Restore a validated configuration snapshot.",
        min_level="A3",
        risk="high",
        reversible=False,
        target_type="asset",
        capability="restore_configuration",
        approval_required=True,
    ),
    "patch.apply": ActionDefinition(
        key="patch.apply",
        label="Apply authorized patch",
        description="Deploy an approved patch through the endpoint management connector.",
        min_level="A3",
        risk="high",
        reversible=False,
        target_type="endpoint",
        capability="apply_patch",
        approval_required=True,
    ),
}

# Explicitly forbidden operation classes. Keeping them named makes denial
# auditable and prevents future code from quietly enabling them.
FORBIDDEN_ACTIONS = {
    "ot.write_register": "Writes to industrial controllers are never automated by the platform",
    "ot.firmware_update": "OT firmware changes require a separate safety case and manual procedure",
    "ot.device_reboot": "Rebooting OT devices can alter physical processes",
    "scan.aggressive": "Aggressive scanning of OT/IoT is prohibited; passive monitoring only",
    "attack.exploit": "Offensive exploitation is outside the defensive mandate",
    "data.exfiltrate": "Exfiltration is not a defensive capability",
}


def get_action(action_type: str) -> ActionDefinition | None:
    return ACTIONS.get(action_type)


LEVELS = ("A0", "A1", "A2", "A3", "A4")


def level_index(level: str) -> int:
    try:
        return LEVELS.index(level)
    except ValueError as exc:
        raise ValueError(f"Unknown autonomy level: {level}") from exc
