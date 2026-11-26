"""Builtin global detection rules seeded as ``org_id = NULL``.

Each definition is a real, executable rule in the typed DSL (see
``app.services.detection``).  Templates are returned by
``GET /api/v1/siem/rules/templates`` and inserted idempotently by
``scripts/seed_siem.py``.
"""

from __future__ import annotations

import copy
from typing import Any

BUILTIN_RULES: list[dict[str, Any]] = [
    {
        "key": "brute-force-auth",
        "name": "Builtin: Brute force authentication failures",
        "description": "Multiple failed authentication attempts from one source within five minutes.",
        "severity": "high",
        "logsource": {"product": "generic", "category": "authentication"},
        "definition": {
            "selection": {
                "message": {
                    "regex": (
                        "(?i)(failed (password|login|authentication)|authentication fail|"
                        "login failed|invalid user|invalid credentials)"
                    )
                }
            },
            "condition": "and",
            "threshold": {"count": 5, "group_by": ["src_ip"], "window_seconds": 300},
        },
        "mitre": ["T1110"],
        "tags": ["attack.credential_access", "builtin", "authentication"],
    },
    {
        "key": "port-scan",
        "name": "Builtin: Horizontal port scan",
        "description": "One source touching at least fifteen distinct destination ports in a minute.",
        "severity": "medium",
        "logsource": {"product": "generic", "category": "network"},
        "definition": {
            "selection": {"src_ip": {"exists": True}, "dst_port": {"exists": True}},
            "condition": "and",
            "threshold": {"count": 15, "group_by": ["src_ip"], "window_seconds": 60},
        },
        "mitre": ["T1046"],
        "tags": ["attack.discovery", "builtin", "network"],
    },
    {
        "key": "threat-intel-match",
        "name": "Builtin: Threat intelligence indicator match",
        "description": "An event observable matches an active organization or global threat indicator.",
        "severity": "high",
        "logsource": {"product": "generic", "category": "threat_intel"},
        "definition": {
            "selection": {"ioc_matches": {"exists": True}},
            "condition": "and",
        },
        "mitre": ["T1071"],
        "tags": ["attack.command_and_control", "builtin", "threat_intel"],
    },
    {
        "key": "privilege-escalation",
        "name": "Builtin: Privilege escalation attempt",
        "description": "Privileged execution or elevation activity (sudo/runas/root/administrator).",
        "severity": "high",
        "logsource": {"product": "generic", "category": "endpoint"},
        "definition": {
            "selection": {
                "message": {
                    "regex": (
                        "(?i)(sudo|su: |runas|administrator|elevat|privilege escalation|uid=0|root account|become root)"
                    )
                }
            },
            "condition": "and",
        },
        "mitre": ["T1068", "T1548"],
        "tags": ["attack.privilege_escalation", "builtin", "host"],
    },
    {
        "key": "malware-known-bad-hash",
        "name": "Builtin: Known-bad malware hash",
        "description": "A file SHA-256 observed in the event matches a threat-intelligence indicator.",
        "severity": "critical",
        "logsource": {"product": "generic", "category": "malware"},
        "definition": {
            "selection": {
                "file_hash_sha256": {"exists": True},
                "ioc_matches": {"known_bad": "sha256"},
            },
            "condition": "and",
        },
        "mitre": ["T1204", "T1105"],
        "tags": ["attack.execution", "builtin", "malware"],
    },
    {
        "key": "large-outbound-transfer",
        "name": "Builtin: Large outbound data transfer",
        "description": "A single event reports at least 100 MiB sent to a remote endpoint.",
        "severity": "medium",
        "logsource": {"product": "generic", "category": "network"},
        "definition": {
            "selection": {"bytes_out": {"gte": 104857600}},
            "condition": "and",
        },
        "mitre": ["T1041"],
        "tags": ["attack.exfiltration", "builtin", "network"],
    },
]


def builtin_rules() -> list[dict[str, Any]]:
    """Return deep copies so callers cannot mutate the catalogue."""
    return copy.deepcopy(BUILTIN_RULES)


__all__ = ["BUILTIN_RULES", "builtin_rules"]
