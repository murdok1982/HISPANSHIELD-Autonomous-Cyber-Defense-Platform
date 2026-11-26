"""Connector adapter registry.

Importing this package registers every shipped adapter with
``app.services.connectors.base.register_adapter``. Modules must import the
package (not individual adapters) so the catalogue is always complete.
"""

from __future__ import annotations

from app.services.connectors.adapters import (  # noqa: F401  (registration side effects)
    elastic_security,
    generic_webhook,
    keycloak,
    microsoft_defender,
    microsoft_sentinel,
    misp,
    opencti,
    opnsense,
    pfsense,
    suricata_file,
    wazuh,
    zeek_file,
)

ADAPTER_MODULES = (
    "wazuh",
    "elastic_security",
    "microsoft_sentinel",
    "misp",
    "opencti",
    "suricata_file",
    "zeek_file",
    "keycloak",
    "pfsense",
    "opnsense",
    "generic_webhook",
    "microsoft_defender",
)

__all__ = ["ADAPTER_MODULES"]
