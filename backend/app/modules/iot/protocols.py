"""IoT protocol registry.

``support_level`` is one of:

- ``full``      → telemetry ingestion, identity enrichment and posture checks.
- ``observe``   → passive metadata only (wireless stacks we never actively touch).

``read_only_default`` must remain true: HISPANSHIELD performs passive monitoring
for every IoT protocol and has no actuator/command capability.
"""

from __future__ import annotations

from typing import Any

IOT_PROTOCOLS: list[dict[str, Any]] = [
    {
        "name": "MQTT",
        "family": "mqtt",
        "default_ports": [1883],
        "read_only_default": True,
        "security_notes": (
            "Plaintext broker traffic; enforce TLS, per-device credentials and topic ACLs. "
            "Anonymous publish/subscribe is a common exposure."
        ),
        "support_level": "full",
    },
    {
        "name": "MQTT/TLS",
        "family": "mqtt",
        "default_ports": [8883],
        "read_only_default": True,
        "security_notes": "TLS-wrapped broker; verify certificate pinning and require mutual TLS for devices.",
        "support_level": "full",
    },
    {
        "name": "CoAP",
        "family": "coap",
        "default_ports": [5683, 5684],
        "read_only_default": True,
        "security_notes": (
            "UDP-based; use DTLS (5684), enforce block-wise transfer limits and disable multicast discovery."
        ),
        "support_level": "full",
    },
    {
        "name": "HTTP/HTTPS",
        "family": "http",
        "default_ports": [80, 443],
        "read_only_default": True,
        "security_notes": (
            "Many devices expose unauthenticated management UIs on plain HTTP. "
            "Redirect to HTTPS, disable default credentials and restrict by management VLAN."
        ),
        "support_level": "full",
    },
    {
        "name": "AMQP",
        "family": "amqp",
        "default_ports": [5671, 5672],
        "read_only_default": True,
        "security_notes": "Use AMQPS (5671) with vhost isolation; disable the guest account and enforce SASL/TLS.",
        "support_level": "full",
    },
    {
        "name": "OPC UA",
        "family": "opcua",
        "default_ports": [4840],
        "read_only_default": True,
        "security_notes": (
            "Industrial interoperability stack; require SignAndEncrypt security policies, "
            "trusted certificates and least-privilege user tokens. Anonymous endpoints are unsafe."
        ),
        "support_level": "full",
    },
    {
        "name": "BLE",
        "family": "ble",
        "default_ports": [],
        "read_only_default": True,
        "security_notes": (
            "Wireless GATT exposure; passive observation only. Audit pairing modes and disable debug GATT services."
        ),
        "support_level": "observe",
    },
    {
        "name": "Zigbee",
        "family": "zigbee",
        "default_ports": [],
        "read_only_default": True,
        "security_notes": (
            "Mesh networks rely on network keys; verify key rotation, install codes and coordinator isolation."
        ),
        "support_level": "observe",
    },
    {
        "name": "Z-Wave",
        "family": "zwave",
        "default_ports": [],
        "read_only_default": True,
        "security_notes": "Use S2 security class; S0 is deprecated. Passive observation only.",
        "support_level": "observe",
    },
    {
        "name": "Thread",
        "family": "thread",
        "default_ports": [],
        "read_only_default": True,
        "security_notes": "IPv6 mesh built on 802.15.4; protect border routers and rotate network credentials.",
        "support_level": "observe",
    },
    {
        "name": "Matter",
        "family": "matter",
        "default_ports": [5540],
        "read_only_default": True,
        "security_notes": (
            "Application layer over Thread/Wi-Fi; verify commissioning attestation and device certificates."
        ),
        "support_level": "observe",
    },
    {
        "name": "LoRaWAN",
        "family": "lorawan",
        "default_ports": [],
        "read_only_default": True,
        "security_notes": "Use OTAA with unique AppKeys and replay protection; never reuse root keys across devices.",
        "support_level": "observe",
    },
    {
        "name": "NB-IoT",
        "family": "nbiot",
        "default_ports": [],
        "read_only_default": True,
        "security_notes": (
            "Cellular LPWAN; enforce private APN, IPsec/DTLS at the application layer and SIM lifecycle control."
        ),
        "support_level": "observe",
    },
    {
        "name": "LTE-M",
        "family": "ltem",
        "default_ports": [],
        "read_only_default": True,
        "security_notes": (
            "Cellular LPWAN; restrict inbound connectivity, pin certificates and monitor data-plan anomalies."
        ),
        "support_level": "observe",
    },
]

_INDEX: dict[str, dict[str, Any]] = {}
_ALIASES: dict[str, str] = {
    "mqtts": "MQTT/TLS",
    "mqtt/tls": "MQTT/TLS",
    "secure-mqtt": "MQTT/TLS",
    "https": "HTTP/HTTPS",
    "http/https": "HTTP/HTTPS",
    "http": "HTTP/HTTPS",
    "amqps": "AMQP",
    "opc-ua": "OPC UA",
    "opcua": "OPC UA",
    "lora": "LoRaWAN",
    "nbiot": "NB-IoT",
    "lte-m": "LTE-M",
    "ltem": "LTE-M",
    "nfc": "BLE",
}

for _entry in IOT_PROTOCOLS:
    _INDEX[_entry["name"].strip().lower()] = _entry

_PROTOCOL_NAMES = {entry["name"] for entry in IOT_PROTOCOLS}


def protocol_spec(value: str) -> dict[str, Any] | None:
    """Resolve a user-supplied protocol label to its canonical registry entry."""
    key = (value or "").strip().lower()
    if not key:
        return None
    if key in _INDEX:
        return _INDEX[key]
    alias = _ALIASES.get(key)
    if alias and alias.lower() in _INDEX:
        return _INDEX[alias.lower()]
    return None


def canonical_protocol(value: str) -> str | None:
    spec = protocol_spec(value)
    return spec["name"] if spec else None


def canonical_protocol_list(values: list[str]) -> list[str]:
    """Normalise a protocol list and reject unknown labels (order preserved)."""
    result: list[str] = []
    for value in values:
        canonical = canonical_protocol(value)
        if canonical is None:
            raise ValueError(f"Unsupported IoT protocol: {value}")
        if canonical not in result:
            result.append(canonical)
    return result


def protocol_names() -> set[str]:
    return set(_PROTOCOL_NAMES)


__all__ = [
    "IOT_PROTOCOLS",
    "canonical_protocol",
    "canonical_protocol_list",
    "protocol_names",
    "protocol_spec",
]
