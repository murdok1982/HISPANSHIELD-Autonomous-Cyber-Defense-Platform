"""OT protocol registry with safety classification.

Every entry keeps ``passive_only_default`` true. ``active_operations_denied``
documents the write/control verbs that HISPANSHIELD will never send; the API
exposes no endpoint capable of performing them.
"""

from __future__ import annotations

from typing import Any

OT_PROTOCOLS: list[dict[str, Any]] = [
    {
        "name": "Modbus TCP",
        "family": "modbus",
        "default_ports": [502],
        "safety_class": "process_critical",
        "support_level": "full",
        "passive_only_default": True,
        "security_notes": (
            "No authentication or integrity protection; any host that can reach 502 can write coils/registers."
        ),
        "active_operations_denied": ["write_coil", "write_register", "diagnostics_restart"],
    },
    {
        "name": "Modbus RTU",
        "family": "modbus",
        "default_ports": [],
        "safety_class": "process_critical",
        "support_level": "observe",
        "passive_only_default": True,
        "security_notes": ("Serial fieldbus; monitor through a passive tap or RTU gateway, never inject frames."),
        "active_operations_denied": ["write_coil", "write_register", "force_listen_only_off"],
    },
    {
        "name": "DNP3",
        "family": "dnp3",
        "default_ports": [20000],
        "safety_class": "safety_critical",
        "support_level": "full",
        "passive_only_default": True,
        "security_notes": (
            "Secure Authentication is optional; control operations directly affect breakers and valves."
        ),
        "active_operations_denied": ["operate", "direct_operate", "select_before_operate", "cold_restart"],
    },
    {
        "name": "OPC UA",
        "family": "opcua",
        "default_ports": [4840],
        "safety_class": "process_critical",
        "support_level": "full",
        "passive_only_default": True,
        "security_notes": (
            "Require SignAndEncrypt and least-privilege tokens; browse methods are read-only, call methods forbidden."
        ),
        "active_operations_denied": ["call_method", "write_value", "add_nodes"],
    },
    {
        "name": "BACnet",
        "family": "bacnet",
        "default_ports": [47808],
        "safety_class": "supervisory",
        "support_level": "full",
        "passive_only_default": True,
        "security_notes": (
            "Building automation has no native auth; write-property can change HVAC/life-safety setpoints."
        ),
        "active_operations_denied": ["write_property", "reinitialize_device", "device_communication_control"],
    },
    {
        "name": "KNX",
        "family": "knx",
        "default_ports": [3671],
        "safety_class": "supervisory",
        "support_level": "observe",
        "passive_only_default": True,
        "security_notes": (
            "KNX IP gateways often allow unauthenticated group writes; observe only, no group value writes."
        ),
        "active_operations_denied": ["group_value_write", "download", "restart"],
    },
    {
        "name": "PROFINET",
        "family": "profinet",
        "default_ports": [],
        "safety_class": "safety_critical",
        "support_level": "observe",
        "passive_only_default": True,
        "security_notes": (
            "Real-time Ethernet for controllers and drives; inline manipulation can halt production safely systems."
        ),
        "active_operations_denied": ["connect", "write_record", "control", "reset"],
    },
    {
        "name": "EtherNet/IP",
        "family": "ethernet_ip",
        "default_ports": [44818, 2222],
        "safety_class": "process_critical",
        "support_level": "full",
        "passive_only_default": True,
        "security_notes": (
            "CIP explicit messaging can change controller tags; ListIdentity probing is passive-friendly only."
        ),
        "active_operations_denied": ["write_tag", "forward_open", "reset_controller"],
    },
    {
        "name": "EtherCAT",
        "family": "ethercat",
        "default_ports": [],
        "safety_class": "safety_critical",
        "support_level": "observe",
        "passive_only_default": True,
        "security_notes": ("Cycle-synchronous motion bus; any injected frame can cause hazardous motion."),
        "active_operations_denied": ["write_register", "state_change", "firmware_update"],
    },
    {
        "name": "IEC 60870-5-104",
        "family": "iec60870",
        "default_ports": [2404],
        "safety_class": "safety_critical",
        "support_level": "full",
        "passive_only_default": True,
        "security_notes": ("Telecontrol protocol for substations; command ASDUs operate primary equipment."),
        "active_operations_denied": ["single_command", "double_command", "setpoint_command", "reset_process"],
    },
    {
        "name": "IEC 61850",
        "family": "iec61850",
        "default_ports": [102],
        "safety_class": "safety_critical",
        "support_level": "observe",
        "passive_only_default": True,
        "security_notes": ("MMS/GOOSE for substation automation; control blocks directly map to switching operations."),
        "active_operations_denied": ["write_control_block", "operate", "file_transfer"],
    },
    {
        "name": "S7",
        "family": "s7",
        "default_ports": [102],
        "safety_class": "safety_critical",
        "support_level": "observe",
        "passive_only_default": True,
        "security_notes": (
            "Siemens S7comm can read/write PLC memory and change run/stop state without authentication on legacy CPUs."
        ),
        "active_operations_denied": ["write_variable", "plc_start", "plc_stop", "download_block"],
    },
    {
        "name": "CAN bus",
        "family": "can",
        "default_ports": [],
        "safety_class": "safety_critical",
        "support_level": "observe",
        "passive_only_default": True,
        "security_notes": ("In-vehicle / machine bus; injecting frames can override safety-critical control loops."),
        "active_operations_denied": ["inject_frame", "replay_frame", "reset_bus"],
    },
]

_INDEX: dict[str, dict[str, Any]] = {entry["name"].strip().lower(): entry for entry in OT_PROTOCOLS}
_ALIASES: dict[str, str] = {
    "modbus": "Modbus TCP",
    "modbus/tcp": "Modbus TCP",
    "modbus-rtu": "Modbus RTU",
    "modbus/rtu": "Modbus RTU",
    "opc-ua": "OPC UA",
    "opcua": "OPC UA",
    "bacnet/ip": "BACnet",
    "ethernet/ip": "EtherNet/IP",
    "ethernet-ip": "EtherNet/IP",
    "iec-60870-5-104": "IEC 60870-5-104",
    "iec104": "IEC 60870-5-104",
    "iec-61850": "IEC 61850",
    "s7comm": "S7",
    "canbus": "CAN bus",
    "can-bus": "CAN bus",
}


def ot_protocol_spec(value: str) -> dict[str, Any] | None:
    key = (value or "").strip().lower()
    if not key:
        return None
    if key in _INDEX:
        return _INDEX[key]
    alias = _ALIASES.get(key)
    if alias:
        return _INDEX[alias.lower()]
    return None


def canonical_ot_protocol(value: str) -> str | None:
    spec = ot_protocol_spec(value)
    return spec["name"] if spec else None


def canonical_ot_protocol_list(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        canonical = canonical_ot_protocol(value)
        if canonical is None:
            raise ValueError(f"Unsupported OT protocol: {value}")
        if canonical not in result:
            result.append(canonical)
    return result


__all__ = [
    "OT_PROTOCOLS",
    "canonical_ot_protocol",
    "canonical_ot_protocol_list",
    "ot_protocol_spec",
]
