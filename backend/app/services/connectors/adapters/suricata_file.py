"""Suricata adapter reading a local ``eve.json`` file (no network access)."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from app.services.connectors.adapters._support import FileLogAdapter, bounded_limit, read_file_tail
from app.services.connectors.base import READ, AdapterResult, CapabilitySpec, ConnectorError, register_adapter


@register_adapter
class SuricataFileAdapter(FileLogAdapter):
    connector_type = "suricata_file"
    display_name = "Suricata EVE log"
    vendor = "OISF"
    product = "Suricata"
    version = "7.x"
    data_formats: ClassVar[tuple[str, ...]] = ("jsonl",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("read_alerts", READ, "Tail alert records from a local eve.json file", "low"),
    )
    security_profile = "local-file-readonly"

    def health_check(self) -> AdapterResult:
        return self._health_result()

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        if capability != "read_alerts":
            raise ConnectorError(f"Unsupported Suricata capability: {capability}")
        limit = bounded_limit(params)
        event_types = self.config.get("event_types")
        allowed = {str(item) for item in event_types} if isinstance(event_types, list) and event_types else {"alert"}
        lines = read_file_tail(self.resolved_path(), max_lines=min(2000, limit * 10))
        items: list[dict[str, Any]] = []
        skipped = 0
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                skipped += 1
                continue
            if not isinstance(record, dict):
                skipped += 1
                continue
            if str(record.get("event_type") or "") not in allowed:
                continue
            items.append(record)
        return AdapterResult(
            ok=True,
            data={"items": items[-limit:], "skipped": skipped, "format": "suricata-eve"},
        )

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=True, data={"verified": True, "items": len(result.data.get("items") or [])})


__all__ = ["SuricataFileAdapter"]
