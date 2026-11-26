"""Zeek adapter reading a local logs directory (no network access)."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from app.services.connectors.adapters._support import (
    FileLogAdapter,
    bounded_limit,
    read_file_tail,
    resolve_file_path,
)
from app.services.connectors.base import READ, AdapterResult, CapabilitySpec, ConnectorError, register_adapter

DEFAULT_LOG_FILES = ("notice.log", "weird.log", "conn.log")


def _record_timestamp(item: dict[str, Any]) -> float:
    try:
        return float(item.get("ts") or 0)
    except (TypeError, ValueError):
        return 0.0


@register_adapter
class ZeekFileAdapter(FileLogAdapter):
    connector_type = "zeek_file"
    display_name = "Zeek logs"
    vendor = "Zeek"
    product = "Zeek Network Security Monitor"
    version = "6.x"
    data_formats: ClassVar[tuple[str, ...]] = ("jsonl",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("read_alerts", READ, "Tail notice/weird records from a local Zeek log directory", "low"),
    )
    security_profile = "local-file-readonly"

    @classmethod
    def path_is_directory(cls) -> bool:
        return True

    def _log_files(self) -> list[str]:
        configured = self.config.get("log_files")
        if isinstance(configured, list) and configured:
            return [str(item) for item in configured]
        return list(DEFAULT_LOG_FILES)

    def health_check(self) -> AdapterResult:
        result = self._health_result()
        directory = self.resolved_path()
        present = [name for name in self._log_files() if (directory / name).is_file()]
        if not present:
            return AdapterResult(
                ok=False,
                error="No configured Zeek log files exist in the directory",
                data={"path": str(directory), "present": []},
            )
        return AdapterResult(
            ok=True,
            data={"path": str(directory), "present": present, "size": result.data.get("size", 0)},
        )

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        if capability != "read_alerts":
            raise ConnectorError(f"Unsupported Zeek capability: {capability}")
        limit = bounded_limit(params)
        directory = self.resolved_path()
        records: list[dict[str, Any]] = []
        skipped = 0
        missing = 0
        for name in self._log_files():
            try:
                log_path = resolve_file_path(directory / name, directory=False, must_exist=True)
            except ConnectorError:
                missing += 1
                continue
            lines = read_file_tail(log_path, max_lines=limit)
            for line in lines:
                try:
                    record = json.loads(line)
                except ValueError:
                    skipped += 1
                    continue
                if not isinstance(record, dict):
                    skipped += 1
                    continue
                record.setdefault("_path", name.removesuffix(".log"))
                records.append(record)
        if not records and missing == len(self._log_files()):
            raise ConnectorError("No readable Zeek log files were found")
        records.sort(key=_record_timestamp, reverse=True)
        return AdapterResult(
            ok=True,
            data={"items": records[:limit], "skipped": skipped, "missing_files": missing, "format": "zeek-json"},
        )

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=True, data={"verified": True, "items": len(result.data.get("items") or [])})


__all__ = ["ZeekFileAdapter"]
