"""OPNsense adapter (alias_util API with HTTP basic auth)."""

from __future__ import annotations

from typing import Any, ClassVar

from app.services.connectors.adapters._support import HttpAdapter, pick_list, safe_segment, validate_firewall_ip
from app.services.connectors.base import (
    WRITE,
    AdapterResult,
    CapabilitySpec,
    ConnectorError,
    register_adapter,
)
from app.services.connectors.http import auth_headers


@register_adapter
class OPNsenseAdapter(HttpAdapter):
    connector_type = "opnsense"
    display_name = "OPNsense firewall"
    vendor = "Deciso"
    product = "OPNsense"
    version = "24.x"
    auth_methods: ClassVar[tuple[str, ...]] = ("basic",)
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec(
            "block_ip",
            WRITE,
            "Add an address to an OPNsense firewall alias",
            "medium",
            requires_approval=True,
        ),
        CapabilitySpec("unblock_ip", WRITE, "Remove an address from an OPNsense firewall alias", "medium"),
    )
    security_profile = "api-key-basic"

    def _headers(self) -> dict[str, str]:
        if not self.secret:
            raise ConnectorError("OPNsense API credentials are not configured")
        configured_key = str(self.config.get("api_key") or "").strip()
        credentials = f"{configured_key}:{self.secret}" if configured_key else self.secret
        if ":" not in credentials:
            raise ConnectorError("OPNsense credentials must be stored as 'key:secret'")
        return {**auth_headers(credentials, "basic"), "Accept": "application/json", "Content-Type": "application/json"}

    def _alias(self) -> str:
        return safe_segment(self.config.get("alias_name"), field="alias name")

    def _list_entries(self, alias: str) -> list[dict[str, Any]]:
        result = self.request("GET", f"/api/firewall/alias_util/list/{alias}", headers=self._headers(), attempts=2)
        return pick_list(result.data, "rows", "data", "data.rows", "items")

    def _entry_address(self, entry: dict[str, Any]) -> str:
        return str(entry.get("ip") or entry.get("address") or entry.get("value") or "")

    def health_check(self) -> AdapterResult:
        alias = self._alias()
        entries = self._list_entries(alias)
        return AdapterResult(ok=True, data={"alias": alias, "entries": len(entries), "authenticated": True})

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        if capability not in {"block_ip", "unblock_ip"}:
            raise ConnectorError(f"Unsupported OPNsense capability: {capability}")
        address = validate_firewall_ip(params)
        alias = self._alias()
        present = any(self._entry_address(entry) == address for entry in self._list_entries(alias))
        if capability == "block_ip":
            if present:
                return AdapterResult(ok=True, data={"ip": address, "alias": alias, "already_blocked": True})
            result = self.request(
                "POST",
                f"/api/firewall/alias_util/add/{alias}",
                headers=self._headers(),
                json_body={
                    "address": address,
                    "description": str(self.config.get("entry_detail") or "HISPANSHIELD defensive block")[:200],
                },
                attempts=1,
            )
            return AdapterResult(
                ok=True,
                status_code=result.status_code,
                external_id=address,
                data={"ip": address, "alias": alias, "already_blocked": False, "result": result.data},
            )
        if not present:
            return AdapterResult(ok=True, data={"ip": address, "alias": alias, "already_absent": True})
        result = self.request(
            "POST",
            f"/api/firewall/alias_util/delete/{alias}",
            headers=self._headers(),
            json_body={"address": address},
            attempts=1,
        )
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            external_id=address,
            data={"ip": address, "alias": alias, "already_absent": False, "result": result.data},
        )

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        address = validate_firewall_ip(params)
        alias = self._alias()
        present = any(self._entry_address(entry) == address for entry in self._list_entries(alias))
        expected = capability == "block_ip"
        return AdapterResult(
            ok=present == expected,
            data={"verified": present == expected, "present": present, "expected": expected, "ip": address},
            error=None if present == expected else "OPNsense alias state does not match the requested change",
        )


__all__ = ["OPNsenseAdapter"]
