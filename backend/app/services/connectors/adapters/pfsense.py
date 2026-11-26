"""pfSense adapter (API v2 firewall aliases, block/unblock with apply)."""

from __future__ import annotations

from typing import Any, ClassVar

from app.services.connectors.adapters._support import (
    HttpAdapter,
    pick_list,
    safe_segment,
    validate_firewall_ip,
)
from app.services.connectors.base import (
    WRITE,
    AdapterResult,
    CapabilitySpec,
    ConnectorError,
    register_adapter,
)


@register_adapter
class PfSenseAdapter(HttpAdapter):
    connector_type = "pfsense"
    display_name = "pfSense firewall"
    vendor = "Netgate"
    product = "pfSense CE/Plus"
    version = "2.7"
    auth_methods: ClassVar[tuple[str, ...]] = ("api_key_header",)
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec(
            "block_ip",
            WRITE,
            "Add an address to a firewall alias and apply the rules",
            "medium",
            requires_approval=True,
        ),
        CapabilitySpec("unblock_ip", WRITE, "Remove an address from a firewall alias and apply", "medium"),
    )
    security_profile = "api-key-header"

    def _headers(self) -> dict[str, str]:
        if not self.secret:
            raise ConnectorError("pfSense API key is not configured")
        header_name = str(self.config.get("api_key_header") or "X-API-Key")
        return {header_name: self.secret, "Accept": "application/json", "Content-Type": "application/json"}

    def _alias_id(self) -> int:
        alias_name = safe_segment(self.config.get("alias_name"), field="alias name")
        result = self.request("GET", "/api/v2/firewall/aliases", headers=self._headers(), attempts=2)
        aliases = pick_list(result.data, "data", "data.aliases", "aliases")
        for alias in aliases:
            if str(alias.get("name")) == alias_name:
                alias_id = alias.get("id")
                if isinstance(alias_id, int):
                    return alias_id
                if isinstance(alias_id, str) and alias_id.isdigit():
                    return int(alias_id)
        raise ConnectorError(f"The configured firewall alias does not exist: {alias_name}")

    def _entries(self, alias_id: int) -> list[dict[str, Any]]:
        result = self.request(
            "GET",
            "/api/v2/firewall/alias_entries",
            headers=self._headers(),
            params={"parent_id": alias_id},
            attempts=2,
        )
        return pick_list(result.data, "data", "data.entries", "entries")

    def _find_entry(self, alias_id: int, address: str) -> dict[str, Any] | None:
        for entry in self._entries(alias_id):
            if str(entry.get("address")) == address:
                return entry
        return None

    def _apply(self) -> AdapterResult:
        return self.request(
            "POST",
            "/api/v2/firewall/apply",
            headers=self._headers(),
            json_body={"async": False},
            expect_json=False,
            attempts=1,
        )

    def health_check(self) -> AdapterResult:
        result = self.request("GET", "/api/v2/firewall/aliases", headers=self._headers(), attempts=2)
        aliases = pick_list(result.data, "data", "data.aliases", "aliases")
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"aliases": len(aliases), "authenticated": True},
        )

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        if capability not in {"block_ip", "unblock_ip"}:
            raise ConnectorError(f"Unsupported pfSense capability: {capability}")
        address = validate_firewall_ip(params)
        alias_id = self._alias_id()
        existing = self._find_entry(alias_id, address)
        if capability == "block_ip":
            if existing is not None:
                return AdapterResult(
                    ok=True,
                    external_id=str(existing.get("id")),
                    data={"ip": address, "alias_id": alias_id, "already_blocked": True},
                )
            created = self.request(
                "POST",
                "/api/v2/firewall/alias_entries",
                headers=self._headers(),
                json_body={
                    "parent_id": alias_id,
                    "address": address,
                    "detail": str(self.config.get("entry_detail") or "HISPANSHIELD defensive block")[:200],
                },
                attempts=1,
            )
            entry_data = created.data.get("data") if isinstance(created.data.get("data"), dict) else {}
            self._apply()
            return AdapterResult(
                ok=True,
                status_code=created.status_code,
                external_id=str(entry_data.get("id") or ""),
                data={"ip": address, "alias_id": alias_id, "already_blocked": False},
            )
        if existing is None:
            return AdapterResult(ok=True, data={"ip": address, "alias_id": alias_id, "already_absent": True})
        entry_id = existing.get("id")
        self.request(
            "DELETE",
            "/api/v2/firewall/alias_entries",
            headers=self._headers(),
            params={"id": entry_id},
            expect_json=False,
            attempts=1,
        )
        self._apply()
        return AdapterResult(
            ok=True,
            external_id=str(entry_id or ""),
            data={"ip": address, "alias_id": alias_id, "already_absent": False},
        )

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        address = validate_firewall_ip(params)
        alias_id = self._alias_id()
        present = self._find_entry(alias_id, address) is not None
        expected = capability == "block_ip"
        return AdapterResult(
            ok=present == expected,
            data={"verified": present == expected, "present": present, "expected": expected, "ip": address},
            error=None if present == expected else "pfSense alias state does not match the requested change",
        )


__all__ = ["PfSenseAdapter"]
