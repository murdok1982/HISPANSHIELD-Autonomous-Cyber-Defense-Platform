"""MISP adapter (threat-intelligence event and attribute search)."""

from __future__ import annotations

from typing import Any, ClassVar

from app.services.connectors.adapters._support import HttpAdapter, bounded_limit, pick_list
from app.services.connectors.base import READ, AdapterResult, CapabilitySpec, ConnectorError, register_adapter


@register_adapter
class MispAdapter(HttpAdapter):
    connector_type = "misp"
    display_name = "MISP"
    vendor = "MISP Project"
    product = "MISP"
    version = "2.4"
    auth_methods: ClassVar[tuple[str, ...]] = ("token_header", "api_key_header")
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("read_indicators", READ, "Search events/attributes for threat indicators", "low"),
    )
    security_profile = "api-key-header"

    def _headers(self) -> dict[str, str]:
        if not self.secret:
            raise ConnectorError("MISP API key is not configured")
        header_name = str(self.config.get("token_header") or "Authorization")
        return {header_name: self.secret, "Accept": "application/json"}

    def health_check(self) -> AdapterResult:
        result = self.request("GET", "/servers/getVersion", headers=self._headers(), attempts=2)
        payload = result.data or {}
        version = (
            payload.get("version") or (payload.get("data") or {}).get("version") if isinstance(payload, dict) else None
        )
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"version": version, "authenticated": True},
        )

    def _flatten_events(self, payload: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        response = payload.get("response")
        if isinstance(response, dict):
            response = response.get("Attribute") or response.get("Event") or []
        if not isinstance(response, list):
            return []
        items: list[dict[str, Any]] = []
        for entry in response:
            if not isinstance(entry, dict):
                continue
            event = entry.get("Event") if isinstance(entry.get("Event"), dict) else {}
            attributes = entry.get("Attribute") or event.get("Attribute") or []
            if not isinstance(attributes, list):
                continue
            event_meta = {
                "uuid": event.get("uuid"),
                "info": event.get("info"),
                "threat_level_id": event.get("threat_level_id"),
                "date": event.get("date"),
                "Tag": event.get("Tag"),
            }
            for attribute in attributes:
                if isinstance(attribute, dict):
                    items.append({"Attribute": attribute, "Event": event_meta})
                if len(items) >= limit:
                    return items
        return items

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        if capability != "read_indicators":
            raise ConnectorError(f"Unsupported MISP capability: {capability}")
        limit = bounded_limit(params)
        mode = str(self.config.get("search_mode") or "events")
        if mode == "attributes":
            body: dict[str, Any] = {"returnFormat": "json", "limit": limit, "page": 1}
            if self.config.get("types"):
                body["type"] = self.config["types"]
            if self.config.get("tags"):
                body["tags"] = self.config["tags"]
            result = self.request("POST", "/attributes/restSearch", headers=self._headers(), json_body=body, attempts=1)
            attributes = pick_list(result.data, "response.Attribute", "response.attributes", "Attribute")
            items = [{"Attribute": attribute, "Event": {}} for attribute in attributes[:limit]]
        else:
            body = {"returnFormat": "json", "limit": limit, "page": 1}
            if bool(self.config.get("published_only", True)):
                body["published"] = True
            if self.config.get("tags"):
                body["tags"] = self.config["tags"]
            result = self.request("POST", "/events/restSearch", headers=self._headers(), json_body=body, attempts=1)
            items = self._flatten_events(result.data if isinstance(result.data, dict) else {}, limit)
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"items": items, "format": "misp", "mode": mode},
        )

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=True, data={"verified": True, "items": len(result.data.get("items") or [])})


__all__ = ["MispAdapter"]
