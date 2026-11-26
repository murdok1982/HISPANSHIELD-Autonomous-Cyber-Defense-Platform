"""Elastic Security adapter (detection signals via the Kibana/ES APIs)."""

from __future__ import annotations

from typing import Any, ClassVar

from app.services.connectors.adapters._support import HttpAdapter, bounded_limit, pick_list
from app.services.connectors.base import READ, AdapterResult, CapabilitySpec, ConnectorError, register_adapter


@register_adapter
class ElasticSecurityAdapter(HttpAdapter):
    connector_type = "elastic_security"
    display_name = "Elastic Security"
    vendor = "Elastic"
    product = "Elastic Security"
    version = "8.x"
    auth_methods: ClassVar[tuple[str, ...]] = ("api_key", "bearer")
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("read_alerts", READ, "Read detection engine signals", "low"),
    )
    security_profile = "tls-required"

    def _headers(self) -> dict[str, str]:
        if not self.secret:
            raise ConnectorError("Elastic Security API credentials are not configured")
        if self.connector.auth_type == "bearer":
            return {"Authorization": f"Bearer {self.secret}"}
        scheme = str(self.config.get("api_key_scheme") or "ApiKey")
        return {"Authorization": f"{scheme} {self.secret}"}

    def health_check(self) -> AdapterResult:
        result = self.request("GET", "/api/status", headers=self._headers(), attempts=2)
        version = None
        if isinstance(result.data, dict):
            version = (
                result.data.get("version", {}).get("number") if isinstance(result.data.get("version"), dict) else None
            )
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"cluster": result.data.get("cluster_name"), "version": version, "authenticated": True},
        )

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        if capability != "read_alerts":
            raise ConnectorError(f"Unsupported Elastic Security capability: {capability}")
        limit = bounded_limit(params)
        search_body: dict[str, Any] = {
            "size": limit,
            "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": "now-7d"}}}]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        if self.config.get("index"):
            search_body["_source"] = True
        endpoint = str(self.config.get("alerts_endpoint") or "signals")
        if endpoint == "search":
            index = str(self.config.get("index") or ".alerts-security.alerts-*")
            result = self.request("POST", f"/{index}/_search", headers=self._headers(), json_body=search_body)
            items = pick_list(result.data, "hits.hits", "items")
        else:
            result = self.request(
                "POST",
                "/api/detection_engine/signals/search",
                headers=self._headers(),
                json_body=search_body,
            )
            items = pick_list(result.data, "hits.hits", "data", "items")
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"items": items[:limit], "total": len(items)},
        )

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=True, data={"verified": True, "items": len(result.data.get("items") or [])})


__all__ = ["ElasticSecurityAdapter"]
