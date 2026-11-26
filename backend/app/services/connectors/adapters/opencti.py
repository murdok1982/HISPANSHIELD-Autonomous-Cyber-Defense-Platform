"""OpenCTI adapter (GraphQL indicator search)."""

from __future__ import annotations

from typing import Any, ClassVar

from app.services.connectors.adapters._support import HttpAdapter, bounded_limit
from app.services.connectors.base import READ, AdapterResult, CapabilitySpec, ConnectorError, register_adapter

_INDICATORS_QUERY = """
query Indicators($first: Int!) {
  indicators(first: $first, orderBy: created_at, orderMode: desc) {
    edges {
      node {
        id
        name
        description
        pattern
        pattern_type
        confidence
        valid_from
        valid_until
        x_opencti_score
        revoked
        created_at
        modified
        objectLabel { value }
      }
    }
  }
}
""".strip()


@register_adapter
class OpenCTIAdapter(HttpAdapter):
    connector_type = "opencti"
    display_name = "OpenCTI"
    vendor = "Filigran"
    product = "OpenCTI"
    version = "6.x"
    auth_methods: ClassVar[tuple[str, ...]] = ("bearer",)
    data_formats: ClassVar[tuple[str, ...]] = ("json", "stix")
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("read_indicators", READ, "Query STIX indicators from the OpenCTI GraphQL API", "low"),
    )

    def _headers(self) -> dict[str, str]:
        if not self.secret:
            raise ConnectorError("OpenCTI API token is not configured")
        return {"Authorization": f"Bearer {self.secret}", "Content-Type": "application/json"}

    def _graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        result = self.request(
            "POST",
            "/graphql",
            headers=self._headers(),
            json_body={"query": query, "variables": variables or {}},
            attempts=1,
        )
        payload = result.data if isinstance(result.data, dict) else {}
        errors = payload.get("errors")
        if errors:
            message = "; ".join(str(error.get("message")) for error in errors if isinstance(error, dict))
            raise ConnectorError(f"OpenCTI GraphQL error: {message[:500]}")
        data = payload.get("data")
        return data if isinstance(data, dict) else {}

    def health_check(self) -> AdapterResult:
        data = self._graphql("query { about { version } }")
        about = data.get("about") if isinstance(data.get("about"), dict) else {}
        return AdapterResult(
            ok=True,
            data={"version": about.get("version"), "authenticated": True},
        )

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        if capability != "read_indicators":
            raise ConnectorError(f"Unsupported OpenCTI capability: {capability}")
        limit = bounded_limit(params)
        data = self._graphql(_INDICATORS_QUERY, {"first": limit})
        indicators = data.get("indicators") if isinstance(data.get("indicators"), dict) else {}
        edges = indicators.get("edges") or []
        nodes = [edge["node"] for edge in edges if isinstance(edge, dict) and isinstance(edge.get("node"), dict)]
        return AdapterResult(ok=True, data={"items": nodes[:limit], "format": "opencti"})

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=True, data={"verified": True, "items": len(result.data.get("items") or [])})


__all__ = ["OpenCTIAdapter"]
