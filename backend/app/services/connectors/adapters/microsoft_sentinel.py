"""Microsoft Sentinel adapter (Azure AD client credentials + Log Analytics query)."""

from __future__ import annotations

from typing import Any, ClassVar

from app.services.connectors.adapters._support import (
    HttpAdapter,
    bounded_limit,
    oauth_token,
    records_from_tables,
)
from app.services.connectors.base import READ, AdapterResult, CapabilitySpec, ConnectorError, register_adapter

DEFAULT_LOGIN_BASE = "https://login.microsoftonline.com"
DEFAULT_LOG_ANALYTICS = "https://api.loganalytics.io"
DEFAULT_SCOPE = "https://api.loganalytics.io/.default"


@register_adapter
class MicrosoftSentinelAdapter(HttpAdapter):
    connector_type = "microsoft_sentinel"
    display_name = "Microsoft Sentinel"
    vendor = "Microsoft"
    product = "Microsoft Sentinel"
    version = "2023-02-01"
    auth_methods: ClassVar[tuple[str, ...]] = ("client_credentials",)
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("read_alerts", READ, "Query SecurityAlert from the Log Analytics workspace", "low"),
    )
    security_profile = "oauth-client-credentials"

    def _setting(self, key: str, default: str | None = None) -> str:
        value = str(self.config.get(key) or default or "").strip()
        if not value:
            raise ConnectorError(f"Connector configuration is missing '{key}'")
        return value

    def _token(self) -> str:
        if not self.secret:
            raise ConnectorError("Azure AD client secret is not configured")
        tenant_id = self._setting("tenant_id")
        client_id = self._setting("client_id")
        scope = str(self.config.get("scope") or DEFAULT_SCOPE)
        login_base = self._setting("login_base_url", DEFAULT_LOGIN_BASE).rstrip("/")
        return oauth_token(
            f"{login_base}/{tenant_id}/oauth2/v2.0/token",
            {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": self.secret,
                "scope": scope,
            },
            cache_key=f"sentinel:{tenant_id}:{client_id}:{scope}",
            verify_tls=self.connector.verify_tls,
        )

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}

    def _query(self, query: str, *, limit: int) -> AdapterResult:
        workspace_id = self._setting("workspace_id")
        resource = self._setting("log_analytics_url", DEFAULT_LOG_ANALYTICS).rstrip("/")
        result = self.request(
            "POST",
            f"{resource}/v1/workspaces/{workspace_id}/query",
            headers=self._headers(),
            json_body={"query": query, "timespan": str(self.config.get("timespan") or "P1D")},
            attempts=1,
        )
        records = records_from_tables(result.data if isinstance(result.data, dict) else {})
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"items": records[:limit], "tables": len(result.data.get("tables") or [])},
        )

    def health_check(self) -> AdapterResult:
        self._token()
        result = self._query("SecurityAlert | take 1", limit=1)
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"authenticated": True, "workspace": self.config.get("workspace_id")},
        )

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        if capability != "read_alerts":
            raise ConnectorError(f"Unsupported Microsoft Sentinel capability: {capability}")
        limit = bounded_limit(params)
        configured_query = self.config.get("query")
        if configured_query:
            query = str(configured_query)[:8000]
        else:
            query = (
                "SecurityAlert "
                f"| where TimeGenerated > ago({str(self.config.get('lookback') or '1d')}) "
                "| order by TimeGenerated desc "
                f"| take {limit} "
                "| project TimeGenerated, AlertName, AlertSeverity, Description, CompromisedEntity, "
                "ProductName, ProviderName, SystemAlertId, Tactics, Techniques, Entities"
            )
        return self._query(query, limit=limit)

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=True, data={"verified": True, "items": len(result.data.get("items") or [])})


__all__ = ["MicrosoftSentinelAdapter"]
