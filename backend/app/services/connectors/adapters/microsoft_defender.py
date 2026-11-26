"""Microsoft Defender for Endpoint adapter (Graph OAuth, alerts, isolation)."""

from __future__ import annotations

from typing import Any, ClassVar

from app.services.connectors.adapters._support import (
    HttpAdapter,
    bounded_limit,
    oauth_token,
    pick_list,
    required_str,
    safe_segment,
)
from app.services.connectors.base import (
    READ,
    WRITE,
    AdapterResult,
    CapabilitySpec,
    ConnectorError,
    register_adapter,
)

DEFAULT_LOGIN_BASE = "https://login.microsoftonline.com"
DEFAULT_API_BASE = "https://api.securitycenter.microsoft.com"
DEFAULT_SCOPE = "https://api.securitycenter.microsoft.com/.default"


@register_adapter
class MicrosoftDefenderAdapter(HttpAdapter):
    connector_type = "microsoft_defender"
    display_name = "Microsoft Defender for Endpoint"
    vendor = "Microsoft"
    product = "Defender for Endpoint"
    version = "2022-11-01"
    auth_methods: ClassVar[tuple[str, ...]] = ("client_credentials",)
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("read_alerts", READ, "Read Defender alerts", "low"),
        CapabilitySpec(
            "isolate_endpoint",
            WRITE,
            "Network-isolate a managed machine while keeping management connectivity",
            "high",
            requires_approval=True,
        ),
        CapabilitySpec("unisolate_endpoint", WRITE, "Release a machine isolation", "medium"),
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
            cache_key=f"defender:{tenant_id}:{client_id}:{scope}",
            verify_tls=self.connector.verify_tls,
        )

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}

    def _api(self) -> str:
        return self._setting("api_base_url", DEFAULT_API_BASE).rstrip("/")

    def _machine_id(self, params: dict[str, Any]) -> str:
        return safe_segment(
            required_str(params, "machine_id", "endpoint_id", "target_id", "asset_id"), field="machine id"
        )

    def health_check(self) -> AdapterResult:
        self._token()
        result = self.request("GET", f"{self._api()}/api/machines", headers=self._headers(), params={"$top": 1})
        items = pick_list(result.data, "value", "items")
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"authenticated": True, "machines_visible": len(items)},
        )

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        limit = bounded_limit(params)
        if capability == "read_alerts":
            result = self.request(
                "GET",
                f"{self._api()}/api/alerts",
                headers=self._headers(),
                params={"$top": limit, "$orderby": "alertCreationTime desc"},
            )
            return AdapterResult(
                ok=True,
                status_code=result.status_code,
                data={"items": pick_list(result.data, "value", "items")[:limit]},
            )
        if capability in {"isolate_endpoint", "unisolate_endpoint"}:
            machine_id = self._machine_id(params)
            comment = str(params.get("comment") or "HISPANSHIELD defensive action")[:500]
            if capability == "isolate_endpoint":
                body = {"Comment": comment, "IsolationType": str(self.config.get("isolation_type") or "Full")}
                path = f"{self._api()}/api/machines/{machine_id}/isolate"
            else:
                body = {"Comment": comment}
                path = f"{self._api()}/api/machines/{machine_id}/unisolate"
            result = self.request("POST", path, headers=self._headers(), json_body=body, attempts=1)
            return AdapterResult(
                ok=True,
                status_code=result.status_code,
                external_id=machine_id,
                data={"machine_id": machine_id, "capability": capability, "response": result.data},
            )
        raise ConnectorError(f"Unsupported Microsoft Defender capability: {capability}")

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        if capability in {"isolate_endpoint", "unisolate_endpoint"}:
            machine_id = result.external_id or self._machine_id(params)
            response = self.request("GET", f"{self._api()}/api/machines/{machine_id}", headers=self._headers())
            health_status = str((response.data or {}).get("healthStatus") or "")
            expected = "Isolated" if capability == "isolate_endpoint" else "Active"
            verified = health_status == expected if health_status else True
            return AdapterResult(
                ok=verified,
                data={"verified": verified, "health_status": health_status or None, "expected": expected},
                error=None if verified else "Defender machine isolation state does not match the request",
            )
        return AdapterResult(ok=True, data={"verified": True, "items": len(result.data.get("items") or [])})


__all__ = ["MicrosoftDefenderAdapter"]
