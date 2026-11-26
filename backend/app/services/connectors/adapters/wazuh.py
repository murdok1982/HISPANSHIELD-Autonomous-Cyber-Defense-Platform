"""Wazuh manager adapter (JWT, alerts, agents and active response)."""

from __future__ import annotations

from typing import Any, ClassVar

from app.services.connectors.adapters._support import (
    HttpAdapter,
    basic_auth_header,
    bounded_limit,
    safe_segment,
    token_cache,
)
from app.services.connectors.base import (
    READ,
    WRITE,
    AdapterResult,
    CapabilitySpec,
    ConnectorError,
    register_adapter,
)

_TOKEN_TTL_SECONDS = 600


@register_adapter
class WazuhAdapter(HttpAdapter):
    connector_type = "wazuh"
    display_name = "Wazuh SIEM/XDR"
    vendor = "Wazuh Inc."
    product = "Wazuh Manager"
    version = "4.x"
    auth_methods: ClassVar[tuple[str, ...]] = ("basic",)
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("read_alerts", READ, "Read alerts from the Wazuh manager", "low"),
        CapabilitySpec("read_agents", READ, "List registered Wazuh agents", "low"),
        CapabilitySpec(
            "active_response",
            WRITE,
            "Run an active-response command on one or more agents",
            "high",
            requires_approval=True,
        ),
        CapabilitySpec(
            "isolate_endpoint",
            WRITE,
            "Isolate an endpoint using a configured active-response command",
            "high",
            requires_approval=True,
        ),
        CapabilitySpec(
            "unisolate_endpoint",
            WRITE,
            "Release an endpoint isolation previously applied by the platform",
            "medium",
        ),
    )

    def _credentials(self) -> tuple[str, str]:
        if not self.secret:
            raise ConnectorError("Wazuh credentials are not configured")
        configured_user = str(self.config.get("username") or "").strip()
        if configured_user:
            return configured_user, self.secret
        if ":" in self.secret:
            username, _, password = self.secret.partition(":")
            return username, password
        return str(self.config.get("default_username") or "wazuh"), self.secret

    def _token(self) -> str:
        username, password = self._credentials()
        cache_key = f"wazuh:{self.base_url}:{username}"
        cached = token_cache.get(cache_key)
        if cached:
            return cached
        result = self.request(
            "POST",
            "/security/user/authenticate",
            headers=basic_auth_header(username, password),
            attempts=1,
            timeout=15.0,
        )
        payload = result.data or {}
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        token = data.get("token") or payload.get("token")
        if not isinstance(token, str) or not token.strip():
            raise ConnectorError("Wazuh did not return a JWT token")
        token_cache.set(cache_key, token, _TOKEN_TTL_SECONDS)
        return token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token()}"}

    def health_check(self) -> AdapterResult:
        result = self.request("GET", "/manager/info", headers=self._headers(), attempts=2)
        info = result.data.get("data") if isinstance(result.data.get("data"), dict) else result.data
        affected = info.get("affected_items") if isinstance(info, dict) else None
        manager = affected[0] if isinstance(affected, list) and affected else info
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"manager": manager, "authenticated": True},
        )

    def _active_response(self, params: dict[str, Any], command_key: str, default_command: str | None) -> AdapterResult:
        agents = params.get("agents") or params.get("agent_ids") or params.get("agent_id") or params.get("target_id")
        if isinstance(agents, list):
            agents_list = ",".join(safe_segment(agent, field="agent id") for agent in agents)
        elif agents is not None:
            agents_list = safe_segment(agents, field="agent id")
        else:
            raise ConnectorError("At least one agent identifier is required")
        command = str(params.get("command") or self.config.get(command_key) or default_command or "").strip()
        if not command:
            raise ConnectorError(f"Active-response command is not configured ({command_key})")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = self.config.get(f"{command_key}_arguments", [])
        if not isinstance(arguments, list):
            arguments = [str(arguments)]
        body: dict[str, Any] = {"command": command, "arguments": [str(item)[:200] for item in arguments][:10]}
        if isinstance(params.get("alert"), dict):
            body["alert"] = params["alert"]
        result = self.request(
            "PUT",
            "/active-response",
            headers=self._headers(),
            params={"agents_list": agents_list},
            json_body=body,
            attempts=1,
        )
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            external_id=agents_list,
            data={
                "agents": agents_list.split(","),
                "command": command,
                "result": result.data,
            },
        )

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        limit = bounded_limit(params)
        if capability == "read_alerts":
            query: dict[str, Any] = {"limit": limit, "sort": "-timestamp"}
            if self.config.get("alert_query"):
                query["q"] = str(self.config["alert_query"])[:500]
            result = self.request("GET", "/alerts", headers=self._headers(), params=query)
            data = result.data.get("data") if isinstance(result.data.get("data"), dict) else result.data
            items = data.get("affected_items") if isinstance(data, dict) else None
            return AdapterResult(
                ok=True,
                status_code=result.status_code,
                data={"items": (items or [])[:limit], "total": data.get("total_affected_items") if items else 0},
            )
        if capability == "read_agents":
            result = self.request(
                "GET", "/agents", headers=self._headers(), params={"limit": limit, "sort": "-lastKeepAlive"}
            )
            data = result.data.get("data") if isinstance(result.data.get("data"), dict) else result.data
            items = data.get("affected_items") if isinstance(data, dict) else None
            return AdapterResult(ok=True, status_code=result.status_code, data={"items": (items or [])[:limit]})
        if capability == "active_response":
            return self._active_response(params, "active_response_command", None)
        if capability == "isolate_endpoint":
            return self._active_response(params, "isolate_command", None)
        if capability == "unisolate_endpoint":
            return self._active_response(params, "unisolate_command", None)
        raise ConnectorError(f"Unsupported Wazuh capability: {capability}")

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        if capability == "read_alerts":
            items = result.data.get("items") or []
            return AdapterResult(ok=True, data={"verified": True, "items": len(items)})
        if capability in {"isolate_endpoint", "unisolate_endpoint", "active_response"}:
            # Wazuh acknowledges active-response without a synchronous read model;
            # verification is the manager command acknowledgement plus agent id echo.
            return AdapterResult(
                ok=True,
                data={"verified": True, "method": "wazuh-active-response-ack", "agents": result.data.get("agents", [])},
            )
        return super().verify(capability, params, result)


__all__ = ["WazuhAdapter"]
