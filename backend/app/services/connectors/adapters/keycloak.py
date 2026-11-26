"""Keycloak admin adapter (OAuth token, users, sessions, enable/disable)."""

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


@register_adapter
class KeycloakAdapter(HttpAdapter):
    connector_type = "keycloak"
    display_name = "Keycloak Identity Provider"
    vendor = "Red Hat"
    product = "Keycloak"
    version = "26.x"
    auth_methods: ClassVar[tuple[str, ...]] = ("client_credentials", "password")
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("read_users", READ, "List users in the configured realm", "low"),
        CapabilitySpec("read_sessions", READ, "List active sessions for a user", "low"),
        CapabilitySpec(
            "disable_user",
            WRITE,
            "Disable a compromised identity",
            "high",
            requires_approval=True,
        ),
        CapabilitySpec("enable_user", WRITE, "Re-enable a previously disabled identity", "medium"),
        CapabilitySpec("revoke_sessions", WRITE, "Revoke all sessions for an identity", "medium"),
    )
    security_profile = "oauth-admin"

    def _realm(self) -> str:
        return safe_segment(self.config.get("realm") or "master", field="realm")

    def _token(self) -> str:
        if not self.secret:
            raise ConnectorError("Keycloak client credentials are not configured")
        realm = self._realm()
        client_id = str(self.config.get("client_id") or "").strip()
        if not client_id:
            raise ConnectorError("Connector configuration is missing 'client_id'")
        if self.connector.auth_type == "password":
            username = str(self.config.get("username") or "").strip()
            if not username:
                raise ConnectorError("Connector configuration is missing 'username' for password grant")
            form: dict[str, Any] = {
                "grant_type": "password",
                "client_id": client_id,
                "username": username,
                "password": self.secret,
            }
            cache_key = f"keycloak:{self.base_url}:{realm}:{client_id}:{username}:password"
        else:
            form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": self.secret}
            cache_key = f"keycloak:{self.base_url}:{realm}:{client_id}:client_credentials"
        return oauth_token(
            f"{self.base_url}/realms/{realm}/protocol/openid-connect/token",
            form,
            cache_key=cache_key,
            verify_tls=self.connector.verify_tls,
        )

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}

    def _user_id(self, params: dict[str, Any]) -> str:
        return safe_segment(required_str(params, "user_id", "target_id", "identity_id"), field="user id")

    def health_check(self) -> AdapterResult:
        self._token()
        result = self.request("GET", "/admin/serverinfo", headers=self._headers(), attempts=2)
        payload = result.data if isinstance(result.data, dict) else {}
        raw_system_info = payload.get("systemInfo")
        system_info: dict[str, Any] = raw_system_info if isinstance(raw_system_info, dict) else {}
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"system_info": system_info, "version": system_info.get("version")},
        )

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        realm = self._realm()
        limit = bounded_limit(params)
        if capability == "read_users":
            query: dict[str, Any] = {"max": limit, "briefRepresentation": "true"}
            if params.get("search"):
                query["search"] = str(params["search"])[:200]
            result = self.request("GET", f"/admin/realms/{realm}/users", headers=self._headers(), params=query)
            items = pick_list(result.data, "items")
            return AdapterResult(ok=True, status_code=result.status_code, data={"items": items[:limit]})
        if capability == "read_sessions":
            user_id = self._user_id(params)
            result = self.request("GET", f"/admin/realms/{realm}/users/{user_id}/sessions", headers=self._headers())
            raw = result.data if isinstance(result.data, dict) else {}
            items = raw.get("sessions") or raw.get("items") or []
            return AdapterResult(ok=True, status_code=result.status_code, data={"items": items[:limit]})
        if capability in {"disable_user", "enable_user"}:
            user_id = self._user_id(params)
            enabled = capability == "enable_user"
            result = self.request(
                "PUT",
                f"/admin/realms/{realm}/users/{user_id}",
                headers=self._headers(),
                json_body={"enabled": enabled},
                expect_json=False,
                attempts=1,
            )
            return AdapterResult(
                ok=True,
                status_code=result.status_code,
                external_id=user_id,
                data={"user_id": user_id, "enabled": enabled},
            )
        if capability == "revoke_sessions":
            user_id = self._user_id(params)
            result = self.request(
                "POST",
                f"/admin/realms/{realm}/users/{user_id}/logout",
                headers=self._headers(),
                expect_json=False,
                attempts=1,
            )
            return AdapterResult(
                ok=True,
                status_code=result.status_code,
                external_id=user_id,
                data={"user_id": user_id, "sessions_revoked": True},
            )
        raise ConnectorError(f"Unsupported Keycloak capability: {capability}")

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        if capability in {"disable_user", "enable_user"}:
            realm = self._realm()
            user_id = result.external_id or self._user_id(params)
            response = self.request("GET", f"/admin/realms/{realm}/users/{user_id}", headers=self._headers())
            expected = capability == "enable_user"
            actual = bool((response.data or {}).get("enabled"))
            return AdapterResult(
                ok=actual == expected,
                data={"verified": actual == expected, "enabled": actual, "expected": expected},
                error=None if actual == expected else "Keycloak user state does not match the requested change",
            )
        return AdapterResult(ok=True, data={"verified": True, "method": "keycloak-ack"})


__all__ = ["KeycloakAdapter"]
