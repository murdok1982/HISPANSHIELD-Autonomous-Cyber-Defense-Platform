"""Generic HTTPS webhook adapter (bearer token or HMAC-signed notifications)."""

from __future__ import annotations

import json
import time
from typing import Any, ClassVar

from app.core.crypto import hmac_sha256_hex
from app.core.db import utcnow
from app.services.connectors.adapters._support import HttpAdapter
from app.services.connectors.base import (
    WRITE,
    AdapterResult,
    CapabilitySpec,
    ConnectorError,
    register_adapter,
)
from app.services.connectors.normalize import sanitize_mapping, sanitize_text

MAX_WEBHOOK_BODY = 65536


@register_adapter
class GenericWebhookAdapter(HttpAdapter):
    connector_type = "generic_webhook"
    display_name = "Generic webhook"
    vendor = "HISPANSHIELD"
    product = "Webhook integration"
    version = "1.0"
    auth_methods: ClassVar[tuple[str, ...]] = ("none", "bearer", "hmac")
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = (
        CapabilitySpec("notify_webhook", WRITE, "Send a signed notification to an approved endpoint", "low"),
    )
    security_profile = "webhook-hmac"

    def _signature_headers(self, body: bytes) -> dict[str, str]:
        if self.connector.auth_type == "bearer":
            if not self.secret:
                raise ConnectorError("Webhook bearer token is not configured")
            return {"Authorization": f"Bearer {self.secret}"}
        if self.connector.auth_type == "hmac":
            if not self.secret:
                raise ConnectorError("Webhook HMAC secret is not configured")
            timestamp = str(int(time.time()))
            signature = hmac_sha256_hex(self.secret, body)
            return {
                "X-HS-Signature": f"sha256={signature}",
                "X-HS-Timestamp": timestamp,
            }
        return {}

    def health_check(self) -> AdapterResult:
        health_url = str(self.config.get("health_url") or "").strip()
        if not health_url:
            return AdapterResult(ok=True, data={"configured": True, "health": "no-op", "url": self.base_url})
        if not health_url.startswith(("http://", "https://")):
            raise ConnectorError("health_url must be an absolute http(s) URL")
        result = self.request(
            "GET",
            health_url,
            headers=self._signature_headers(b""),
            expect_json=False,
            attempts=2,
        )
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"configured": True, "status_code": result.status_code, "health_url": health_url},
        )

    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        if capability != "notify_webhook":
            raise ConnectorError(f"Unsupported generic webhook capability: {capability}")
        if not self.base_url:
            raise ConnectorError("Webhook URL is not configured")
        payload = {
            "source": "HISPANSHIELD",
            "event": sanitize_text(params.get("event") or params.get("action") or "notification", limit=120),
            "summary": sanitize_text(params.get("summary") or params.get("message"), limit=2000),
            "severity": sanitize_text(params.get("severity"), limit=20),
            "target": sanitize_text(params.get("target") or params.get("target_id"), limit=300),
            "details": sanitize_mapping(params.get("details") or params.get("data") or {}),
            "timestamp": utcnow().isoformat(),
        }
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        if len(body) > MAX_WEBHOOK_BODY:
            raise ConnectorError("Webhook notification payload exceeds the size limit")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._signature_headers(body),
        }
        result = self.request(
            "POST",
            self.base_url,
            headers=headers,
            data=body,
            expect_json=False,
            attempts=1,
        )
        return AdapterResult(
            ok=True,
            status_code=result.status_code,
            data={"delivered": True, "status_code": result.status_code, "bytes": len(body)},
        )

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        return AdapterResult(
            ok=bool(result.data.get("delivered")),
            data={"verified": bool(result.data.get("delivered")), "method": "webhook-http-ack"},
        )


__all__ = ["GenericWebhookAdapter"]
