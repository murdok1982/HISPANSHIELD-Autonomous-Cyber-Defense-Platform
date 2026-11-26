"""HTTP client for connectors: pinned SSRF validation, bounded retries, no redirects."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from app.core import outbound
from app.core.config import settings
from app.core.ssrf import SSRFError
from app.services.connectors.base import AdapterResult, ConnectorError

DEFAULT_TIMEOUT = 20.0
MAX_ATTEMPTS = 3


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
    data: dict[str, Any] | bytes | None = None,
    verify_tls: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
    attempts: int = 1,
    expect_json: bool = True,
    allow_private: bool | None = None,
) -> AdapterResult:
    """Execute an outbound connector request with pinned-DNS SSRF validation.

    Retries are only attempted for idempotent methods (GET/HEAD/OPTIONS) because
    repeating a write can duplicate a defensive action. TLS verification cannot
    be disabled: the pinned backend always uses a verifying default context.
    """
    if not verify_tls:
        raise ConnectorError("TLS verification cannot be disabled for connector egress")

    permit_private = settings.connector_allow_private_networks if allow_private is None else allow_private
    retryable = method.upper() in {"GET", "HEAD", "OPTIONS"}
    max_attempts = attempts if retryable else 1
    last_error: str | None = None
    content = None
    request_headers = dict(headers or {})
    if isinstance(data, bytes):
        content = data
    elif data is not None:
        content = urlencode(data, doseq=True).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    for attempt in range(1, max_attempts + 1):
        try:
            response = outbound.request(
                method,
                url,
                headers=request_headers,
                params=params,
                json_body=json_body,
                content=content,
                timeout=timeout,
                allow_private=permit_private,
                max_response_bytes=200_000,
                user_agent="HISPANSHIELD-Connector/1.0",
            )
            if response.status_code >= 400:
                last_error = f"HTTP {response.status_code}: {response.text[:500]}"
                if response.status_code in {429, 500, 502, 503, 504} and attempt < max_attempts:
                    continue
                raise ConnectorError(
                    last_error,
                    status_code=response.status_code,
                    retryable=response.status_code in {429, 500, 502, 503, 504},
                )
            if not expect_json:
                return AdapterResult(ok=True, data={"body": response.text[:20000]}, status_code=response.status_code)
            try:
                payload = response.json()
            except ValueError as exc:
                raise ConnectorError("Target returned a non-JSON response", status_code=response.status_code) from exc
            return AdapterResult(
                ok=True,
                data=payload if isinstance(payload, dict) else {"items": payload},
                status_code=response.status_code,
            )
        except outbound.OutboundTimeout as exc:
            last_error = f"Transport error: {exc}"
            if attempt < max_attempts:
                continue
            raise ConnectorError(last_error, retryable=True) from exc
        except outbound.OutboundTransportError as exc:
            last_error = f"Transport error: {exc}"
            if attempt < max_attempts:
                continue
            raise ConnectorError(last_error, retryable=True) from exc
        except outbound.OutboundResponseTooLarge as exc:
            raise ConnectorError("Target response exceeded the 200 KB connector limit") from exc
        except SSRFError as exc:
            raise ConnectorError(f"Blocked outbound destination: {exc}") from exc
    raise ConnectorError(last_error or "Connector request failed", retryable=True)


def auth_headers(secret: str | None, auth_type: str, config: dict[str, Any] | None = None) -> dict[str, str]:
    config = config or {}
    headers: dict[str, str] = {}
    if not secret:
        return headers
    if auth_type == "bearer":
        headers["Authorization"] = f"Bearer {secret}"
    elif auth_type == "api_key_header":
        headers[str(config.get("api_key_header", "X-API-Key"))] = secret
    elif auth_type == "token_header":
        headers[str(config.get("token_header", "Authorization"))] = secret
    elif auth_type == "basic":
        import base64

        headers["Authorization"] = "Basic " + base64.b64encode(secret.encode()).decode()
    return headers


def ensure_https(url: str, verify_tls: bool) -> None:
    if settings.is_production and not url.startswith("https://"):
        raise ConnectorError("Connectors must use HTTPS in production")
    if not verify_tls and settings.is_production:
        raise ConnectorError("TLS verification cannot be disabled in production")
