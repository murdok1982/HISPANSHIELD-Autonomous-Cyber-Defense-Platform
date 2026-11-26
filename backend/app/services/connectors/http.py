"""HTTP client for connectors: SSRF validation, bounded retries, no redirects."""

from __future__ import annotations

from typing import Any

import httpx

from app.core.config import settings
from app.core.ssrf import SSRFError, validate_outbound_url
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
    data: dict[str, Any] | None = None,
    verify_tls: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
    attempts: int = 1,
    expect_json: bool = True,
) -> AdapterResult:
    """Execute an outbound connector request with SSRF validation.

    Retries are only attempted for idempotent methods (GET/HEAD/OPTIONS) because
    repeating a write can duplicate a defensive action.
    """
    try:
        validate_outbound_url(url)
    except SSRFError as exc:
        raise ConnectorError(f"Blocked outbound destination: {exc}") from exc

    retryable = method.upper() in {"GET", "HEAD", "OPTIONS"}
    max_attempts = attempts if retryable else 1
    last_error: str | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            with httpx.Client(
                timeout=timeout,
                verify=verify_tls,
                follow_redirects=False,
                headers={"User-Agent": "HISPANSHIELD-Connector/1.0", **(headers or {})},
            ) as client:
                response = client.request(method, url, params=params, json=json_body, data=data)
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
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_error = f"Transport error: {exc}"
            if attempt < max_attempts:
                continue
            raise ConnectorError(last_error, retryable=True) from exc
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
