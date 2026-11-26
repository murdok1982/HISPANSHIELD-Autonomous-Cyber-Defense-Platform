"""Signed HTTPS client for the HISPANSHIELD edge control plane.

Protocol (must match ``backend/app/modules/edge``):

* ``POST /api/v1/edge/gateways/register`` is public and uses the one-time
  enrollment token.
* Every other gateway call carries ``X-Gateway-Fingerprint``,
  ``X-Gateway-Timestamp`` (epoch seconds) and ``X-Gateway-Signature`` where the
  signed message is ``f"{timestamp}\\n{METHOD}\\n{PATH}\\n{sha256_hex(body)}"``
  and ``PATH`` is the exact request path sent on the wire.
* Config bundles are HMAC-SHA256 over canonical JSON
  (``sort_keys=True, separators=(",", ":")``).

TLS verification is never disabled here: custom CAs and client certificates are
supported, plain ``http://`` requires an explicit lab-only opt-in.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from hispanshield_edge import AGENT_VERSION
from hispanshield_edge.config import ConfigError, GatewayConfig
from hispanshield_edge.queue import MAX_EVENTS_PER_ENVELOPE, VALID_KINDS

logger = logging.getLogger("hispanshield_edge.client")

ENROLL_PATH = "/api/v1/edge/gateways/register"
HEARTBEAT_PATH = "/api/v1/edge/gateways/{gateway_id}/heartbeat"
EVENTS_PATH = "/api/v1/edge/gateways/{gateway_id}/events"
CONFIG_BUNDLE_PATH = "/api/v1/edge/gateways/{gateway_id}/config-bundle"
MAX_SIGNATURE_SKEW_SECONDS = 300
CLOCK_WARNING_SECONDS = 120


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class EdgeClientError(RuntimeError):
    """Base class for gateway transport failures."""


class TransportError(EdgeClientError):
    """Connection refused/reset/timeout: the request may or may not have landed."""


class FatalAuthError(EdgeClientError):
    """401/403 or revoked gateway: retrying cannot help, re-enrollment is required."""


class RetryableHTTPError(EdgeClientError):
    def __init__(self, message: str, *, status: int, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class PermanentHTTPError(EdgeClientError):
    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


class ConflictError(EdgeClientError):
    def __init__(self, message: str, *, status: int = 409) -> None:
        super().__init__(message)
        self.status = status


class ReplayError(ConflictError):
    """The backend already holds this sequence (safe to mark delivered)."""


class ConfigFetchUnavailable(EdgeClientError):
    """Remote config fetch is not available to this credential (non fatal)."""


class InvalidBundleError(EdgeClientError):
    """A config bundle was unsigned, tampered with or bound to another gateway."""


# --------------------------------------------------------------------------- #
# Signing primitives (module level so tests can assert wire parity)
# --------------------------------------------------------------------------- #
def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def build_signature_message(timestamp: str, method: str, path: str, body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return f"{timestamp}\n{method.upper()}\n{path}\n{digest}".encode()


def compute_signature(secret: str, timestamp: str, method: str, path: str, body: bytes) -> str:
    return hmac.new(
        secret.encode(), build_signature_message(timestamp, method, path, body), hashlib.sha256
    ).hexdigest()


def sign_config_bundle(secret: str, bundle: dict[str, Any]) -> str:
    return hmac.new(secret.encode(), canonical_json(bundle), hashlib.sha256).hexdigest()


def verify_signed_bundle(
    secret: str,
    document: Any,
    *,
    expected_gateway_id: str | None = None,
    expected_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Validate a ``{bundle, signature, algorithm}`` document and return the bundle."""
    if not isinstance(document, dict):
        raise InvalidBundleError("config bundle document is not an object")
    bundle = document.get("bundle")
    signature = document.get("signature")
    algorithm = document.get("algorithm")
    if not isinstance(bundle, dict) or not isinstance(signature, str) or not isinstance(algorithm, str):
        raise InvalidBundleError("config bundle is missing bundle/signature/algorithm")
    if algorithm != "HMAC-SHA256":
        raise InvalidBundleError(f"unsupported config bundle algorithm: {algorithm!r}")
    normalized = signature.strip().lower()
    if len(normalized) != 64 or not all(char in "0123456789abcdef" for char in normalized):
        raise InvalidBundleError("config bundle signature must be 64 hex characters")
    expected = sign_config_bundle(secret, bundle)
    if not hmac.compare_digest(normalized.encode(), expected.encode()):
        raise InvalidBundleError("config bundle signature is invalid")
    if expected_gateway_id is not None and str(bundle.get("gateway_id")) != str(expected_gateway_id):
        raise InvalidBundleError("config bundle belongs to a different gateway")
    if expected_fingerprint is not None and bundle.get("fingerprint") != expected_fingerprint:
        raise InvalidBundleError("config bundle fingerprint does not match this machine")
    bundle_config = bundle.get("config")
    if not isinstance(bundle_config, dict):
        raise InvalidBundleError("config bundle payload has no config object")
    return bundle


def parse_server_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise EdgeClientError("server_time is missing from the response")
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class EnrollmentResult:
    gateway_id: str
    org_id: str
    fingerprint: str
    status: str
    enrolled_at: datetime
    shared_key: str
    bundle: dict[str, Any]
    raw_bundle: dict[str, Any]

    def __repr__(self) -> str:  # never leak the shared key
        return (
            f"EnrollmentResult(gateway_id={self.gateway_id!r}, org_id={self.org_id!r}, "
            f"fingerprint={self.fingerprint!r}, status={self.status!r})"
        )


@dataclass(frozen=True, slots=True)
class HeartbeatResult:
    ok: bool
    server_time: datetime
    cursor: int
    next_heartbeat_seconds: int
    config_version: str


@dataclass(frozen=True, slots=True)
class IngestResult:
    accepted: bool
    sequence: int
    processed: int
    duplicates: int
    cursor: int


@dataclass(frozen=True, slots=True)
class VerifiedBundle:
    config: dict[str, Any]
    gateway_id: str | None
    fingerprint: str | None
    issued_at: str | None
    expires_at: str | None
    raw_bundle: dict[str, Any]


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
class EdgeClient:
    def __init__(
        self,
        config: GatewayConfig,
        *,
        timeout: float = 20.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Any = time.sleep,
    ) -> None:
        self.config = config
        self._sleep = sleep
        split = urlsplit(config.base_url)
        if split.scheme == "http" and not config.allow_insecure_http:
            raise ConfigError("plain http:// is refused; enable allow_insecure_http only in a lab")
        self._origin = f"{split.scheme}://{split.netloc}"
        self._prefix = split.path.rstrip("/")
        verify: bool | str = True
        if config.ca_bundle:
            verify = config.ca_bundle
        cert: str | tuple[str, str] | None = None
        if config.client_cert:
            cert = (config.client_cert, config.client_key) if config.client_key else config.client_cert
        try:
            self._http = httpx.Client(
                timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
                verify=verify,
                cert=cert,
                follow_redirects=False,
                trust_env=False,
                transport=transport,
                headers={
                    "User-Agent": f"hispanshield-edge/{AGENT_VERSION}",
                    "Accept": "application/json",
                },
            )
        except (httpx.HTTPError, OSError, ValueError) as exc:
            raise ConfigError(f"cannot build TLS client: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Low level
    # ------------------------------------------------------------------ #
    def api_path(self, endpoint: str) -> str:
        if not endpoint.startswith("/"):
            raise EdgeClientError("endpoint must start with '/'")
        return f"{self._prefix}{endpoint}"

    def _signed_headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        if not self.config.shared_key:
            raise FatalAuthError("gateway has no shared key; enrollment is required")
        timestamp = str(int(time.time()))
        signature = compute_signature(self.config.shared_key, timestamp, method, path, body)
        return {
            "Content-Type": "application/json",
            "X-Gateway-Fingerprint": self.config.fingerprint,
            "X-Gateway-Timestamp": timestamp,
            "X-Gateway-Signature": signature,
        }

    @staticmethod
    def _encode(payload: Any) -> bytes:
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")

    def _send(
        self,
        method: str,
        endpoint: str,
        *,
        body: bytes | None = None,
        signed: bool,
        timeout: float | None = None,
    ) -> httpx.Response:
        path = self.api_path(endpoint)
        raw = body if body is not None else b""
        headers = self._signed_headers(method, path, raw) if signed else {"Content-Type": "application/json"}
        try:
            return self._http.request(
                method,
                f"{self._origin}{path}",
                content=raw or None,
                headers=headers,
                timeout=timeout,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise TransportError(f"cannot connect to core: {exc.__class__.__name__}") from exc
        except httpx.HTTPError as exc:
            raise TransportError(f"transport failure: {exc.__class__.__name__}") from exc

    @staticmethod
    def _detail(response: httpx.Response) -> str:
        try:
            payload = response.json()
        except ValueError:
            return response.text[:200]
        if isinstance(payload, dict):
            detail = payload.get("detail") or payload.get("message") or payload
        else:
            detail = payload
        return str(detail)[:300]

    def _retry_after(self, response: httpx.Response) -> float | None:
        value = response.headers.get("Retry-After")
        if not value:
            return None
        try:
            return max(0.0, min(float(value), 3600.0))
        except ValueError:
            return None

    def _raise_http(self, response: httpx.Response, *, context: str) -> None:
        status = response.status_code
        detail = self._detail(response)
        if status in {401, 403}:
            raise FatalAuthError(f"{context}: authentication rejected ({status}): {detail}")
        if status == 429:
            raise RetryableHTTPError(
                f"{context}: rate limited ({detail})", status=status, retry_after=self._retry_after(response)
            )
        if status >= 500:
            raise RetryableHTTPError(f"{context}: server error {status}: {detail}", status=status)
        if status == 409:
            raise ConflictError(f"{context}: conflict: {detail}", status=status)
        if 400 <= status < 500:
            raise PermanentHTTPError(f"{context}: rejected {status}: {detail}", status=status)
        raise EdgeClientError(f"{context}: unexpected status {status}")

    def _backoff(self, attempt: int, *, base: float = 0.5, cap: float = 15.0) -> None:
        delay = min(cap, base * (2**attempt))
        self._sleep(delay * (1 + random.SystemRandom().uniform(0, 0.25)))  # noqa: S311 - jitter only

    # ------------------------------------------------------------------ #
    # Enrollment (public, unsigned)
    # ------------------------------------------------------------------ #
    def enroll(
        self,
        *,
        enrollment_token: str,
        name: str,
        version: str = AGENT_VERSION,
        certificate_serial: str | None = None,
        attempts: int = 2,
    ) -> EnrollmentResult:
        if not enrollment_token or len(enrollment_token) < 16:
            raise ConfigError("enrollment token is required")
        payload: dict[str, Any] = {
            "enrollment_token": enrollment_token,
            "fingerprint": self.config.fingerprint,
            "name": name or self.config.fingerprint,
            "version": version,
        }
        if certificate_serial:
            payload["certificate_serial"] = certificate_serial
        body = self._encode(payload)
        last_error: Exception | None = None
        for attempt in range(max(1, attempts)):
            try:
                response = self._send("POST", ENROLL_PATH, body=body, signed=False, timeout=30.0)
            except TransportError as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    self._backoff(attempt)
                    continue
                raise
            if response.status_code in {200, 201}:
                data = response.json()
                self._validate_enrollment_response(data)
                bundle = verify_signed_bundle(
                    data["shared_key"],
                    data.get("config_bundle"),
                    expected_gateway_id=str(data["gateway_id"]),
                    expected_fingerprint=self.config.fingerprint,
                )
                return EnrollmentResult(
                    gateway_id=str(data["gateway_id"]),
                    org_id=str(data["org_id"]),
                    fingerprint=str(data["fingerprint"]),
                    status=str(data["status"]),
                    enrolled_at=parse_server_time(data["enrolled_at"]),
                    shared_key=str(data["shared_key"]),
                    bundle=bundle,
                    raw_bundle=data["config_bundle"],
                )
            if response.status_code in {429, 500, 502, 503, 504} and attempt + 1 < attempts:
                self._backoff(attempt)
                continue
            self._raise_http(response, context="enrollment")
        raise last_error or EdgeClientError("enrollment failed")

    @staticmethod
    def _validate_enrollment_response(data: Any) -> None:
        if not isinstance(data, dict):
            raise EdgeClientError("enrollment response is not an object")
        for key in ("gateway_id", "org_id", "fingerprint", "status", "enrolled_at", "shared_key", "config_bundle"):
            if key not in data:
                raise EdgeClientError(f"enrollment response is missing {key}")
        if not isinstance(data["shared_key"], str) or len(data["shared_key"]) < 16:
            raise EdgeClientError("enrollment response shared_key is invalid")

    # ------------------------------------------------------------------ #
    # Heartbeat (signed POST, idempotent)
    # ------------------------------------------------------------------ #
    def heartbeat(
        self,
        *,
        buffer_stats: dict[str, Any] | None = None,
        status: str | None = None,
        attempts: int = 3,
    ) -> HeartbeatResult:
        self.config.require_enrolled()
        payload = {
            "version": AGENT_VERSION,
            "buffer_stats": buffer_stats or {},
        }
        if status:
            payload["status"] = status[:20]
        body = self._encode(payload)
        endpoint = HEARTBEAT_PATH.format(gateway_id=self.config.gateway_id)
        last_error: Exception | None = None
        for attempt in range(max(1, attempts)):
            try:
                response = self._send("POST", endpoint, body=body, signed=True, timeout=20.0)
            except TransportError as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    self._backoff(attempt)
                    continue
                raise
            if response.status_code in {200, 201}:
                data = response.json()
                if not isinstance(data, dict) or "server_time" not in data:
                    raise EdgeClientError("heartbeat response is malformed")
                return HeartbeatResult(
                    ok=bool(data.get("ok", True)),
                    server_time=parse_server_time(data["server_time"]),
                    cursor=int(data.get("cursor", 0)),
                    next_heartbeat_seconds=int(data.get("next_heartbeat_seconds", 60)),
                    config_version=str(data.get("config_version", "")),
                )
            if response.status_code in {409, 429, 500, 502, 503, 504} and attempt + 1 < attempts:
                self._backoff(attempt)
                continue
            self._raise_http(response, context="heartbeat")
        raise last_error or EdgeClientError("heartbeat failed")

    # ------------------------------------------------------------------ #
    # Events (signed POST, sequence ordered)
    # ------------------------------------------------------------------ #
    def send_batch(
        self,
        *,
        sequence: int,
        kind: str,
        events: list[dict[str, Any]],
        batch_id: str | None = None,
    ) -> IngestResult:
        self.config.require_enrolled()
        if kind not in VALID_KINDS:
            raise ValueError(f"unsupported event kind: {kind!r}")
        if not 1 <= len(events) <= MAX_EVENTS_PER_ENVELOPE:
            raise ValueError("batch must contain between 1 and 500 events")
        payload: dict[str, Any] = {"sequence": int(sequence), "kind": kind, "events": events}
        if batch_id:
            payload["batch_id"] = batch_id[:80]
        body = self._encode(payload)
        endpoint = EVENTS_PATH.format(gateway_id=self.config.gateway_id)

        # Exactly one retry, and only when the connection itself failed: the
        # backend's sequence replay check makes this safe, read timeouts are not
        # retried because the batch may already be committed.
        response: httpx.Response | None = None
        for attempt in range(2):
            try:
                response = self._send("POST", endpoint, body=body, signed=True, timeout=30.0)
                break
            except TransportError:
                if attempt == 1:
                    raise
                self._sleep(0.25)
        if response is None:  # pragma: no cover - loop always sets or raises
            raise TransportError("event batch was not sent")
        if response.status_code in {200, 201}:
            data = response.json()
            if not isinstance(data, dict):
                raise EdgeClientError("event ingest response is not an object")
            return IngestResult(
                accepted=bool(data.get("accepted", True)),
                sequence=int(data.get("sequence", sequence)),
                processed=int(data.get("processed", 0)),
                duplicates=int(data.get("duplicates", 0)),
                cursor=int(data.get("cursor", sequence)),
            )
        if response.status_code == 409:
            detail = self._detail(response)
            lowered = detail.lower()
            if "replay" in lowered or "sequence" in lowered:
                raise ReplayError(f"batch sequence {sequence} already ingested: {detail}")
            raise ConflictError(f"event batch conflict: {detail}")
        self._raise_http(response, context="event batch")

    # ------------------------------------------------------------------ #
    # Signed config bundle
    # ------------------------------------------------------------------ #
    def fetch_config_bundle(self, *, attempts: int = 2) -> VerifiedBundle:
        self.config.require_enrolled()
        endpoint = CONFIG_BUNDLE_PATH.format(gateway_id=self.config.gateway_id)
        last_error: Exception | None = None
        for attempt in range(max(1, attempts)):
            try:
                response = self._send("GET", endpoint, body=b"", signed=True, timeout=20.0)
            except TransportError as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    self._backoff(attempt)
                    continue
                raise
            if response.status_code in {200, 201}:
                data = response.json()
                bundle = verify_signed_bundle(
                    self.config.shared_key,
                    data,
                    expected_gateway_id=self.config.gateway_id,
                    expected_fingerprint=self.config.fingerprint,
                )
                return VerifiedBundle(
                    config=bundle["config"],
                    gateway_id=bundle.get("gateway_id"),
                    fingerprint=bundle.get("fingerprint"),
                    issued_at=bundle.get("issued_at"),
                    expires_at=bundle.get("expires_at"),
                    raw_bundle=data,
                )
            if response.status_code in {401, 403, 404}:
                # The core exposes this route to tenant operators; a gateway
                # credential cannot mint a tenant session. Not fatal: the signed
                # enrollment bundle remains the source of truth.
                raise ConfigFetchUnavailable(
                    f"remote config bundle not available to gateway credential ({response.status_code})"
                )
            if response.status_code == 409:
                raise FatalAuthError(f"gateway is revoked: {self._detail(response)}")
            if response.status_code in {429, 500, 502, 503, 504} and attempt + 1 < attempts:
                self._backoff(attempt)
                continue
            self._raise_http(response, context="config bundle")
        raise last_error or EdgeClientError("config bundle fetch failed")

    # ------------------------------------------------------------------ #
    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> EdgeClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


__all__ = [
    "CLOCK_WARNING_SECONDS",
    "CONFIG_BUNDLE_PATH",
    "ENROLL_PATH",
    "EVENTS_PATH",
    "HEARTBEAT_PATH",
    "MAX_SIGNATURE_SKEW_SECONDS",
    "ConfigFetchUnavailable",
    "ConflictError",
    "EdgeClient",
    "EdgeClientError",
    "EnrollmentResult",
    "FatalAuthError",
    "HeartbeatResult",
    "IngestResult",
    "InvalidBundleError",
    "PermanentHTTPError",
    "ReplayError",
    "RetryableHTTPError",
    "TransportError",
    "VerifiedBundle",
    "build_signature_message",
    "canonical_json",
    "compute_signature",
    "parse_server_time",
    "sign_config_bundle",
    "verify_signed_bundle",
]
