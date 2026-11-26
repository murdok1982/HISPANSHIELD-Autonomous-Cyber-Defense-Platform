"""Provider client contracts shared by Ollama and OpenAI-compatible backends.

Every outbound call re-validates the destination with the SSRF helper using
``allow_private=True`` (local inference servers are expected on loopback/LAN)
while cloud metadata endpoints remain blocked. API keys are only ever placed in
request headers and are never logged or returned to clients.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.core import outbound
from app.core.ssrf import SSRFError, validate_outbound_url
from app.services.llm.safety import redact_prompt

MAX_RESPONSE_BYTES = 2_000_000


class ProviderError(Exception):
    """Normalized provider failure; ``message`` never contains credentials."""

    def __init__(self, message: str, *, timeout: bool = False, status_code: int | None = None) -> None:
        super().__init__(redact_prompt(message, 500))
        self.timeout = timeout
        self.status_code = status_code


@dataclass
class HealthResult:
    ok: bool
    detail: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class ChatResult:
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def _validate(url: str, allow_private: bool) -> None:
    try:
        validate_outbound_url(url, allow_private=allow_private, require_https=not allow_private)
    except SSRFError as exc:
        raise ProviderError(f"Blocked AI provider destination: {exc}") from exc


class BaseProviderClient(ABC):
    kind: str = ""

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        timeout: float,
        *,
        allow_private: bool = True,
        allowed_private_cidrs: list[str] | None = None,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self._api_key = api_key or None
        self._allow_private = allow_private
        self._allowed_private_cidrs = allowed_private_cidrs
        self.timeout = max(1.0, float(timeout))
        _validate(self.base_url, self._allow_private)

    # -- transport ---------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        _validate(url, self._allow_private)
        try:
            response = outbound.request(
                method,
                url,
                headers=self._headers(),
                json_body=json_body,
                timeout=timeout or self.timeout,
                allow_private=self._allow_private,
                require_https=not self._allow_private,
                allowed_private_cidrs=self._allowed_private_cidrs,
                max_response_bytes=MAX_RESPONSE_BYTES,
                user_agent="HISPANSHIELD-AI/1.0",
            )
        except outbound.OutboundTimeout as exc:
            raise ProviderError("AI provider request timed out", timeout=True) from exc
        except outbound.OutboundTransportError as exc:
            raise ProviderError(f"AI provider transport error: {exc}") from exc
        except outbound.OutboundResponseTooLarge as exc:
            raise ProviderError("AI provider response exceeded the size limit") from exc

        body = response.content[:MAX_RESPONSE_BYTES]
        if response.status_code >= 400:
            snippet = body.decode("utf-8", errors="replace")[:300]
            raise ProviderError(
                f"AI provider returned HTTP {response.status_code}: {snippet}", status_code=response.status_code
            )
        if not body:
            return {}
        try:
            payload = response.json()
        except ValueError as exc:
            raise ProviderError("AI provider returned a non-JSON response") from exc
        if not isinstance(payload, dict):
            raise ProviderError("AI provider returned an unexpected payload shape")
        return payload

    # -- contract ----------------------------------------------------------
    @abstractmethod
    def health(self) -> HealthResult:
        """Cheap read-only reachability check."""

    @abstractmethod
    def list_models(self) -> list[str]:
        """Return the models actually reported by the runtime (never invented)."""

    @abstractmethod
    def chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        *,
        max_tokens: int,
        temperature: float,
    ) -> ChatResult:
        """Run a non-streaming chat completion."""

    @abstractmethod
    def embeddings(self, model: str, inputs: list[str]) -> list[list[float]]:
        """Return one embedding vector per input, in input order."""
