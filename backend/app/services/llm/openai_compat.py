"""OpenAI-compatible provider client (vLLM, llama.cpp server, hosted compatibles)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.services.llm.base import BaseProviderClient, ChatResult, HealthResult, ProviderError


class OpenAICompatibleClient(BaseProviderClient):
    kind = "openai_compatible"

    def _api_prefix(self) -> str:
        path = urlparse(self.base_url).path.rstrip("/")
        if path.endswith("/v1"):
            return self.base_url
        return f"{self.base_url}/v1"

    def _call(self, method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        prefix = self._api_prefix()
        # Re-use the validated base origin with the derived /v1 prefix.
        base = self.base_url
        self.base_url = prefix
        try:
            return self._request(method, endpoint, **kwargs)
        finally:
            self.base_url = base

    def health(self) -> HealthResult:
        try:
            payload = self._call("GET", "/models")
        except ProviderError as exc:
            return HealthResult(ok=False, error=str(exc))
        data = payload.get("data")
        if not isinstance(data, list):
            return HealthResult(ok=False, error="OpenAI-compatible /v1/models returned no data list")
        return HealthResult(ok=True, detail={"models": len(data)})

    def list_models(self) -> list[str]:
        payload = self._call("GET", "/models")
        data = payload.get("data")
        if not isinstance(data, list):
            raise ProviderError("OpenAI-compatible /v1/models returned no data list")
        names: list[str] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            identifier = item.get("id")
            if isinstance(identifier, str) and identifier.strip():
                names.append(identifier.strip()[:160])
        return sorted(set(names))

    def chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        *,
        max_tokens: int,
        temperature: float,
    ) -> ChatResult:
        payload = self._call(
            "POST",
            "/chat/completions",
            json_body={
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": False,
            },
        )
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderError("OpenAI-compatible response did not include choices")
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise ProviderError("OpenAI-compatible response did not include message content")
        usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
        return ChatResult(
            content=content,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            raw={"model": payload.get("model"), "finish_reason": first.get("finish_reason")},
        )

    def embeddings(self, model: str, inputs: list[str]) -> list[list[float]]:
        payload = self._call(
            "POST",
            "/embeddings",
            json_body={"model": model, "input": inputs},
        )
        data = payload.get("data")
        if not isinstance(data, list) or len(data) != len(inputs):
            raise ProviderError("OpenAI-compatible /v1/embeddings returned an unexpected payload")
        ordered: list[list[float]] = []
        for item in data:
            if not isinstance(item, dict) or not isinstance(item.get("embedding"), list):
                raise ProviderError("OpenAI-compatible embedding entry is malformed")
            ordered.append(_coerce_vector(item["embedding"]))
        return ordered


def _coerce_vector(values: list[Any]) -> list[float]:
    try:
        return [float(value) for value in values]
    except (TypeError, ValueError) as exc:
        raise ProviderError("OpenAI-compatible provider returned a malformed embedding vector") from exc
