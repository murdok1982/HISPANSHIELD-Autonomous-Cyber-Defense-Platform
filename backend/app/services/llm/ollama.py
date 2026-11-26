"""Ollama provider client (native ``/api`` endpoints)."""

from __future__ import annotations

from typing import Any

from app.services.llm.base import BaseProviderClient, ChatResult, HealthResult, ProviderError


class OllamaClient(BaseProviderClient):
    kind = "ollama"

    def health(self) -> HealthResult:
        try:
            payload = self._request("GET", "/api/tags")
        except ProviderError as exc:
            return HealthResult(ok=False, error=str(exc))
        models = payload.get("models")
        if not isinstance(models, list):
            return HealthResult(ok=False, error="Ollama /api/tags returned no model list")
        return HealthResult(ok=True, detail={"models": len(models)})

    def list_models(self) -> list[str]:
        payload = self._request("GET", "/api/tags")
        models = payload.get("models")
        if not isinstance(models, list):
            raise ProviderError("Ollama /api/tags returned no model list")
        names: list[str] = []
        for item in models:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("model")
            if isinstance(name, str) and name.strip():
                names.append(name.strip()[:160])
        return sorted(set(names))

    def chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        *,
        max_tokens: int,
        temperature: float,
    ) -> ChatResult:
        payload = self._request(
            "POST",
            "/api/chat",
            json_body={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature, "num_predict": max_tokens},
            },
        )
        message = payload.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise ProviderError("Ollama response did not include message.content")
        return ChatResult(
            content=content,
            prompt_tokens=int(payload.get("prompt_eval_count") or 0),
            completion_tokens=int(payload.get("eval_count") or 0),
            raw={"model": payload.get("model"), "done": payload.get("done")},
        )

    def embeddings(self, model: str, inputs: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in inputs:
            payload = self._request(
                "POST",
                "/api/embeddings",
                json_body={"model": model, "prompt": text},
            )
            embedding = payload.get("embedding")
            if not isinstance(embedding, list) or not embedding:
                raise ProviderError("Ollama response did not include an embedding")
            vectors.append(_coerce_vector(embedding))
        return vectors


def _coerce_vector(values: list[Any]) -> list[float]:
    try:
        return [float(value) for value in values]
    except (TypeError, ValueError) as exc:
        raise ProviderError("Ollama returned a malformed embedding vector") from exc
