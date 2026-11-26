"""JSON-RPC 2.0 MCP client plus a bounded JSON-Schema subset validator.

Only HTTP POST transport is supported: SSE is rejected at the API boundary and the
client never upgrades a stream. Endpoints pass through the SSRF validator with
``allow_private=True`` (on-premise MCP servers) while metadata endpoints stay
blocked.
"""

from __future__ import annotations

import itertools
from typing import Any

from app.core import outbound
from app.core.ssrf import SSRFError, validate_outbound_url

_MAX_SCHEMA_DEPTH = 8
_SUPPORTED_TYPES = {"string", "integer", "number", "boolean", "array", "object", "null"}


class JsonRpcError(Exception):
    def __init__(self, message: str, *, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


def validate_endpoint(endpoint: str) -> str:
    try:
        return validate_outbound_url(endpoint, allow_private=True)
    except SSRFError as exc:
        raise JsonRpcError(f"Blocked MCP endpoint: {exc}") from exc


class JsonRpcClient:
    def __init__(self, endpoint: str, timeout: float = 20.0) -> None:
        self.endpoint = validate_endpoint(endpoint)
        self.timeout = max(1.0, min(float(timeout), 120.0))
        self._ids = itertools.count(1)

    def call(self, method: str, params: dict[str, Any] | None = None, *, timeout: float | None = None) -> Any:
        request_id = next(self._ids)
        body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        # Re-validate on every call to defeat DNS rebinding between discovery and execution.
        endpoint = validate_endpoint(self.endpoint)
        try:
            response = outbound.request(
                "POST",
                endpoint,
                json_body=body,
                headers={"Accept": "application/json"},
                timeout=timeout or self.timeout,
                allow_private=True,
                max_response_bytes=2_000_000,
            )
        except outbound.OutboundTimeout as exc:
            raise JsonRpcError("MCP request timed out") from exc
        except outbound.OutboundTransportError as exc:
            raise JsonRpcError(f"MCP transport error: {exc}") from exc

        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            raise JsonRpcError("SSE MCP transport is not supported")
        if response.status_code >= 400:
            raise JsonRpcError(f"MCP server returned HTTP {response.status_code}", code=response.status_code)
        try:
            payload = response.json()
        except ValueError as exc:
            raise JsonRpcError("MCP server returned a non-JSON response") from exc
        if not isinstance(payload, dict):
            raise JsonRpcError("MCP server returned an unexpected JSON-RPC payload")
        error = payload.get("error")
        if error:
            message = error.get("message") if isinstance(error, dict) else str(error)
            code = error.get("code") if isinstance(error, dict) else None
            raise JsonRpcError(str(message)[:500], code=code if isinstance(code, int) else None)
        if "result" not in payload:
            raise JsonRpcError("MCP JSON-RPC response is missing result")
        return payload["result"]

    def initialize(self) -> dict[str, Any]:
        result = self.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "hispanshield", "version": "1.0.0"},
            },
        )
        if not isinstance(result, dict):
            raise JsonRpcError("MCP initialize returned an unexpected result")
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        result = self.call("tools/list", {})
        tools = result.get("tools") if isinstance(result, dict) else None
        if tools is None and isinstance(result, list):
            tools = result
        if not isinstance(tools, list):
            raise JsonRpcError("MCP tools/list returned no tools array")
        return [tool for tool in tools if isinstance(tool, dict)]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return self.call("tools/call", {"name": name, "arguments": arguments})


def _type_matches(expected: str, value: Any) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "null":
        return value is None
    return False


def _validate_value(schema: dict[str, Any], value: Any, path: str, depth: int) -> list[str]:
    if depth > _MAX_SCHEMA_DEPTH:
        return [f"{path}: schema nesting exceeds {_MAX_SCHEMA_DEPTH} levels"]
    errors: list[str] = []
    expected = schema.get("type")
    if expected is None:
        # Unsupported but harmless: keyword-free schemas accept any JSON value.
        return errors
    types = [expected] if isinstance(expected, str) else expected
    if not isinstance(types, list) or not types or any(item not in _SUPPORTED_TYPES for item in types):
        return [f"{path}: unsupported schema type {expected!r}"]
    if not any(_type_matches(item, value) for item in types):
        return [f"{path}: expected type {expected}, got {type(value).__name__}"]

    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        errors.append(f"{path}: value is not one of the allowed enum values")

    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if isinstance(minimum, int) and len(value) < minimum:
            errors.append(f"{path}: shorter than minLength {minimum}")
        if isinstance(maximum, int) and len(value) > maximum:
            errors.append(f"{path}: longer than maxLength {maximum}")
    if isinstance(value, int | float) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int | float) and value < minimum:
            errors.append(f"{path}: below minimum {minimum}")
        if isinstance(maximum, int | float) and value > maximum:
            errors.append(f"{path}: above maximum {maximum}")
    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        maximum_items = schema.get("maxItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            errors.append(f"{path}: fewer than minItems {minimum_items}")
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            errors.append(f"{path}: more than maxItems {maximum_items}")
        items_schema = schema.get("items")
        if isinstance(items_schema, dict):
            for index, item in enumerate(value[:100]):
                errors.extend(_validate_value(items_schema, item, f"{path}[{index}]", depth + 1))
    if isinstance(value, dict):
        properties = schema.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        required = schema.get("required")
        required = required if isinstance(required, list) else []
        for key in required:
            if isinstance(key, str) and key not in value:
                errors.append(f"{path}.{key}: required property is missing")
        additional = schema.get("additionalProperties", True)
        if additional is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}.{key}: additional properties are not allowed")
        for key, item in value.items():
            child = properties.get(key)
            if isinstance(child, dict):
                errors.extend(_validate_value(child, item, f"{path}.{key}", depth + 1))
    return errors


def validate_arguments(schema: dict[str, Any] | None, arguments: dict[str, Any]) -> list[str]:
    if not isinstance(arguments, dict):
        return ["arguments must be a JSON object"]
    if not schema:
        return []
    if not isinstance(schema, dict):
        return ["tool input schema is malformed"]
    if schema.get("x-hispanshield-malformed") is True:
        return ["tool input schema is malformed; execution refused"]
    errors = _validate_value(schema, arguments, "arguments", 0)
    return errors[:20]


__all__ = ["JsonRpcClient", "JsonRpcError", "validate_arguments", "validate_endpoint"]
