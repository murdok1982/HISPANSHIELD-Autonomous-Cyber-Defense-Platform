"""Strict request/response contracts for the connector registry."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.schemas import ORMModel, StrictModel

MAX_CONFIG_BYTES = 65536
MAX_PARAMS_BYTES = 32768
MAX_PARAM_DEPTH = 5
MAX_SECRET_LENGTH = 8192


def _contains_control(value: Any, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(value, str):
        return any(character in value for character in ("\x00", "\r"))
    if isinstance(value, dict):
        return any(
            _contains_control(key, depth + 1) or _contains_control(item, depth + 1) for key, item in value.items()
        )
    if isinstance(value, list | tuple):
        return any(_contains_control(item, depth + 1) for item in value)
    return False


def _depth(value: Any, depth: int = 0) -> int:
    if isinstance(value, dict):
        return max([depth, *(_depth(item, depth + 1) for item in value.values())])
    if isinstance(value, list | tuple):
        return max([depth, *(_depth(item, depth + 1) for item in value)])
    return depth


class ConnectorCreate(StrictModel):
    name: str = Field(min_length=2, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._()/@:-]{1,159}$")
    connector_type: str = Field(min_length=2, max_length=60, pattern=r"^[a-z][a-z0-9_]+$")
    version: str = Field(default="1.0.0", max_length=20, pattern=r"^\d+\.\d+(?:\.\d+)?$")
    base_url: str | None = Field(default=None, max_length=500)
    auth_type: str = Field(default="none", max_length=40, pattern=r"^[a-z][a-z0-9_]*$")
    secret: str | None = Field(default=None, max_length=MAX_SECRET_LENGTH)
    config: dict[str, Any] = Field(default_factory=dict)
    verify_tls: bool = True
    rate_limit_per_minute: int = Field(default=60, ge=1, le=6000)
    enabled: bool = True

    @field_validator("base_url")
    @classmethod
    def _clean_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("secret")
    @classmethod
    def _clean_secret(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if "\x00" in value or "\r" in value or "\n" in value:
            raise ValueError("Secret contains invalid control characters")
        return value

    @field_validator("config")
    @classmethod
    def _bounded_config(cls, value: dict[str, Any]) -> dict[str, Any]:
        if _contains_control(value):
            raise ValueError("Configuration contains invalid control characters")
        if len(json.dumps(value, default=str, ensure_ascii=False)) > MAX_CONFIG_BYTES:
            raise ValueError("Configuration exceeds the size limit")
        if _depth(value) > MAX_PARAM_DEPTH:
            raise ValueError("Configuration nesting is too deep")
        return value


class ConnectorPatch(StrictModel):
    name: str | None = Field(
        default=None, min_length=2, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._()/@:-]{1,159}$"
    )
    version: str | None = Field(default=None, max_length=20, pattern=r"^\d+\.\d+(?:\.\d+)?$")
    base_url: str | None = Field(default=None, max_length=500)
    auth_type: str | None = Field(default=None, max_length=40, pattern=r"^[a-z][a-z0-9_]*$")
    secret: str | None = Field(default=None, max_length=MAX_SECRET_LENGTH)
    config: dict[str, Any] | None = None
    verify_tls: bool | None = None
    rate_limit_per_minute: int | None = Field(default=None, ge=1, le=6000)
    enabled: bool | None = None

    @field_validator("base_url")
    @classmethod
    def _clean_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("secret")
    @classmethod
    def _clean_secret(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if "\x00" in value or "\r" in value or "\n" in value:
            raise ValueError("Secret contains invalid control characters")
        return value

    @field_validator("config")
    @classmethod
    def _bounded_config(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        if _contains_control(value):
            raise ValueError("Configuration contains invalid control characters")
        if len(json.dumps(value, default=str, ensure_ascii=False)) > MAX_CONFIG_BYTES:
            raise ValueError("Configuration exceeds the size limit")
        if _depth(value) > MAX_PARAM_DEPTH:
            raise ValueError("Configuration nesting is too deep")
        return value

    @model_validator(mode="after")
    def _at_least_one_field(self) -> ConnectorPatch:
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided")
        return self


class ConnectorInvokeRequest(StrictModel):
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("params")
    @classmethod
    def _bounded_params(cls, value: dict[str, Any]) -> dict[str, Any]:
        if _contains_control(value):
            raise ValueError("Parameters contain invalid control characters")
        if len(value) > 100:
            raise ValueError("Too many parameters")
        if len(json.dumps(value, default=str, ensure_ascii=False)) > MAX_PARAMS_BYTES:
            raise ValueError("Parameters exceed the size limit")
        if _depth(value) > MAX_PARAM_DEPTH:
            raise ValueError("Parameter nesting is too deep")
        return value


class ConnectorSyncRequest(StrictModel):
    limit: int = Field(default=100, ge=1, le=200)


class CapabilityOut(BaseModel):
    name: str
    direction: str
    description: str
    risk: str
    requires_approval: bool = False
    data_formats: list[str] = Field(default_factory=list)


class CatalogAdapterOut(BaseModel):
    connector_id: str
    display_name: str
    vendor: str
    product: str
    version: str
    auth_methods: list[str]
    capabilities: list[CapabilityOut]
    data_formats: list[str]
    security_profile: str
    requires_base_url: bool
    file_based: bool
    configured: bool
    connector_count: int


class ConnectorCatalogOut(BaseModel):
    adapters: list[CatalogAdapterOut]
    configured: list[str]
    missing: list[str]
    generated_at: datetime


class ConnectorHealthOut(BaseModel):
    state: str
    stale: bool
    circuit_open: bool
    last_health_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None


class ConnectorOut(BaseModel):
    id: UUID
    name: str
    connector_type: str
    version: str
    base_url: str | None
    auth_type: str
    has_secret: bool
    config: dict[str, Any]
    capabilities: dict[str, Any]
    status: str
    enabled: bool
    verify_tls: bool
    rate_limit_per_minute: int
    last_health_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    health: ConnectorHealthOut


class ConnectorRunOut(ORMModel):
    id: UUID
    connector_id: UUID
    operation: str
    direction: str
    status: str
    latency_ms: int | None
    request_id: str | None
    error: str | None
    detail: dict[str, Any]
    created_at: datetime


class ConnectorHealthResultOut(BaseModel):
    connector_id: UUID
    status: str
    ok: bool
    latency_ms: int
    detail: dict[str, Any]
    error: str | None = None
    run_id: UUID | None = None
    last_health_at: datetime | None = None


class ConnectorInvokeResultOut(BaseModel):
    connector_id: UUID
    capability: str
    ok: bool
    status_code: int | None
    data: dict[str, Any]
    error: str | None = None
    latency_ms: int
    run_id: UUID | None = None


class ConnectorSyncResultOut(BaseModel):
    connector_id: UUID
    status: str
    events_created: int
    events_duplicate: int
    indicators_created: int
    indicators_updated: int
    alerts_read: int
    capabilities: list[str] = Field(default_factory=list)
    latency_ms: int
    run_id: UUID | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class ConnectorHealthSummaryOut(BaseModel):
    generated_at: datetime
    total: int
    enabled: int
    by_status: dict[str, int]
    stale_count: int
    stale: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    catalog_size: int


__all__ = [
    "CapabilityOut",
    "CatalogAdapterOut",
    "ConnectorCatalogOut",
    "ConnectorCreate",
    "ConnectorHealthOut",
    "ConnectorHealthResultOut",
    "ConnectorHealthSummaryOut",
    "ConnectorInvokeRequest",
    "ConnectorInvokeResultOut",
    "ConnectorOut",
    "ConnectorPatch",
    "ConnectorRunOut",
    "ConnectorSyncRequest",
    "ConnectorSyncResultOut",
]
