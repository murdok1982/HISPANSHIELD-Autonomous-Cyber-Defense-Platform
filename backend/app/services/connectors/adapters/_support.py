"""Shared plumbing for connector adapters (HTTP, OAuth token cache, safe files).

The token cache lives only in process memory: connector credentials and issued
JWTs are never persisted in ``Connector.config``. File-based adapters only read
from operator-approved roots and are hard-capped at 20 MiB per read.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, ClassVar

from app.services.connectors.base import AdapterResult, ConnectorAdapter, ConnectorError
from app.services.connectors.http import ensure_https, request_json
from app.services.connectors.secrets import config_secret_values, scrub_secret

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_ITEMS = 200
MAX_LINE_CHARS = 65536
MAX_TIMEOUT_SECONDS = 60.0

DEFAULT_TIMEOUT = 20.0

# Operator-approved roots for local log connectors. Never derived from the
# connector payload itself, otherwise an admin-scoped connector could read /etc.
DEFAULT_FILE_ROOTS = (
    "/var/log/suricata",
    "/var/log/zeek",
    "/var/log/hispanshield",
    str(Path(tempfile.gettempdir()) / "hispanshield"),
)

_PATH_FORBIDDEN = ("\x00",)


class TokenCache:
    """Thread-safe in-memory cache for short-lived vendor access tokens."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[str, float]] = {}

    def get(self, key: str) -> str | None:
        now = time.time()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            token, expires_at = entry
            if expires_at <= now + 5:
                self._entries.pop(key, None)
                return None
            return token

    def set(self, key: str, token: str, ttl_seconds: float) -> None:
        with self._lock:
            self._entries[key] = (token, time.time() + max(1.0, ttl_seconds))

    def clear(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._entries.clear()
            else:
                self._entries.pop(key, None)


token_cache = TokenCache()


def basic_auth_header(username: str, password: str) -> dict[str, str]:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def bounded_limit(params: dict[str, Any] | None, *, default: int = 100) -> int:
    raw = (params or {}).get("limit", default)
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = default
    return max(1, min(limit, MAX_ITEMS))


def required_str(params: dict[str, Any] | None, *names: str) -> str:
    source = params or {}
    for name in names:
        value = source.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    raise ConnectorError(f"Missing required parameter: {names[0]}")


def safe_segment(value: Any, *, field: str = "identifier") -> str:
    text = str(value or "").strip()
    if not text or len(text) > 200:
        raise ConnectorError(f"Invalid {field}")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@-")
    if any(character not in allowed for character in text):
        raise ConnectorError(f"Invalid {field}")
    return text


def validate_firewall_ip(params: dict[str, Any] | None) -> str:
    """Validate an address destined for a firewall alias (no CIDR, no multicast)."""
    raw = required_str(params, "ip", "address", "target_id")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ConnectorError("The supplied indicator is not a valid IP address") from exc
    if address.is_multicast or address.is_unspecified:
        raise ConnectorError("Multicast and unspecified addresses cannot be blocked")
    return str(address)


def pick_list(payload: Any, *paths: str) -> list[dict[str, Any]]:
    """Extract the first list of objects found at one of the dotted paths."""
    for path in paths:
        current: Any = payload
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
                current = current[int(part)]
            else:
                current = None
                break
        if isinstance(current, list):
            items = [item for item in current if isinstance(item, dict)]
            if items:
                return items
    return []


def records_from_tables(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert Log Analytics ``{tables: [{columns, rows}]}`` into flat records."""
    tables = payload.get("tables")
    if not isinstance(tables, list):
        return []
    records: list[dict[str, Any]] = []
    for table in tables:
        if not isinstance(table, dict):
            continue
        columns = table.get("columns") or []
        names = [str(column.get("name")) for column in columns if isinstance(column, dict)]
        rows = table.get("rows") or []
        if not names or not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, list):
                continue
            records.append({name: row[index] if index < len(row) else None for index, name in enumerate(names)})
            if len(records) >= 500:
                return records
    return records


def allowed_file_roots() -> list[Path]:
    configured = os.environ.get("HS_CONNECTOR_FILE_ROOTS", "")
    entries = [entry for entry in configured.split(os.pathsep) if entry.strip()] if configured.strip() else []
    raw_roots = entries or list(DEFAULT_FILE_ROOTS)
    roots: list[Path] = []
    for entry in raw_roots:
        try:
            roots.append(Path(entry).expanduser().resolve())
        except (OSError, RuntimeError):
            continue
    return roots


def resolve_file_path(raw: Any, *, directory: bool | None = None, must_exist: bool = True) -> Path:
    """Resolve a connector file path, refusing traversal and unapproved roots."""
    text = str(raw or "").strip()
    if not text:
        raise ConnectorError("A local path must be configured for this connector")
    if any(marker in text for marker in _PATH_FORBIDDEN):
        raise ConnectorError("Path contains invalid characters")
    candidate = Path(text).expanduser()
    if not candidate.is_absolute():
        raise ConnectorError("Connector paths must be absolute")
    if ".." in candidate.parts:
        raise ConnectorError("Path traversal is not permitted")
    try:
        resolved = candidate.resolve(strict=must_exist)
    except (OSError, RuntimeError) as exc:
        raise ConnectorError(f"Path cannot be resolved: {exc.__class__.__name__}") from exc
    roots = allowed_file_roots()
    if not roots or not any(resolved.is_relative_to(root) for root in roots):
        raise ConnectorError("Path is outside the approved connector log directories")
    if directory is True and not resolved.is_dir():
        raise ConnectorError("Configured path is not a directory")
    if directory is False and not resolved.is_file():
        raise ConnectorError("Configured path is not a file")
    return resolved


def read_file_tail(path: Path, *, max_lines: int, max_bytes: int = MAX_FILE_BYTES) -> list[str]:
    """Read at most ``max_bytes`` from the end of a file and return the last lines."""
    limit = max(1, min(max_lines, MAX_ITEMS * 10))
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
                handle.readline()  # discard the partially-read first line
                data = handle.read(max_bytes)
            else:
                data = handle.read(max_bytes)
    except OSError as exc:
        raise ConnectorError(f"Unable to read log file: {exc.strerror or exc.__class__.__name__}") from exc
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()[-limit:]
    return [line[:MAX_LINE_CHARS] for line in lines]


def oauth_token(
    url: str,
    form: dict[str, Any],
    *,
    cache_key: str,
    verify_tls: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    cached = token_cache.get(cache_key)
    if cached:
        return cached
    ensure_https(url, verify_tls)
    try:
        result = request_json(
            "POST", url, data=form, verify_tls=verify_tls, timeout=timeout, attempts=1, expect_json=True
        )
    except ConnectorError as exc:
        candidates = [str(value) for key, value in form.items() if key in {"client_secret", "password"} and value]
        raise ConnectorError(
            scrub_secret(str(exc), *candidates) or "Identity provider request failed",
            retryable=exc.retryable,
            status_code=exc.status_code,
        ) from exc
    payload = result.data or {}
    token = payload.get("access_token") or payload.get("token")
    if not isinstance(token, str) or not token.strip():
        raise ConnectorError("Identity provider did not return an access token")
    expires_in = payload.get("expires_in", 300)
    try:
        ttl = float(expires_in)
    except (TypeError, ValueError):
        ttl = 300.0
    token_cache.set(cache_key, token, ttl)
    return token


class HttpAdapter(ConnectorAdapter):
    """Adapter base that routes every call through the SSRF-safe HTTP helper."""

    requires_base_url: ClassVar[bool] = True
    file_based: ClassVar[bool] = False
    timeout_seconds: ClassVar[float] = DEFAULT_TIMEOUT

    def build_url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        if not self.base_url:
            raise ConnectorError("Connector base URL is not configured")
        return f"{self.base_url}{path}"

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | list[Any] | None = None,
        data: dict[str, Any] | bytes | None = None,
        expect_json: bool = True,
        attempts: int = 3,
        timeout: float | None = None,
    ) -> AdapterResult:
        url = self.build_url(path)
        ensure_https(url, self.connector.verify_tls)
        try:
            return request_json(
                method,
                url,
                headers=headers,
                params=params,
                json_body=json_body,
                data=data,  # type: ignore[arg-type]
                verify_tls=self.connector.verify_tls,
                timeout=timeout or self.timeout_seconds,
                attempts=attempts,
                expect_json=expect_json,
            )
        except ConnectorError as exc:
            # Vendor responses are untrusted: never let an echoed credential
            # reach run records, audit payloads or API error bodies.
            candidates = [self.secret, *config_secret_values(self.config)]
            raise ConnectorError(
                scrub_secret(str(exc), *candidates) or "Connector request failed",
                retryable=exc.retryable,
                status_code=exc.status_code,
            ) from exc

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> None:
        """Validate adapter-specific configuration before it is persisted."""
        return None


class FileLogAdapter(ConnectorAdapter):
    """Adapter base for local log files (no network access at all)."""

    requires_base_url: ClassVar[bool] = False
    file_based: ClassVar[bool] = True
    auth_methods: ClassVar[tuple[str, ...]] = ("none",)

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> None:
        raw_path = config.get("path")
        resolve_file_path(raw_path, directory=cls.path_is_directory(), must_exist=False)
        log_files = config.get("log_files")
        if log_files is not None:
            if not isinstance(log_files, list) or not all(isinstance(item, str) for item in log_files):
                raise ConnectorError("'log_files' must be a list of file names")
            for name in log_files:
                if "/" in name or "\\" in name or name in {".", ".."}:
                    raise ConnectorError("'log_files' entries must be bare file names")

    @classmethod
    def path_is_directory(cls) -> bool:
        return False

    def resolved_path(self) -> Path:
        return resolve_file_path(self.config.get("path"), directory=self.path_is_directory(), must_exist=True)

    def _health_result(self) -> AdapterResult:
        path = self.resolved_path()
        try:
            stat = path.stat()
        except OSError as exc:
            raise ConnectorError(f"Log path is not readable: {exc.strerror or exc.__class__.__name__}") from exc
        if self.path_is_directory():
            if not path.is_dir():
                raise ConnectorError("Configured log path is not a directory")
        elif stat.st_size == 0:
            return AdapterResult(
                ok=True,
                data={"path": str(path), "size": 0, "state": "empty"},
            )
        return AdapterResult(ok=True, data={"path": str(path), "size": stat.st_size, "state": "readable"})


__all__ = [
    "DEFAULT_FILE_ROOTS",
    "DEFAULT_TIMEOUT",
    "FileLogAdapter",
    "HttpAdapter",
    "MAX_FILE_BYTES",
    "MAX_ITEMS",
    "TokenCache",
    "allowed_file_roots",
    "basic_auth_header",
    "bounded_limit",
    "oauth_token",
    "pick_list",
    "read_file_tail",
    "records_from_tables",
    "required_str",
    "resolve_file_path",
    "safe_segment",
    "token_cache",
    "validate_firewall_ip",
]
