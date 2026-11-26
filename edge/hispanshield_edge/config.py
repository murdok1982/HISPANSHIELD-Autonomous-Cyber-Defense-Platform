"""Gateway configuration: strict local schema, atomic private persistence.

Security properties:

* The file holding ``shared_key`` is written with mode ``0600`` and the parent
  directory with ``0700``; writes are atomic (``mkstemp`` + ``fsync`` +
  ``os.replace``) so a crash can never leave a truncated config.
* ``GatewayConfig.__repr__`` and :meth:`GatewayConfig.describe` never expose the
  HMAC shared key.
* Only the backend allow-listed runtime keys are honoured. Unknown keys found in
  a server bundle (or in a tampered file) are ignored and reported, never merged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import socket
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger("hispanshield_edge.config")

DEFAULT_CONFIG_PATH = Path("edge-data/gateway.json")
FINGERPRINT_PATTERN = re.compile(r"^[A-Za-z0-9:._-]{8,128}$")

# Mirror of ``GatewayConfigPatch`` in the backend: a gateway can never widen its
# own policy surface, every other key is dropped on the floor.
ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "buffer_max_events",
        "batch_size",
        "flush_interval_seconds",
        "heartbeat_interval_seconds",
        "log_level",
        "collectors",
        "store_forward",
        "allow_remote_config",
        "tags",
    }
)

DEFAULT_RUNTIME_CONFIG: dict[str, Any] = {
    "buffer_max_events": 50_000,
    "batch_size": 200,
    "flush_interval_seconds": 30,
    "heartbeat_interval_seconds": 60,
    "log_level": "info",
    "collectors": ["syslog", "network", "ot", "iot"],
    "store_forward": True,
    "allow_remote_config": True,
    "tags": [],
}

_INT_BOUNDS: dict[str, tuple[int, int]] = {
    "buffer_max_events": (100, 1_000_000),
    "batch_size": (1, 500),
    "flush_interval_seconds": (5, 3600),
    "heartbeat_interval_seconds": (15, 3600),
}
_LOG_LEVELS = frozenset({"debug", "info", "warning", "error"})
_LIST_MAX_ITEMS = 20
_LIST_TOKEN_MAX = 40


class ConfigError(ValueError):
    """Raised when local configuration is missing, malformed or unsafe."""


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def machine_fingerprint(machine_id_path: str | None = None) -> str:
    """Return a stable, non-reversible fingerprint for this machine.

    The fingerprint feeds server-side dedupe and is not a credential, but it is
    still hashed so it cannot be used to correlate a host across tenants.
    """
    candidates = [machine_id_path] if machine_id_path else ["/etc/machine-id", "/var/lib/dbus/machine-id"]
    machine_id = ""
    for candidate in candidates:
        try:
            machine_id = Path(candidate).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if machine_id:
            break
    if not machine_id:
        machine_id = f"host-{platform.node()}-{socket.gethostname()}"
    digest = hashlib.sha256(f"{machine_id}|{socket.gethostname()}".encode()).hexdigest()
    return f"hs-{digest[:40]}"


def _validate_fingerprint(value: str) -> str:
    token = value.strip()
    if not isinstance(token, str) or not FINGERPRINT_PATTERN.match(token):
        raise ConfigError("fingerprint must match ^[A-Za-z0-9:._-]{8,128}$")
    return token


def _clean_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    cleaned: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        token = item.strip().lower()
        if not token or len(token) > _LIST_TOKEN_MAX:
            continue
        if not token.replace("-", "").replace("_", "").isalnum():
            continue
        if token not in cleaned:
            cleaned.append(token)
    return cleaned[:_LIST_MAX_ITEMS]


def filter_runtime_config(values: Any) -> tuple[dict[str, Any], list[str]]:
    """Return ``(allow-listed settings, ignored keys)`` for an untrusted mapping."""
    if not isinstance(values, dict):
        return {}, []
    accepted: dict[str, Any] = {}
    ignored: list[str] = []
    for key, value in values.items():
        name = str(key)
        if name not in ALLOWED_CONFIG_KEYS or name.startswith("_"):
            ignored.append(name)
            continue
        if name in _INT_BOUNDS:
            low, high = _INT_BOUNDS[name]
            if isinstance(value, bool) or not isinstance(value, int):
                ignored.append(name)
                continue
            accepted[name] = max(low, min(high, value))
        elif name == "log_level":
            if isinstance(value, str) and value.lower() in _LOG_LEVELS:
                accepted[name] = value.lower()
            else:
                ignored.append(name)
        elif name in {"collectors", "tags"}:
            cleaned = _clean_list(value)
            if cleaned is None:
                ignored.append(name)
            else:
                accepted[name] = cleaned
        elif name in {"store_forward", "allow_remote_config"}:
            if isinstance(value, bool):
                accepted[name] = value
            else:
                ignored.append(name)
    return accepted, ignored


def sanitize_runtime_config(values: Any, base: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge allow-listed runtime settings over ``base`` (defaults when absent)."""
    merged = dict(DEFAULT_RUNTIME_CONFIG if base is None else base)
    accepted, _ignored = filter_runtime_config(values)
    merged.update(accepted)
    return merged


def _require_type(payload: dict[str, Any], key: str, expected: type, default: Any) -> Any:
    value = payload.get(key, default)
    if value is None and default is None:
        return None
    if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
        raise ConfigError(f"config field {key!r} must be {expected.__name__}")
    return value


@dataclass(slots=True)
class GatewayConfig:
    """Everything the gateway needs to operate. ``shared_key`` is write-only."""

    base_url: str
    fingerprint: str
    name: str = ""
    version: str = "0.1.0"
    gateway_id: str | None = None
    org_id: str | None = None
    shared_key: str = field(default="", repr=False)
    config: dict[str, Any] = field(default_factory=dict)
    config_version: str | None = None
    enrolled_at: str | None = None
    allow_insecure_http: bool = False
    ca_bundle: str | None = None
    client_cert: str | None = None
    client_key: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.base_url = str(self.base_url).strip().rstrip("/")
        if not self.base_url:
            raise ConfigError("base_url is required")
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ConfigError("base_url must be an absolute https:// URL")
        if parsed.scheme == "http" and not self.allow_insecure_http:
            raise ConfigError("plain http:// is refused; pass --insecure only for a lab network")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ConfigError("base_url must not contain credentials, query or fragment")
        self.fingerprint = _validate_fingerprint(str(self.fingerprint))
        if self.name and len(self.name) > 160:
            raise ConfigError("name must be at most 160 characters")
        if self.ca_bundle is not None:
            self.ca_bundle = str(self.ca_bundle)
            if not Path(self.ca_bundle).is_file():
                raise ConfigError(f"ca_bundle does not exist: {self.ca_bundle}")
        if self.client_key and not self.client_cert:
            raise ConfigError("client_key requires client_cert")
        if self.client_cert is not None:
            self.client_cert = str(self.client_cert)
            if not Path(self.client_cert).is_file():
                raise ConfigError(f"client_cert does not exist: {self.client_cert}")
        if self.client_key is not None:
            self.client_key = str(self.client_key)
            if not Path(self.client_key).is_file():
                raise ConfigError(f"client_key does not exist: {self.client_key}")
        self.config_version = str(self.config_version) if self.config_version is not None else None
        self.config = sanitize_runtime_config(self.config)

    # ------------------------------------------------------------------ #
    # Serialization
    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "fingerprint": self.fingerprint,
            "name": self.name,
            "version": self.version,
            "gateway_id": self.gateway_id,
            "org_id": self.org_id,
            "shared_key": self.shared_key,
            "config": dict(self.config),
            "config_version": self.config_version,
            "enrolled_at": self.enrolled_at,
            "allow_insecure_http": self.allow_insecure_http,
            "ca_bundle": self.ca_bundle,
            "client_cert": self.client_cert,
            "client_key": self.client_key,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> GatewayConfig:
        if not isinstance(payload, dict):
            raise ConfigError("config file must contain a JSON object")
        base_url = _require_type(payload, "base_url", str, None)
        if not base_url:
            raise ConfigError("config file is missing base_url")
        fingerprint = _require_type(payload, "fingerprint", str, None)
        if not fingerprint:
            raise ConfigError("config file is missing fingerprint")
        allow_insecure = _require_type(payload, "allow_insecure_http", bool, False)
        config = payload.get("config", {})
        if not isinstance(config, dict):
            raise ConfigError("config field 'config' must be an object")
        return cls(
            base_url=base_url,
            fingerprint=fingerprint,
            name=_require_type(payload, "name", str, ""),
            version=_require_type(payload, "version", str, "0.1.0"),
            gateway_id=_require_type(payload, "gateway_id", str, None),
            org_id=_require_type(payload, "org_id", str, None),
            shared_key=_require_type(payload, "shared_key", str, ""),
            config=config,
            config_version=_require_type(payload, "config_version", str, None),
            enrolled_at=_require_type(payload, "enrolled_at", str, None),
            allow_insecure_http=allow_insecure,
            ca_bundle=_require_type(payload, "ca_bundle", str, None),
            client_cert=_require_type(payload, "client_cert", str, None),
            client_key=_require_type(payload, "client_key", str, None),
        )

    def describe(self) -> dict[str, Any]:
        """Redacted view suitable for logs, CLI output and status files."""
        return {
            "base_url": self.base_url,
            "gateway_id": self.gateway_id,
            "org_id": self.org_id,
            "fingerprint": self.fingerprint,
            "name": self.name,
            "version": self.version,
            "config_version": self.config_version,
            "enrolled_at": self.enrolled_at,
            "enrolled": self.is_enrolled,
            "allow_insecure_http": self.allow_insecure_http,
            "tls": {
                "ca_bundle": self.ca_bundle,
                "client_cert": self.client_cert,
                "client_key_configured": bool(self.client_key),
            },
            "config": dict(self.config),
        }

    @property
    def is_enrolled(self) -> bool:
        return bool(self.gateway_id and self.shared_key)

    def require_enrolled(self) -> None:
        if not self.is_enrolled:
            raise ConfigError("gateway is not enrolled; run 'hispanshield-edge enroll' first")

    def update_runtime_config(self, server_config: Any) -> list[str]:
        """Apply a verified server config; returns ignored (non allow-listed) keys."""
        accepted, ignored = filter_runtime_config(server_config)
        self.config = {**self.config, **accepted}
        return ignored

    def set_enrolled(self, *, gateway_id: str, org_id: str, shared_key: str, server_config: Any) -> None:
        if not gateway_id or not org_id or not shared_key:
            raise ConfigError("enrollment response is missing gateway credentials")
        self.gateway_id = gateway_id
        self.org_id = org_id
        self.shared_key = shared_key
        self.enrolled_at = _iso_now()
        self.update_runtime_config(server_config)


# --------------------------------------------------------------------------- #
# Private atomic file handling
# --------------------------------------------------------------------------- #
_WARNED_LOOSE_DIRS: set[str] = set()


def _ensure_private_dir(path: Path) -> None:
    created = not path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created:
        try:
            path.chmod(0o700)
        except OSError as exc:  # pragma: no cover - exotic filesystems
            logger.warning("could not set 0700 on %s: %s", path, exc)
        return
    try:
        if path.stat().st_mode & 0o077:
            key = str(path.absolute())
            if key not in _WARNED_LOOSE_DIRS:
                _WARNED_LOOSE_DIRS.add(key)
                logger.warning("directory %s is accessible by group/other; expected 0700", path)
    except OSError:  # pragma: no cover - exotic filesystems
        pass


def write_private_json(path: Path | str, payload: Any, *, mode: int = 0o600) -> Path:
    """Atomically write JSON with restrictive permissions and fsync."""
    target = Path(path)
    parent = target.parent if str(target.parent) else Path(".")
    _ensure_private_dir(parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, default=str)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
        os.chmod(target, mode)
        dir_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return target


def save_config(config: GatewayConfig, path: Path | str = DEFAULT_CONFIG_PATH) -> Path:
    return write_private_json(path, config.to_dict(), mode=0o600)


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> GatewayConfig:
    target = Path(path)
    try:
        stat = target.stat()
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {target}") from exc
    if stat.st_mode & 0o077:
        logger.warning("config file %s is accessible by group/other; expected mode 0600", target)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read config file {target}: {exc}") from exc
    return GatewayConfig.from_dict(payload)


def new_config(
    *,
    base_url: str,
    fingerprint: str | None = None,
    name: str = "",
    allow_insecure_http: bool = False,
    ca_bundle: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    version: str = "0.1.0",
) -> GatewayConfig:
    return GatewayConfig(
        base_url=base_url,
        fingerprint=fingerprint or machine_fingerprint(),
        name=name,
        version=version,
        allow_insecure_http=allow_insecure_http,
        ca_bundle=ca_bundle,
        client_cert=client_cert,
        client_key=client_key,
    )


__all__ = [
    "ALLOWED_CONFIG_KEYS",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_RUNTIME_CONFIG",
    "ConfigError",
    "GatewayConfig",
    "filter_runtime_config",
    "load_config",
    "machine_fingerprint",
    "new_config",
    "sanitize_runtime_config",
    "save_config",
    "write_private_json",
]
