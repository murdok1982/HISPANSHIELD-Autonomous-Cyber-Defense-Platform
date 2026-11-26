from __future__ import annotations

import json
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from hispanshield_edge.config import (
    ConfigError,
    GatewayConfig,
    filter_runtime_config,
    load_config,
    machine_fingerprint,
    new_config,
    sanitize_runtime_config,
    save_config,
)


def test_config_roundtrip_is_private_and_atomic(tmp_path: Path):
    path = tmp_path / "nested" / "gateway.json"
    config = GatewayConfig(
        base_url="https://core.example.com/prefix/",
        fingerprint="hs-0123456789abcdef",
        name="site-a",
        gateway_id="gw-1",
        org_id="org-1",
        shared_key="super-secret-shared-key",
        config={"batch_size": 42, "unknown": "ignored"},
    )
    save_config(config, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert not list(path.parent.glob("*.tmp"))
    loaded = load_config(path)
    assert loaded.base_url == "https://core.example.com/prefix"
    assert loaded.shared_key == "super-secret-shared-key"
    assert loaded.config["batch_size"] == 42
    assert "unknown" not in loaded.config
    assert loaded.to_dict()["fingerprint"] == "hs-0123456789abcdef"


def test_describe_and_repr_never_leak_secrets(tmp_path: Path):
    client_cert = tmp_path / "cert.pem"
    client_key = tmp_path / "key.pem"
    client_cert.write_text("dummy-cert", encoding="utf-8")
    client_key.write_text("dummy", encoding="utf-8")
    config = GatewayConfig(
        base_url="https://core.example.com",
        fingerprint="hs-0123456789abcdef",
        shared_key="do-not-print-me",
        client_cert=str(client_cert),
        client_key=str(client_key),
        config={},
    )
    described = json.dumps(config.describe())
    assert "do-not-print-me" not in described
    assert "do-not-print-me" not in repr(config)
    assert config.describe()["tls"]["client_key_configured"] is True


def test_atomic_write_preserves_previous_file_on_failure(tmp_path: Path, monkeypatch):
    path = tmp_path / "gateway.json"
    config = new_config(base_url="https://core.example.com", fingerprint="hs-0123456789abcdef")
    save_config(config, path)
    original = path.read_bytes()

    def _fail_replace(*_args, **_kwargs):
        raise OSError("simulated crash before rename")

    monkeypatch.setattr("hispanshield_edge.config.os.replace", _fail_replace)
    with pytest.raises(OSError):
        save_config(config, path)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.tmp"))


def test_plain_http_requires_explicit_lab_opt_in():
    with pytest.raises(ConfigError):
        GatewayConfig(base_url="http://127.0.0.1:8000", fingerprint="hs-0123456789abcdef")
    config = GatewayConfig(
        base_url="http://127.0.0.1:8000",
        fingerprint="hs-0123456789abcdef",
        allow_insecure_http=True,
    )
    assert config.base_url == "http://127.0.0.1:8000"


def test_base_url_rejects_credentials_and_bad_scheme():
    with pytest.raises(ConfigError):
        GatewayConfig(base_url="ftp://core.example.com", fingerprint="hs-0123456789abcdef")
    with pytest.raises(ConfigError):
        GatewayConfig(base_url="https://user:pass@core.example.com", fingerprint="hs-0123456789abcdef")


def test_fingerprint_validation_and_machine_derivation():
    assert machine_fingerprint().startswith("hs-")
    assert len(machine_fingerprint()) <= 128
    with pytest.raises(ConfigError):
        GatewayConfig(base_url="https://core.example.com", fingerprint="short")


def test_allow_list_drops_unknown_keys_and_bad_types():
    values = {
        "batch_size": 9999,
        "buffer_max_events": 50,
        "heartbeat_interval_seconds": "60",
        "store_forward": "yes",
        "collectors": ["Syslog", "syslog", "bad key!", 3],
        "tags": ["prod", "edge", "prod"],
        "allow_remote_config": False,
        "policy_override": "full-control",
        "_security": {"hmac_secret_encrypted": "x"},
    }
    accepted, ignored = filter_runtime_config(values)
    assert accepted["batch_size"] == 500  # clamped to the envelope limit
    assert accepted["buffer_max_events"] == 100  # clamped to the server minimum
    assert accepted["collectors"] == ["syslog"]
    assert accepted["tags"] == ["prod", "edge"]
    assert accepted["allow_remote_config"] is False
    assert "heartbeat_interval_seconds" not in accepted
    assert "store_forward" not in accepted
    assert set(ignored) == {
        "heartbeat_interval_seconds",
        "store_forward",
        "policy_override",
        "_security",
    }
    merged = sanitize_runtime_config(values)
    assert merged["batch_size"] == 500
    assert "policy_override" not in merged
    assert merged["flush_interval_seconds"] == 30


def test_load_config_rejects_malformed_json(tmp_path: Path):
    path = tmp_path / "gateway.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_warns_on_loose_permissions(tmp_path: Path, caplog):
    path = tmp_path / "gateway.json"
    save_config(new_config(base_url="https://core.example.com", fingerprint="hs-0123456789abcdef"), path)
    path.chmod(0o644)
    caplog.set_level("WARNING")
    load_config(path)
    assert "accessible by group/other" in caplog.text


def test_update_runtime_config_ignores_unknown_server_keys():
    config = GatewayConfig(
        base_url="https://core.example.com",
        fingerprint="hs-0123456789abcdef",
        config={"batch_size": 10},
    )
    ignored = config.update_runtime_config(
        {"batch_size": 25, "autonomy": "maximum", "allow_remote_config": False, "_security": {}}
    )
    assert config.config["batch_size"] == 25
    assert config.config["allow_remote_config"] is False
    assert "autonomy" not in config.config
    assert set(ignored) == {"autonomy", "_security"}


def test_dataclass_is_not_repr_leaky_after_replace():
    config = GatewayConfig(
        base_url="https://core.example.com",
        fingerprint="hs-0123456789abcdef",
        shared_key="token-value",
    )
    assert "token-value" not in repr(replace(config, name="x"))
