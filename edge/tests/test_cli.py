from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from conftest import free_port
from fake_core import ENROLLMENT_TOKEN, FINGERPRINT, GATEWAY_ID, ORG_ID, SECRET, FakeCore
from hispanshield_edge import cli
from hispanshield_edge.config import GatewayConfig, load_config, save_config
from hispanshield_edge.queue import DurableQueue


def _enrolled_config(base_url: str, *, key: str = SECRET) -> GatewayConfig:
    return GatewayConfig(
        base_url=base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=key,
        allow_insecure_http=True,
    )


def test_cli_enroll_saves_private_config_and_never_prints_secrets(core: FakeCore, tmp_path: Path, monkeypatch, capsys):
    config_path = tmp_path / "gateway.json"
    monkeypatch.setenv(cli.ENROLL_TOKEN_ENV, ENROLLMENT_TOKEN)
    code = cli.main(
        ["enroll", "--url", core.base_url, "--config", str(config_path), "--insecure", "--name", "edge-cli"]
    )
    output = capsys.readouterr()
    assert code == cli.EXIT_OK
    assert config_path.exists()
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    loaded = load_config(config_path)
    assert loaded.gateway_id == GATEWAY_ID
    assert loaded.shared_key == SECRET
    assert ENROLLMENT_TOKEN not in output.out
    assert SECRET not in output.out
    assert "gateway_id" in output.out


def test_cli_enroll_requires_token_when_stdin_is_not_a_tty(core: FakeCore, tmp_path: Path, monkeypatch, capsys):
    monkeypatch.delenv(cli.ENROLL_TOKEN_ENV, raising=False)
    code = cli.main(["enroll", "--url", core.base_url, "--config", str(tmp_path / "g.json"), "--insecure"])
    assert code == cli.EXIT_CONFIG
    assert "token required" in capsys.readouterr().err


def test_cli_enroll_refuses_to_overwrite_without_force(core: FakeCore, tmp_path: Path, monkeypatch, capsys):
    config_path = tmp_path / "gateway.json"
    save_config(_enrolled_config(core.base_url), config_path)
    monkeypatch.setenv(cli.ENROLL_TOKEN_ENV, ENROLLMENT_TOKEN)
    code = cli.main(["enroll", "--url", core.base_url, "--config", str(config_path), "--insecure"])
    assert code == cli.EXIT_CONFIG
    assert "--force" in capsys.readouterr().err


def test_cli_enroll_bad_token_returns_auth_exit_code(core: FakeCore, tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv(cli.ENROLL_TOKEN_ENV, "hs_enroll.bad-token.0000000000000000")
    code = cli.main(["enroll", "--url", core.base_url, "--config", str(tmp_path / "g.json"), "--insecure"])
    assert code == cli.EXIT_AUTH
    assert not (tmp_path / "g.json").exists()


def test_cli_status_reports_enrolled_gateway(core: FakeCore, tmp_path: Path, capsys):
    config_path = tmp_path / "gateway.json"
    save_config(_enrolled_config(core.base_url), config_path)
    queue = DurableQueue(tmp_path / "edge-queue.sqlite3")
    queue.enqueue("json", [{"a": 1}])
    queue.close()
    code = cli.main(["status", "--config", str(config_path), "--json"])
    assert code == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["gateway"]["enrolled"] is True
    assert payload["queue"]["pending_envelopes"] == 1
    assert SECRET not in json.dumps(payload)


def test_cli_status_missing_config_exit_code(tmp_path: Path, capsys):
    assert cli.main(["status", "--config", str(tmp_path / "missing.json")]) == cli.EXIT_CONFIG
    assert "not found" in capsys.readouterr().err


def test_cli_queue_lists_and_drops_with_confirmation(tmp_path: Path, capsys):
    queue = DurableQueue(tmp_path / "edge-queue.sqlite3")
    sequence = queue.enqueue("json", [{"a": 1}])
    queue.close()
    config_path = tmp_path / "gateway.json"

    assert cli.main(["queue", "--config", str(config_path), "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["pending_envelopes"] == 1
    assert payload["pending"][0]["sequence"] == sequence

    assert cli.main(["queue", "--config", str(config_path), "--drop", str(sequence)]) == cli.EXIT_CONFIG
    assert cli.main(["queue", "--config", str(config_path), "--drop", str(sequence), "--yes"]) == cli.EXIT_OK
    reopened = DurableQueue(tmp_path / "edge-queue.sqlite3")
    try:
        assert reopened.stats()["pending_envelopes"] == 0
    finally:
        reopened.close()


def test_cli_flush_offline_returns_unavailable_and_keeps_data(tmp_path: Path, capsys):
    port = free_port()
    config_path = tmp_path / "gateway.json"
    save_config(_enrolled_config(f"http://127.0.0.1:{port}"), config_path)
    queue = DurableQueue(tmp_path / "edge-queue.sqlite3")
    queue.enqueue("json", [{"a": 1}])
    queue.close()
    code = cli.main(["flush", "--config", str(config_path)])
    assert code == cli.EXIT_UNAVAILABLE
    reopened = DurableQueue(tmp_path / "edge-queue.sqlite3")
    try:
        assert reopened.stats()["pending_envelopes"] == 1
    finally:
        reopened.close()


def test_cli_flush_401_returns_auth_error(tmp_path: Path, core: FakeCore):
    config_path = tmp_path / "gateway.json"
    save_config(_enrolled_config(core.base_url, key="wrong-shared-key-0123456789"), config_path)
    queue = DurableQueue(tmp_path / "edge-queue.sqlite3")
    queue.enqueue("json", [{"a": 1}])
    queue.close()
    assert cli.main(["flush", "--config", str(config_path)]) == cli.EXIT_AUTH


def test_cli_run_once_offline_returns_unavailable(tmp_path: Path, capsys):
    port = free_port()
    config_path = tmp_path / "gateway.json"
    save_config(_enrolled_config(f"http://127.0.0.1:{port}"), config_path)
    code = cli.main(["run", "--config", str(config_path), "--once"])
    payload = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_UNAVAILABLE
    assert payload["heartbeat"] is None
    assert payload["error"]


def test_cli_run_once_ingests_spool_offline(tmp_path: Path, capsys):
    port = free_port()
    config_path = tmp_path / "gateway.json"
    save_config(_enrolled_config(f"http://127.0.0.1:{port}"), config_path)
    spool = tmp_path / "spool"
    spool.mkdir()
    (spool / "events.jsonl").write_text(json.dumps({"offline": True}) + "\n", encoding="utf-8")
    code = cli.main(["run", "--config", str(config_path), "--once"])
    payload = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_UNAVAILABLE
    assert payload["collected"] == 1
    queue = DurableQueue(tmp_path / "edge-queue.sqlite3")
    try:
        assert queue.stats()["pending_envelopes"] == 1
    finally:
        queue.close()


def test_cli_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert "hispanshield-edge" in capsys.readouterr().out
