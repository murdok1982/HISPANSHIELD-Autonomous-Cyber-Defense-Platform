from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from conftest import free_port
from fake_core import FINGERPRINT, GATEWAY_ID, ORG_ID, SECRET, FakeCore
from hispanshield_edge.agent import GatewayAgent, configure_logging
from hispanshield_edge.client import EdgeClient, FatalAuthError, InvalidBundleError
from hispanshield_edge.config import GatewayConfig, load_config
from hispanshield_edge.queue import DurableQueue


def _agent(
    config: GatewayConfig,
    queue: DurableQueue,
    tmp_path: Path,
    *,
    client: EdgeClient | None = None,
) -> GatewayAgent:
    if client is None:
        client = EdgeClient(config, sleep=lambda _seconds: None)
    return GatewayAgent(
        config,
        queue,
        client=client,
        spool_dir=tmp_path / "spool",
        data_dir=tmp_path,
        config_path=tmp_path / "gateway.json",
    )


def _offline_config(tmp_path: Path, port: int) -> GatewayConfig:
    return GatewayConfig(
        base_url=f"http://127.0.0.1:{port}",
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
    )


def test_spool_collection_offline_then_strict_order_flush(tmp_path: Path, queue: DurableQueue):
    port = free_port()
    config = _offline_config(tmp_path, port)
    agent = _agent(config, queue, tmp_path)
    agent.start_collectors()
    try:
        spool = tmp_path / "spool"
        for file_index in range(2):
            lines = [json.dumps({"event_uid": f"{file_index}-{index}", "index": index}) for index in range(500)]
            (spool / f"batch-{file_index}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        summary = agent.once(heartbeat=False)
        assert summary["collected"] == 1000
        assert summary["sent_batches"] == 0
        assert summary["error"] is not None
        pending = queue.pending(10)
        assert [item.sequence for item in pending] == [1, 2, 3, 4, 5, 6]
        assert [len(item.events) for item in pending] == [200, 200, 100, 200, 200, 100]
        assert queue.stats()["max_attempts"] == 1
    finally:
        agent.stop_collectors()
        agent.client.close()

    core = FakeCore(port=port).start()
    try:
        online_agent = _agent(config, queue, tmp_path, client=EdgeClient(config, sleep=lambda _seconds: None))
        result = online_agent.flush_pending(max_batches=10)
        assert result["sent_batches"] == 6
        assert result["sent_events"] == 1000
        assert queue.pending(10) == []
        assert queue.cursor() == 6
        assert core.state.cursor == 6
        sequences = [json.loads(item["body"])["sequence"] for item in core.events_requests()]
        assert sequences == [1, 2, 3, 4, 5, 6]
        delivered = set()
        for item in core.events_requests():
            delivered.update(event["event_uid"] for event in json.loads(item["body"])["events"])
        assert len(delivered) == 1000
        online_agent.client.close()
    finally:
        core.stop()


def test_replay_is_marked_delivered_and_flush_continues(tmp_path: Path, queue: DurableQueue, core: FakeCore):
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
    )
    queue.enqueue("json", [{"event_uid": "first"}])
    queue.enqueue("json", [{"event_uid": "second"}])
    core.state.cursor = 1
    agent = _agent(config, queue, tmp_path)
    try:
        result = agent.flush_pending()
        assert result["replays"] == 1
        assert result["sent_batches"] == 1
        assert queue.pending(10) == []
        assert core.state.cursor == 2
        assert queue.cursor() == 2
    finally:
        agent.client.close()


def test_503_defers_without_data_loss_then_recovers(tmp_path: Path, queue: DurableQueue, core: FakeCore):
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
    )
    queue.enqueue("json", [{"event_uid": "keep-me"}])
    core.state.fail_events_remaining = 1
    agent = _agent(config, queue, tmp_path)
    try:
        first = agent.flush_pending()
        assert first["sent_batches"] == 0
        assert first["error"] is not None
        assert queue.stats()["pending_envelopes"] == 1
        assert queue.stats()["max_attempts"] == 1
        second = agent.flush_pending()
        assert second["sent_batches"] == 1
        assert queue.pending(10) == []
        body = json.loads(core.events_requests()[-1]["body"])
        assert body["events"] == [{"event_uid": "keep-me"}]
    finally:
        agent.client.close()


def test_401_is_fatal_and_preserves_the_queue(tmp_path: Path, queue: DurableQueue, core: FakeCore):
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
    )
    queue.enqueue("json", [{"event_uid": "x"}])
    core.state.signature_mode = "invalid"
    agent = _agent(config, queue, tmp_path)
    try:
        with pytest.raises(FatalAuthError):
            agent.flush_pending()
        assert queue.stats()["pending_envelopes"] == 1
    finally:
        agent.client.close()


def test_revoked_gateway_404_is_fatal(tmp_path: Path, queue: DurableQueue, core: FakeCore):
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
    )
    queue.enqueue("json", [{"event_uid": "x"}])
    core.state.revoked = True
    agent = _agent(config, queue, tmp_path)
    try:
        with pytest.raises(FatalAuthError):
            agent.flush_pending()
        assert queue.stats()["pending_envelopes"] == 1
    finally:
        agent.client.close()


def test_heartbeat_warns_on_clock_skew(tmp_path: Path, queue: DurableQueue, core: FakeCore, caplog):
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
    )
    core.state.server_time_offset = 200.0
    agent = _agent(config, queue, tmp_path)
    caplog.set_level(logging.WARNING)
    try:
        result = agent.heartbeat_once()
        assert abs(result["skew_seconds"]) > 120
        assert "clock.skew" in caplog.text
        assert agent.counters()["server_time_skew_seconds"] > 120
    finally:
        agent.client.close()


def test_remote_config_is_applied_only_after_signature_check(tmp_path: Path, queue: DurableQueue, core: FakeCore):
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
        config={"batch_size": 200},
    )
    config_path = tmp_path / "gateway.json"
    from hispanshield_edge.config import save_config

    save_config(config, config_path)
    agent = _agent(config, queue, tmp_path)
    try:
        core.state.config_mode = "tampered"
        with pytest.raises(InvalidBundleError):
            agent.refresh_config_if_due(force=True)
        assert config.config["batch_size"] == 200

        core.state.config_mode = "signed"
        assert agent.refresh_config_if_due(force=True) is True
        assert config.config["batch_size"] == 50
        assert config.config["heartbeat_interval_seconds"] == 15
        assert "unknown_policy_override" not in config.config
        assert "_internal_secret" not in config.config
        persisted = load_config(config_path)
        assert persisted.config["batch_size"] == 50
    finally:
        agent.client.close()


def test_tenant_only_config_route_is_non_fatal(tmp_path: Path, queue: DurableQueue, core: FakeCore):
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
    )
    core.state.config_mode = "tenant_only"
    agent = _agent(config, queue, tmp_path)
    try:
        assert agent.refresh_config_if_due(force=True) is False
        assert config.config["batch_size"] == 200
    finally:
        agent.client.close()


def test_status_file_contains_no_secrets(tmp_path: Path, queue: DurableQueue, core: FakeCore):
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
    )
    queue.enqueue("json", [{"event_uid": "x"}])
    agent = _agent(config, queue, tmp_path)
    try:
        agent.write_status()
        text = (tmp_path / "status.json").read_text(encoding="utf-8")
        assert SECRET not in text
        assert "shared_key" not in text
        assert '"cursor"' in text
        assert '"pending_envelopes": 1' in text
    finally:
        agent.client.close()


def test_once_keeps_collecting_while_offline(tmp_path: Path, queue: DurableQueue):
    port = free_port()
    config = _offline_config(tmp_path, port)
    agent = _agent(config, queue, tmp_path)
    agent.start_collectors()
    try:
        (tmp_path / "spool" / "events.jsonl").write_text(json.dumps({"offline": True}) + "\n", encoding="utf-8")
        summary = agent.once()
        assert summary["collected"] == 1
        assert summary["error"]
        assert queue.stats()["pending_envelopes"] == 1
        assert queue.stats()["next_sequence"] == 2
    finally:
        agent.stop_collectors()
        agent.client.close()


def test_agent_respects_server_batch_size_when_collecting(tmp_path: Path, queue: DurableQueue):
    config = GatewayConfig(
        base_url="https://core.example.com",
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
        config={"batch_size": 2},
    )
    agent = _agent(config, queue, tmp_path)
    agent.start_collectors()
    try:
        spool = tmp_path / "spool"
        spool.mkdir(exist_ok=True)
        (spool / "three.jsonl").write_text(
            "\n".join(json.dumps({"n": index}) for index in range(3)) + "\n",
            encoding="utf-8",
        )
        assert agent.collect_once() == 3
        assert [len(item.events) for item in queue.pending(10)] == [2, 1]
    finally:
        agent.stop_collectors()
        agent.client.close()


def test_structured_logs_are_json_and_secret_free(tmp_path: Path, queue: DurableQueue, core: FakeCore):
    stream = __import__("io").StringIO()
    configure_logging("debug", stream=stream)
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id=ORG_ID,
        shared_key=SECRET,
        allow_insecure_http=True,
    )
    agent = _agent(config, queue, tmp_path)
    try:
        agent.heartbeat_once()
    finally:
        agent.client.close()
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    assert lines
    assert all("ts" in line and "level" in line for line in lines)
    assert any(line["message"] == "heartbeat.ok" for line in lines)
    assert SECRET not in stream.getvalue()
