from __future__ import annotations

import logging
from datetime import UTC, datetime

import pytest

from fake_core import ENROLLMENT_TOKEN, FINGERPRINT, GATEWAY_ID, SECRET, FakeCore
from hispanshield_edge.client import (
    ConfigFetchUnavailable,
    EdgeClient,
    FatalAuthError,
    InvalidBundleError,
    ReplayError,
    RetryableHTTPError,
    TransportError,
)
from hispanshield_edge.config import ConfigError, GatewayConfig


@pytest.fixture
def client(enrolled_config) -> EdgeClient:
    instance = EdgeClient(enrolled_config, sleep=lambda _seconds: None)
    try:
        yield instance
    finally:
        instance.close()


def test_enrollment_happy_path_verifies_bundle_and_hides_token(caplog, core: FakeCore):
    config = GatewayConfig(
        base_url=core.base_url,
        fingerprint=FINGERPRINT,
        allow_insecure_http=True,
    )
    caplog.set_level(logging.DEBUG)
    client = EdgeClient(config, sleep=lambda _seconds: None)
    try:
        result = client.enroll(enrollment_token=ENROLLMENT_TOKEN, name="site-a", attempts=2)
    finally:
        client.close()
    assert result.gateway_id == GATEWAY_ID
    assert result.shared_key == SECRET
    assert result.bundle["config"]["batch_size"] == 50
    assert "unknown_policy_override" in result.bundle["config"]
    assert "_internal_secret" not in result.bundle["config"]
    assert ENROLLMENT_TOKEN not in caplog.text
    assert SECRET not in caplog.text
    assert ENROLLMENT_TOKEN not in repr(result)
    assert SECRET not in repr(result)
    body = core.state.requests[0]["body"]
    assert ENROLLMENT_TOKEN.encode() in body


def test_enrollment_bad_token_is_fatal_and_not_retried(core: FakeCore):
    config = GatewayConfig(base_url=core.base_url, fingerprint=FINGERPRINT, allow_insecure_http=True)
    client = EdgeClient(config, sleep=lambda _seconds: None)
    try:
        with pytest.raises(FatalAuthError):
            client.enroll(enrollment_token="hs_enroll.invalid-token.000000000000", name="x", attempts=3)
    finally:
        client.close()
    register_calls = [item for item in core.state.requests if item["path"].endswith("/register")]
    assert len(register_calls) == 1


def test_heartbeat_is_signed_and_parsed(client: EdgeClient, core: FakeCore):
    result = client.heartbeat(buffer_stats={"pending": 3}, status="healthy")
    assert result.ok is True
    assert result.cursor == 0
    assert result.next_heartbeat_seconds == 60
    assert core.state.heartbeats == 1
    request = core.state.requests[-1]
    assert request["headers"]["X-Gateway-Fingerprint"] == FINGERPRINT
    assert len(request["headers"]["X-Gateway-Signature"]) == 64
    assert request["headers"]["X-Gateway-Timestamp"].isdigit()


def test_heartbeat_detects_clock_skew(client: EdgeClient, core: FakeCore):
    core.state.server_time_offset = 150.0
    result = client.heartbeat()
    skew = (result.server_time - datetime.now(UTC)).total_seconds()
    assert 140 < skew < 160


def test_send_batch_accepted_and_replay_detected(client: EdgeClient, core: FakeCore):
    result = client.send_batch(sequence=1, kind="json", events=[{"event_uid": "a"}, {"event_uid": "b"}])
    assert result.accepted is True
    assert result.processed == 2
    assert result.cursor == 1
    assert core.state.cursor == 1
    with pytest.raises(ReplayError):
        client.send_batch(sequence=1, kind="json", events=[{"event_uid": "a"}])


def test_events_401_is_fatal(client: EdgeClient, core: FakeCore):
    core.state.signature_mode = "invalid"
    with pytest.raises(FatalAuthError):
        client.send_batch(sequence=1, kind="json", events=[{"a": 1}])


def test_events_503_is_retryable_and_not_swallowed(client: EdgeClient, core: FakeCore):
    core.state.fail_events_remaining = 1
    with pytest.raises(RetryableHTTPError) as excinfo:
        client.send_batch(sequence=1, kind="json", events=[{"a": 1}])
    assert excinfo.value.status == 503
    assert core.state.cursor == 0
    result = client.send_batch(sequence=1, kind="json", events=[{"a": 1}])
    assert result.accepted is True


def test_transport_error_on_closed_port_is_typed():
    from conftest import free_port

    port = free_port()
    config = GatewayConfig(
        base_url=f"http://127.0.0.1:{port}",
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id="22222222-2222-2222-2222-222222222222",
        shared_key=SECRET,
        allow_insecure_http=True,
    )
    client = EdgeClient(config, timeout=2.0, sleep=lambda _seconds: None)
    try:
        with pytest.raises(TransportError):
            client.send_batch(sequence=1, kind="json", events=[{"a": 1}])
    finally:
        client.close()


def test_config_bundle_available_to_signed_request(client: EdgeClient, core: FakeCore):
    core.state.config_mode = "signed"
    verified = client.fetch_config_bundle()
    assert verified.config["batch_size"] == 50
    assert verified.gateway_id == GATEWAY_ID
    assert "issued_at" in verified.raw_bundle["bundle"]


def test_config_bundle_tenant_only_is_non_fatal(client: EdgeClient, core: FakeCore):
    core.state.config_mode = "tenant_only"
    with pytest.raises(ConfigFetchUnavailable):
        client.fetch_config_bundle()


def test_config_bundle_tampered_is_rejected(client: EdgeClient, core: FakeCore):
    core.state.config_mode = "tampered"
    with pytest.raises(InvalidBundleError):
        client.fetch_config_bundle()


def test_client_refuses_plain_http_without_opt_in():
    with pytest.raises(ConfigError):
        EdgeClient(
            GatewayConfig(
                base_url="http://127.0.0.1:9", fingerprint=FINGERPRINT, shared_key=SECRET, gateway_id=GATEWAY_ID
            )
        )


def test_no_redirect_following(client: EdgeClient):
    assert client._http.follow_redirects is False


def test_read_timeout_is_not_retried_for_events(monkeypatch):
    import httpx

    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        raise httpx.ReadTimeout("timed out", request=request)

    config = GatewayConfig(
        base_url="https://core.example.com",
        fingerprint=FINGERPRINT,
        gateway_id=GATEWAY_ID,
        org_id="22222222-2222-2222-2222-222222222222",
        shared_key=SECRET,
    )
    client = EdgeClient(config, transport=httpx.MockTransport(handler), sleep=lambda _seconds: None)
    try:
        with pytest.raises(TransportError) as excinfo:
            client.send_batch(sequence=1, kind="json", events=[{"a": 1}])
        assert excinfo.value.connect_failed is False
        assert calls["count"] == 1
    finally:
        client.close()


def test_unenrolled_client_cannot_sign_calls(core: FakeCore):
    config = GatewayConfig(base_url=core.base_url, fingerprint=FINGERPRINT, allow_insecure_http=True)
    client = EdgeClient(config, sleep=lambda _seconds: None)
    try:
        with pytest.raises(ConfigError):
            client.send_batch(sequence=1, kind="json", events=[{"a": 1}])
    finally:
        client.close()
