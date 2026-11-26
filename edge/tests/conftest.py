from __future__ import annotations

import socket
from pathlib import Path

import pytest

from fake_core import FINGERPRINT, GATEWAY_ID, ORG_ID, SECRET, FakeCore
from hispanshield_edge.config import GatewayConfig
from hispanshield_edge.queue import DurableQueue


@pytest.fixture
def core() -> FakeCore:
    server = FakeCore().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def make_config(core: FakeCore):
    def _factory(**overrides):
        payload = {
            "base_url": core.base_url,
            "fingerprint": FINGERPRINT,
            "name": "edge-test",
            "gateway_id": GATEWAY_ID,
            "org_id": ORG_ID,
            "shared_key": SECRET,
            "allow_insecure_http": True,
            "config": {},
        }
        payload.update(overrides)
        return GatewayConfig(**payload)

    return _factory


@pytest.fixture
def enrolled_config(make_config) -> GatewayConfig:
    return make_config()


@pytest.fixture
def queue(tmp_path: Path) -> DurableQueue:
    durable = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        yield durable
    finally:
        durable.close()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
