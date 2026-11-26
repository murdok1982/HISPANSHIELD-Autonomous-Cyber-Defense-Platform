"""Connection-time SSRF checks: DNS pinning must reject at connect, not only pre-check."""

from __future__ import annotations

import socket

import httpcore
import pytest

from app.core.outbound import PinnedDNSBackend
from app.core.ssrf import SSRFError, validate_outbound_url


def test_pinned_backend_blocks_private_addresses_at_connect_time(monkeypatch) -> None:
    def fake_getaddrinfo(host, port, **kwargs):  # type: ignore[no-untyped-def]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    backend = PinnedDNSBackend(allow_private=False)
    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("rebind.example", 80)


def test_pinned_backend_always_blocks_metadata_even_with_private_allowed() -> None:
    backend = PinnedDNSBackend(allow_private=True)
    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("169.254.169.254", 80)


def test_pinned_backend_enforces_private_allowlist_at_connect_time(monkeypatch) -> None:
    def fake_getaddrinfo(host, port, **kwargs):  # type: ignore[no-untyped-def]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    backend = PinnedDNSBackend(allow_private=True, allowed_private_cidrs=["127.0.0.0/8"])
    with pytest.raises(httpcore.ConnectError, match="private allowlist"):
        backend.connect_tcp("rebind.example", 11434)


def test_empty_private_allowlist_denies_all_private_destinations(monkeypatch) -> None:
    def fake_getaddrinfo(host, port, **kwargs):  # type: ignore[no-untyped-def]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    backend = PinnedDNSBackend(allow_private=True, allowed_private_cidrs=[])
    with pytest.raises(httpcore.ConnectError, match="private allowlist"):
        backend.connect_tcp("localhost", 11434)


def test_pinned_backend_rejects_invalid_resolution(monkeypatch) -> None:
    def fake_getaddrinfo(host, port, **kwargs):  # type: ignore[no-untyped-def]
        return []

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    backend = PinnedDNSBackend(allow_private=False)
    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("empty.example", 443)


def test_outbound_precheck_still_rejects_private_without_allowlist() -> None:
    with pytest.raises(SSRFError):
        validate_outbound_url("http://127.0.0.1:8080/", allow_private=False)


def test_log_paths_redact_ingestion_tokens() -> None:
    from app.core.logging import _safe_log_path

    redacted = _safe_log_path("/api/v1/ingest/hs_ing_supersecrettoken")
    assert "supersecrettoken" not in redacted
    assert redacted.endswith("/<redacted>")
    assert _safe_log_path("/api/v1/events") == "/api/v1/events"
