"""A strict in-process fake of the HISPANSHIELD edge control plane.

It verifies the exact HMAC scheme the backend implements, enforces sequence
monotonicity and can simulate 401/409/503, tampered bundles and tenant-only
config routes. No production code is imported from ``backend/``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

GATEWAY_ID = "11111111-1111-1111-1111-111111111111"
ORG_ID = "22222222-2222-2222-2222-222222222222"
FINGERPRINT = "hs-test-fingerprint-0001"
SECRET = "test-shared-key-0123456789abcdef"
ENROLLMENT_TOKEN = "hs_enroll.test-token-0123456789.abcdef"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class FakeCoreState:
    def __init__(self) -> None:
        self.secret = SECRET
        self.gateway_id = GATEWAY_ID
        self.org_id = ORG_ID
        self.fingerprint = FINGERPRINT
        self.enrollment_token = ENROLLMENT_TOKEN
        self.cursor = 0
        self.requests: list[dict[str, Any]] = []
        self.heartbeats = 0
        self.fail_events_remaining = 0
        self.fail_status = 503
        self.signature_mode = "valid"  # valid | invalid
        self.config_mode = "signed"  # signed | tampered | tenant_only
        self.server_time_offset = 0.0
        self.config: dict[str, Any] = {
            "batch_size": 50,
            "heartbeat_interval_seconds": 15,
            "buffer_max_events": 1000,
            "flush_interval_seconds": 30,
            "unknown_policy_override": "grant-everything",
            "_internal_secret": "must-never-appear",
        }

    def bundle(self) -> dict[str, Any]:
        issued = datetime.now(UTC)
        bundle = {
            "gateway_id": self.gateway_id,
            "org_id": self.org_id,
            "name": "edge-test",
            "fingerprint": self.fingerprint,
            "version": "0.1.0",
            "config": {key: value for key, value in self.config.items() if not key.startswith("_")},
            "issued_at": issued.isoformat(),
            "expires_at": (issued + timedelta(minutes=15)).isoformat(),
        }
        signature = hmac.new(
            self.secret.encode(),
            json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()
        return {"bundle": bundle, "signature": signature, "algorithm": "HMAC-SHA256"}

    def verify(self, headers: Any, method: str, path: str, body: bytes) -> bool:
        if self.signature_mode != "valid":
            return False
        fingerprint = headers.get("X-Gateway-Fingerprint")
        timestamp = headers.get("X-Gateway-Timestamp")
        signature = headers.get("X-Gateway-Signature")
        if fingerprint != self.fingerprint or not timestamp or not signature:
            return False
        if not timestamp.isdigit() or abs(int(time.time()) - int(timestamp)) > 300:
            return False
        message = f"{timestamp}\n{method.upper()}\n{path}\n{hashlib.sha256(body).hexdigest()}".encode()
        expected = hmac.new(self.secret.encode(), message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature.lower(), expected)


class FakeCore:
    def __init__(self, *, port: int = 0) -> None:
        self.state = FakeCoreState()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._port = port

    @property
    def base_url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def start(self) -> FakeCore:
        core = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:
                return

            def _body(self) -> bytes:
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length) if length else b""

            def _send(self, status: int, payload: Any) -> None:
                body = json.dumps(payload, default=str).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _record(self, body: bytes) -> None:
                core.state.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": dict(self.headers.items()),
                        "body": body,
                    }
                )

            def _authorized(self, body: bytes) -> bool:
                return core.state.verify(self.headers, self.command, self.path, body)

            def do_POST(self) -> None:  # noqa: N802
                body = self._body()
                self._record(body)
                if self.path == "/api/v1/edge/gateways/register":
                    try:
                        payload = json.loads(body or b"{}")
                    except json.JSONDecodeError:
                        self._send(400, {"detail": "invalid JSON"})
                        return
                    if payload.get("enrollment_token") != core.state.enrollment_token:
                        self._send(401, {"detail": "Enrollment token is invalid, expired or already used"})
                        return
                    self._send(
                        201,
                        {
                            "gateway_id": core.state.gateway_id,
                            "org_id": core.state.org_id,
                            "fingerprint": payload.get("fingerprint", core.state.fingerprint),
                            "status": "active",
                            "enrolled_at": _now_iso(),
                            "shared_key": core.state.secret,
                            "config_bundle": core.state.bundle(),
                        },
                    )
                    return
                if self.path == f"/api/v1/edge/gateways/{core.state.gateway_id}/heartbeat":
                    if not self._authorized(body):
                        self._send(401, {"detail": "Gateway signature is invalid or expired"})
                        return
                    core.state.heartbeats += 1
                    server_time = datetime.now(UTC) + timedelta(seconds=core.state.server_time_offset)
                    self._send(
                        200,
                        {
                            "ok": True,
                            "server_time": server_time.isoformat().replace("+00:00", "Z"),
                            "cursor": core.state.cursor,
                            "next_heartbeat_seconds": 60,
                            "config_version": "v1",
                        },
                    )
                    return
                if self.path == f"/api/v1/edge/gateways/{core.state.gateway_id}/events":
                    if not self._authorized(body):
                        self._send(401, {"detail": "Gateway signature is invalid or expired"})
                        return
                    if core.state.fail_events_remaining > 0:
                        core.state.fail_events_remaining -= 1
                        self._send(core.state.fail_status, {"detail": "temporarily unavailable"})
                        return
                    try:
                        envelope = json.loads(body)
                    except json.JSONDecodeError:
                        self._send(400, {"detail": "invalid JSON"})
                        return
                    sequence = int(envelope.get("sequence", -1))
                    if sequence <= core.state.cursor:
                        self._send(409, {"detail": "Sequence already ingested; replay rejected"})
                        return
                    core.state.cursor = sequence
                    self._send(
                        200,
                        {
                            "accepted": True,
                            "sequence": sequence,
                            "processed": len(envelope.get("events", [])),
                            "duplicates": 0,
                            "cursor": sequence,
                        },
                    )
                    return
                self._send(404, {"detail": "not found"})

            def do_GET(self) -> None:  # noqa: N802
                body = self._body()
                self._record(body)
                if self.path == f"/api/v1/edge/gateways/{core.state.gateway_id}/config-bundle":
                    if not self._authorized(body):
                        self._send(401, {"detail": "Gateway signature is invalid or expired"})
                        return
                    if core.state.config_mode == "tenant_only":
                        self._send(401, {"detail": "Not authenticated"})
                        return
                    bundle = core.state.bundle()
                    if core.state.config_mode == "tampered":
                        bundle["bundle"]["config"]["batch_size"] = 999
                    self._send(200, bundle)
                    return
                self._send(404, {"detail": "not found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", self._port), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="fake-core", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def events_requests(self) -> list[dict[str, Any]]:
        return [item for item in self.state.requests if item["path"].endswith("/events")]

    def __enter__(self) -> FakeCore:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()
