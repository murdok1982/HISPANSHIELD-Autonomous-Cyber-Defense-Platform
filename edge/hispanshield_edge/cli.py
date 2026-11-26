"""Operator CLI for the HISPANSHIELD edge gateway agent.

Exit codes: 0 success, 1 unexpected error, 2 configuration/usage, 3 fatal
authentication (re-enrollment required), 4 core unreachable / deferred,
5 rejected configuration bundle.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import socket
import sys
from collections.abc import Sequence
from pathlib import Path

from hispanshield_edge import AGENT_VERSION
from hispanshield_edge.agent import GatewayAgent, configure_logging
from hispanshield_edge.client import (
    ConfigFetchUnavailable,
    EdgeClient,
    EdgeClientError,
    FatalAuthError,
    InvalidBundleError,
    PermanentHTTPError,
    RetryableHTTPError,
    TransportError,
)
from hispanshield_edge.config import (
    ConfigError,
    GatewayConfig,
    load_config,
    new_config,
    save_config,
)
from hispanshield_edge.queue import DurableQueue

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_AUTH = 3
EXIT_UNAVAILABLE = 4
EXIT_BAD_BUNDLE = 5

DEFAULT_CONFIG = "edge-data/gateway.json"
ENROLL_TOKEN_ENV = "HISPANSHIELD_ENROLL_TOKEN"


def _print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _map_error(exc: BaseException) -> int:
    if isinstance(exc, FatalAuthError):
        return EXIT_AUTH
    if isinstance(exc, InvalidBundleError):
        return EXIT_BAD_BUNDLE
    if isinstance(exc, (ConfigError, ValueError)):
        return EXIT_CONFIG
    if isinstance(exc, (TransportError, RetryableHTTPError, ConfigFetchUnavailable)):
        return EXIT_UNAVAILABLE
    if isinstance(exc, PermanentHTTPError):
        return EXIT_ERROR
    if isinstance(exc, EdgeClientError):
        return EXIT_UNAVAILABLE
    return EXIT_ERROR


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_enroll(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if path.exists() and not args.force:
        _error(f"config already exists at {path}; use --force to replace it")
        return EXIT_CONFIG
    token = args.token or os.environ.get(ENROLL_TOKEN_ENV, "")
    if not token:
        if sys.stdin.isatty():
            token = getpass.getpass("Enrollment token: ")
        else:
            _error(f"enrollment token required via --token or {ENROLL_TOKEN_ENV}")
            return EXIT_CONFIG
    token = token.strip()
    if len(token) < 16:
        _error("enrollment token is too short")
        return EXIT_CONFIG

    config = new_config(
        base_url=args.url,
        fingerprint=args.fingerprint,
        name=args.name or socket.gethostname(),
        allow_insecure_http=args.insecure,
        ca_bundle=args.ca_bundle,
        client_cert=args.client_cert,
        client_key=args.client_key,
        version=AGENT_VERSION,
    )
    client = EdgeClient(config, sleep=lambda _seconds: None)
    try:
        result = client.enroll(
            enrollment_token=token,
            name=config.name,
            version=AGENT_VERSION,
            certificate_serial=args.certificate_serial,
            attempts=2,
        )
        config.set_enrolled(
            gateway_id=result.gateway_id,
            org_id=result.org_id,
            shared_key=result.shared_key,
            server_config=result.bundle.get("config", {}),
        )
        config.config_version = str(int(result.enrolled_at.timestamp()))
        save_config(config, path)
    except (EdgeClientError, ConfigError, OSError) as exc:
        _error(f"enrollment failed: {exc}")
        return _map_error(exc)
    finally:
        client.close()

    _print_json(
        {
            "enrolled": True,
            "gateway_id": config.gateway_id,
            "org_id": config.org_id,
            "fingerprint": config.fingerprint,
            "name": config.name,
            "config_path": str(path),
            "config": config.config,
        }
    )
    return EXIT_OK


def _open_queue(path: Path) -> DurableQueue:
    return DurableQueue(path)


def cmd_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    data_dir = Path(args.data_dir) if args.data_dir else Path(args.config).parent
    data_dir.mkdir(parents=True, exist_ok=True)
    queue_db = Path(args.queue_db) if args.queue_db else data_dir / "edge-queue.sqlite3"
    spool_dir = Path(args.spool_dir) if args.spool_dir else data_dir / "spool"
    log_level = args.log_level or str(config.config.get("log_level", "info"))
    configure_logging(log_level)

    queue = _open_queue(queue_db)
    agent: GatewayAgent | None = None
    try:
        agent = GatewayAgent(
            config,
            queue,
            spool_dir=spool_dir,
            ot_spool_dir=Path(args.ot_spool) if args.ot_spool else None,
            syslog_port=args.syslog_port,
            syslog_bind=args.syslog_bind,
            data_dir=data_dir,
            config_path=args.config,
        )
        if args.once:
            summary = agent.once()
            _print_json(summary)
            if summary.get("blocked"):
                return EXIT_ERROR
            if summary.get("error"):
                return EXIT_UNAVAILABLE
            return EXIT_OK
        return agent.run()
    except FatalAuthError as exc:
        _error(str(exc))
        return EXIT_AUTH
    except InvalidBundleError as exc:
        _error(str(exc))
        return EXIT_BAD_BUNDLE
    except ConfigError as exc:
        _error(str(exc))
        return EXIT_CONFIG
    except (TransportError, RetryableHTTPError, ConfigFetchUnavailable) as exc:
        _error(str(exc))
        return EXIT_UNAVAILABLE
    except OSError as exc:
        _error(f"filesystem error: {exc}")
        return EXIT_ERROR
    finally:
        if agent is not None:
            agent.close()
        queue.close()


def _read_status(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def cmd_status(args: argparse.Namespace) -> int:
    try:
        config: GatewayConfig = load_config(args.config)
    except ConfigError as exc:
        _error(str(exc))
        return EXIT_CONFIG
    data_dir = Path(args.data_dir) if args.data_dir else Path(args.config).parent
    queue_path = Path(args.queue_db) if args.queue_db else data_dir / "edge-queue.sqlite3"
    queue_stats = None
    if queue_path.exists():
        queue = DurableQueue(queue_path)
        try:
            queue_stats = queue.stats()
        finally:
            queue.close()
    status = _read_status(data_dir / "status.json")
    payload = {
        "gateway": config.describe(),
        "queue_present": queue_path.exists(),
        "queue": queue_stats,
        "process": status,
    }
    if args.json:
        _print_json(payload)
        return EXIT_OK
    print(f"gateway_id     : {config.gateway_id or '(not enrolled)'}")
    print(f"base_url       : {config.base_url}")
    print(f"fingerprint    : {config.fingerprint}")
    print(f"enrolled       : {config.is_enrolled}")
    if queue_stats:
        print(f"pending        : {queue_stats['pending_envelopes']} envelopes / {queue_stats['pending_bytes']} bytes")
        print(f"oldest pending : {queue_stats['oldest_age_s']}s")
        print(f"cursor         : {queue_stats['cursor']}")
        print(f"next sequence  : {queue_stats['next_sequence']}")
        if queue_stats.get("blocking_error"):
            blocking = queue_stats["blocking_error"]
            print(f"blocked        : sequence {blocking['sequence']}: {blocking['error']}")
    else:
        print("pending        : queue not created yet")
    if status:
        counters = status.get("counters", {})
        print(f"agent state    : {status.get('state')}")
        print(f"last heartbeat : {counters.get('last_heartbeat_at')}")
        print(f"last error     : {counters.get('last_error')}")
    return EXIT_OK


def cmd_flush(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        config.require_enrolled()
    except ConfigError as exc:
        _error(str(exc))
        return EXIT_CONFIG
    data_dir = Path(args.data_dir) if args.data_dir else Path(args.config).parent
    queue_path = Path(args.queue_db) if args.queue_db else data_dir / "edge-queue.sqlite3"
    if not queue_path.exists():
        _error(f"queue not found: {queue_path}")
        return EXIT_CONFIG
    queue = DurableQueue(queue_path)
    client = EdgeClient(config)
    try:
        agent = GatewayAgent(config, queue, client=client, data_dir=data_dir, config_path=args.config)
        result = agent.flush_pending(max_batches=args.max_batches)
        _print_json({"flush": result, "queue": queue.stats()})
        if result["error"]:
            return EXIT_UNAVAILABLE
        return EXIT_OK
    except FatalAuthError as exc:
        _error(str(exc))
        return EXIT_AUTH
    except (TransportError, RetryableHTTPError) as exc:
        _error(str(exc))
        return EXIT_UNAVAILABLE
    finally:
        client.close()
        queue.close()


def cmd_queue(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir) if args.data_dir else Path(args.config).parent
    queue_path = Path(args.queue_db) if args.queue_db else data_dir / "edge-queue.sqlite3"
    if not queue_path.exists():
        _error(f"queue not found: {queue_path}")
        return EXIT_CONFIG
    queue = DurableQueue(queue_path)
    try:
        if args.drop is not None:
            if not args.yes:
                _error("refusing to drop an envelope without --yes; this is destructive")
                return EXIT_CONFIG
            if not queue.drop(args.drop):
                _error(f"sequence {args.drop} is not pending")
                return EXIT_ERROR
        stats = queue.stats()
        pending = queue.pending(args.pending)
        payload = {
            "stats": stats,
            "pending": [
                {
                    "sequence": envelope.sequence,
                    "kind": envelope.kind,
                    "events": len(envelope.events),
                    "age_s": round(envelope.age_seconds, 1),
                    "attempts": envelope.attempts,
                    "last_error": envelope.last_error,
                }
                for envelope in pending
            ],
        }
        if args.json:
            _print_json(payload)
            return EXIT_OK
        for key, value in stats.items():
            print(f"{key}: {value}")
        if pending:
            print("\nPending envelopes (oldest first):")
            for envelope in pending:
                print(
                    f"  seq={envelope.sequence} kind={envelope.kind} events={len(envelope.events)} "
                    f"age={envelope.age_seconds:.0f}s attempts={envelope.attempts} "
                    f"error={envelope.last_error or '-'}"
                )
        return EXIT_OK
    finally:
        queue.close()


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hispanshield-edge",
        description="HISPANSHIELD edge gateway agent (store-and-forward, signed HTTPS)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {AGENT_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    enroll = subparsers.add_parser("enroll", help="register this gateway with a one-time token")
    enroll.add_argument("--url", required=True, help="core base URL, e.g. https://core.example.com")
    enroll.add_argument("--token", help=f"one-time enrollment token (prefer ${ENROLL_TOKEN_ENV})")
    enroll.add_argument("--name", help="gateway display name (default: hostname)")
    enroll.add_argument("--config", default=DEFAULT_CONFIG, help="config file path")
    enroll.add_argument("--fingerprint", help="explicit fingerprint (default: derived from machine-id)")
    enroll.add_argument("--certificate-serial", help="mTLS certificate serial for the inventory")
    enroll.add_argument("--insecure", action="store_true", help="allow plain http:// (lab only)")
    enroll.add_argument("--ca-bundle", help="custom CA bundle (PEM) for the core certificate")
    enroll.add_argument("--client-cert", help="client certificate for mTLS")
    enroll.add_argument("--client-key", help="client private key for mTLS")
    enroll.add_argument("--force", action="store_true", help="replace an existing config file")
    enroll.set_defaults(func=cmd_enroll)

    run = subparsers.add_parser("run", help="run the collection and shipping loop")
    run.add_argument("--config", default=DEFAULT_CONFIG, help="config file path")
    run.add_argument("--spool-dir", help="JSON/JSONL spool directory (default: <data-dir>/spool)")
    run.add_argument("--ot-spool", help="read-only OT observation spool (JSONL)")
    run.add_argument("--syslog-port", type=int, help="enable the passive UDP syslog listener on this port")
    run.add_argument("--syslog-bind", default="127.0.0.1", help="syslog bind address (default loopback)")
    run.add_argument("--data-dir", help="directory for queue/status (default: config directory)")
    run.add_argument("--queue-db", help="override the SQLite queue path")
    run.add_argument("--log-level", choices=["debug", "info", "warning", "error"])
    run.add_argument("--once", action="store_true", help="run a single cycle and exit")
    run.set_defaults(func=cmd_run)

    status = subparsers.add_parser("status", help="show gateway and queue status")
    status.add_argument("--config", default=DEFAULT_CONFIG)
    status.add_argument("--data-dir")
    status.add_argument("--queue-db")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    flush = subparsers.add_parser("flush", help="ship pending batches now (no collectors)")
    flush.add_argument("--config", default=DEFAULT_CONFIG)
    flush.add_argument("--data-dir")
    flush.add_argument("--queue-db")
    flush.add_argument("--max-batches", type=int, default=1000)
    flush.set_defaults(func=cmd_flush)

    queue = subparsers.add_parser("queue", help="inspect the durable queue")
    queue.add_argument("--config", default=DEFAULT_CONFIG)
    queue.add_argument("--data-dir")
    queue.add_argument("--queue-db")
    queue.add_argument("--pending", type=int, default=10, help="show the oldest N pending envelopes")
    queue.add_argument("--json", action="store_true")
    queue.add_argument("--drop", type=int, metavar="SEQUENCE", help="drop one pending envelope (destructive)")
    queue.add_argument("--yes", action="store_true", help="confirm --drop")
    queue.set_defaults(func=cmd_queue)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        logging.getLogger("hispanshield_edge.cli").info("interrupted by operator")
        return EXIT_OK
    except (ConfigError, ValueError) as exc:
        _error(str(exc))
        return EXIT_CONFIG
    except (FatalAuthError, InvalidBundleError, EdgeClientError) as exc:
        _error(str(exc))
        return _map_error(exc)
    except OSError as exc:
        _error(str(exc))
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _error(f"unexpected failure: {exc}")
        return EXIT_ERROR


__all__ = [
    "ENROLL_TOKEN_ENV",
    "EXIT_AUTH",
    "EXIT_BAD_BUNDLE",
    "EXIT_CONFIG",
    "EXIT_ERROR",
    "EXIT_OK",
    "EXIT_UNAVAILABLE",
    "build_parser",
    "main",
]
