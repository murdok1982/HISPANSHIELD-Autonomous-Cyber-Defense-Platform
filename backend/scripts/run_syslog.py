"""Optional syslog listener entrypoint (never auto-started by the API).

Examples::

    HS_SYSLOG_TOKEN=hs_ing_... python scripts/run_syslog.py --udp-port 5514 --tcp-port 5514

Environment: ``HS_SYSLOG_TOKEN``, ``HS_SYSLOG_BIND``, ``HS_SYSLOG_UDP_PORT``,
``HS_SYSLOG_TCP_PORT``, ``HS_SYSLOG_MAX_MESSAGE_BYTES``.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import signal
from typing import Any

from sqlalchemy import select

from app.core.crypto import token_hash
from app.core.db import SessionLocal
from app.models.events import IngestSource
from app.modules.events.service import audit_ingest, ingest_parsed_events
from app.workers.syslog_receiver import SourceBinding, SyslogReceiver


def resolve_source(token: str) -> SourceBinding | None:
    with SessionLocal() as db:
        source = db.execute(
            select(IngestSource).where(IngestSource.token_hash == token_hash(token))
        ).scalar_one_or_none()
        if source is None or not source.enabled:
            return None
        return SourceBinding(
            org_id=source.org_id,
            source_id=source.id,
            name=source.name,
            parser=source.parser,
        )


def store_event(binding: SourceBinding, raw: bytes, event: Any) -> None:
    with SessionLocal() as db:
        source = db.get(IngestSource, binding.source_id)
        if source is None or not source.enabled or source.org_id != binding.org_id:
            return
        ingest_parsed_events(db, org_id=source.org_id, source=source, events=[event])
        audit_ingest(
            db,
            org_id=source.org_id,
            source=source,
            accepted=1,
            rejected=0,
            detail={"transport": "syslog", "bytes": len(raw)},
        )
        db.commit()


async def _resolve_async(token: str) -> SourceBinding | None:
    return await asyncio.to_thread(resolve_source, token)


async def _store_async(binding: SourceBinding, raw: bytes, event: Any) -> None:
    await asyncio.to_thread(store_event, binding, raw, event)


async def run(args: argparse.Namespace) -> None:
    default_token = args.token or os.environ.get("HS_SYSLOG_TOKEN")
    receiver = SyslogReceiver(
        resolver=_resolve_async,
        sink=_store_async,
        default_token=default_token or None,
        host=args.bind,
        udp_port=args.udp_port,
        tcp_port=args.tcp_port,
        max_message_bytes=args.max_message_bytes,
    )
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # pragma: no cover - Windows
            loop.add_signal_handler(sig, receiver.request_stop)
    await receiver.start()
    await receiver.wait_closed()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HISPANSHIELD syslog receiver")
    parser.add_argument(
        "--bind",
        default=os.environ.get("HS_SYSLOG_BIND", "127.0.0.1"),
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        default=int(os.environ.get("HS_SYSLOG_UDP_PORT", "5514")),
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=int(os.environ.get("HS_SYSLOG_TCP_PORT", "5514")),
    )
    parser.add_argument(
        "--max-message-bytes",
        type=int,
        default=int(os.environ.get("HS_SYSLOG_MAX_MESSAGE_BYTES", "16384")),
    )
    parser.add_argument("--token", default=None, help="Default ingestion token for messages without HS-TOKEN envelope")
    args = parser.parse_args(argv)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        return 130
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())


__all__ = ["main", "resolve_source", "run", "store_event"]
