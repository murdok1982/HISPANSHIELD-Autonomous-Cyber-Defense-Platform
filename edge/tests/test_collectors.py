from __future__ import annotations

import json
import socket
import time
from pathlib import Path

from hispanshield_edge.collectors import (
    OtSpoolCollector,
    SpoolCollector,
    SyslogUDPCollector,
    parse_syslog,
)
from hispanshield_edge.queue import DurableQueue


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_spool_jsonl_is_ingested_and_archived(tmp_path: Path, queue: DurableQueue):
    spool_dir = tmp_path / "spool"
    collector = SpoolCollector(queue, spool_dir)
    collector.start()
    try:
        _write(
            spool_dir / "batch-1.jsonl",
            "\n".join(
                [
                    json.dumps({"event_uid": "a", "value": 1}),
                    "",
                    json.dumps({"event_uid": "b", "value": 2}),
                ]
            ),
        )
        assert collector.poll() == 2
        assert not (spool_dir / "batch-1.jsonl").exists()
        assert len(list((spool_dir / "archive").iterdir())) == 1
        pending = queue.pending(10)
        assert len(pending) == 1
        assert pending[0].kind == "json"
        assert pending[0].events == [{"event_uid": "a", "value": 1}, {"event_uid": "b", "value": 2}]
        stats = collector.stats()
        assert stats["files_processed"] == 1
        assert stats["events_enqueued"] == 2
    finally:
        collector.stop()


def test_spool_json_array_document_and_batches(queue: DurableQueue, tmp_path: Path):
    spool_dir = tmp_path / "spool"
    collector = SpoolCollector(queue, spool_dir, batch_size=2)
    collector.start()
    try:
        _write(spool_dir / "array.json", json.dumps([{"n": 1}, {"n": 2}, {"n": 3}]))
        assert collector.poll() == 3
        assert [len(item.events) for item in queue.pending(10)] == [2, 1]
    finally:
        collector.stop()


def test_spool_invalid_file_is_quarantined(queue: DurableQueue, tmp_path: Path):
    spool_dir = tmp_path / "spool"
    collector = SpoolCollector(queue, spool_dir)
    collector.start()
    try:
        _write(spool_dir / "broken.json", "{not-json")
        assert collector.poll() == 0
        failed = list((spool_dir / "failed").iterdir())
        assert any(path.name.endswith(".json") for path in failed)
        assert any(path.name.endswith(".error") for path in failed)
        assert queue.stats()["pending_envelopes"] == 0
        assert collector.stats()["files_failed"] == 1
    finally:
        collector.stop()


def test_spool_rejects_object_larger_than_256kb(queue: DurableQueue, tmp_path: Path):
    spool_dir = tmp_path / "spool"
    collector = SpoolCollector(queue, spool_dir)
    collector.start()
    try:
        _write(spool_dir / "huge.json", json.dumps({"payload": "x" * (256 * 1024)}))
        assert collector.poll() == 0
        assert queue.stats()["pending_envelopes"] == 0
        error_files = list((spool_dir / "failed").glob("*.error"))
        assert error_files
        assert "limit" in error_files[0].read_text(encoding="utf-8")
    finally:
        collector.stop()


def test_spool_requeues_claimed_files_after_crash(queue: DurableQueue, tmp_path: Path):
    spool_dir = tmp_path / "spool"
    (spool_dir / "processing").mkdir(parents=True)
    _write(spool_dir / "processing" / "orphan.jsonl", json.dumps({"recovered": True}) + "\n")
    collector = SpoolCollector(queue, spool_dir)
    collector.start()
    try:
        assert (spool_dir / "orphan.jsonl").exists()
        assert collector.poll() == 1
        assert queue.pending(1)[0].events == [{"recovered": True}]
    finally:
        collector.stop()


def test_parse_syslog_rfc3164():
    event = parse_syslog(b"<34>Oct 11 22:14:15 mymachine su[230]: 'su root' failed for lonvick")
    assert event is not None
    assert event["raw_format"] == "syslog"
    assert event["syslog_format"] == "rfc3164"
    assert event["facility"] == 4
    assert event["severity"] == 2
    assert event["priority"] == 34
    assert event["host"] == "mymachine"
    assert event["app"] == "su"
    assert event["procid"] == "230"
    assert "failed for lonvick" in event["message"]


def test_parse_syslog_rfc5424_with_structured_data():
    raw = (
        b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
        b'[exampleSDID@32473 iut="3" eventSource="Application"] An application event'
    )
    event = parse_syslog(raw)
    assert event is not None
    assert event["syslog_format"] == "rfc5424"
    assert event["priority"] == 165
    assert event["host"] == "mymachine.example.com"
    assert event["app"] == "evntslog"
    assert event["msgid"] == "ID47"
    assert event["message"] == "An application event"


def test_parse_syslog_unstructured_falls_back_to_raw_message():
    event = parse_syslog(b"plain text without syslog framing\n")
    assert event is not None
    assert event["syslog_format"] == "unknown"
    assert event["message"] == "plain text without syslog framing"


def test_syslog_collector_receives_and_persists_datagrams(queue: DurableQueue):
    collector = SyslogUDPCollector(queue, port=0, batch_size=10)
    collector.start()
    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"<34>Oct 11 22:14:15 host1 app[1]: first message", ("127.0.0.1", collector.bound_port))
            sender.sendto(
                b'<165>1 2003-10-11T22:14:15.003Z host2 evntslog - ID47 [x@1 k="v"] second',
                ("127.0.0.1", collector.bound_port),
            )
        finally:
            sender.close()
        deadline = time.monotonic() + 5
        while collector.stats()["received"] < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        collector.flush()
    finally:
        collector.stop()
    pending = queue.pending(10)
    assert len(pending) == 1
    assert pending[0].kind == "network"
    assert len(pending[0].events) == 2
    assert pending[0].events[0]["message"] == "first message"
    assert pending[0].events[1]["message"] == "second"
    assert collector.stats()["enqueued"] == 2


def test_syslog_oversize_datagram_is_dropped(queue: DurableQueue):
    collector = SyslogUDPCollector(queue, port=0)
    assert collector.handle_datagram(b"x" * (64 * 1024 + 1)) is False
    assert collector.stats()["dropped_oversize"] == 1
    assert queue.stats()["pending_envelopes"] == 0


def test_ot_spool_reads_incrementally_without_writing(tmp_path: Path, queue: DurableQueue):
    ot_dir = tmp_path / "ot-readonly"
    ot_dir.mkdir()
    observations = ot_dir / "observations.jsonl"
    _write(observations, json.dumps({"point": "P1", "value": 3}) + "\n")
    before = sorted(path.name for path in ot_dir.iterdir())
    collector = OtSpoolCollector(queue, ot_dir, tmp_path / "ot-offsets.json")
    collector.start()
    try:
        assert collector.poll() == 1
        with observations.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"point": "P2", "value": 4}) + "\n")
        assert collector.poll() == 1
        assert collector.poll() == 0
        assert sorted(path.name for path in ot_dir.iterdir()) == before
        assert observations.exists()
        pending = queue.pending(10)
        assert [item.kind for item in pending] == ["ot", "ot"]
        assert pending[1].events == [{"point": "P2", "value": 4}]
        stats = collector.stats()
        assert stats["network_connections"] == 0
        assert stats["mode"] == "read_only_spool"
    finally:
        collector.stop()

    restarted = OtSpoolCollector(queue, ot_dir, tmp_path / "ot-offsets.json")
    restarted.start()
    try:
        assert restarted.poll() == 0
    finally:
        restarted.stop()


def test_ot_spool_never_opens_a_socket(tmp_path: Path, queue: DurableQueue, monkeypatch):
    ot_dir = tmp_path / "ot"
    ot_dir.mkdir()
    _write(ot_dir / "observations.jsonl", json.dumps({"plc": "line-1", "state": "idle"}) + "\n")

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("OT collector must never open a network socket")

    monkeypatch.setattr(socket, "socket", _forbidden)
    collector = OtSpoolCollector(queue, ot_dir, tmp_path / "offsets.json")
    collector.start()
    try:
        assert collector.poll() == 1
    finally:
        collector.stop()


def test_ot_spool_skips_malformed_lines_but_keeps_valid_ones(tmp_path: Path, queue: DurableQueue):
    ot_dir = tmp_path / "ot"
    ot_dir.mkdir()
    _write(
        ot_dir / "observations.jsonl",
        "this is not json\n" + json.dumps({"ok": True}) + "\n" + "[]\n" + json.dumps({"ok": 2}) + "\n",
    )
    collector = OtSpoolCollector(queue, ot_dir, tmp_path / "offsets.json")
    collector.start()
    try:
        assert collector.poll() == 2
        assert collector.stats()["lines_rejected"] == 2
        assert queue.pending(1)[0].events == [{"ok": True}, {"ok": 2}]
    finally:
        collector.stop()


def test_ot_offsets_do_not_advance_when_enqueue_fails(tmp_path: Path, queue: DurableQueue, monkeypatch):
    ot_dir = tmp_path / "ot"
    ot_dir.mkdir()
    _write(ot_dir / "observations.jsonl", json.dumps({"point": "P1"}) + "\n")
    collector = OtSpoolCollector(queue, ot_dir, tmp_path / "offsets.json")
    collector.start()
    original = queue.enqueue
    calls = {"count": 0}

    def flaky(kind, events):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("simulated disk full")
        return original(kind, events)

    monkeypatch.setattr(queue, "enqueue", flaky)
    try:
        assert collector.poll() == 0
        assert queue.stats()["pending_envelopes"] == 0
        assert collector.poll() == 1
        assert queue.pending(1)[0].events == [{"point": "P1"}]
    finally:
        collector.stop()


def test_spool_collector_ignores_directories(tmp_path: Path, queue: DurableQueue):
    spool_dir = tmp_path / "spool"
    (spool_dir / "subdir.jsonl").mkdir(parents=True)
    collector = SpoolCollector(queue, spool_dir)
    collector.start()
    try:
        assert collector.poll() == 0
        assert collector.stats()["files_processed"] == 0
    finally:
        collector.stop()
