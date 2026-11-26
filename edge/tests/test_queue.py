from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from hispanshield_edge.queue import (
    DurableQueue,
    QueueCorruptionError,
    QueueError,
)


def test_enqueue_assigns_monotonic_sequences(tmp_path: Path):
    queue = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        sequences = [queue.enqueue("json", [{"n": index}]) for index in range(5)]
        assert sequences == [1, 2, 3, 4, 5]
        pending = queue.pending(10)
        assert [item.sequence for item in pending] == [1, 2, 3, 4, 5]
        assert pending[2].events == [{"n": 2}]
        assert pending[2].kind == "json"
        assert queue.next_sequence() == 6
    finally:
        queue.close()


def test_queue_survives_restart_without_reusing_sequences(tmp_path: Path):
    path = tmp_path / "queue.sqlite3"
    first = DurableQueue(path)
    first.enqueue("network", [{"event_uid": "a"}])
    first.mark_sent(1, 1)
    first.close()

    second = DurableQueue(path)
    try:
        assert second.pending(10) == []
        assert second.cursor() == 1
        assert second.enqueue("ot", [{"event_uid": "b"}]) == 2
        assert [item.sequence for item in second.pending(10)] == [2]
    finally:
        second.close()


def test_pending_is_oldest_first_and_bounded(tmp_path: Path):
    queue = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        for index in range(10):
            queue.enqueue("iot", [{"index": index}])
        pending = queue.pending(3)
        assert [item.sequence for item in pending] == [1, 2, 3]
        assert queue.stats()["pending_envelopes"] == 10
    finally:
        queue.close()


def test_mark_sent_persists_cursor_monotonically_and_frees_envelope(tmp_path: Path):
    queue = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        sequence = queue.enqueue("json", [{"x": 1}])
        assert queue.mark_sent(sequence, 7) is True
        assert queue.cursor() == 7
        assert queue.pending(1) == []
        second = queue.enqueue("json", [{"x": 2}])
        queue.mark_sent(second, 3)
        assert queue.cursor() == 7
        assert queue.mark_sent(sequence, 1) is False
    finally:
        queue.close()


def test_mark_failed_counts_attempts_and_bounds_error(tmp_path: Path):
    queue = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        sequence = queue.enqueue("json", [{"x": 1}])
        assert queue.mark_failed(sequence, "boom") == 1
        assert queue.mark_failed(sequence, "x" * 2000) == 2
        envelope = queue.pending(1)[0]
        assert envelope.attempts == 2
        assert envelope.last_error is not None
        assert len(envelope.last_error) == 500
        assert queue.stats()["max_attempts"] == 2
    finally:
        queue.close()


def test_trim_drops_oldest_unsent_only_and_logs(tmp_path: Path, caplog):
    queue = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        queue.enqueue("json", [{"old": 1}])
        queue.mark_sent(1, 1)
        for index in range(5):
            queue.enqueue("json", [{"new": index}])
        caplog.set_level("ERROR")
        dropped = queue.trim(3)
        assert dropped == 2
        assert [item.sequence for item in queue.pending(10)] == [4, 5, 6]
        assert "dropped_oldest_unsent_events=2" in caplog.text
        assert queue.trim(10) == 0
    finally:
        queue.close()


def test_trim_limits_events_not_envelopes(tmp_path: Path, caplog):
    queue = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        for batch in range(3):
            queue.enqueue("json", [{"batch": batch, "n": index} for index in range(10)])
        caplog.set_level("ERROR")
        assert queue.stats()["pending_events"] == 30
        dropped = queue.trim(15)
        assert dropped == 20
        assert [item.sequence for item in queue.pending(10)] == [3]
        assert queue.stats()["pending_events"] == 10
        assert "dropped_envelopes=2" in caplog.text
    finally:
        queue.close()


def test_concurrent_enqueue_from_two_connections_is_unique(tmp_path: Path):
    path = tmp_path / "queue.sqlite3"
    first = DurableQueue(path)
    second = DurableQueue(path)
    errors: list[BaseException] = []

    def worker(queue: DurableQueue, name: str) -> None:
        try:
            for index in range(100):
                queue.enqueue("json", [{"worker": name, "index": index}])
        except BaseException as exc:  # noqa: BLE001 - surfaced by assertion
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(first, "a")),
        threading.Thread(target=worker, args=(second, "b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    try:
        assert errors == []
        pending = first.pending(300)
        sequences = [item.sequence for item in pending]
        assert sequences == list(range(1, 201))
        assert first.next_sequence() == 201
    finally:
        first.close()
        second.close()


def test_drop_is_explicit_and_reported(tmp_path: Path):
    queue = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        sequence = queue.enqueue("json", [{"x": 1}])
        assert queue.drop(sequence) is True
        assert queue.drop(sequence) is False
        assert queue.pending(1) == []
    finally:
        queue.close()


def test_invalid_batch_rejected_before_write(tmp_path: Path):
    queue = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        with pytest.raises(QueueError):
            queue.enqueue("unknown", [{"x": 1}])
        with pytest.raises(QueueError):
            queue.enqueue("json", [])
        with pytest.raises(QueueError):
            queue.enqueue("json", [{"x": 1}] * 501)
        with pytest.raises(QueueError):
            queue.enqueue("json", ["not-an-object"])
        assert queue.stats()["pending_envelopes"] == 0
    finally:
        queue.close()


def test_corrupt_payload_is_detected_not_silently_sent(tmp_path: Path):
    path = tmp_path / "queue.sqlite3"
    queue = DurableQueue(path)
    sequence = queue.enqueue("json", [{"x": 1}])
    queue.close()
    raw = sqlite3.connect(path)
    try:
        raw.execute("UPDATE envelope SET payload_json='{broken' WHERE sequence=?", (sequence,))
        raw.commit()
    finally:
        raw.close()
    reopened = DurableQueue(path)
    try:
        with pytest.raises(QueueCorruptionError):
            reopened.pending(1)
    finally:
        reopened.close()


def test_queue_file_is_private(tmp_path: Path):
    import stat

    queue = DurableQueue(tmp_path / "private.sqlite3")
    try:
        assert stat.S_IMODE((tmp_path / "private.sqlite3").stat().st_mode) == 0o600
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    finally:
        queue.close()


def test_stats_report_age_and_bytes(tmp_path: Path):
    queue = DurableQueue(tmp_path / "queue.sqlite3")
    try:
        queue.enqueue("json", [{"payload": "x" * 500}])
        time.sleep(0.01)
        stats = queue.stats()
        assert stats["pending_envelopes"] == 1
        assert stats["pending_bytes"] > 500
        assert stats["oldest_age_s"] > 0
        assert stats["cursor"] == 0
        assert stats["blocking_error"] is None
        assert stats["path"].endswith("queue.sqlite3")
    finally:
        queue.close()
