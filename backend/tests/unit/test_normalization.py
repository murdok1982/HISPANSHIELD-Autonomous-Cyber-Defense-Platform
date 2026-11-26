"""OCSF normalization: one test per supported wire format plus malformed input."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime

import pytest

from app.services.normalization import ParseError, parse_payload
from app.services.normalization.ocsf import (
    make_event,
    parse_timestamp,
    severity_from_cef,
    severity_from_syslog,
    severity_to_id,
    status_from_value,
)
from app.workers.syslog_receiver import SourceBinding, SyslogReceiver


def _one(body: bytes | str, content_type: str | None = None, parser: str = "auto"):
    raw = body.encode() if isinstance(body, str) else body
    events = parse_payload(raw, content_type=content_type, parser=parser)
    assert len(events) == 1
    return events[0]


def test_json_maps_ocsf_fields_and_preserves_unknown():
    event = _one(
        json.dumps(
            {
                "timestamp": "2026-01-02T03:04:05Z",
                "severity": "high",
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.5",
                "src_port": 40000,
                "dst_port": 443,
                "protocol": "tcp",
                "user_name": "alice",
                "host_name": "web-01",
                "message": "connection to malicious host",
                "vendor_specific": {"region": "eu-west", "tags": ["a", "b"]},
            }
        ),
        "application/json",
    )
    assert event.class_uid == 4001
    assert event.class_name == "Network Activity"
    assert event.category_uid == 4
    assert event.severity_id == 4
    assert event.src_ip == "1.2.3.4"
    assert event.src_port == 40000
    assert event.dst_port == 443
    assert event.protocol == "TCP"
    assert event.user_name == "alice"
    assert event.host_name == "web-01"
    assert event.occurred_at == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert event.normalized["metadata"]["version"] == "1.1.0"
    assert event.normalized["unmapped"]["vendor_specific.region"] == "eu-west"
    assert event.normalized["unmapped"]["vendor_specific.tags[0]"] == "a"


def test_json_nested_aliases_and_raw_retention():
    document = {
        "event": {
            "source": {"ip": "8.8.8.8"},
            "destination": {"ip": "9.9.9.9"},
        },
        "actor": {"user": {"name": "bob"}},
        "message": "nested aliases",
        "@timestamp": "2026-02-03T00:00:00+02:00",
        "unknown": {"deep": {"value": 42}},
    }
    event = _one(json.dumps(document))
    assert event.src_ip == "8.8.8.8"
    assert event.dst_ip == "9.9.9.9"
    assert event.user_name == "bob"
    assert event.occurred_at == datetime(2026, 2, 2, 22, 0, 0, tzinfo=UTC)
    assert event.raw["unknown"]["deep"]["value"] == 42
    assert event.normalized["unmapped"]["unknown.deep.value"] == 42


def test_json_array_and_ndjson_payloads():
    events = parse_payload(
        json.dumps([{"message": "one"}, {"message": "two"}]).encode(),
        content_type="application/json",
    )
    assert [event.message for event in events] == ["one", "two"]

    ndjson = b'{"message":"alpha"}\n{"message":"beta"}\n'
    events = parse_payload(ndjson, content_type="application/x-ndjson")
    assert [event.message for event in events] == ["alpha", "beta"]


def test_json_malformed_is_rejected():
    with pytest.raises(ParseError) as exc:
        parse_payload(b'{"message": ', content_type="application/json")
    assert exc.value.code == "malformed_json"


def test_json_array_of_scalars_is_rejected():
    with pytest.raises(ParseError) as exc:
        parse_payload(b"[1,2,3]", content_type="application/json")
    assert exc.value.code == "malformed_json"


def test_cef_maps_header_extension_and_unmapped():
    line = (
        "CEF:0|ACME|EDR|1.2|4001|Failed login|9|"
        "src=1.2.3.4 dst=10.0.0.8 spt=5555 dpt=443 proto=TCP suser=root "
        "dvc=endpoint-7 msg=Failed login for root request=https://evil.example/login "
        "rt=1767225600000 vendorKey=keepme"
    )
    event = _one(line, "text/cef")
    assert event.raw_format == "cef"
    assert event.severity_id == 4
    assert event.src_ip == "1.2.3.4"
    assert event.dst_ip == "10.0.0.8"
    assert event.src_port == 5555
    assert event.dst_port == 443
    assert event.user_name == "root"
    assert event.host_name == "endpoint-7"
    assert event.url == "https://evil.example/login"
    assert event.domain == "evil.example"
    assert event.class_uid == 3002
    assert event.occurred_at.year == 2026
    assert event.normalized["unmapped"]["vendorKey"] == "keepme"
    assert event.raw["header"]["signature_id"] == "4001"


def test_cef_malformed_is_rejected():
    with pytest.raises(ParseError) as exc:
        parse_payload(b"CEF:0|only|three", content_type="text/cef")
    assert exc.value.code == "malformed_cef"


def test_leef_10_maps_attributes():
    line = "LEEF:1.0|IBM|QRadar|1.0|42|src=1.2.3.4\tdst=5.6.7.8\tspt=1234\tdpt=22\tsev=9\tmsg=SSH attack\turl=https://bad.example/x\tfoo=bar"
    event = _one(line, "text/leef")
    assert event.raw_format == "leef"
    assert event.severity_id == 4
    assert event.src_ip == "1.2.3.4"
    assert event.dst_ip == "5.6.7.8"
    assert event.src_port == 1234
    assert event.dst_port == 22
    assert event.url == "https://bad.example/x"
    assert event.normalized["unmapped"]["foo"] == "bar"


def test_leef_20_custom_delimiter():
    line = "LEEF:2.0|Vendor|Product|2.0|99|^userName=eve^src=6.6.6.6^sev=3^cat=Audit^msg=Login"
    event = _one(line, "text/leef")
    assert event.user_name == "eve"
    assert event.src_ip == "6.6.6.6"
    assert event.severity_id == 2
    assert event.normalized["extra"]["category"] == "Audit"


def test_leef_malformed_is_rejected():
    with pytest.raises(ParseError) as exc:
        parse_payload(b"LEEF:1.0|vendor|product", content_type="text/leef")
    assert exc.value.code == "malformed_leef"


def test_rfc5424_parses_structured_data_and_user():
    line = (
        "<34>1 2026-01-02T03:04:05.123Z edge-01 sshd 4312 ID47 "
        '[exampleSDID@32473 iut="3" user="alice"] Failed password for alice'
    )
    event = _one(line, "text/plain")
    assert event.raw_format == "syslog"
    assert event.severity_id == 4  # pri 34 -> severity 2 (critical)
    assert event.host_name == "edge-01"
    assert event.process_name == "sshd"
    assert event.user_name == "alice"
    assert event.message == "Failed password for alice"
    assert event.occurred_at == datetime(2026, 1, 2, 3, 4, 5, 123000, tzinfo=UTC)
    structured = event.normalized["extra"]["structured_data"]
    assert structured[0]["id"] == "exampleSDID@32473"
    assert event.normalized["extra"]["procid"] == "4312"


def test_rfc3164_parses_timestamp_host_and_tag():
    line = "<13>Mar  4 10:11:12 host-2 app[321]: Something happened"
    event = _one(line, "text/plain")
    assert event.host_name == "host-2"
    assert event.process_name == "app"
    assert event.message == "Something happened"
    assert event.severity_id == 1  # pri 13 -> severity 5 (notice)
    assert event.occurred_at.month == 3
    assert event.occurred_at.day == 4
    assert event.normalized["extra"]["rfc"] == "3164"
    assert event.normalized["extra"]["pid"] == 321


def test_syslog_embedded_cef_keeps_syslog_context():
    line = (
        "<134>Jan  1 00:00:00 fw-1 CEF:0|ACME|FW|1.0|7|Blocked|7|src=2.3.4.5 dst=10.1.1.1 dpt=443 msg=Blocked traffic"
    )
    event = _one(line, "text/plain")
    assert event.raw_format == "syslog"
    assert event.src_ip == "2.3.4.5"
    assert event.host_name == "fw-1"
    assert event.message == "Blocked traffic"
    assert event.raw["embedded_format"] == "cef"


def test_syslog_malformed_is_rejected():
    with pytest.raises(ParseError) as exc:
        parse_payload(b"<999>not a valid priority syslog", content_type="text/plain")
    assert exc.value.code == "malformed_syslog"

    with pytest.raises(ParseError) as exc:
        parse_payload(b"no priority at all", content_type="text/plain")
    assert exc.value.code == "malformed_syslog"


def test_otel_resource_logs():
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "host.name", "value": {"stringValue": "otel-host"}},
                        {"key": "service.name", "value": {"stringValue": "checkout"}},
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "demo"},
                        "logRecords": [
                            {
                                "timeUnixNano": "1767225600000000000",
                                "severityNumber": 17,
                                "severityText": "ERROR",
                                "body": {"stringValue": "payment failed"},
                                "attributes": [
                                    {
                                        "key": "network.peer.address",
                                        "value": {"stringValue": "203.0.113.9"},
                                    },
                                    {"key": "user.name", "value": {"stringValue": "carol"}},
                                    {"key": "custom.attr", "value": {"stringValue": "kept"}},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    event = _one(json.dumps(payload), "application/json")
    assert event.raw_format == "otel"
    assert event.severity_id == 4
    assert event.host_name == "otel-host"
    assert event.src_ip == "203.0.113.9"
    assert event.user_name == "carol"
    assert event.message == "payment failed"
    assert event.normalized["unmapped"]["attribute.custom.attr"] == "kept"
    assert event.normalized["extra"]["service_name"] == "checkout"


def test_otel_single_record_and_malformed():
    record = {
        "timestamp": "2026-05-06T07:08:09Z",
        "severityText": "WARN",
        "body": "slow query",
        "attributes": [{"key": "server.address", "value": {"stringValue": "api.example"}}],
    }
    event = _one(json.dumps(record), "application/json")
    assert event.severity_id == 3
    assert event.domain == "api.example"
    assert event.message == "slow query"

    with pytest.raises(ParseError) as exc:
        parse_payload(b'{"resourceLogs": "not-a-list"}', content_type="application/json")
    assert exc.value.code == "malformed_otel"

    with pytest.raises(ParseError) as exc:
        parse_payload(b'{"resourceLogs": []}', content_type="application/json")
    assert exc.value.code == "empty_payload"


def test_severity_and_status_mapping():
    assert severity_to_id("critical") == 5
    assert severity_to_id(6) == 5
    assert severity_to_id("informational") == 1
    assert severity_to_id("nonsense") == 0
    assert severity_from_cef(0) == 1
    assert severity_from_cef(4) == 2
    assert severity_from_cef(10) == 5
    assert severity_from_cef("Very-High") == 5
    assert severity_from_syslog(0) == 5
    assert severity_from_syslog(6) == 1
    assert status_from_value("failed") == 2
    assert status_from_value("success") == 1
    assert status_from_value("weird") is None


def test_control_characters_are_sanitized():
    event = _one(
        json.dumps({"message": "bad\x00message\x07with\x1fcontrols", "src_ip": "1.2.3.4"}),
        "application/json",
    )
    assert "\x00" not in event.message
    assert "\x07" not in event.message
    assert event.message == "bad message with controls"
    assert "\x00" not in json.dumps(event.normalized)


def test_make_event_drops_invalid_network_values():
    event = make_event(
        raw_format="json",
        raw={"src": "999.1.1.1"},
        message="invalid indicators",
        src_ip="999.1.1.1",
        dst_ip="not-an-ip",
        dst_port=70000,
        file_hash_sha256="not-a-hash",
    )
    assert event.src_ip is None
    assert event.dst_ip is None
    assert event.dst_port is None
    assert event.file_hash_sha256 is None
    assert event.raw["src"] == "999.1.1.1"


def test_timestamp_parsing_variants():
    fallback = datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_timestamp(1767225600, default=fallback) == datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_timestamp("1767225600000", default=fallback) == datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_timestamp("2026-01-01T00:00:00Z", default=fallback) == fallback
    assert parse_timestamp("garbage", default=fallback) == fallback


def test_syslog_udp_roundtrip_with_in_memory_sink():
    received = []
    binding = SourceBinding(org_id=uuid.uuid4(), source_id=uuid.uuid4(), name="udp-test")

    async def scenario():
        receiver = SyslogReceiver(
            resolver=lambda token: binding if token == "good-token-value" else None,
            sink=lambda _binding, _raw, event: received.append(event),
            host="127.0.0.1",
            udp_port=0,
            tcp_port=0,
            max_message_bytes=4096,
        )
        await receiver.start()
        assert receiver.bound_udp_port
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=("127.0.0.1", receiver.bound_udp_port),
        )
        transport.sendto(b"HS-TOKEN:good-token-value <34>1 2026-01-01T00:00:00Z edge app - - - failed login")
        for _ in range(100):
            if received:
                break
            await asyncio.sleep(0.02)
        transport.close()
        stats = receiver.stats()
        await receiver.stop()
        return stats

    stats = asyncio.run(scenario())
    assert len(received) == 1
    assert received[0].host_name == "edge"
    assert received[0].severity_id == 4
    assert stats["accepted"] == 1


def test_syslog_receiver_rejects_unknown_source_and_oversize():
    async def scenario():
        receiver = SyslogReceiver(
            resolver=lambda token: None,
            sink=lambda *_args: None,
            host="127.0.0.1",
            udp_port=0,
            tcp_port=0,
            max_message_bytes=512,
        )
        await receiver.start()
        no_token = await receiver.handle_message(b"<34>1 2026-01-01T00:00:00Z host app - - - msg")
        unknown = await receiver.handle_message(b"HS-TOKEN:unknown <34>1 2026-01-01T00:00:00Z h a - - - m")
        oversize = await receiver.handle_message(b"HS-TOKEN:unknown " + b"x" * 600)
        stats = receiver.stats()
        await receiver.stop()
        return no_token, unknown, oversize, stats

    no_token, unknown, oversize, stats = asyncio.run(scenario())
    assert no_token["rejected"] == 1
    assert unknown["rejected"] == 1
    assert oversize["rejected"] == 1
    assert stats["rejected_unknown_source"] == 2
    assert stats["rejected_oversize"] == 1
