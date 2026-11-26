"""Unit tests for vendor payload normalization into OCSF events and indicators."""

from __future__ import annotations

from datetime import UTC

import pytest

from app.services.connectors.normalize import (
    bounded_items,
    dedupe_key,
    normalize_alert,
    normalize_elastic_signal,
    normalize_indicator,
    normalize_misp_attribute,
    normalize_opencti_indicator,
    normalize_sentinel_alert,
    normalize_suricata_event,
    normalize_wazuh_alert,
    normalize_zeek_event,
    parse_timestamp,
    sanitize_mapping,
    sanitize_text,
    severity_from_text,
    wazuh_severity,
)

WAZUH_ALERT = {
    "id": "1718000000.12345",
    "timestamp": "2024-06-10T10:15:30.000Z",
    "rule": {
        "id": "5710",
        "level": 10,
        "description": "Multiple failed logins followed by a successful login",
        "groups": ["authentication_failed", "sshd"],
        "mitre": {"id": ["T1110"], "technique": ["Brute Force"]},
    },
    "agent": {"id": "001", "name": "web-01", "ip": "192.0.2.10"},
    "data": {
        "srcip": "203.0.113.50",
        "dstip": "192.0.2.10",
        "srcport": "40022",
        "dstport": "22",
        "protocol": "tcp",
        "srcuser": "root",
        "sha256": "a" * 64,
        "url": "https://evil.example/login",
    },
    "full_log": "Failed password for root",
}


def test_wazuh_alert_maps_core_fields() -> None:
    event = normalize_wazuh_alert(WAZUH_ALERT, connector_name="wazuh-prod")
    assert event is not None
    assert event["event_uid"].startswith("wazuh:")
    assert event["occurred_at"].year == 2024
    assert event["severity_id"] == 4
    assert event["class_uid"] == 2004
    assert event["category_uid"] == 2
    assert event["src_ip"] == "203.0.113.50"
    assert event["dst_ip"] == "192.0.2.10"
    assert event["src_port"] == 40022
    assert event["dst_port"] == 22
    assert event["protocol"] == "tcp"
    assert event["host_name"] == "web-01"
    assert event["user_name"] == "root"
    assert event["file_hash_sha256"] == "a" * 64
    assert event["mitre_techniques"] == ["T1110"]
    assert event["source_connector"] == "wazuh-prod"
    assert event["raw"]["id"] == "1718000000.12345"
    assert len(event["dedupe_key"]) == 64


@pytest.mark.parametrize(
    ("level", "expected"),
    [(0, 1), (3, 2), (5, 3), (8, 4), (13, 5), ("critical", 5)],
)
def test_wazuh_severity_bands(level: object, expected: int) -> None:
    assert wazuh_severity(level) == expected


def test_elastic_signal_normalizes_nested_source() -> None:
    signal = {
        "_id": "signal-1",
        "_index": ".alerts-security.alerts-default",
        "_source": {
            "@timestamp": "2024-06-10T10:15:30Z",
            "kibana": {"alert": {"rule": {"name": "Suspicious PowerShell"}, "severity": "high"}},
            "signal": {"rule": {"rule_id": "rule-1", "severity": "high"}},
            "host": {"name": "win-01"},
            "user": {"name": "DOMAIN\\bob"},
            "process": {"name": "powershell.exe"},
            "source": {"ip": "198.51.100.7"},
            "destination": {"ip": "10.0.0.9", "port": 443},
            "network": {"transport": "tcp"},
            "file": {"hash": {"sha256": "b" * 64}},
            "url": {"full": "https://example.test/a"},
            "threat": {"technique": [{"id": "T1059.001"}]},
        },
    }
    event = normalize_elastic_signal(signal, connector_name="elastic")
    assert event is not None
    assert event["severity_id"] == 4
    assert event["host_name"] == "win-01"
    assert event["user_name"] == "DOMAIN\\bob"
    assert event["process_name"] == "powershell.exe"
    assert event["src_ip"] == "198.51.100.7"
    assert event["dst_port"] == 443
    assert event["url"] == "https://example.test/a"
    assert event["mitre_techniques"] == ["T1059.001"]
    assert event["normalized"]["vendor"] == "elastic"


def test_sentinel_alert_parses_entities_and_severity() -> None:
    row = {
        "TimeGenerated": "2024-06-10T10:15:30Z",
        "AlertName": "Impossible travel",
        "AlertSeverity": "Medium",
        "Description": "Sign-in from two continents",
        "CompromisedEntity": "alice@example.test",
        "SystemAlertId": "alert-42",
        "Tactics": "InitialAccess,CredentialAccess",
        "Techniques": "T1078,T1110",
        "Entities": '[{"Type": "account", "AccountName": "alice"}, {"Type": "ip", "Address": "203.0.113.66"}]',
    }
    event = normalize_sentinel_alert(row, connector_name="sentinel")
    assert event is not None
    assert event["severity_id"] == 3
    assert event["src_ip"] == "203.0.113.66"
    assert event["user_name"] == "alice"
    assert event["mitre_techniques"] == ["T1078", "T1110"]
    assert event["normalized"]["tactics"] == ["InitialAccess", "CredentialAccess"]


def test_suricata_alert_normalizes_network_activity() -> None:
    record = {
        "timestamp": "2024-06-10T10:15:30.123456+0000",
        "event_type": "alert",
        "flow_id": 90210,
        "src_ip": "203.0.113.9",
        "dest_ip": "192.0.2.44",
        "src_port": 51000,
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "signature": "ET SCAN SSH Brute Force",
            "severity": 1,
            "signature_id": 2001219,
            "metadata": {"mitre_technique_id": ["T1110"]},
        },
        "dns": {"rrname": "evil.example"},
    }
    event = normalize_suricata_event(record, connector_name="suricata")
    assert event is not None
    assert event["severity_id"] == 4
    assert event["class_uid"] == 4001
    assert event["category_uid"] == 4
    assert event["protocol"] == "TCP"
    assert event["domain"] == "evil.example"
    assert event["mitre_techniques"] == ["T1110"]


def test_zeek_notice_normalizes_and_maps_severity() -> None:
    record = {
        "ts": 1718014530.5,
        "_path": "notice",
        "uid": "C1z2",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 48000,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 53,
        "proto": "udp",
        "note": "DNS::Tunnel",
        "msg": "Abnormal DNS volume",
        "severity": "WARNING",
        "query": "chrome.cloud.test",
        "user": "svc",
    }
    event = normalize_zeek_event(record, connector_name="zeek")
    assert event is not None
    assert event["severity_id"] == 2
    assert event["src_ip"] == "10.0.0.5"
    assert event["dst_port"] == 53
    assert event["domain"] == "chrome.cloud.test"
    assert event["normalized"]["log"] == "notice"


def test_misp_attribute_maps_ip_and_hash_types() -> None:
    event_meta = {"uuid": "event-1", "info": "Phishing campaign", "threat_level_id": "1", "date": "2024-06-01"}
    ip_indicator = normalize_misp_attribute(
        {"Attribute": {"type": "ip-dst", "value": "198.51.100.4", "to_ids": True}, "Event": event_meta},
        connector_name="misp-prod",
    )
    assert ip_indicator is not None
    assert ip_indicator["indicator_type"] == "ip"
    assert ip_indicator["value"] == "198.51.100.4"
    assert ip_indicator["severity"] == "high"
    assert ip_indicator["confidence"] == 90
    assert ip_indicator["source"] == "misp-prod"
    assert ip_indicator["stix"]["type"] == "indicator"

    hash_indicator = normalize_misp_attribute(
        {"Attribute": {"type": "sha256", "value": "C" * 64, "comment": "dropper"}, "Event": {}}
    )
    assert hash_indicator is not None
    assert hash_indicator["indicator_type"] == "sha256"
    assert hash_indicator["value"] == "C" * 64
    assert hash_indicator["description"] == "dropper"


def test_misp_unsupported_type_is_skipped() -> None:
    assert normalize_misp_attribute({"Attribute": {"type": "vulnerability", "value": "CVE-2024-1"}}) is None


def test_opencti_indicator_parses_stix_patterns() -> None:
    ip_indicator = normalize_opencti_indicator(
        {
            "id": "indicator--1",
            "pattern": "[ipv4-addr:value = '198.51.100.9']",
            "pattern_type": "stix",
            "confidence": 85,
            "x_opencti_score": 90,
            "valid_from": "2024-06-01T00:00:00Z",
            "valid_until": "2024-12-01T00:00:00Z",
            "objectLabel": [{"value": "c2"}],
            "revoked": False,
        },
        connector_name="opencti",
    )
    assert ip_indicator is not None
    assert ip_indicator["indicator_type"] == "ip"
    assert ip_indicator["value"] == "198.51.100.9"
    assert ip_indicator["severity"] == "critical"
    assert ip_indicator["tags"] == ["c2"]
    assert ip_indicator["expires_at"] is not None

    hash_indicator = normalize_opencti_indicator(
        {"pattern": "[file:hashes.'SHA-256' = '" + "d" * 64 + "']", "x_opencti_score": 55}
    )
    assert hash_indicator is not None
    assert hash_indicator["indicator_type"] == "sha256"

    assert normalize_opencti_indicator({"pattern": "not-a-stix-pattern"}) is None


def test_sanitize_text_strips_control_chars_and_truncates() -> None:
    assert sanitize_text("  hello\x00\x07   world\n") == "hello world"
    assert sanitize_text("", limit=10) is None
    truncated = sanitize_text("x" * 500, limit=100)
    assert truncated is not None and len(truncated) == 100 and truncated.endswith("…")


def test_sanitize_mapping_bounds_depth_and_lists() -> None:
    payload = {"a": [{"b": "x" * 5000} for _ in range(100)], "c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}
    bounded = sanitize_mapping(payload)
    assert isinstance(bounded, dict)
    assert len(bounded["a"]) == 50
    assert len(bounded["a"][0]["b"]) <= 2000
    assert bounded["c"]["d"]["e"]["f"]["g"] == {"h": "[truncated]"}


def test_dedupe_key_is_stable_and_distinct() -> None:
    first = dedupe_key("wazuh", "rule-1", "2024-01-01T00:00:00")
    assert first == dedupe_key("wazuh", "rule-1", "2024-01-01T00:00:00")
    assert first != dedupe_key("wazuh", "rule-2", "2024-01-01T00:00:00")
    assert len(first) == 64


def test_bounded_items_filters_non_dicts_and_caps() -> None:
    items = [{"id": 1}, "bad", {"id": 2}, {"id": 3}]
    assert bounded_items(items, 2) == [{"id": 1}, {"id": 2}]
    assert bounded_items(items, 200) == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert bounded_items("not-a-list", 5) == []


@pytest.mark.parametrize(
    ("raw", "expected_year"),
    [
        ("2024-06-10T10:15:30Z", 2024),
        ("2024-06-10T10:15:30", 2024),
        (1718014530, 2024),
        (1718014530000, 2024),
    ],
)
def test_parse_timestamp_variants(raw: object, expected_year: int) -> None:
    parsed = parse_timestamp(raw)
    assert parsed.year == expected_year
    assert parsed.tzinfo == UTC


def test_normalize_alert_dispatch_and_unknown_type() -> None:
    assert normalize_alert("wazuh", WAZUH_ALERT) is not None
    assert normalize_alert("not_installed", WAZUH_ALERT) is None
    assert normalize_indicator("misp", {"Attribute": {"type": "domain", "value": "Evil.Example"}}) is not None


@pytest.mark.parametrize(
    ("text", "expected"),
    [("High", 4), ("information", 0), ("notice", 1), ("fatal", 6), (None, 0), ("7", 4)],
)
def test_severity_from_text(text: object, expected: int) -> None:
    assert severity_from_text(text) == expected


def test_malformed_records_return_none_or_safe_dict() -> None:
    assert normalize_wazuh_alert({}) is not None  # empty but structurally valid
    assert normalize_sentinel_alert({"Entities": "{not-json"}) is not None
    assert normalize_elastic_signal({"_source": {}}) is not None
    assert normalize_misp_attribute({"Attribute": {"type": "ip-dst", "value": ""}}) is None
