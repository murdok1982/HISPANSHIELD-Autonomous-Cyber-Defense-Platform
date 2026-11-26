"""Unit tests for the bounded STIX 2.1 pattern parser."""

from __future__ import annotations

import pytest

from app.modules.threat_intel.stix import (
    StixError,
    confidence_to_severity,
    normalize_value,
    parse_bundle,
    parse_pattern,
)


def test_parse_ipv4_pattern() -> None:
    matches = parse_pattern("[ipv4-addr:value = '198.51.100.9']")
    assert [(item.indicator_type, item.value) for item in matches] == [("ip", "198.51.100.9")]


def test_parse_domain_url_and_file_hash_comparisons() -> None:
    pattern = (
        "[domain-name:value = 'Evil.Example.' OR url:value = 'https://evil.example/payload' "
        "OR file:hashes.'SHA-256' = 'ABCDEF" + "0" * 58 + "']"
    )
    matches = parse_pattern(pattern)
    assert ("domain", "evil.example") in [(item.indicator_type, item.value) for item in matches]
    assert ("url", "https://evil.example/payload") in [(item.indicator_type, item.value) for item in matches]
    assert ("sha256", "abcdef" + "0" * 58) in [(item.indicator_type, item.value) for item in matches]


def test_parse_email_and_ipv6() -> None:
    matches = parse_pattern("[email-addr:value = 'SOC@Example.EU' OR ipv6-addr:value = '2001:db8::1']")
    pairs = {(item.indicator_type, item.value) for item in matches}
    assert ("email", "soc@example.eu") in pairs
    assert ("ip", "2001:db8::1") in pairs


def test_pattern_length_is_bounded() -> None:
    with pytest.raises(StixError, match="2000"):
        parse_pattern("[domain-name:value = '" + ("a" * 2100) + "']")


def test_comparison_count_is_bounded() -> None:
    comparisons = " OR ".join(f"[ipv4-addr:value = '198.51.100.{index}']" for index in range(12))
    with pytest.raises(StixError, match="comparisons"):
        parse_pattern(comparisons)


def test_malformed_operand_is_rejected_not_guessed() -> None:
    with pytest.raises(StixError):
        parse_pattern("[domain-name:value = 'not a domain']")
    with pytest.raises(StixError):
        parse_pattern("[ipv4-addr:value = '999.1.1.1']")


def test_unsupported_pattern_is_rejected() -> None:
    with pytest.raises(StixError, match="no supported indicator"):
        parse_pattern("[x-custom-object:value = 'something']")
    with pytest.raises(StixError, match="bracketed"):
        parse_pattern("domain-name:value = 'example.com'")


def test_normalize_value_validation_and_canonicalization() -> None:
    assert normalize_value("domain", "  EVIL.Example.  ") == "evil.example"
    assert normalize_value("sha256", "A" * 64) == "a" * 64
    assert normalize_value("url", "https://example.com/a") == "https://example.com/a"
    with pytest.raises(StixError):
        normalize_value("url", "ftp://example.com/file")
    with pytest.raises(StixError):
        normalize_value("ip", "not-an-ip")
    with pytest.raises(StixError):
        normalize_value("domain", "bad\x00.example")
    with pytest.raises(StixError):
        normalize_value("digest", "whatever")


def test_bundle_parses_metadata_and_deduplicates() -> None:
    pattern = "[ipv4-addr:value = '203.0.113.5']"
    bundle = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": pattern,
                "confidence": 92,
                "labels": ["malicious-activity", "c2"],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-12-31T23:59:59Z",
                "name": "C2 node",
            },
            {
                "type": "indicator",
                "id": "indicator--2",
                "pattern": pattern,
                "confidence": 10,
            },
            {"type": "malware", "id": "malware--1", "name": "Example"},
        ],
    }
    records = parse_bundle(bundle)
    assert len(records) == 1
    record = records[0]
    assert record.indicator_type == "ip"
    assert record.value == "203.0.113.5"
    assert record.confidence == 92
    assert record.severity == "critical"
    assert record.valid_until is not None
    assert record.labels == ["malicious-activity", "c2"]


def test_bundle_rejects_invalid_documents() -> None:
    with pytest.raises(StixError, match="JSON object"):
        parse_bundle(["not", "a", "bundle"])
    with pytest.raises(StixError, match="not a STIX"):
        parse_bundle({"type": "report", "objects": []})
    with pytest.raises(StixError, match="objects array"):
        parse_bundle({"type": "bundle"})
    with pytest.raises(StixError, match="no importable indicator"):
        parse_bundle({"type": "bundle", "objects": [{"type": "malware"}]})


def test_bundle_indicator_limit_is_enforced() -> None:
    objects = [
        {"type": "indicator", "pattern": f"[ipv4-addr:value = '198.51.{index // 250}.{index % 250 + 1}']"}
        for index in range(1005)
    ]
    with pytest.raises(StixError):
        parse_bundle({"type": "bundle", "objects": objects})


def test_confidence_to_severity_thresholds() -> None:
    assert confidence_to_severity(95) == "critical"
    assert confidence_to_severity(75) == "high"
    assert confidence_to_severity(50) == "medium"
    assert confidence_to_severity(5) == "low"
