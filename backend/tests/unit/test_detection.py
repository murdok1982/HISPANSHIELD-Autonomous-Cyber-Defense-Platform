"""Detection DSL validation, evaluation and threshold dedupe."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.db import utcnow
from app.models.events import Alert, DetectionRule, SecurityEvent
from app.services.detection import (
    DefinitionError,
    evaluate_rule,
    run_detection,
    validate_definition,
)


def _event(org_id, **overrides):
    values = {
        "org_id": org_id,
        "event_uid": str(uuid.uuid4()),
        "occurred_at": utcnow(),
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "severity_id": 3,
        "message": "generic event",
        "raw": {},
        "normalized": {"extra": {}},
        "raw_format": "json",
        "schema_version": "1.1.0",
        "ioc_matches": [],
        "mitre_techniques": [],
        "is_demo": False,
    }
    values.update(overrides)
    return SecurityEvent(**values)


def _rule(org_id, definition, **overrides):
    values = {
        "org_id": org_id,
        "name": f"rule-{uuid.uuid4().hex[:8]}",
        "severity": "high",
        "status": "production",
        "enabled": True,
        "version": 1,
        "logsource": {},
        "definition": definition,
        "mitre": ["T1110"],
        "tags": ["test"],
        "created_by": "tests",
    }
    values.update(overrides)
    return DetectionRule(**values)


def test_validate_definition_accepts_full_dsl():
    validate_definition(
        {
            "selection": {
                "user_name": "root",
                "dst_port": [22, 3389, {"gte": 8000}],
                "message": {"regex": "(?i)failed login"},
                "ioc_matches": {"exists": True},
            },
            "condition": "or",
            "threshold": {"count": 5, "group_by": ["src_ip"], "window_seconds": 300},
            "timeframe_seconds": 300,
        }
    )


def test_validate_definition_rejects_unknown_key_and_bad_condition():
    with pytest.raises(DefinitionError) as exc:
        validate_definition({"selection": {"message": "x"}, "aggregation": "count"})
    assert any("Unknown keys" in item["message"] for item in exc.value.details)

    with pytest.raises(DefinitionError) as exc:
        validate_definition({"selection": {"message": "x"}, "condition": "xor"})
    assert any(item["path"] == "definition.condition" for item in exc.value.details)


def test_validate_definition_rejects_catastrophic_regex():
    with pytest.raises(DefinitionError) as exc:
        validate_definition({"selection": {"message": {"regex": "(a+)+$"}}})
    assert any("nested quantifier" in item["message"] for item in exc.value.details)

    with pytest.raises(DefinitionError) as exc:
        validate_definition({"selection": {"message": {"regex": "(a|aa)+$"}}})
    assert any("nested quantifier" in item["message"] for item in exc.value.details)

    with pytest.raises(DefinitionError) as exc:
        validate_definition({"selection": {"message": {"regex": "x" * 201}}})
    assert any("1..200" in item["message"] for item in exc.value.details)


def test_evaluate_rule_scalar_list_and_contains():
    event = {"user_name": "root", "src_ip": "1.2.3.4", "message": "Failed login for root"}
    assert evaluate_rule({"selection": {"user_name": "ROOT"}}, event).matched
    assert evaluate_rule({"selection": {"src_ip": ["8.8.8.8", "1.2.3.4"]}}, event).matched
    assert evaluate_rule({"selection": {"message": {"contains": "failed login"}}}, event).matched
    assert not evaluate_rule({"selection": {"message": {"contains": "success"}}}, event).matched


def test_evaluate_rule_condition_or_and_regex():
    event = {"user_name": "bob", "message": "sudo: session opened for root"}
    definition = {
        "selection": {"user_name": "alice", "message": {"regex": r"sudo.*root"}},
        "condition": "or",
    }
    result = evaluate_rule(definition, event)
    assert result.matched
    assert "message" in result.matched_fields
    assert "0/0" not in result.explanation


def test_evaluate_rule_known_bad_matcher():
    event = {
        "file_hash_sha256": "a" * 64,
        "ioc_matches": [{"indicator_type": "sha256", "value": "a" * 64}],
    }
    definition = {
        "selection": {"file_hash_sha256": {"exists": True}, "ioc_matches": {"known_bad": "sha256"}},
        "condition": "and",
    }
    assert evaluate_rule(definition, event).matched

    event["ioc_matches"] = [{"indicator_type": "domain", "value": "evil.example"}]
    assert not evaluate_rule(definition, event).matched


def test_threshold_rule_creates_one_deduped_alert(db, seeded):
    org = seeded["org"]
    rule = _rule(
        org.id,
        {
            "selection": {"message": {"contains": "failed login"}},
            "condition": "and",
            "threshold": {"count": 3, "group_by": ["src_ip"], "window_seconds": 300},
        },
    )
    db.add(rule)
    events = [_event(org.id, message="failed login for bob", src_ip="6.6.6.6", severity_id=4) for _ in range(3)]
    db.add_all(events)
    db.commit()

    outcome = run_detection(db, org_id=org.id, events=events)
    db.commit()

    assert outcome.alerts_created == 1
    alerts = list(db.execute(select(Alert).where(Alert.org_id == org.id)).scalars())
    assert len(alerts) == 1
    assert alerts[0].count == 3
    assert len(alerts[0].event_ids) == 3
    assert alerts[0].evidence["observed"] == 3
    assert alerts[0].dedupe_key is not None


def test_dedupe_window_expiry_creates_a_new_alert(db, seeded):
    org = seeded["org"]
    rule = _rule(
        org.id,
        {
            "selection": {"message": {"contains": "failed login"}},
            "threshold": {"count": 2, "group_by": ["src_ip"], "window_seconds": 300},
        },
    )
    db.add(rule)
    first = [_event(org.id, message="failed login", src_ip="7.7.7.7") for _ in range(2)]
    db.add_all(first)
    db.commit()
    run_detection(db, org_id=org.id, events=first)
    db.commit()
    alert = db.execute(select(Alert).where(Alert.org_id == org.id)).scalar_one()
    assert alert.count == 2

    alert.last_seen = utcnow() - timedelta(minutes=11)
    db.add(alert)
    later = _event(org.id, message="failed login", src_ip="7.7.7.7")
    db.add(later)
    db.commit()
    run_detection(db, org_id=org.id, events=[later])
    db.commit()

    alerts = list(db.execute(select(Alert).where(Alert.org_id == org.id)).scalars())
    assert len(alerts) == 2


def test_disabled_rule_is_not_evaluated(db, seeded):
    org = seeded["org"]
    rule = _rule(
        org.id,
        {"selection": {"message": {"contains": "failed login"}}},
        enabled=False,
    )
    db.add(rule)
    event = _event(org.id, message="failed login")
    db.add(event)
    db.commit()

    outcome = run_detection(db, org_id=org.id, events=[event])
    db.commit()
    assert outcome.alerts_created == 0
    assert db.execute(select(Alert).where(Alert.org_id == org.id)).scalar_one_or_none() is None


def test_invalid_persisted_rule_is_skipped_without_breaking_ingest(db, seeded):
    org = seeded["org"]
    rule = _rule(org.id, {"selection": {}})
    db.add(rule)
    event = _event(org.id, message="anything")
    db.add(event)
    db.commit()

    outcome = run_detection(db, org_id=org.id, events=[event])
    assert outcome.alerts_created == 0
    assert any(item["error"] == "invalid_definition" for item in outcome.errors)


def test_global_rule_applies_to_organization(db, seeded):
    org = seeded["org"]
    global_rule = _rule(
        None,
        {"selection": {"message": {"regex": "(?i)privilege escalation"}}},
        name="global-privilege",
    )
    db.add(global_rule)
    event = _event(org.id, message="Privilege escalation detected")
    db.add(event)
    db.commit()

    outcome = run_detection(db, org_id=org.id, events=[event])
    db.commit()
    assert outcome.alerts_created == 1
    alert = db.execute(select(Alert).where(Alert.org_id == org.id)).scalar_one()
    assert alert.rule_id == global_rule.id
    assert alert.severity == "high"


def test_non_threshold_rule_dedupes_within_window(db, seeded):
    org = seeded["org"]
    rule = _rule(org.id, {"selection": {"message": {"contains": "malware"}}})
    db.add(rule)
    first = _event(org.id, message="malware found", src_ip="1.1.1.1")
    second = _event(org.id, message="malware found", src_ip="1.1.1.1")
    db.add_all([first, second])
    db.commit()

    outcome = run_detection(db, org_id=org.id, events=[first, second])
    db.commit()
    assert outcome.alerts_created == 1
    assert outcome.alerts_updated == 1
    alert = db.execute(select(Alert).where(Alert.org_id == org.id)).scalar_one()
    assert alert.count == 2
    assert len(alert.event_ids) == 2
