"""Unit tests for the deterministic autonomy guardrail primitives.

These tests never touch the database: they pin the strict parsing of the
``Policy.definition`` guardrail keys and the UTC freeze-window arithmetic that
the broker relies on before any side effect.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.services.policy_engine import (
    BLAST_RADIUS_BY_ACTION,
    DEFAULT_MAX_ACTIONS_PER_DAY,
    DEFAULT_MAX_ACTIONS_PER_HOUR,
    DEFAULT_MAX_BLAST_RADIUS,
    FreezeWindow,
    GuardrailLimits,
    PolicyDefinitionError,
    _in_freeze_window,
    parse_guardrail_limits,
)


def _utc(year: int, month: int, day: int, hour: int, minute: int) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def test_defaults_are_safe_and_fully_populated() -> None:
    limits = parse_guardrail_limits({})

    assert limits.max_actions_per_hour == DEFAULT_MAX_ACTIONS_PER_HOUR
    assert limits.max_actions_per_day == DEFAULT_MAX_ACTIONS_PER_DAY
    assert limits.cooldown_seconds == 0
    assert limits.change_freeze_windows == ()
    assert limits.max_blast_radius == DEFAULT_MAX_BLAST_RADIUS
    assert limits.blast_radius == {}
    assert limits.denied_target_kinds == frozenset()
    assert limits.allowed_target_kinds == frozenset()
    assert limits.blast_radius_for("configuration.restore") == 5


def test_declared_limits_are_parsed_and_normalised() -> None:
    limits = parse_guardrail_limits(
        {
            "max_actions_per_hour": 3,
            "max_actions_per_day": 10,
            "cooldown_seconds": 90,
            "max_blast_radius": 3,
            "blast_radius": {"session.revoke": 1, "ip.block": 3},
            "denied_target_kinds": ["ot", "iot"],
            "allowed_target_kinds": ["identity", "ip"],
            "change_freeze_windows": [
                {"start": "22:00", "end": "02:00", "days": [0, 4, 6]},
                {"start": "12:00", "end": "13:30"},
            ],
        }
    )

    assert (limits.max_actions_per_hour, limits.max_actions_per_day, limits.cooldown_seconds) == (3, 10, 90)
    assert limits.max_blast_radius == 3
    assert limits.blast_radius_for("session.revoke") == 1
    assert limits.blast_radius_for("ip.block") == 3
    assert limits.blast_radius_for("identity.disable") == BLAST_RADIUS_BY_ACTION["identity.disable"]
    assert limits.denied_target_kinds == frozenset({"ot", "iot"})
    assert limits.allowed_target_kinds == frozenset({"identity", "ip"})
    assert [window.as_dict() for window in limits.change_freeze_windows] == [
        {"start": "22:00", "end": "02:00", "days": [0, 4, 6]},
        {"start": "12:00", "end": "13:30", "days": None},
    ]


@pytest.mark.parametrize(
    ("definition", "needle"),
    [
        ({"max_actions_per_hour": -1}, "max_actions_per_hour"),
        ({"max_actions_per_hour": "60"}, "max_actions_per_hour"),
        ({"max_actions_per_day": True}, "max_actions_per_day"),
        ({"cooldown_seconds": 1.5}, "cooldown_seconds"),
        ({"max_blast_radius": 0}, "max_blast_radius"),
        ({"max_blast_radius": 6}, "max_blast_radius"),
        ({"blast_radius": {"not.an.action": 2}}, "unknown action"),
        ({"blast_radius": {"ip.block": 0}}, "ip.block"),
        ({"blast_radius": {"ip.block": "3"}}, "ip.block"),
        ({"denied_target_kinds": "ot"}, "denied_target_kinds"),
        ({"denied_target_kinds": ["ot", 7]}, "denied_target_kinds"),
        ({"allowed_target_kinds": [""]}, "allowed_target_kinds"),
        ({"change_freeze_windows": {"start": "00:00", "end": "01:00"}}, "change_freeze_windows"),
        ({"change_freeze_windows": [{"start": "24:00", "end": "01:00"}]}, "HH:MM"),
        ({"change_freeze_windows": [{"start": "00:00"}]}, "start/end"),
        ({"change_freeze_windows": [{"start": "00:00", "end": "01:00", "days": [0, 7]}]}, "days"),
        ({"change_freeze_windows": [{"start": "00:00", "end": "01:00", "days": ["mon"]}]}, "days"),
        ({"change_freeze_windows": ["00:00-01:00"]}, "must be an object"),
    ],
)
def test_malformed_guardrails_are_rejected(definition: dict, needle: str) -> None:
    with pytest.raises(PolicyDefinitionError) as exc:
        parse_guardrail_limits(definition)

    assert needle in str(exc.value)


def test_non_object_definition_is_rejected() -> None:
    with pytest.raises(PolicyDefinitionError):
        parse_guardrail_limits(["not", "an", "object"])


def test_full_day_window_when_start_equals_end() -> None:
    window = FreezeWindow(0, 0)
    assert window.contains(_utc(2026, 1, 5, 0, 0))
    assert window.contains(_utc(2026, 1, 5, 23, 59))


def test_window_boundaries_are_start_inclusive_end_exclusive() -> None:
    window = FreezeWindow(9 * 60, 17 * 60)
    assert not window.contains(_utc(2026, 1, 5, 8, 59))
    assert window.contains(_utc(2026, 1, 5, 9, 0))
    assert window.contains(_utc(2026, 1, 5, 16, 59))
    assert not window.contains(_utc(2026, 1, 5, 17, 0))


def test_window_wraps_past_midnight() -> None:
    window = FreezeWindow(22 * 60, 2 * 60)
    assert window.contains(_utc(2026, 1, 5, 23, 30))
    assert window.contains(_utc(2026, 1, 5, 0, 30))
    assert window.contains(_utc(2026, 1, 5, 1, 59))
    assert not window.contains(_utc(2026, 1, 5, 12, 0))
    assert not window.contains(_utc(2026, 1, 5, 2, 0))


def test_window_day_filter_uses_iso_weekday() -> None:
    # 2026-01-05 is a Monday (weekday 0); 2026-01-06 is Tuesday (weekday 1).
    window = FreezeWindow(0, 0, frozenset({0}))
    assert window.contains(_utc(2026, 1, 5, 12, 0))
    assert not window.contains(_utc(2026, 1, 6, 12, 0))


def test_in_freeze_window_returns_the_matching_window() -> None:
    first = FreezeWindow(0, 60)
    second = FreezeWindow(23 * 60, 60)
    assert _in_freeze_window(_utc(2026, 1, 5, 0, 30), [first, second]) is first
    assert _in_freeze_window(_utc(2026, 1, 5, 23, 30), [first, second]) is second
    assert _in_freeze_window(_utc(2026, 1, 5, 12, 0), [first, second]) is None


def test_naive_datetimes_are_interpreted_as_utc() -> None:
    window = FreezeWindow(9 * 60, 10 * 60)
    assert window.contains(datetime(2026, 1, 5, 9, 30))  # noqa: DTZ001 - explicit naive-UTC contract


def test_guardrail_limits_can_be_built_directly_for_helpers() -> None:
    limits = GuardrailLimits(max_blast_radius=1)
    assert limits.blast_radius_for("investigation.enrich") == 1
    assert limits.blast_radius_for("configuration.restore") == 5
