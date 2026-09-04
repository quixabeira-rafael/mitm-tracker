from __future__ import annotations

import random

import pytest

from mitm_tracker.delay import (
    MAX_DELAY_MS,
    DelayError,
    DelayProfile,
    parse_duration_ms,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", 0),
        ("800", 800),
        ("800ms", 800),
        (" 800 ms ", 800),
        ("800MS", 800),
        ("2s", 2000),
        ("1.5s", 1500),
        ("0.25s", 250),
        (750, 750),
        (750.4, 750),
    ],
)
def test_parse_duration_ms_accepts_supported_forms(value, expected: int) -> None:
    assert parse_duration_ms(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "abc", "-100", "-1s", "800m", "1,5s", "800 ms extra", True],
)
def test_parse_duration_ms_rejects_invalid(value) -> None:
    with pytest.raises(DelayError):
        parse_duration_ms(value)


def test_parse_duration_ms_rejects_above_cap() -> None:
    with pytest.raises(DelayError):
        parse_duration_ms(MAX_DELAY_MS + 1)


def test_profile_defaults_to_inactive() -> None:
    profile = DelayProfile()
    assert profile.active is False
    assert profile.next_delay_ms() == 0
    assert profile.describe() == "off"


def test_profile_parse_none_is_inactive() -> None:
    assert DelayProfile.parse(None, None) == DelayProfile()


def test_profile_parse_reads_units() -> None:
    profile = DelayProfile.parse("1.5s", "200ms")
    assert profile.base_ms == 1500
    assert profile.jitter_ms == 200


def test_profile_parse_rejects_jitter_without_base() -> None:
    with pytest.raises(DelayError):
        DelayProfile.parse(None, "200ms")


def test_fixed_delay_has_no_spread() -> None:
    profile = DelayProfile(base_ms=800)
    assert profile.min_ms == 800
    assert profile.max_ms == 800
    assert {profile.next_delay_ms() for _ in range(20)} == {800}


def test_jitter_stays_inside_the_window() -> None:
    profile = DelayProfile(base_ms=800, jitter_ms=200)
    assert (profile.min_ms, profile.max_ms) == (600, 1000)
    rng = random.Random(1234)
    draws = [profile.next_delay_ms(rng) for _ in range(500)]
    assert min(draws) >= 600
    assert max(draws) <= 1000
    assert len(set(draws)) > 1


def test_jitter_wider_than_base_clamps_at_zero() -> None:
    profile = DelayProfile(base_ms=100, jitter_ms=500)
    assert profile.min_ms == 0
    rng = random.Random(7)
    assert all(profile.next_delay_ms(rng) >= 0 for _ in range(100))


def test_jitter_max_clamps_at_the_cap() -> None:
    profile = DelayProfile(base_ms=MAX_DELAY_MS, jitter_ms=5_000)
    assert profile.max_ms == MAX_DELAY_MS


def test_describe_renders_window() -> None:
    assert DelayProfile(base_ms=800).describe() == "800ms"
    assert (
        DelayProfile(base_ms=800, jitter_ms=200).describe()
        == "800ms +/-200ms (600-1000ms)"
    )


def test_to_dict_shape() -> None:
    assert DelayProfile(base_ms=800, jitter_ms=200).to_dict() == {
        "delay_ms": 800,
        "delay_jitter_ms": 200,
    }
