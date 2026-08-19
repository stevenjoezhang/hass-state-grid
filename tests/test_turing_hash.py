"""Tests for the clean-room Python port of the Turing feature hash."""

import pytest

from custom_components.state_grid.turing.device_token import generate_device_token
from custom_components.state_grid.turing.feature_profile import StableProfile
from custom_components.state_grid.turing.hash_python import (
    build_feature_hash_buffer,
    generate_feature_hash_tags,
    turing_hash64,
)


def test_native_feature_hash_vector() -> None:
    """Match a buffer and result captured at native sub_40f154."""
    features = {205: "A", 207: "B", 303: "C", 308: "D", 309: "E"}

    assert build_feature_hash_buffer(features, 1_750_000_000_000) == (b"ABCDE72347517")
    assert generate_feature_hash_tags(features, 1_750_000_000_000) == (
        "01707628991401630d",
        "707628991401630d",
    )


def test_feature_values_follow_integer_key_order_and_utf8() -> None:
    features = {309: "末", 1: "first", 205: "", 207: "中"}

    assert build_feature_hash_buffer(features, 0) == "first中末26".encode()


@pytest.mark.parametrize(
    ("timestamp_ms", "states"),
    [
        (0, ("26", "a2")),
        (1, ("29", "ac")),
        (1_750_000_000_000, ("7234", "7517")),
    ],
)
def test_lcg_vectors(timestamp_ms: int, states: tuple[str, str]) -> None:
    features = {1: "", 2: "", 3: "", 4: "", 5: ""}

    assert build_feature_hash_buffer(features, timestamp_ms) == "".join(states).encode()


def test_hash64_known_native_vector() -> None:
    assert turing_hash64(b"ABCDE72347517") == 0x707628991401630D


def test_negative_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        build_feature_hash_buffer({1: "value"}, -1)


def test_complete_token_generation_needs_no_native_runtime() -> None:
    profile = StableProfile(bytes(range(32)))

    generated = generate_device_token(profile, timestamp_ms=1_750_000_000_000)

    assert generated.token.startswith("v3:")
    assert generated.token_time == "1750000000"
    assert generated.feature_count == 62
    assert generated.nested_feature_count > 0
