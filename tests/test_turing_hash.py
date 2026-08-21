"""Tests for the clean-room Python port of the Turing feature hash."""

import base64

import pytest

from custom_components.state_grid.turing.device_token import generate_device_token
from custom_components.state_grid.turing.feature_profile import (
    OFFICIAL_JAVA_KEYS,
    StableProfile,
)
from custom_components.state_grid.turing.hash_python import (
    build_feature_hash_buffer,
    generate_feature_hash_tags,
    turing_hash64,
)
from custom_components.state_grid.turing.profile_diagnostics import (
    FIELD_POLICY,
    build_profile_diagnostics,
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
    profile = StableProfile(bytes(range(32)), boot_epoch_ms=1_749_913_600_000)

    generated = generate_device_token(profile, timestamp_ms=1_750_000_000_000)
    packed = base64.b64decode(generated.token[3:])

    assert generated.token.startswith("v3:")
    assert generated.token_time == "1750000000"
    assert generated.feature_count == 62
    assert generated.nested_feature_count == 62
    assert generated.fallback_status_code == -22056
    assert 2800 <= len(generated.token) <= 3100
    assert 2100 <= len(packed) <= 2300


def test_native_reference_profile_has_stable_identity_and_dynamic_runtime() -> None:
    profile = StableProfile(bytes(range(32)), boot_epoch_ms=1_700_000_000_000)

    first = profile.native_feature_map(1_750_000_000_000)
    second = profile.native_feature_map(1_750_003_600_000)

    assert len(first) == 62
    assert set(first) == set(second)
    assert first[126] == second[126] == "1700000000000"
    assert first[16] == second[16]
    assert first[148] == second[148]
    assert first[34] != second[34]
    assert first[125] != second[125]


def test_java_map_matches_official_shape_and_native_aliases() -> None:
    profile = StableProfile(bytes(range(32)), boot_epoch_ms=1_700_000_000_000)
    timestamp = 1_750_000_000_000
    java = profile.feature_map(timestamp)
    native = profile.native_feature_map(timestamp)

    assert tuple(java) == OFFICIAL_JAVA_KEYS
    assert len(java) == FIELD_POLICY["coverage"]["java_fields"] == 52
    assert len(native) == FIELD_POLICY["coverage"]["native_fields"] == 62
    assert java[257] == native[107]
    assert java[267] == native[17]
    assert java[279] == native[120]
    assert java[281] == native[126]
    assert java[284] == native[146]
    assert java[285] == native[149]
    assert java[286] == native[150]
    assert java[287] == native[151]
    assert java[288] == native[152]
    assert java[2018] in native[17]
    assert java[257] == "com.sgcc.wsgw.cn_DAB5608ECD1ABEF80E5FA277CF3B8D50"


def test_policy_lifetimes_drive_stable_and_request_values() -> None:
    profile = StableProfile(bytes(range(32)), boot_epoch_ms=1_700_000_000_000)
    first = profile.feature_map(1_750_000_000_000)
    second = profile.feature_map(1_750_003_600_000)

    for key in (1, 257, 267, 279, 281, 2013, 2016, 2017, 2018):
        assert first[key] == second[key]
    for key in (4, 210, 303, 3004):
        assert first[key] != second[key]


def test_policy_diagnostic_json_is_complete_and_consistent() -> None:
    profile = StableProfile(bytes(range(32)), boot_epoch_ms=1_700_000_000_000)
    document = build_profile_diagnostics(
        profile,
        timestamp_ms=1_750_000_000_000,
        include_values=True,
    )

    assert document["summary"]["java_field_count"] == 52
    assert document["summary"]["native_field_count"] == 62
    assert document["summary"]["direct_field_count"] == 7
    assert document["summary"]["invariant_failures"] == 0
    assert document["summary"]["lifetime_unexpected_changes"] == 0
    assert 3700 <= document["summary"]["m90_length"] <= 4100
    assert len(document["java_fields"]) == 52
    assert len(document["native_fields"]) == 62
    assert all(check["pass"] for check in document["invariants"])
    assert document["lifetime_probe"]["java_changed_ids"] == [
        4,
        210,
        303,
        3004,
    ]
    assert document["lifetime_probe"]["native_changed_tags"] == [34, 125]
    assert document["lifetime_probe"]["direct_changed_tags"] == [3, 10, 12, 4]
