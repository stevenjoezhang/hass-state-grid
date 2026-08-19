"""Build a pure-Python TuringFD V90 ``deviceTokenTX`` candidate."""

from __future__ import annotations

import json
import secrets
import string
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .feature_profile import StableProfile
from .hash_python import generate_feature_hash_tags
from .jce import encode_mode1, serialize_m90_full, serialize_turing_nested

CHANNEL = "10000191"
BUILD_MARKER = "77F2B17A00A92C71"
FALLBACK_STATUS_CODE = -10004
TOKEN_SCHEMA_VERSION = 4
PERFORMANCE_FEATURES = (
    22,
    100,
    101,
    102,
    103,
    104,
    105,
    106,
    115,
    116,
    107,
    113,
    114,
    117,
    44,
    17,
    118,
    120,
    122,
    126,
    24,
    140,
    138,
    145,
    146,
    149,
    150,
    151,
)

# Java Cantaloupe feature key -> nested tag written by 0x410734/0x4107cc.
NESTED_TAG_BY_FEATURE_KEY = {
    207: 28,
    252: 102,
    256: 106,
    268: 115,
    258: 113,
    259: 114,
    240: 44,
    210: 34,
    267: 17,
    257: 107,
    274: 47,
    276: 49,
    275: 48,
    2001: 200,
    269: 116,
    270: 117,
    273: 119,
    278: 50,
    266: 45,
    272: 118,
    279: 120,
    280: 122,
    281: 126,
    282: 138,
    2019: 133,
    2021: 140,
    283: 145,
    284: 146,
    2029: 147,
    2024: 147,
    271: 46,
    501: 136,
    2020: 143,
    2023: 144,
}


@dataclass(frozen=True)
class GeneratedDeviceToken:
    token: str
    token_time: str
    timestamp_ms: int
    profile_id: str
    feature_count: int
    nested_feature_count: int
    fallback_status_code: int

    def cache_document(self) -> dict[str, str | int]:
        return {
            "schema_version": TOKEN_SCHEMA_VERSION,
            "token": self.token,
            "token_time": self.token_time,
            "timestamp_ms": self.timestamp_ms,
            "profile_id": self.profile_id,
            "feature_count": self.feature_count,
            "nested_feature_count": self.nested_feature_count,
            "fallback_status_code": self.fallback_status_code,
        }


def _tail_map(value: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    for entry in value.split(","):
        if "_" not in entry:
            continue
        key, item = entry.split("_", 1)
        try:
            result.append((int(key), item))
        except ValueError:
            continue
    return result


def _mapped_nested_features(features: Mapping[int, str]) -> list[tuple[int, str]]:
    mapped: dict[int, str] = {}
    for source_key, nested_tag in NESTED_TAG_BY_FEATURE_KEY.items():
        value = features.get(source_key)
        if value not in (None, ""):
            mapped[nested_tag] = str(value)
    return sorted(mapped.items())


def _direct_values(
    features: Mapping[int, str], tag10: str, tag12: str
) -> list[tuple[int, str]]:
    direct: list[tuple[int, str]] = []
    for source_key, tag in ((303, 3), (308, 8), (309, 9), (4, 4)):
        value = features.get(source_key)
        if value not in (None, ""):
            direct.append((tag, str(value)))
    # sub_410e2c appends Process UID only when tag 3 exists.
    if features.get(303) and features.get(2018):
        direct.append((7, f"{features[303]}_{features[2018]}"))
    direct.extend(((10, tag10), (12, tag12)))
    return direct


def _fallback_nonce() -> str:
    alphabet = string.digits + string.ascii_lowercase + string.ascii_uppercase
    return "".join(secrets.choice(alphabet) for _ in range(32))


def _performance_context() -> str:
    return ",".join(f"{feature}_0" for feature in PERFORMANCE_FEATURES) + ",s9_0"


def generate_device_token(
    profile: StableProfile,
    *,
    timestamp_ms: int | None = None,
    network_host: str = "127.0.0.1",
    fallback_status_code: int = FALLBACK_STATUS_CODE,
) -> GeneratedDeviceToken:
    """Generate one fresh mode-1 candidate without Android or Frida."""
    timestamp_ms = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    identity = profile.identity()
    features = profile.feature_map(timestamp_ms)
    # Carambola places Cinterface.a() in Java map key "4".  Native 0x410518
    # consumes it inside the nested/direct feature object.
    features[4] = _performance_context()

    tag10, tag12 = generate_feature_hash_tags(features, timestamp_ms)

    nested_features = _mapped_nested_features(features)
    nested = serialize_turing_nested(
        timestamp_ms=timestamp_ms,
        metadata={0: 90, 1: "90", 2: BUILD_MARKER, 3: CHANNEL, 4: 2},
        feature_values=nested_features,
        network=("0", network_host),
        direct_values=_direct_values(features, tag10, tag12),
        type8_values={
            1: features.get(405, ""),
            2: features.get(402, ""),
            3: features.get(403, "0"),
            4: features.get(404, ""),
            5: features.get(401, ""),
            8: _tail_map(features.get(406, "")),
        },
    )
    m90 = serialize_m90_full(
        channel=identity.channel,
        brand=identity.brand,
        model=identity.model,
        timestamp_ms=timestamp_ms,
        cache_flag=1,
        nested_fields=nested,
        # sub_11018 obtains top-level map key 4 via Context.getPackageName().
        context_value=identity.package_name,
        status_code=fallback_status_code,
        status_text=str(fallback_status_code),
        extra_field=_fallback_nonce(),
    )
    token = encode_mode1(m90)
    return GeneratedDeviceToken(
        token=token,
        token_time=str(timestamp_ms)[:10],
        timestamp_ms=timestamp_ms,
        profile_id=identity.profile_id,
        feature_count=len(features),
        nested_feature_count=len(nested_features),
        fallback_status_code=fallback_status_code,
    )


def load_or_generate_cached_device_token(
    profile: StableProfile,
    *,
    cache_file: Path,
    max_age_ms: int = 14_400_000,
    fallback_status_code: int = FALLBACK_STATUS_CODE,
) -> GeneratedDeviceToken:
    """Mirror the App's four-hour Hawk cache with a private JSON state file."""
    now_ms = int(time.time() * 1000)
    identity = profile.identity()
    if cache_file.is_file():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            timestamp_ms = int(data["timestamp_ms"])
            if (
                data.get("schema_version") == TOKEN_SCHEMA_VERSION
                and data.get("profile_id") == identity.profile_id
                and int(data.get("fallback_status_code", 0)) == fallback_status_code
                and now_ms <= timestamp_ms + max_age_ms
                and str(data.get("token", "")).startswith("v3:")
            ):
                return GeneratedDeviceToken(
                    token=str(data["token"]),
                    token_time=str(data["token_time"]),
                    timestamp_ms=timestamp_ms,
                    profile_id=identity.profile_id,
                    feature_count=int(data.get("feature_count", 0)),
                    nested_feature_count=int(data.get("nested_feature_count", 0)),
                    fallback_status_code=fallback_status_code,
                )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            pass
    generated = generate_device_token(
        profile,
        timestamp_ms=now_ms,
        fallback_status_code=fallback_status_code,
    )
    cache_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = cache_file.with_name(cache_file.name + ".tmp")
    temporary.write_text(
        json.dumps(generated.cache_document(), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(cache_file)
    cache_file.chmod(0o600)
    return generated
