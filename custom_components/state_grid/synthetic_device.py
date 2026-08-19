"""Persistent zero-Android device identity and Turing token generation."""

from __future__ import annotations

import base64
import secrets
import string
import time
from collections.abc import Mapping
from typing import Any

from .const import CLIENT_PRIVATE_KEY_HEX, SERVER_PUBLIC_KEY_HEX
from .models import DeviceProfile
from .turing.device_token import GeneratedDeviceToken, generate_device_token
from .turing.feature_profile import StableProfile

STATE_SCHEMA = 1
TOKEN_CACHE_MS = 14_400_000


def create_device_state() -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA,
        "seed_b64": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    }


def _stable_app_guid(profile: StableProfile) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(
        alphabet[value % len(alphabet)] for value in profile.bytes("app-guid", 60)
    )


def _profile(state: Mapping[str, Any]) -> StableProfile:
    if int(state.get("schema_version", 0)) != STATE_SCHEMA:
        raise ValueError("unsupported synthetic device state")
    seed = base64.b64decode(str(state["seed_b64"]), validate=True)
    return StableProfile(seed)


def _cached_token(
    state: Mapping[str, Any], profile: StableProfile
) -> GeneratedDeviceToken | None:
    cache = state.get("token_cache")
    if not isinstance(cache, Mapping):
        return None
    timestamp_ms = int(cache.get("timestamp_ms", 0))
    if int(time.time() * 1000) > timestamp_ms + TOKEN_CACHE_MS:
        return None
    if cache.get("profile_id") != profile.identity().profile_id:
        return None
    token = str(cache.get("token", ""))
    if not token.startswith("v3:"):
        return None
    return GeneratedDeviceToken(
        token=token,
        token_time=str(cache["token_time"]),
        timestamp_ms=timestamp_ms,
        profile_id=str(cache["profile_id"]),
        feature_count=int(cache.get("feature_count", 0)),
        nested_feature_count=int(cache.get("nested_feature_count", 0)),
        fallback_status_code=int(cache.get("fallback_status_code", -10004)),
    )


def build_device_profile(
    state: Mapping[str, Any],
    *,
    province: str = "",
    city: str = "",
    region: str = "",
) -> tuple[DeviceProfile, dict[str, Any]]:
    """Return the App request profile and updated serializable device state."""
    profile = _profile(state)
    generated = _cached_token(state, profile)
    if generated is None:
        generated = generate_device_token(profile)
    identity = profile.identity()
    updated = dict(state)
    updated["token_cache"] = generated.cache_document()
    return (
        DeviceProfile(
            server_public_key=SERVER_PUBLIC_KEY_HEX,
            client_private_key=CLIENT_PRIVATE_KEY_HEX,
            device_token_tx=generated.token,
            device_token_tx_time=generated.token_time,
            app_guid=_stable_app_guid(profile),
            device_id="000000",
            device_model=identity.model,
            android_release=identity.release,
            device_ip="127.0.0.1",
            address_province=province,
            address_city=city,
            address_region=region,
            province_header=province,
        ),
        updated,
    )
