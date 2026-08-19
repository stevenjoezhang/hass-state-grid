"""Stable synthetic Android feature profiles for local Turing protocol tests.

The profile is anchored by a random 256-bit seed persisted in a caller-chosen
state file.  It is stable for one installation, does not expose raw host
identifiers, and avoids profile collisions between independently initialized
machines.  Do not copy the state file to another host: doing so deliberately
clones the simulated device.

This module models the *shape* of the Turing feature input discovered in this
analysis.  It is for offline/native-harness regression, not a claim that a
synthetic profile will pass a production risk decision.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1
CHANNEL = "10000191"
PACKAGE_NAME = "com.sgcc.wsgw.cn"
BUILD_MARKER = "77F2B17A00A92C71"

_DEVICE_CATALOG = (
    {
        "brand": "Xiaomi",
        "manufacturer": "Xiaomi",
        "model": "23127PN0CC",
        "device": "garnet",
        "product": "garnet",
        "board": "garnet",
        "hardware": "qcom",
    },
    {
        "brand": "HONOR",
        "manufacturer": "HONOR",
        "model": "BVL-AN16",
        "device": "BVL",
        "product": "BVL",
        "board": "kalama",
        "hardware": "qcom",
    },
    {
        "brand": "vivo",
        "manufacturer": "vivo",
        "model": "V2324A",
        "device": "V2324A",
        "product": "V2324A",
        "board": "kalama",
        "hardware": "qcom",
    },
)

# All map keys directly assigned by Cantaloupe plus the native tail inputs.
FEATURE_KEYS = (
    1,
    2,
    205,
    207,
    210,
    240,
    250,
    251,
    252,
    253,
    254,
    255,
    256,
    257,
    258,
    259,
    264,
    266,
    267,
    268,
    269,
    270,
    272,
    273,
    274,
    275,
    276,
    278,
    279,
    280,
    281,
    282,
    283,
    284,
    285,
    286,
    287,
    288,
    303,
    308,
    309,
    401,
    402,
    403,
    404,
    405,
    406,
    2013,
    2016,
    2017,
    2018,
    2019,
    2020,
    2021,
    2022,
    2023,
    2024,
    2025,
    2028,
    2029,
    3005,
)
BOOLEAN_KEYS = {2, 251, 252, 258, 259, 278, 3005, 2025, 2028}


@dataclass(frozen=True)
class AndroidIdentity:
    profile_id: str
    android_id: str
    oaid: str
    wifi_mac: str
    serial: str
    build_id: str
    incremental: str
    release: str
    sdk_int: int
    brand: str
    manufacturer: str
    model: str
    device: str
    product: str
    board: str
    hardware: str
    package_name: str = PACKAGE_NAME
    channel: str = CHANNEL


class StableProfile:
    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("Turing profile seed must be 32 bytes")
        self._seed = seed

    def bytes(self, label: str, size: int = 32) -> bytes:
        if size < 1:
            raise ValueError("size must be positive")
        output = bytearray()
        counter = 0
        while len(output) < size:
            output.extend(
                hmac.new(
                    self._seed,
                    b"wsgw-turing-profile-v1\0"
                    + label.encode("utf-8")
                    + counter.to_bytes(4, "big"),
                    hashlib.sha256,
                ).digest()
            )
            counter += 1
        return bytes(output[:size])

    def hex(self, label: str, size: int = 16) -> str:
        return self.bytes(label, size).hex()

    def integer(self, label: str, lower: int, upper: int) -> int:
        if lower > upper:
            raise ValueError("invalid integer range")
        value = int.from_bytes(self.bytes(label, 8), "big")
        return lower + value % (upper - lower + 1)

    def uuid(self, label: str) -> str:
        value = bytearray(self.bytes(label, 16))
        value[6] = (value[6] & 0x0F) | 0x40
        value[8] = (value[8] & 0x3F) | 0x80
        return str(uuid.UUID(bytes=bytes(value)))

    def identity(self) -> AndroidIdentity:
        model = _DEVICE_CATALOG[
            self.integer("device-catalog", 0, len(_DEVICE_CATALOG) - 1)
        ]
        mac = bytearray(self.bytes("wifi-mac", 6))
        mac[0] = (mac[0] & 0xFE) | 0x02  # locally administered, unicast
        build_number = self.integer("build-number", 100000, 999999)
        return AndroidIdentity(
            profile_id=self.uuid("profile-id"),
            android_id=self.hex("android-id", 8),
            oaid=self.uuid("oaid"),
            wifi_mac=":".join(f"{part:02x}" for part in mac),
            serial="TUR" + self.hex("serial", 7).upper(),
            build_id="UP1A." + str(build_number),
            incremental=str(self.integer("incremental", 100000000, 999999999)),
            release="13",
            sdk_int=33,
            **model,
        )

    def feature_map(self, now_ms: int | None = None) -> dict[int, str]:
        """Create a deterministic profile plus explicitly dynamic time fields."""
        identity = self.identity()
        current = int(time.time() * 1000) if now_ms is None else int(now_ms)
        boot_age_ms = self.integer("boot-age-ms", 3_600_000, 86_400_000 * 14)
        # Cantaloupe inserts empty strings for unavailable optional probes.
        # Random hexadecimal placeholders look like positive anti-tamper hits
        # and cause a much higher-risk profile than an ordinary clean device.
        feature_map = {key: "" for key in FEATURE_KEYS}
        feature_map.update(
            {
                1: identity.channel,
                2: "0",
                205: "",
                207: self.hex("risk-device-id", 20),
                210: "C:1",
                251: "0",
                252: "0",
                253: "0",
                254: "0",
                255: "0",
                257: f"{identity.package_name}_3.2.3",
                258: "0",
                259: "0",
                264: identity.model,
                267: self.hex("feature-device-id", 16),
                270: "0",
                272: "v4;0_v6;0",
                274: "",  # State Grid does not supply an ITuringDeviceInfoProvider.
                275: "",
                276: "",
                278: "",
                281: str(current - boot_age_ms),
                282: "5,2,5;5",
                283: "",
                284: "2,0,wlan0,192.168.1.100,223.5.5.5",
                285: "zh-CN,en-US",
                286: "Asia/Shanghai",
                287: "46000",
                288: "0",
                303: "",  # first request has no prior 703 timing record
                308: "0",
                309: identity.profile_id,
                401: "",
                402: "",
                403: "0",
                404: "",
                405: "",
                406: "",  # SDK builder supplies an empty clientMetaDataMap.
                2013: "",
                2018: str(self.integer("uid", 10000, 19999)),
                2019: (
                    "android.app.ApplicationPackageManager,"
                    "android.content.pm.PackageManager,"
                ),
                2021: "0,0,-1,,",
                2025: "0",
                2028: "0",
                2029: "0",
                3005: "0",
            }
        )
        return feature_map


def load_or_create_profile(state_file: Path) -> StableProfile:
    """Load a persistent profile seed or atomically create one with mode 0600."""
    if state_file.exists():
        payload = json.loads(state_file.read_text(encoding="utf-8"))
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported profile state schema")
        return StableProfile(base64.b64decode(payload["seed_b64"], validate=True))
    state_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    seed = secrets.token_bytes(32)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "seed_b64": base64.b64encode(seed).decode("ascii"),
        "created_at": datetime.now(UTC).isoformat(),
    }
    temporary = state_file.with_name(state_file.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(state_file)
    state_file.chmod(0o600)
    return StableProfile(seed)


def profile_document(profile: StableProfile, now_ms: int | None = None) -> dict:
    identity = profile.identity()
    return {
        "schema_version": SCHEMA_VERSION,
        "identity": asdict(identity),
        "feature_map": {
            str(key): value for key, value in profile.feature_map(now_ms).items()
        },
    }
