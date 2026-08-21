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
REFERENCE_ENVIRONMENT = json.loads(
    Path(__file__).with_name("reference_environment.json").read_text(encoding="utf-8")
)
REFERENCE_NATIVE_FEATURES = {
    int(key): str(value)
    for key, value in REFERENCE_ENVIRONMENT["stable_feature_values"].items()
}
JAVA_SDK_CONSTANTS = {
    int(key): str(value)
    for key, value in REFERENCE_ENVIRONMENT["java_sdk_constants"].items()
}

_DEVICE_CATALOG = (
    {
        "brand": "google",
        "manufacturer": "Google",
        "model": "sdk_gphone64_arm64",
        "device": "emu64a",
        "product": "sdk_gphone64_arm64",
        "board": "goldfish_arm64",
        "hardware": "ranchu",
    },
)

# Exact 52-entry Java Map captured from the official App.  Values may change,
# but presence and key set are part of the App/SDK shape.
OFFICIAL_JAVA_KEYS: tuple[int | str, ...] = (
    1,
    4,
    205,
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
    271,
    272,
    273,
    279,
    280,
    281,
    282,
    284,
    285,
    286,
    287,
    288,
    303,
    308,
    309,
    402,
    406,
    2001,
    2005,
    2013,
    2016,
    2017,
    2018,
    2019,
    2021,
    2029,
    3001,
    3002,
    3004,
    3005,
    "com.google.android.providers.gsf.permission.READ_GSERVICES",
)

JAVA_PERFORMANCE_ORDER: tuple[int | str, ...] = (
    133,
    138,
    140,
    -17,
    17,
    145,
    146,
    149,
    22,
    150,
    151,
    24,
    100,
    101,
    102,
    103,
    104,
    105,
    106,
    107,
    44,
    113,
    114,
    115,
    116,
    117,
    118,
    120,
    122,
    "s9",
)
JAVA_PERFORMANCE_REFERENCE = {
    133: 0,
    138: 1,
    140: 0,
    -17: 0,
    17: 1,
    145: 0,
    146: 0,
    149: 0,
    22: 1,
    150: 0,
    151: 0,
    24: 0,
    100: 6,
    101: 114,
    102: 0,
    103: 0,
    104: 0,
    105: 0,
    106: 3,
    107: 0,
    44: 0,
    113: 2,
    114: 1,
    115: 1,
    116: 0,
    117: 0,
    118: 0,
    120: 8,
    122: 0,
    "s9": 1,
}
NATIVE_PERFORMANCE_ORDER: tuple[int, ...] = (
    21,
    7,
    10,
    14,
    33,
    11,
    24,
    12,
    23,
    8,
    13,
    25,
    20,
    35,
    42,
    121,
    135,
    124,
    125,
    129,
    131,
    134,
    132,
    137,
    142,
    141,
    9,
    15,
    16,
)
NATIVE_PERFORMANCE_REFERENCE = {
    21: 1,
    7: 0,
    10: 3,
    14: 0,
    33: 0,
    11: 0,
    24: 0,
    12: 0,
    23: 0,
    8: 0,
    13: 0,
    25: 0,
    20: 0,
    35: 0,
    42: 0,
    121: 1,
    135: 2,
    124: 0,
    125: 0,
    129: 0,
    131: 0,
    134: 0,
    132: 0,
    137: 1,
    142: 0,
    141: 0,
    9: 16,
    15: 0,
    16: 0,
}

# sign, kind, owner (None means App UID), three fixed tuple fields, and the
# final metric width.  This preserves the official seven-entry shape while
# keeping hashes and request metrics profile-specific.
PROCESS_ENTRY_TEMPLATES = (
    (-1, 3, 1000, 17, 0, 438, 3),
    (-1, 1, 0, 20, 0, 493, 3),
    (1, 1, 1000, 1864, 1036632, 420, 2),
    (-1, 1, 0, 20, 0, 493, 2),
    (1, 3, 1000, 17, 0, 438, 3),
    (1, 1, None, 19, 0, 292, 6),
    (-1, 1, None, 19, 0, 292, 6),
)


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
    def __init__(
        self,
        seed: bytes,
        *,
        boot_epoch_ms: int | None = None,
        install_epoch_ms: int | None = None,
    ):
        if len(seed) != 32:
            raise ValueError("Turing profile seed must be 32 bytes")
        self._seed = seed
        self._boot_epoch_ms = boot_epoch_ms
        self._install_epoch_ms = install_epoch_ms

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

    def request_integer(
        self, label: str, timestamp_ms: int, lower: int, upper: int
    ) -> int:
        """Derive a plausible request-scoped number without host identifiers."""
        return self.integer(f"request:{timestamp_ms}:{label}", lower, upper)

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
        return AndroidIdentity(
            profile_id=self.uuid("profile-id"),
            android_id=self.hex("android-id", 8),
            oaid=self.uuid("oaid"),
            wifi_mac=":".join(f"{part:02x}" for part in mac),
            serial="TUR" + self.hex("serial", 7).upper(),
            build_id="TE1A.240213.009",
            incremental="12342917",
            release="13",
            sdk_int=33,
            **model,
        )

    def _timing_value(self, label: str, timestamp_ms: int, reference: int) -> int:
        if reference <= 0:
            return 0
        radius = max(1, reference // 4)
        digits = len(str(reference))
        same_width_lower = 10 ** (digits - 1) if digits > 1 else 0
        same_width_upper = 10**digits - 1
        return self.request_integer(
            f"timing:{label}",
            timestamp_ms,
            max(same_width_lower, reference - radius),
            min(same_width_upper, reference + radius),
        )

    def java_performance_context(self, timestamp_ms: int) -> str:
        values = []
        for feature in JAVA_PERFORMANCE_ORDER:
            elapsed = self._timing_value(
                str(feature), timestamp_ms, JAVA_PERFORMANCE_REFERENCE[feature]
            )
            values.append(f"{feature}_{elapsed}")
        return ",".join(values)

    def direct_performance_context(self, timestamp_ms: int) -> str:
        values = []
        for feature in NATIVE_PERFORMANCE_ORDER:
            elapsed = self._timing_value(
                f"native-{feature}",
                timestamp_ms,
                NATIVE_PERFORMANCE_REFERENCE[feature],
            )
            values.append(f"{feature}_{elapsed}")
        suffix = ",".join(values)
        return f"{self.java_performance_context(timestamp_ms)},{suffix}"

    def native_feature_map(self, now_ms: int | None = None) -> dict[int, str]:
        """Build the complete native 62-tag reference feature map."""
        identity = self.identity()
        current = int(time.time() * 1000) if now_ms is None else int(now_ms)
        boot_epoch_ms = self._boot_epoch_ms
        if boot_epoch_ms is None:
            boot_epoch_ms = current - self.integer(
                "boot-age-ms", 3_600_000, 86_400_000 * 14
            )
        uid = self.integer("uid", 10000, 19999)
        install_epoch_ms = self._install_epoch_ms
        if install_epoch_ms is None:
            install_epoch_ms = boot_epoch_ms - self.integer(
                "install-age-ms", 86_400_000, 86_400_000 * 180
            )

        install_a = base64.urlsafe_b64encode(self.bytes("install-a", 16)).decode()
        install_b = (
            base64.urlsafe_b64encode(self.bytes("install-b", 16)).decode().rstrip("=")
            + "="
        )
        install_context = (
            f"1:1:{uid}:{install_epoch_ms}:"
            f"{identity.package_name}::"
            f"{self.integer('install-slot', 100_000_000, 999_999_999)}:"
            f"app/~~{install_a}/-{install_b},"
        )

        process_entries = []
        for index, template in enumerate(PROCESS_ENTRY_TEMPLATES):
            sign, kind, owner_value, first, second, third, metric_digits = template
            magnitude = self.integer(
                f"process-hash-{index}",
                1_000_000_000_000_000_000,
                9_000_000_000_000_000_000,
            )
            process_hash = magnitude * sign
            owner = uid if owner_value is None else owner_value
            metric = self.request_integer(
                f"process-metric-{index}",
                current,
                10 ** (metric_digits - 1),
                10**metric_digits - 1,
            )
            process_entries.append(
                f"{process_hash}:{kind}:{owner}_{first}_{second}_{third}_{metric}"
            )

        interface_id = self.hex("interface-id", 3)
        network_interfaces = (
            f"8,eth0;69699;3;fe80::5054:ff:fe{interface_id[:2]}:{interface_id[2:]};"
            f"fec0::5054:ff:fe{interface_id[:2]}:{interface_id[2:]};10.0.2.15,"
            "dummy0;65731;1;fe80::8c95:a4ff:fe59:322"
        )
        collection_latency = self.request_integer(
            "collection-latency", current, 8000, 16000
        )

        values = dict(REFERENCE_NATIVE_FEATURES)
        values.update(
            {
                16: identity.android_id,
                17: install_context,
                26: self.hex("native-device-id", 16),
                34: f"C:1,T:{current},LT:{collection_latency}",
                125: ",".join(process_entries),
                126: str(boot_epoch_ms),
                129: network_interfaces,
                141: str(self.integer("native-property-141", 1_000_000, 9_999_999)),
                146: "1,272494655,eth0,10.0.2.15,10.0.2.3",
                148: identity.oaid,
            }
        )
        if len(values) != 62:
            raise RuntimeError(
                f"native feature map must contain 62 tags, got {len(values)}"
            )
        return values

    def feature_map(
        self,
        now_ms: int | None = None,
        *,
        fallback_status_code: int = -22056,
        token_nonce: str | None = None,
    ) -> dict[int | str, str]:
        """Build the official 52-key Java Map from the same native state."""
        identity = self.identity()
        current = int(time.time() * 1000) if now_ms is None else int(now_ms)
        native = self.native_feature_map(current)
        nonce = token_nonce or self.hex(f"diagnostic-nonce:{current}", 16)
        stage_values = [
            self.request_integer(f"stage-{index}", current, 1000, 2200)
            for index in range(3)
        ]
        feature_map: dict[int | str, str] = {
            1: identity.channel,
            4: self.java_performance_context(current),
            205: native[22],
            210: native[34],
            240: native[44],
            250: native[100],
            251: native[101],
            252: native[102],
            253: native[103],
            254: native[104],
            255: native[105],
            256: native[106],
            257: native[107],
            258: native[113],
            259: native[114],
            264: native[24],
            266: native[45],
            267: native[17],
            268: native[115],
            269: native[116],
            270: native[117],
            271: native[46],
            272: native[118],
            273: "",
            279: native[120],
            280: native[122],
            281: native[126],
            282: native[138],
            284: native[146],
            285: native[149],
            286: native[150],
            287: native[151],
            288: native[152],
            303: f"5_1_{fallback_status_code}_{'_'.join(map(str, stage_values))}",
            308: "1",
            309: "",
            402: "",
            406: "",
            2001: native[200],
            2005: "0",
            2013: JAVA_SDK_CONSTANTS[2013],
            2016: JAVA_SDK_CONSTANTS[2016],
            2017: JAVA_SDK_CONSTANTS[2017],
            2018: str(self.integer("uid", 10000, 19999)),
            2019: native[133],
            2021: native[140],
            2029: "0",
            3001: str(fallback_status_code),
            3002: "1",
            3004: nonce,
            3005: "1",
            "com.google.android.providers.gsf.permission.READ_GSERVICES": "1",
        }
        if tuple(feature_map) != OFFICIAL_JAVA_KEYS:
            raise RuntimeError("Java feature Map key order/coverage drifted")
        return feature_map


def load_or_create_profile(state_file: Path) -> StableProfile:
    """Load a persistent profile seed or atomically create one with mode 0600."""
    if state_file.exists():
        payload = json.loads(state_file.read_text(encoding="utf-8"))
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported profile state schema")
        return StableProfile(
            base64.b64decode(payload["seed_b64"], validate=True),
            boot_epoch_ms=payload.get("boot_epoch_ms"),
            install_epoch_ms=payload.get("install_epoch_ms"),
        )
    state_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    seed = secrets.token_bytes(32)
    now_ms = int(time.time() * 1000)
    boot_epoch_ms = now_ms - secrets.randbelow(86_400_000 * 14 - 3_600_000) - 3_600_000
    install_epoch_ms = (
        boot_epoch_ms - secrets.randbelow(86_400_000 * 180 - 86_400_000) - 86_400_000
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "seed_b64": base64.b64encode(seed).decode("ascii"),
        "boot_epoch_ms": boot_epoch_ms,
        "install_epoch_ms": install_epoch_ms,
        "created_at": datetime.now(UTC).isoformat(),
    }
    temporary = state_file.with_name(state_file.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(state_file)
    state_file.chmod(0o600)
    return StableProfile(
        seed,
        boot_epoch_ms=boot_epoch_ms,
        install_epoch_ms=install_epoch_ms,
    )


def profile_document(profile: StableProfile, now_ms: int | None = None) -> dict:
    identity = profile.identity()
    return {
        "schema_version": SCHEMA_VERSION,
        "identity": asdict(identity),
        "feature_map": {
            str(key): value for key, value in profile.feature_map(now_ms).items()
        },
    }
