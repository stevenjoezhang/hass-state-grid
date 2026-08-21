"""Policy-aware diagnostics for the pure-Python Turing profile generator."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .device_token import (
    BUILD_MARKER,
    CHANNEL,
    FALLBACK_STATUS_CODE,
    NESTED_TAG_BY_FEATURE_KEY,
    _direct_values,
    _tail_map,
)
from .feature_profile import OFFICIAL_JAVA_KEYS, StableProfile
from .hash_python import generate_feature_hash_tags
from .jce import serialize_m90_full, serialize_turing_nested

FIELD_POLICY = json.loads(
    Path(__file__).with_name("field_policy.json").read_text(encoding="utf-8")
)
POLICY_JAVA = {str(item["id"]): item for item in FIELD_POLICY["java_fields"]}
POLICY_NATIVE = {int(item["id"]): item for item in FIELD_POLICY["native_fields"]}
OFFICIAL_M90_LENGTH = 3943


def _field_value(value: str, include_values: bool) -> dict[str, Any]:
    raw = value.encode("utf-8")
    result: dict[str, Any] = {
        "utf8_length": len(raw),
        "sha256_16": hashlib.sha256(raw).hexdigest()[:16],
    }
    if include_values:
        result["value"] = value
    return result


def _policy_row(
    identifier: int | str,
    value: str,
    policy: dict[str, Any],
    include_values: bool,
) -> dict[str, Any]:
    return {
        "id": identifier,
        **_field_value(value, include_values),
        "meaning": policy["meaning"],
        "official_match": policy["official_match"],
        "lifetime": policy["lifetime"],
        "change_rule": policy["change_rule"],
        "reference_value": policy["reference_value"],
        "official_utf8_length": policy["official_utf8_length"],
        "destination_or_source": policy["destination_or_source"],
    }


def _invariants(
    identity: Any,
    java: dict[int | str, str],
    native: dict[int, str],
    direct: dict[int, str],
    tag10: str,
    tag12: str,
    timestamp_ms: int,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, category: str) -> None:
        checks.append({"name": name, "pass": bool(passed), "category": category})

    add(
        "Java key set equals official 52-key policy",
        tuple(java) == OFFICIAL_JAVA_KEYS,
        "coverage",
    )
    add(
        "native tag set equals official 62-tag policy",
        set(native) == set(POLICY_NATIVE),
        "coverage",
    )
    for java_key, native_tag in NESTED_TAG_BY_FEATURE_KEY.items():
        if java_key in java and native_tag in native:
            add(
                f"Java {java_key} equals native {native_tag}",
                java[java_key] == native[native_tag],
                "same-source",
            )

    add("root model equals native 24", identity.model == native[24], "identity")
    add("root brand equals native 23", identity.brand == native[23], "identity")
    add("Java 264 equals native 24", java[264] == native[24], "identity")
    add(
        "fingerprint contains brand/model",
        native[8].startswith(identity.brand + "/") and identity.model in native[8],
        "Build",
    )
    add(
        "fingerprint contains release/build/incremental",
        f":{identity.release}/{identity.build_id}/{identity.incremental}:" in native[8],
        "Build",
    )
    add(
        "sensor count agrees with native 108",
        native[11].count("type=") == int(native[108]),
        "hardware",
    )
    add("direct 10 equals 01 + direct 12", tag10 == "01" + tag12, "hash")
    add(
        "direct hash values preserved",
        direct[10] == tag10 and direct[12] == tag12,
        "hash",
    )
    add(
        "direct performance starts with Java 4",
        direct[4].startswith(java[4] + ","),
        "timing",
    )

    process_match = re.match(r"^([^,]+),(\d+),([^,]+),(\d+),", direct[7])
    install_match = re.match(r"^1:1:(\d+):[^:]*:([^:]+)::", native[17])
    if process_match and install_match:
        add(
            "process UID equals install UID",
            process_match.group(2) == install_match.group(1),
            "identity",
        )
        process_package = process_match.group(1).split(":", 1)[0]
        add(
            "process package equals install package",
            process_package == install_match.group(2),
            "identity",
        )
        add(
            "Java 2018 equals process UID",
            java[2018] == process_match.group(2),
            "identity",
        )
        install_epoch_ms = int(native[17].split(":", 5)[3])
        boot_epoch_ms = int(native[126])
        add(
            "install time precedes boot time",
            install_epoch_ms < boot_epoch_ms,
            "time",
        )
        add(
            "boot time does not exceed request time",
            boot_epoch_ms <= timestamp_ms,
            "time",
        )
    else:
        add("process/install values are parseable", False, "identity")

    app_width, app_height = map(int, native[14].split("*", 1))
    display_match = re.search(r",(\d+)x(\d+),", native[131])
    add("display summary is parseable", display_match is not None, "display")
    if display_match:
        display_width, display_height = map(int, display_match.groups())
        add("app/display widths agree", app_width == display_width, "display")
        add(
            "app height does not exceed display",
            app_height <= display_height,
            "display",
        )

    active_network = native[146].split(",")
    add("active network has expected fields", len(active_network) >= 5, "network")
    if len(active_network) >= 5:
        interface, ip_address = active_network[2], active_network[3]
        add(
            "active interface appears in interface summary",
            interface in native[129],
            "network",
        )
        add(
            "active IPv4 appears in interface summary",
            ip_address in native[129],
            "network",
        )

    signature_match = re.fullmatch(
        re.escape(identity.package_name) + r"_[0-9A-F]{32}", native[107]
    )
    add(
        "package/signature summary has official shape",
        signature_match is not None,
        "identity",
    )
    return checks


def build_profile_diagnostics(
    profile: StableProfile,
    *,
    timestamp_ms: int,
    include_values: bool = False,
    fallback_status_code: int = FALLBACK_STATUS_CODE,
) -> dict[str, Any]:
    """Generate a value-aware or redacted diagnostic document without a token."""
    identity = profile.identity()
    nonce = profile.hex(f"diagnostic-nonce:{timestamp_ms}", 16)
    java = profile.feature_map(
        timestamp_ms,
        fallback_status_code=fallback_status_code,
        token_nonce=nonce,
    )
    native = profile.native_feature_map(timestamp_ms)
    tag10, tag12 = generate_feature_hash_tags(native, timestamp_ms)
    process_context = (
        f"{identity.package_name}:tools,{java[2018]},untrusted_app,{java[2018]},,init"
    )
    direct_pairs = _direct_values(
        java,
        tag10,
        tag12,
        process_context,
        profile.direct_performance_context(timestamp_ms),
    )
    direct = dict(direct_pairs)
    probe_timestamp_ms = timestamp_ms + 3_600_000
    probe_nonce = profile.hex(f"diagnostic-nonce:{probe_timestamp_ms}", 16)
    probe_java = profile.feature_map(
        probe_timestamp_ms,
        fallback_status_code=fallback_status_code,
        token_nonce=probe_nonce,
    )
    probe_native = profile.native_feature_map(probe_timestamp_ms)
    probe_tag10, probe_tag12 = generate_feature_hash_tags(
        probe_native, probe_timestamp_ms
    )
    probe_process_context = (
        f"{identity.package_name}:tools,{probe_java[2018]},untrusted_app,"
        f"{probe_java[2018]},,init"
    )
    probe_direct = dict(
        _direct_values(
            probe_java,
            probe_tag10,
            probe_tag12,
            probe_process_context,
            profile.direct_performance_context(probe_timestamp_ms),
        )
    )
    java_changed = [key for key in java if java[key] != probe_java[key]]
    native_changed = [tag for tag in native if native[tag] != probe_native[tag]]
    direct_changed = [tag for tag in direct if direct[tag] != probe_direct[tag]]
    stable_lifetimes = {
        "app_version",
        "profile",
        "install",
        "boot",
        "process",
        "network",
        "config",
        "user_state",
    }
    unexpected_java_changes = [
        key
        for key in java_changed
        if POLICY_JAVA[str(key)]["lifetime"] in stable_lifetimes
    ]
    unexpected_native_changes = [
        tag
        for tag in native_changed
        if POLICY_NATIVE[tag]["lifetime"] in stable_lifetimes
    ]
    nested = serialize_turing_nested(
        timestamp_ms=timestamp_ms,
        metadata={0: 90, 1: "90", 2: BUILD_MARKER, 3: CHANNEL, 4: 2},
        feature_values=sorted(native.items()),
        network=("3.2.3,113", identity.package_name),
        direct_values=direct_pairs,
        extra_map_values=((2, ""),),
        type8_values={
            1: "",
            2: java[402],
            3: 0,
            4: "",
            5: "",
            8: _tail_map(java[406]),
        },
    )
    m90 = serialize_m90_full(
        channel=identity.channel,
        brand=identity.brand,
        model=identity.model,
        timestamp_ms=timestamp_ms,
        cache_flag=1,
        nested_fields=nested,
        context_value=identity.package_name,
        status_code=fallback_status_code,
        status_text=str(fallback_status_code),
        extra_field=nonce,
    )
    checks = _invariants(
        identity,
        java,
        native,
        direct,
        tag10,
        tag12,
        timestamp_ms,
    )
    required_java = [
        item
        for item in FIELD_POLICY["java_fields"]
        if item["official_match"] == "required"
    ]
    required_native = [
        item
        for item in FIELD_POLICY["native_fields"]
        if item["official_match"] == "required"
    ]
    return {
        "schema_version": 1,
        "contains_raw_values": include_values,
        "timestamp_ms": timestamp_ms,
        "summary": {
            "java_field_count": len(java),
            "native_field_count": len(native),
            "direct_field_count": len(direct),
            "java_total_value_bytes": sum(
                len(value.encode()) for value in java.values()
            ),
            "native_total_value_bytes": sum(
                len(value.encode()) for value in native.values()
            ),
            "m90_length": len(m90),
            "official_reference_m90_length": OFFICIAL_M90_LENGTH,
            "m90_length_delta": len(m90) - OFFICIAL_M90_LENGTH,
            "required_java_field_count": len(required_java),
            "required_native_field_count": len(required_native),
            "invariant_count": len(checks),
            "invariant_failures": sum(not check["pass"] for check in checks),
            "lifetime_unexpected_changes": (
                len(unexpected_java_changes) + len(unexpected_native_changes)
            ),
        },
        "identity": asdict(identity)
        if include_values
        else {
            key: _field_value(str(value), False)
            for key, value in asdict(identity).items()
        },
        "java_fields": [
            _policy_row(key, value, POLICY_JAVA[str(key)], include_values)
            for key, value in java.items()
        ],
        "native_fields": [
            _policy_row(tag, native[tag], POLICY_NATIVE[tag], include_values)
            for tag in sorted(native)
        ],
        "direct_fields": [
            {"tag": tag, **_field_value(value, include_values)}
            for tag, value in direct_pairs
        ],
        "lifetime_probe": {
            "interval_ms": probe_timestamp_ms - timestamp_ms,
            "java_changed_ids": java_changed,
            "native_changed_tags": native_changed,
            "direct_changed_tags": direct_changed,
            "unexpected_java_changes": unexpected_java_changes,
            "unexpected_native_changes": unexpected_native_changes,
        },
        "m90": {
            "byte_length": len(m90),
            "sha256": hashlib.sha256(m90).hexdigest(),
            **({"base64": base64.b64encode(m90).decode()} if include_values else {}),
        },
        "invariants": checks,
    }
