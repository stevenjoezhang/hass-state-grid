"""Recovered password-login and new-device verification plaintext maps."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

CHECK_CODE_AES_KEY = b"LNPO+ISJ+QeqNemFK+3OMUdexSn2i6pB"


@dataclass(frozen=True)
class LoginMapContext:
    push_id: str = "000000"
    push_token_ali: str = "000000"
    city_id: str = ""
    province_id: str = ""
    district_id: str = ""
    is_encrypt: bool = False
    device_ip: str = "127.0.0.1"
    device_id: str = "000000"
    android_release: str = "13"
    operator_type: str = ""
    device_model: str = "sdk_gphone64_arm64"
    code: str = ""
    code_key: str = ""
    avalon_valid_code: str = ""


def password_md5(raw_password: str) -> str:
    return hashlib.md5(raw_password.encode("utf-8")).hexdigest()


def generate_check_code(
    account: str,
    *,
    timestamp_ms: int | None = None,
    random_24: str | None = None,
) -> str:
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)
    if random_24 is None:
        random_24 = f"{secrets.randbits(63):024d}"
    if len(random_24) != 24 or not random_24.isdigit():
        raise ValueError("random_24 must contain exactly 24 decimal digits")
    padder = PKCS7(128).padder()
    raw = f"{account}{timestamp_ms}".encode()
    padded = padder.update(raw) + padder.finalize()
    encryptor = Cipher(algorithms.AES(CHECK_CODE_AES_KEY), modes.ECB()).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return random_24 + encrypted.hex()


def build_password_login_map(
    account: str,
    password: str,
    *,
    context: LoginMapContext,
    timestamp_ms: int | None = None,
    random_24: str | None = None,
) -> dict[str, Any]:
    combined_push_id = f"{context.push_id},{context.push_token_ali}"
    return {
        "quInfo": {
            "code": context.code,
            "codeKey": context.code_key,
            "account": account,
            "password": password_md5(password),
            "optSys": "Android",
            "pushId": combined_push_id,
            "addressCity": context.city_id,
            "addressProvince": context.province_id,
            "addressRegion": context.district_id,
        },
        "uscInfo": {
            "isEncrypt": str(context.is_encrypt).lower(),
            "devciceIp": context.device_ip,
            "devciceId": context.device_id,
            "tenant": "state_grid",
            "member": "2202",
            "optSys": f"Android {context.android_release}",
            "operatorType": context.operator_type,
            "devciceName": context.device_model,
            "pushId": combined_push_id,
        },
        "checkCode": generate_check_code(
            account, timestamp_ms=timestamp_ms, random_24=random_24
        ),
        "avalonValidCode": context.avalon_valid_code,
    }


def build_device_sms_payload(account: str, context: LoginMapContext) -> dict[str, Any]:
    return {
        "uscInfo": {
            "tenant": "state_grid",
            "member": "2202",
            "devciceId": context.device_id,
            "devciceName": context.device_model,
            "devciceIp": context.device_ip,
        },
        "quInfo": {
            "voiceCodeFlag": False,
            "account": account,
            "sendType": 0,
            "businessType": "logindevice",
        },
    }


def build_login_sms_payload(account: str, context: LoginMapContext) -> dict[str, Any]:
    payload = build_device_sms_payload(account, context)
    payload["quInfo"]["businessType"] = "login"
    return payload


def build_sms_login_map(
    account: str,
    code: str,
    code_key: str,
    *,
    context: LoginMapContext,
) -> dict[str, Any]:
    if len(code) != 6 or not code.isdigit():
        raise ValueError("SMS login code must contain exactly six digits")
    if not code_key:
        raise ValueError("SMS login codeKey must not be empty")
    combined_push_id = f"{context.push_id},{context.push_token_ali}"
    return {
        "quInfo": {
            "account": account,
            "businessType": "login",
            "code": code,
            "optSys": "Android",
            "pushId": combined_push_id,
            "codeKey": code_key,
        },
        "uscInfo": {
            "isEncrypt": str(context.is_encrypt).lower(),
            "devciceIp": context.device_ip,
            "devciceId": context.device_id,
            "tenant": "state_grid",
            "member": "2202",
            "optSys": f"Android {context.android_release}",
            "operatorType": context.operator_type,
            "devciceName": context.device_model,
            "pushId": combined_push_id,
        },
    }


def _java_string_hash(value: str) -> int:
    result = 0
    for char in value:
        result = (31 * result + ord(char)) & 0xFFFFFFFF
    return result


def _java_hashmap_order(value: Any) -> Any:
    if isinstance(value, Mapping):
        buckets: dict[int, list[str]] = {}
        for key in value:
            hashed = _java_string_hash(str(key))
            hashed ^= hashed >> 16
            buckets.setdefault(hashed & 15, []).append(str(key))
        return {
            key: _java_hashmap_order(value[key])
            for bucket in sorted(buckets)
            for key in buckets[bucket]
        }
    if isinstance(value, list):
        return [_java_hashmap_order(item) for item in value]
    return value


def login_header_md5(params: Mapping[str, Any]) -> str:
    """Match LoginModel: sorted outer keys and nested Java HashMap wire order."""
    material = "".join(
        key
        + json.dumps(
            _java_hashmap_order(params[key]),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        for key in sorted(params)
    )
    return hashlib.md5(material.encode("utf-8")).hexdigest()
