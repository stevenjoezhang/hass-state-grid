#!/usr/bin/env python3
"""Small, dependency-free JCE/Tars writer for the recovered Turing envelope.

This module implements the standard primitive/map/struct wire rules recovered
from the original ARM64 implementation. It deliberately does not invent device values:
callers must supply their own feature values.  ``serialize_m90_minimal`` is
the complete top-level shape for the base-token (mode-0) branch and the
nested tag-4 feature object used by mode 1.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import struct
import time
import zlib
from collections.abc import Iterable

DELTA = 0x9E3779B9
STATIC_KEY = b"HtIs!oM*4d4zcDf^"
TURING_RSA_PUBLIC_KEY_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtZX4OooO48FiYa3fwzU+"
    "fhPHO3YsMBP1MiV1Kp+osNDDPtf4EPCjuzI75ea+8Dbq8uQeCXWszSpWUWH1c2F"
    "0khl5BOCzDLyd166i4Hnh3jWW3PNu9ETh81aZh9c353U+c2fok/nPcepmGm3jl3"
    "GZrcxpN9/2wYcCl+t0TWRz+PuTNn0X8/Uf4inmxUJDWclZhao8oYKZM09rH6LRY"
    "ZiszAV9HpO3b9OFd0+/BARTqd+qUbfObMh3jGvIQUjsbpIT+ttPlqS4RyiVPUVG1"
    "gyYuS+/XNXbB59MkMlorIzj7esvC96F5OY5nKl7hvruFfHvEpbo4OL4jmveAMUgu"
    "4cSJQIDAQAB"
)

# JCE/Tars type identifiers.
BYTE, SHORT, INT, LONG = 0, 1, 2, 3
FLOAT, DOUBLE, STRING1, STRING4 = 4, 5, 6, 7
MAP, LIST, STRUCT_BEGIN, STRUCT_END = 8, 9, 10, 11
ZERO_TAG, SIMPLE_LIST = 12, 13


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _u64(value: int) -> int:
    return value & 0xFFFFFFFFFFFFFFFF


def _mix47(value: int) -> int:
    value = _u64(value)
    return _u64(value ^ (value >> 47))


def turing_hash64(data: bytes, seed: int = 0) -> int:
    """Port native ``sub_40f154(buffer, length, seed)`` exactly.

    The function is a small 64-bit multiplicative hash with an 8-byte block
    loop and byte-tail constants; it has no Android/libc dependencies.
    """
    raw = bytes(data)
    length = len(raw)
    multiplier = 0xC6A4A7935BD1E995
    state = _u64(_u64(length) * multiplier) ^ _u64(seed)
    blocks = length // 8
    for index in range(blocks):
        word = int.from_bytes(raw[index * 8 : index * 8 + 8], "little")
        word_mix = _mix47(_u64(word * multiplier))
        word_mix = _u64(word_mix * multiplier)
        # The K constant is XORed into both operands immediately before the
        # final eor, so it cancels; retaining it in the expression would
        # produce a different hash.
        state = _u64((word_mix ^ state) * multiplier)
    tail = raw[blocks * 8 :]
    if len(tail) >= 7:
        state ^= tail[6] << 48
    if len(tail) >= 6:
        b = tail[5] << 40
        # K XORs are paired around the byte, leaving a plain XOR.
        state ^= b
    if len(tail) >= 5:
        b = tail[4] << 32
        state ^= b
    if len(tail) >= 4:
        state ^= tail[3] << 24
    if len(tail) >= 3:
        b = tail[2] << 16
        state ^= b
    if len(tail) >= 2:
        k = 0x118727C03FB9FFC6
        b = tail[1] << 8
        state ^= k & b
    if len(tail) >= 1:
        state ^= tail[0]
    # Non-empty tail paths enter the switch epilogue through one extra
    # multiply; the zero-tail branch jumps directly to the avalanche.
    if tail:
        state = _u64(state * multiplier)
    state = _mix47(state)
    state = _u64(state * multiplier)
    return _mix47(state)


def _mx(sum_value: int, y: int, z: int, p: int, e: int, key: list[int]) -> int:
    return _u32(
        (((z >> 5) ^ _u32(y << 2)) + ((y >> 3) ^ _u32(z << 4)))
        ^ ((y ^ sum_value) + (z ^ key[(p & 3) ^ e]))
    )


def _xxtea_key(key_bytes: bytes | None) -> list[int]:
    material = b"DFG#$%^#%$RGHR(&*M<><" if key_bytes is None else key_bytes
    if len(material) > 16:
        material = hashlib.md5(material).digest()
    material = material.ljust(16, b"\0")
    return list(struct.unpack("<4I", material[:16]))


def xxtea_encrypt(plain: bytes, key_bytes: bytes | None) -> bytes:
    """Match ``Quarenden.a`` encryption, including its embedded length word."""
    if not plain:
        return plain
    count = len(plain) // 4 + (1 if len(plain) % 4 == 0 else 2)
    values = [0] * count
    for index, byte in enumerate(plain):
        values[index // 4] |= byte << ((index % 4) * 8)
    values[-1] = len(plain)
    n = count - 1
    key = _xxtea_key(key_bytes)
    rounds = 6 + 52 // (n + 1)
    total = 0
    z = values[n]
    while rounds:
        total = _u32(total + DELTA)
        e = (total >> 2) & 3
        for p in range(n):
            y = values[p + 1]
            values[p] = _u32(values[p] + _mx(total, y, z, p, e, key))
            z = values[p]
        y = values[0]
        values[n] = _u32(values[n] + _mx(total, y, z, n, e, key))
        z = values[n]
        rounds -= 1
    return struct.pack(f"<{count}I", *values)


class JceWriter:
    def __init__(self) -> None:
        self.buf = bytearray()

    def head(self, tag: int, type_id: int) -> None:
        if not 0 <= tag <= 255:
            raise ValueError("JCE tag must fit in one byte")
        if tag < 15:
            self.buf.append((tag << 4) | type_id)
        else:
            self.buf.append(0xF0 | type_id)
            self.buf.append(tag)

    def zero(self, tag: int) -> None:
        self.head(tag, ZERO_TAG)

    def byte(self, tag: int, value: int) -> None:
        value = int(value)
        if value == 0:
            self.zero(tag)
        else:
            self.head(tag, BYTE)
            self.buf += struct.pack("<b", value)

    def short(self, tag: int, value: int) -> None:
        value = int(value)
        if -128 <= value <= 127:
            self.byte(tag, value)
        else:
            self.head(tag, SHORT)
            self.buf += struct.pack(">h", value)

    def int32(self, tag: int, value: int) -> None:
        value = int(value)
        if -32768 <= value <= 32767:
            self.short(tag, value)
        else:
            self.head(tag, INT)
            self.buf += struct.pack(">i", value)

    def int64(self, tag: int, value: int) -> None:
        value = int(value)
        if -2147483648 <= value <= 2147483647:
            self.int32(tag, value)
        else:
            self.head(tag, LONG)
            self.buf += struct.pack(">q", value)

    def string(self, tag: int, value: str | bytes) -> None:
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        if len(raw) <= 255:
            self.head(tag, STRING1)
            self.buf.append(len(raw))
        else:
            self.head(tag, STRING4)
            self.buf += struct.pack(">i", len(raw))
        self.buf += raw

    def map_int_string(self, tag: int, entries: Iterable[tuple[int, str]]) -> None:
        items = list(entries)
        self.head(tag, MAP)
        self.int32(0, len(items))
        for key, value in items:
            self.int32(0, key)
            self.string(1, value)

    def raw_struct(self, tag: int, fields: bytes) -> None:
        self.head(tag, STRUCT_BEGIN)
        self.buf += fields
        self.head(0, STRUCT_END)

    def finish(self) -> bytes:
        return bytes(self.buf)


def serialize_m90_minimal(
    *,
    channel: str,
    brand: str,
    model: str,
    timestamp_ms: int,
    cache_flag: int,
    base_token: str,
    context_value: str | None = None,
) -> bytes:
    """Serialize the recovered top-level mode-0 ``m90`` object.

    Native ``sub_411018`` writes map entries in the order model (2), brand
    (1), channel (3), and optional context (4).  Keeping that order matters
    for byte-for-byte regression tests even though a JCE decoder treats maps
    semantically.
    """
    writer = JceWriter()
    entries = [(2, model), (1, brand), (3, channel)]
    if context_value is not None:
        entries.append((4, context_value))
    writer.map_int_string(0, entries)
    writer.int64(1, timestamp_ms)
    # ``sub_4470fc`` only emits tag 2 when the parsed 3002 value is nonzero;
    # a Java value of "0" is therefore represented by omission, not ZERO_TAG.
    if int(cache_flag):
        writer.int32(2, cache_flag)
    writer.string(3, base_token)
    return writer.finish()


def serialize_feature_struct(
    values: dict[int, str],
    *,
    helper_tag10: str | None = None,
    helper_tag12: str | None = None,
    hash_buffer: bytes | None = None,
) -> bytes:
    """Write the recovered direct tag-4 string fields.

    The native `0x410734/0x4107cc` branches are represented by the integer
    keys in `native/turing-feature-writes.tsv`.  The two flattened native
    helper outputs (tags 10 and 12) are optional until their input hashes are
    recovered; omitting an unavailable optional field matches the SDK's
    empty-string branches.
    """
    if hash_buffer is not None:
        digest = f"{turing_hash64(hash_buffer, 0):x}"
        helper_tag10 = "01" + digest
        helper_tag12 = digest
    writer = JceWriter()
    for tag, value in sorted(values.items()):
        if value is not None and value != "":
            writer.string(int(tag), value)
    if helper_tag10:
        writer.string(10, helper_tag10)
    if helper_tag12:
        writer.string(12, helper_tag12)
    return writer.finish()


def serialize_turing_nested(
    *,
    timestamp_ms: int,
    metadata: dict[int, str | int],
    feature_values: Iterable[tuple[int, str]] = (),
    network: tuple[str, str] = ("", ""),
    outer_string4: str = "",
    direct_values: Iterable[tuple[int, str]] = (),
    extra_map_values: Iterable[tuple[int, str]] = (),
    outer_string7: str = "",
    type8_values: dict[int, str | int] | None = None,
) -> bytes:
    """Serialize the complete recovered tag-0..8 nested struct shape.

    The field layout comes directly from `sub_4177d0`, `sub_418358`,
    `sub_4186ac`, and `sub_417d5c`.  `feature_values` is the map populated by
    `0x410734/0x4107cc`; `direct_values` is the separate map populated by
    `0x410e2c/0x439e3c`.  Values are caller-supplied because several of them
    are device-specific.
    """
    out = JceWriter()
    out.int64(0, timestamp_ms)

    # a0[4] / sub_418358: V90 metadata object.
    meta = JceWriter()
    meta.int32(0, int(metadata.get(0, 90)))
    meta.string(1, str(metadata.get(1, "")))
    meta.string(2, str(metadata.get(2, "")))
    meta.string(3, str(metadata.get(3, "")))
    meta.int32(4, int(metadata.get(4, 2)))
    out.raw_struct(1, meta.finish())

    # a0[5] / sub_417d5c: feature map.
    out.map_int_string(2, feature_values)

    # a0[6] / sub_4186ac: two-string network object.
    net = JceWriter()
    net.string(0, network[0])
    net.string(1, network[1])
    out.raw_struct(3, net.finish())

    if outer_string4:
        out.string(4, outer_string4)

    # a0[8]: native direct map.  This is a map<int32,string>, not a nested
    # struct; its tags include 3,4,7,8,9,10,12 in the current build.
    direct = list(direct_values)
    if direct:
        out.map_int_string(5, direct)

    extra = list(extra_map_values)
    if extra:
        out.map_int_string(6, extra)
    if outer_string7:
        out.string(7, outer_string7)

    # a0[11] / sub_417d5c: parsed 401..406 metadata and optional map.
    v8 = type8_values or {}
    tail = JceWriter()
    tail.string(0, str(v8.get(0, "")))
    if v8.get(1):
        tail.string(1, str(v8[1]))
    tail.string(2, str(v8.get(2, "")))
    tail.int32(3, int(v8.get(3, 0)))
    tail.string(4, str(v8.get(4, "")))
    tail.string(5, str(v8.get(5, "")))
    if v8.get(6):
        tail.string(6, str(v8[6]))
    if v8.get(7):
        tail.string(7, str(v8[7]))
    tail_map = v8.get(8, ())
    if tail_map:
        tail.map_int_string(8, tail_map)
    out.raw_struct(8, tail.finish())
    return out.finish()


def serialize_m90_full(
    *,
    channel: str,
    brand: str,
    model: str,
    timestamp_ms: int,
    cache_flag: int,
    nested_fields: bytes,
    context_value: str | None = None,
    status_code: int | None = None,
    status_text: str | None = None,
    extra_field: str | None = None,
) -> bytes:
    """Serialize the recovered mode-1 top-level object around tag 4."""
    writer = JceWriter()
    entries = [(2, model), (1, brand), (3, channel)]
    if context_value:
        entries.append((4, context_value))
    writer.map_int_string(0, entries)
    writer.int64(1, timestamp_ms)
    if cache_flag:
        writer.int32(2, cache_flag)
    writer.raw_struct(4, nested_fields)
    if status_code:
        writer.int32(5, status_code)
    if status_text:
        writer.string(6, status_text)
    if extra_field:
        writer.string(7, extra_field)
    return writer.finish()


def encode_mode0(
    native_blob: bytes,
    *,
    timestamp_ms: int | None = None,
) -> str:
    """Apply the recovered Java-level mode-0 ``v3:`` envelope."""
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)
    timestamp = struct.pack(">Q", int(timestamp_ms))
    compressed = zlib.compress(b"\x02" + bytes(native_blob))
    cipher = xxtea_encrypt(compressed, STATIC_KEY + timestamp)
    packed = b"\0" + timestamp + cipher
    # Android Base64 flag 2 means NO_WRAP; padding is retained.
    return "v3:" + base64.b64encode(packed).decode("ascii")


def _rsa_public_numbers() -> tuple[int, int]:
    """Read the 2048-bit modulus/exponent from Cherry.java's SPKI blob."""
    der = base64.b64decode(TURING_RSA_PUBLIC_KEY_B64)
    marker = b"\x02\x82\x01\x01"
    pos = der.find(marker)
    if pos < 0:
        raise ValueError("RSA modulus not found")
    # DER INTEGER is 257 bytes because a leading 00 keeps the 2048-bit
    # unsigned modulus positive.  The old parser included that 00 and dropped
    # the final modulus byte, accidentally creating a 2040-bit public key.
    encoded_modulus = der[pos + 4 : pos + 4 + 257]
    if len(encoded_modulus) != 257 or encoded_modulus[0] != 0:
        raise ValueError("unexpected RSA modulus encoding")
    modulus = int.from_bytes(encoded_modulus[1:], "big")
    exp_marker = b"\x02\x03\x01\x00\x01"
    exp_pos = der.find(exp_marker, pos + 4 + 257)
    if exp_pos < 0:
        raise ValueError("RSA exponent not found")
    return modulus, 65537


def rsa_pkcs1_v15_encrypt(message: bytes) -> bytes:
    modulus, exponent = _rsa_public_numbers()
    size = (modulus.bit_length() + 7) // 8
    if len(message) > size - 11:
        raise ValueError("RSA message too long")
    padding = bytearray()
    while len(padding) < size - len(message) - 3:
        padding.extend(byte for byte in secrets.token_bytes(32) if byte)
    encoded = b"\0\x02" + bytes(padding[: size - len(message) - 3]) + b"\0" + message
    return pow(int.from_bytes(encoded, "big"), exponent, modulus).to_bytes(size, "big")


def encode_mode1(native_blob: bytes, *, random_key: bytes | None = None) -> str:
    """Apply the recovered mode-1 RSA/XXTEA envelope.

    ``native_blob`` must already be the exact m90 tag stream.  The RSA public
    key is sufficient for client-side construction; the matching private key
    is intentionally not present here and is not needed by this function.
    """
    if random_key is None:
        alphabet = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        key = bytes(secrets.choice(alphabet) for _ in range(16))
    else:
        key = bytes(random_key)
    if len(key) != 16:
        raise ValueError("mode-1 key must be exactly 16 bytes")
    # Carambola's exact smali builds a new byte array with marker 0x02 at
    # index zero for both mode 0 and mode 1 before DeflaterOutputStream.
    compressed = zlib.compress(b"\x02" + bytes(native_blob))
    cipher = xxtea_encrypt(compressed, key)
    packed = b"\x01" + rsa_pkcs1_v15_encrypt(key) + cipher
    return "v3:" + base64.b64encode(packed).decode("ascii")
