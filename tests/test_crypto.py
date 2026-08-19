from gmssl import sm2

from custom_components.state_grid.crypto import (
    build_request_envelope,
    compact_json,
    sm4_decrypt_hex,
    verify_request_envelope,
)

SERVER_PRIVATE = "1" * 64


def test_request_envelope_round_trip() -> None:
    probe = sm2.CryptSM2(private_key=SERVER_PRIVATE, public_key="", mode=1)
    server_public = probe._kg(int(SERVER_PRIVATE, 16), probe.ecc_table["g"])
    payload = {
        "serviceCode": "BCP_000026",
        "source": "app",
        "target": "test",
        "data": {"startTime": "2026-08-01", "endTime": "2026-08-31"},
    }
    key_text = "bdb70549e6a0428880bbb7dd766de085"
    envelope = build_request_envelope(
        payload,
        server_public,
        timestamp="1787054400000",
        key_text=key_text,
    )

    assert set(envelope) == {"data", "sign", "skey", "timestamp"}
    assert len(envelope["skey"]) == 258
    assert envelope["skey"].startswith("04")
    assert verify_request_envelope(envelope)

    server = sm2.CryptSM2(private_key=SERVER_PRIVATE, public_key=server_public, mode=1)
    unwrapped = server.decrypt(bytes.fromhex(envelope["skey"][2:])).decode("ascii")
    assert unwrapped == key_text
    plaintext = sm4_decrypt_hex(envelope["data"], unwrapped).decode("utf-8")
    assert plaintext == compact_json(payload)
