from custom_components.state_grid.login import (
    LoginMapContext,
    build_device_sms_payload,
    build_password_login_map,
    generate_check_code,
    login_header_md5,
)


def test_check_code_known_vector() -> None:
    assert generate_check_code(
        "11111111111",
        timestamp_ms=1700000000000,
        random_24="000001234567890123456789",
    ) == (
        "000001234567890123456789"
        "75632da3be842c1e29f4ea7a72e06ca4"
        "6cbe56b5abe93c05f5866135498093e4"
    )


def test_password_login_map_and_header_md5() -> None:
    context = LoginMapContext(
        city_id="420100",
        province_id="420000",
        district_id="420106",
        code="123456",
        code_key="one-shot-key",
    )
    params = build_password_login_map(
        "11111111111",
        "test-password",
        context=context,
        timestamp_ms=1700000000000,
        random_24="000001234567890123456789",
    )

    assert list(params) == ["quInfo", "uscInfo", "checkCode", "avalonValidCode"]
    assert params["quInfo"]["code"] == "123456"
    assert params["quInfo"]["codeKey"] == "one-shot-key"
    assert params["uscInfo"]["member"] == "2202"
    assert params["quInfo"]["password"] == "dfb450efddbb5387197c84460623675b"
    assert len(login_header_md5(params)) == 32


def test_device_verification_sms_payload() -> None:
    payload = build_device_sms_payload(
        "11111111111",
        LoginMapContext(device_id="device", device_model="model", device_ip="ip"),
    )
    assert payload == {
        "uscInfo": {
            "tenant": "state_grid",
            "member": "2202",
            "devciceId": "device",
            "devciceName": "model",
            "devciceIp": "ip",
        },
        "quInfo": {
            "voiceCodeFlag": False,
            "account": "11111111111",
            "sendType": 0,
            "businessType": "logindevice",
        },
    }
