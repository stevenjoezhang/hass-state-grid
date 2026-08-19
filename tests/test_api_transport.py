import asyncio
import json
from datetime import date

import pytest
from gmssl import sm2

from custom_components.state_grid.api import (
    StateGridAppApi,
    StateGridAuthenticationError,
)
from custom_components.state_grid.crypto import (
    compact_json,
    sm4_decrypt_hex,
    sm4_encrypt_hex,
    verify_request_envelope,
)
from custom_components.state_grid.models import (
    DeviceProfile,
    LoginSession,
    PowerAccount,
)

PRIVATE_KEY = "1" * 64


def _public_key() -> str:
    probe = sm2.CryptSM2(private_key=PRIVATE_KEY, public_key="", mode=1)
    return probe._kg(int(PRIVATE_KEY, 16), probe.ecc_table["g"])


def _response_envelope(value: dict) -> dict[str, str]:
    key_text = "0123456789abcdef0123456789abcdef"
    public_key = _public_key()
    crypt = sm2.CryptSM2(private_key="", public_key=public_key, mode=1)
    return {
        "encryptData": sm4_encrypt_hex(compact_json(value), key_text),
        "respKey": "04" + crypt.encrypt(key_text.encode("ascii")).hex().upper(),
        "timestamp": "1787054400000",
    }


class FakeResponse:
    status = 200

    def __init__(self, value: dict) -> None:
        self.value = value

    async def text(self) -> str:
        return json.dumps(self.value)


class FakeRequestContext:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    async def __aenter__(self) -> FakeResponse:
        return self.response

    async def __aexit__(self, *_args) -> None:
        return None


class FakeHttp:
    def __init__(self, *responses: dict) -> None:
        self.responses = list(responses)
        self.requests: list[dict] = []

    def post(self, url, **kwargs) -> FakeRequestContext:
        self.requests.append({"url": url, **kwargs})
        return FakeRequestContext(FakeResponse(self.responses.pop(0)))


def _profile() -> DeviceProfile:
    return DeviceProfile(
        server_public_key=_public_key(),
        client_private_key=PRIVATE_KEY,
        device_token_tx="synthetic-device-token",
        device_token_tx_time="1787054400",
        app_guid="A" * 60,
        address_province="420000",
        address_city="420100",
        address_region="420106",
    )


def _decrypt_request(body: str) -> dict:
    envelope = json.loads(body)
    assert verify_request_envelope(envelope)
    crypt = sm2.CryptSM2(private_key=PRIVATE_KEY, public_key=_public_key(), mode=1)
    key_text = crypt.decrypt(bytes.fromhex(envelope["skey"][2:])).decode("ascii")
    return json.loads(sm4_decrypt_hex(envelope["data"], key_text).decode())


def test_async_login_transport_and_session_parsing() -> None:
    response = _response_envelope(
        {
            "code": 1,
            "data": {
                "srvrt": {"resultCode": "0000", "resultMessage": "ok"},
                "bizrt": {
                    "token": "t" * 36,
                    "tokenExpireTime": 1296000,
                    "userInfo": {
                        "userId": "u" * 32,
                        "addressProvince": "420000",
                        "powerUserList": [
                            {
                                "id": "account-1",
                                "powerUserNo": "cons-no",
                                "powerUserNo_dst": "cons-no-dst",
                                "proNo": "42101",
                                "orgNo": "org",
                                "elecType": "01",
                            }
                        ],
                    },
                },
            },
        }
    )
    http = FakeHttp(response)
    api = StateGridAppApi(
        http, username="11111111111", password="password", profile=_profile()
    )

    session = asyncio.run(api.async_login())

    assert session.token == "t" * 36
    assert session.user_id == "u" * 32
    assert [account.account_id for account in api.accounts] == ["account-1"]
    assert http.requests[0]["url"].endswith("/member/c2/f01")
    assert len(http.requests[0]["headers"]["md5"]) == 32
    assert len(http.requests[0]["headers"]["timeStamp"]) == 14
    assert len(http.requests[0]["headers"]["AppGuidNew"]) == 60

    plaintext = _decrypt_request(http.requests[0]["data"])
    assert plaintext["uscInfo"]["member"] == "2202"
    assert plaintext["quInfo"]["account"] == "11111111111"
    assert plaintext["quInfo"]["password"] != "password"


def test_sms_and_daily_query_transport() -> None:
    sms_response = _response_envelope(
        {
            "code": 1,
            "data": {
                "srvrt": {"resultCode": "0000", "resultMessage": "ok"},
                "bizrt": {"codeKey": "short-lived-key"},
            },
        }
    )
    daily_response = _response_envelope(
        {
            "code": 1,
            "data": {
                "returnCode": "1",
                "totalPq": "3.5",
                "sevenEleList": [
                    {"day": "20260801", "dayElePq": "1.2"},
                    {"day": "20260802", "dayElePq": "2.3"},
                ],
            },
        }
    )
    http = FakeHttp(sms_response, daily_response)
    login_session = LoginSession(
        token="t" * 36,
        user_id="u" * 32,
        expires_at=9999999999,
        user_info={"addressProvince": "420000"},
    )
    api = StateGridAppApi(
        http,
        username="11111111111",
        password="password",
        profile=_profile(),
        login_session=login_session,
    )

    code_key = asyncio.run(api.async_send_device_verification_sms())
    assert code_key == "short-lived-key"
    sms_plain = _decrypt_request(http.requests[0]["data"])
    assert sms_plain["quInfo"]["businessType"] == "logindevice"
    assert "md5" not in http.requests[0]["headers"]

    account = PowerAccount.from_api(
        {
            "id": "account-1",
            "powerUserNo": "cons-no",
            "powerUserNo_dst": "cons-no-dst",
            "proNo": "42101",
            "orgNo": "org",
            "elecType": "01",
        }
    )
    readings, total = asyncio.run(
        api.async_query_daily_usage(account, date(2026, 8, 1), date(2026, 8, 31))
    )
    assert total == 3.5
    assert [reading.usage for reading in readings] == [1.2, 2.3]
    query_headers = http.requests[1]["headers"]
    assert query_headers["t"] == "t" * 36
    assert query_headers["userid"] == "u" * 32
    assert len(query_headers["timeStamp"]) == 23


def test_login_business_failure_is_authentication_error() -> None:
    response = _response_envelope(
        {
            "code": 1,
            "data": {
                "srvrt": {
                    "resultCode": "1001",
                    "resultMessage": "credentials rejected",
                }
            },
        }
    )
    api = StateGridAppApi(
        FakeHttp(response),
        username="11111111111",
        password="wrong-password",
        profile=_profile(),
    )

    with pytest.raises(StateGridAuthenticationError):
        asyncio.run(api.async_login())


def test_pure_sms_login_flow() -> None:
    send_response = _response_envelope(
        {
            "code": 1,
            "data": {
                "srvrt": {"resultCode": "0000", "resultMessage": "ok"},
                "bizrt": {"codeKey": "sms-code-key"},
            },
        }
    )
    login_response = _response_envelope(
        {
            "code": 1,
            "data": {
                "srvrt": {"resultCode": "0000", "resultMessage": "ok"},
                "bizrt": {
                    "token": "s" * 36,
                    "tokenExpireTime": 1296000,
                    "userInfo": {"userId": "u" * 32, "powerUserList": []},
                },
            },
        }
    )
    http = FakeHttp(send_response, login_response)
    api = StateGridAppApi(http, username="11111111111", password="", profile=_profile())

    code_key = asyncio.run(api.async_send_login_sms())
    session = asyncio.run(api.async_sms_login("123456", code_key))

    assert session.token == "s" * 36
    send_plain = _decrypt_request(http.requests[0]["data"])
    assert send_plain["quInfo"]["businessType"] == "login"
    login_plain = _decrypt_request(http.requests[1]["data"])
    assert login_plain["quInfo"]["code"] == "123456"
    assert login_plain["quInfo"]["codeKey"] == "sms-code-key"
    assert http.requests[1]["url"].endswith("/member/c2/f02")
