"""Tests for password-first configuration flow policy."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResultType
from test_api_transport import FakeHttp, _profile, _response_envelope

from custom_components.state_grid import config_flow, synthetic_device
from custom_components.state_grid.api import (
    StateGridApiError,
    StateGridDeviceVerificationRequired,
)
from custom_components.state_grid.config_flow import StateGridConfigFlow
from custom_components.state_grid.const import CONF_AUTH_ERROR, CONF_SYNTHETIC_DEVICE


def test_initial_form_contains_only_username_and_password() -> None:
    result = asyncio.run(StateGridConfigFlow().async_step_user())

    fields = [marker.schema for marker in result["data_schema"].schema]
    assert result["type"] is FlowResultType.FORM
    assert fields == [CONF_USERNAME, CONF_PASSWORD]


def test_device_challenge_sends_sms_and_opens_code_form() -> None:
    class ChallengeApi:
        login_session = None

        async def async_login(self, **_kwargs):
            raise StateGridDeviceVerificationRequired("4006", "verification required")

        async def async_send_device_verification_sms(self) -> str:
            return "device-code-key"

    flow = StateGridConfigFlow()

    async def build_api(*, username: str, password: str, state) -> None:
        flow._api = ChallengeApi()
        flow._pending = {
            CONF_USERNAME: username,
            CONF_PASSWORD: password,
            CONF_SYNTHETIC_DEVICE: state,
        }

    flow._build_api = build_api
    result = asyncio.run(
        flow.async_step_user({CONF_USERNAME: "11111111111", CONF_PASSWORD: "password"})
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "device_verification"
    assert result["description_placeholders"] == {"phone_suffix": "1111"}
    assert flow._code_key == "device-code-key"


def test_upstream_error_message_is_exposed_without_length_limit() -> None:
    message = "完整上游错误详情" * 1_000

    class ErrorApi:
        login_session = None

        async def async_login(self, **_kwargs):
            raise StateGridApiError("UPSTREAM-42", message, source="srvrt")

    flow = StateGridConfigFlow()

    async def build_api(*, username: str, password: str, state) -> None:
        flow._api = ErrorApi()
        flow._pending = {
            CONF_USERNAME: username,
            CONF_PASSWORD: password,
            CONF_SYNTHETIC_DEVICE: state,
        }

    flow._build_api = build_api
    result = asyncio.run(
        flow.async_step_user({CONF_USERNAME: "11111111111", CONF_PASSWORD: "password"})
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "server_error"}
    assert result["description_placeholders"]["error_source"] == "srvrt"
    assert result["description_placeholders"]["error_code"] == "UPSTREAM-42"
    assert result["description_placeholders"]["error_message"] == message


def test_reauth_form_displays_original_failure(monkeypatch):
    flow = StateGridConfigFlow()
    original_error = (
        "srvrt -200 session invalidated -> srvrt RK008 security check failed"
    )
    entry = SimpleNamespace(
        data={
            CONF_USERNAME: "11111111111",
            CONF_PASSWORD: "password",
            CONF_SYNTHETIC_DEVICE: {"seed": "existing"},
            CONF_AUTH_ERROR: original_error,
        }
    )
    monkeypatch.setattr(flow, "_get_reauth_entry", lambda: entry)

    async def build_api(**kwargs):
        flow._pending = {CONF_PASSWORD: kwargs["password"]}
        assert kwargs["state"] is entry.data[CONF_SYNTHETIC_DEVICE]

    monkeypatch.setattr(flow, "_build_api", build_api)
    result = asyncio.run(flow.async_step_reauth(entry.data))
    assert result["step_id"] == "reauth_confirm"
    assert result["description_placeholders"]["auth_error"] == original_error


def test_reauth_refreshes_device_token_after_waiting_days(monkeypatch):
    now = 1_800_000_000
    monkeypatch.setattr(synthetic_device.time, "time", lambda: now)
    build_profile = config_flow.build_device_profile
    keys = _profile()

    def test_profile(state):
        profile, updated = build_profile(state)
        return replace(
            profile,
            server_public_key=keys.server_public_key,
            client_private_key=keys.client_private_key,
        ), updated

    monkeypatch.setattr(config_flow, "build_device_profile", test_profile)
    http = FakeHttp(
        _response_envelope(
            {
                "code": 1,
                "data": {
                    "srvrt": {"resultCode": "4006", "resultMessage": "SMS required"}
                },
            }
        ),
        _response_envelope(
            {
                "code": 1,
                "data": {
                    "srvrt": {"resultCode": "0000"},
                    "bizrt": {"codeKey": "sms-key"},
                },
            }
        ),
    )
    monkeypatch.setattr(config_flow, "async_get_clientsession", lambda hass: http)
    flow = StateGridConfigFlow()
    flow.hass = SimpleNamespace(async_add_executor_job=asyncio.to_thread)

    async def scenario():
        nonlocal now
        await flow._build_api(
            username="11111111111",
            password="password",
            state=synthetic_device.create_device_state(),
        )
        original = flow._api.profile
        seed = flow._pending[CONF_SYNTHETIC_DEVICE]["seed_b64"]
        now += 3 * 86400
        result = await flow.async_step_reauth_confirm({"continue": True})
        assert result["step_id"] == "device_verification"
        assert flow._pending[CONF_SYNTHETIC_DEVICE]["seed_b64"] == seed
        assert flow._api.profile.app_guid == original.app_guid
        assert flow._api.profile.device_token_tx != original.device_token_tx
        assert len(http.requests) == 2
        assert all(
            request["headers"]["deviceTokenTXTime"] == str(now)
            for request in http.requests
        )

    asyncio.run(scenario())


def test_setup_retry_keeps_same_device_seed(monkeypatch):
    flow = StateGridConfigFlow()
    states = []

    class ErrorApi:
        async def async_login(self):
            raise StateGridApiError("RK008", "security check failed")

    async def build_api(*, username, password, state):
        states.append(state)
        flow._api = ErrorApi()
        flow._pending = {CONF_USERNAME: username, CONF_SYNTHETIC_DEVICE: state}

    monkeypatch.setattr(flow, "_build_api", build_api)

    async def scenario():
        inputs = {CONF_USERNAME: "11111111111", CONF_PASSWORD: "password"}
        await flow.async_step_user(inputs)
        await flow.async_step_user(inputs)
        assert states[0] is states[1]

    asyncio.run(scenario())
