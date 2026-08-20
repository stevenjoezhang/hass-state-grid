"""Tests for password-first configuration flow policy."""

import asyncio

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResultType

from custom_components.state_grid.api import (
    StateGridApiError,
    StateGridDeviceVerificationRequired,
)
from custom_components.state_grid.config_flow import StateGridConfigFlow
from custom_components.state_grid.const import CONF_SYNTHETIC_DEVICE


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
