"""Zero-Android config flow using the App's native SMS-login API."""

from __future__ import annotations

from collections.abc import Mapping
from functools import partial
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    StateGridApiError,
    StateGridAppApi,
    StateGridAuthenticationError,
    StateGridNetworkError,
)
from .const import (
    CONF_HISTORY_MONTHS,
    CONF_LOGIN_SESSION,
    CONF_SYNTHETIC_DEVICE,
    CONF_UPDATE_INTERVAL_HOURS,
    DEFAULT_HISTORY_MONTHS,
    DEFAULT_UPDATE_INTERVAL_HOURS,
    DOMAIN,
)
from .synthetic_device import build_device_profile, create_device_state

CONF_VERIFICATION_CODE = "verification_code"
CONF_PROVINCE = "province"
CONF_CITY = "city"
CONF_REGION = "region"


class StateGridConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Set up a direct App SMS login with a locally generated Turing token."""

    VERSION = 2

    def __init__(self) -> None:
        self._api: StateGridAppApi | None = None
        self._pending: dict[str, Any] = {}
        self._code_key = ""
        self._reauth_entry: config_entries.ConfigEntry | None = None

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        return StateGridOptionsFlow(config_entry)

    async def _build_api_and_send_sms(
        self,
        *,
        username: str,
        state: Mapping[str, Any],
        province: str,
        city: str,
        region: str,
    ) -> None:
        profile, updated_state = await self.hass.async_add_executor_job(
            partial(
                build_device_profile,
                state,
                province=province,
                city=city,
                region=region,
            )
        )
        self._api = StateGridAppApi(
            async_get_clientsession(self.hass),
            username=username,
            password="",
            profile=profile,
        )
        self._pending = {
            CONF_USERNAME: username,
            CONF_SYNTHETIC_DEVICE: updated_state,
            CONF_PROVINCE: province,
            CONF_CITY: city,
            CONF_REGION: region,
        }
        self._code_key = await self._api.async_send_login_sms()

    async def _finish(self):
        assert self._api is not None and self._api.login_session is not None
        data = {
            **self._pending,
            CONF_LOGIN_SESSION: self._api.login_session.as_dict(),
        }
        unique_id = self._api.login_session.user_id or self._pending[CONF_USERNAME]
        await self.async_set_unique_id(unique_id)
        if self._reauth_entry is not None:
            self._abort_if_unique_id_mismatch(reason="wrong_account")
            return self.async_update_reload_and_abort(
                self._reauth_entry, data_updates=data
            )
        self._abort_if_unique_id_configured()
        username = str(self._pending[CONF_USERNAME])
        return self.async_create_entry(title=f"国家电网 · {username[-4:]}", data=data)

    async def async_step_user(self, user_input=None):
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                await self._build_api_and_send_sms(
                    username=user_input[CONF_USERNAME],
                    state=create_device_state(),
                    province=user_input.get(CONF_PROVINCE, ""),
                    city=user_input.get(CONF_CITY, ""),
                    region=user_input.get(CONF_REGION, ""),
                )
            except StateGridNetworkError:
                errors["base"] = "cannot_connect"
            except (StateGridApiError, ValueError):
                errors["base"] = "unknown"
            else:
                return await self.async_step_sms_login()
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): str,
                    vol.Optional(CONF_PROVINCE, default=""): str,
                    vol.Optional(CONF_CITY, default=""): str,
                    vol.Optional(CONF_REGION, default=""): str,
                }
            ),
            errors=errors,
        )

    async def async_step_sms_login(self, user_input=None):
        errors: dict[str, str] = {}
        if user_input is not None:
            assert self._api is not None
            try:
                await self._api.async_sms_login(
                    user_input[CONF_VERIFICATION_CODE], self._code_key
                )
            except (StateGridAuthenticationError, ValueError):
                errors["base"] = "invalid_verification_code"
            except StateGridNetworkError:
                errors["base"] = "cannot_connect"
            except StateGridApiError:
                errors["base"] = "invalid_verification_code"
            else:
                self._code_key = ""
                return await self._finish()
        return self.async_show_form(
            step_id="sms_login",
            data_schema=vol.Schema({vol.Required(CONF_VERIFICATION_CODE): str}),
            errors=errors,
            description_placeholders={
                "phone_suffix": str(self._pending.get(CONF_USERNAME, ""))[-4:]
            },
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]):
        self._reauth_entry = self._get_reauth_entry()
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        assert self._reauth_entry is not None
        errors: dict[str, str] = {}
        if user_input is not None:
            data = self._reauth_entry.data
            try:
                await self._build_api_and_send_sms(
                    username=data[CONF_USERNAME],
                    state=data[CONF_SYNTHETIC_DEVICE],
                    province=str(data.get(CONF_PROVINCE, "")),
                    city=str(data.get(CONF_CITY, "")),
                    region=str(data.get(CONF_REGION, "")),
                )
            except StateGridNetworkError:
                errors["base"] = "cannot_connect"
            except (StateGridApiError, ValueError):
                errors["base"] = "unknown"
            else:
                return await self.async_step_sms_login()
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required("send_sms", default=True): bool}),
            errors=errors,
        )


class StateGridOptionsFlow(config_entries.OptionsFlow):
    """Configure polling and history depth."""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self.entry = entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_HISTORY_MONTHS,
                        default=self.entry.options.get(
                            CONF_HISTORY_MONTHS, DEFAULT_HISTORY_MONTHS
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=3)),
                    vol.Required(
                        CONF_UPDATE_INTERVAL_HOURS,
                        default=self.entry.options.get(
                            CONF_UPDATE_INTERVAL_HOURS,
                            DEFAULT_UPDATE_INTERVAL_HOURS,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=6, max=24)),
                }
            ),
        )
