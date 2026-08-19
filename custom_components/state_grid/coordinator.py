"""DataUpdateCoordinator for 国家电网 daily electricity data."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    StateGridApiError,
    StateGridAppApi,
    StateGridAuthenticationError,
    StateGridDeviceVerificationRequired,
    StateGridNetworkError,
)
from .const import (
    CONF_HISTORY_MONTHS,
    CONF_LOGIN_SESSION,
    CONF_UPDATE_INTERVAL_HOURS,
    DEFAULT_HISTORY_MONTHS,
    DEFAULT_UPDATE_INTERVAL_HOURS,
    DOMAIN,
)
from .models import AccountUsage

_LOGGER = logging.getLogger(__name__)


class StateGridDataCoordinator(DataUpdateCoordinator[dict[str, AccountUsage]]):
    """Refresh all power accounts while sharing one App login session."""

    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, api: StateGridAppApi
    ) -> None:
        self.entry = entry
        self.api = api
        hours = int(
            entry.options.get(CONF_UPDATE_INTERVAL_HOURS, DEFAULT_UPDATE_INTERVAL_HOURS)
        )
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(hours=max(6, min(hours, 24))),
        )

    async def _async_update_data(self) -> dict[str, AccountUsage]:
        months = int(
            self.entry.options.get(CONF_HISTORY_MONTHS, DEFAULT_HISTORY_MONTHS)
        )
        old_session = self.entry.data.get(CONF_LOGIN_SESSION)
        try:
            result = await self.api.async_query_history(months=months)
        except StateGridDeviceVerificationRequired as error:
            raise ConfigEntryAuthFailed("device_verification_required") from error
        except StateGridAuthenticationError as error:
            raise ConfigEntryAuthFailed("invalid_auth") from error
        except (StateGridNetworkError, StateGridApiError) as error:
            raise UpdateFailed(str(error)) from error
        if self.api.login_session is not None:
            new_session = self.api.login_session.as_dict()
            if new_session != old_session:
                self.hass.config_entries.async_update_entry(
                    self.entry,
                    data={**self.entry.data, CONF_LOGIN_SESSION: new_session},
                )
        return result


@dataclass
class StateGridRuntimeData:
    api: StateGridAppApi
    coordinator: StateGridDataCoordinator
    remove_update_listener: Callable[[], None]
