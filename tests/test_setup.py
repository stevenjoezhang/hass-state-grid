"""Regression tests for runtime profile refresh and entry update handling."""

import asyncio
import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, sentinel

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from custom_components.state_grid.const import (
    CONF_SYNTHETIC_DEVICE,
    CONF_UPDATE_INTERVAL_HOURS,
    DOMAIN,
    PLATFORMS,
)

setup = importlib.import_module("custom_components.state_grid.__init__")


def test_setup_passes_profile_provider_and_persists_each_new_cache(monkeypatch) -> None:
    original_state = {"seed": "stable", "token_cache": "old"}
    initial_state = {"seed": "stable", "token_cache": "initial"}
    renewed_state = {"seed": "stable", "token_cache": "renewed"}
    entry = SimpleNamespace(
        entry_id="test-entry",
        data={
            CONF_USERNAME: "test-user",
            CONF_PASSWORD: "test-password",
            CONF_SYNTHETIC_DEVICE: original_state,
        },
        options={},
        add_update_listener=Mock(return_value=sentinel.remove_listener),
    )
    update_entry = Mock(side_effect=lambda entry, *, data: setattr(entry, "data", data))
    hass = SimpleNamespace(
        data={},
        async_add_executor_job=AsyncMock(side_effect=lambda job: job()),
        config_entries=SimpleNamespace(
            async_update_entry=update_entry,
            async_forward_entry_setups=AsyncMock(),
        ),
    )
    build_profile = Mock(
        side_effect=[
            (sentinel.initial_profile, initial_state),
            (sentinel.renewed_profile, renewed_state),
            (sentinel.renewed_profile, renewed_state),
        ]
    )
    api_factory = Mock(return_value=sentinel.api)
    coordinator = SimpleNamespace(async_config_entry_first_refresh=AsyncMock())
    monkeypatch.setattr(setup, "build_device_profile", build_profile)
    monkeypatch.setattr(
        setup, "async_get_clientsession", Mock(return_value=sentinel.http)
    )
    monkeypatch.setattr(setup, "StateGridAppApi", api_factory)
    monkeypatch.setattr(
        setup, "StateGridDataCoordinator", Mock(return_value=coordinator)
    )

    async def run():
        assert await setup.async_setup_entry(hass, entry)
        assert entry.data[CONF_SYNTHETIC_DEVICE] == initial_state
        kwargs = api_factory.call_args.kwargs
        assert kwargs["profile"] is sentinel.initial_profile
        assert kwargs["password"] == "test-password"
        assert await kwargs["profile_provider"]() is sentinel.renewed_profile
        assert entry.data[CONF_SYNTHETIC_DEVICE] == renewed_state
        assert await kwargs["profile_provider"]() is sentinel.renewed_profile

    asyncio.run(run())

    assert [call.args[0] for call in build_profile.call_args_list] == [
        original_state,
        initial_state,
        renewed_state,
    ]
    assert update_entry.call_count == 2
    assert hass.async_add_executor_job.await_count == 3
    coordinator.async_config_entry_first_refresh.assert_awaited_once()
    hass.config_entries.async_forward_entry_setups.assert_awaited_once_with(
        entry, PLATFORMS
    )
    assert hass.data[DOMAIN][entry.entry_id].api is sentinel.api
    assert entry.data[CONF_USERNAME] == "test-user"


def test_internal_state_updates_do_not_reload_but_options_changes_do() -> None:
    entry = SimpleNamespace(
        entry_id="test-entry",
        options={CONF_UPDATE_INTERVAL_HOURS: 12},
        data={CONF_SYNTHETIC_DEVICE: {"token_cache": "refreshed"}},
    )
    coordinator = SimpleNamespace(configured_options=dict(entry.options))
    hass = SimpleNamespace(
        data={DOMAIN: {entry.entry_id: SimpleNamespace(coordinator=coordinator)}},
        config_entries=SimpleNamespace(async_reload=AsyncMock()),
    )

    async def run():
        await setup._async_reload_entry(hass, entry)
        hass.config_entries.async_reload.assert_not_awaited()
        entry.options = {CONF_UPDATE_INTERVAL_HOURS: 6}
        await setup._async_reload_entry(hass, entry)
        await setup._async_reload_entry(hass, entry)

    asyncio.run(run())

    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)
    assert coordinator.configured_options == entry.options
