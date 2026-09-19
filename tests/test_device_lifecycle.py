"""Offline regression tests for device and login token lifetimes."""

import asyncio
from dataclasses import replace

import pytest
from test_api_transport import FakeHttp, FakeResponse, _profile, _response_envelope

from custom_components.state_grid import synthetic_device
from custom_components.state_grid.api import (
    StateGridAppApi,
    StateGridAuthenticationError,
    StateGridDeviceVerificationRequired,
    StateGridInteractiveChallengeRequired,
)
from custom_components.state_grid.models import LoginSession

START = 1_800_000_000


def _result(code="0000", message="ok", **data):
    return _response_envelope(
        {
            "code": 1,
            "data": {"srvrt": {"resultCode": code, "resultMessage": message}, **data},
        }
    )


def _login_result():
    return _result(
        bizrt={
            "token": "renewed-token",
            "tokenExpireTime": 1296000,
            "userInfo": {"userId": "test-user"},
        }
    )


def _session():
    return LoginSession("old-token", "test-user", START + 1296000)


def test_token_cache_refresh_keeps_device_identity(monkeypatch):
    now = START
    monkeypatch.setattr(synthetic_device.time, "time", lambda: now)
    state = synthetic_device.create_device_state()
    original_state = dict(state)
    initial, state = synthetic_device.build_device_profile(state)

    now += 3 * 3600
    cached, state = synthetic_device.build_device_profile(state)
    assert cached == initial

    now += 3600
    boundary, state = synthetic_device.build_device_profile(state)
    assert boundary == initial

    now += 1
    refreshed, state = synthetic_device.build_device_profile(state)
    assert refreshed.device_token_tx != initial.device_token_tx
    assert refreshed.device_token_tx_time == str(now)
    assert (
        replace(
            refreshed,
            device_token_tx=initial.device_token_tx,
            device_token_tx_time=initial.device_token_tx_time,
        )
        == initial
    )
    assert all(state[key] == value for key, value in original_state.items())

    # A backwards clock adjustment must not pin a future-dated token forever.
    now -= 1
    corrected, _ = synthetic_device.build_device_profile(state)
    assert corrected.device_token_tx_time == str(now)


def test_long_running_query_and_relogin_use_fresh_device_token(monkeypatch):
    now = START
    monkeypatch.setattr(synthetic_device.time, "time", lambda: now)
    state = synthetic_device.create_device_state()
    keys = _profile()

    async def profile_provider():
        nonlocal state
        profile, state = await asyncio.to_thread(
            synthetic_device.build_device_profile, state
        )
        return replace(
            profile,
            server_public_key=keys.server_public_key,
            client_private_key=keys.client_private_key,
        )

    async def scenario():
        nonlocal now
        http = FakeHttp(
            _result(),
            _result("-200", "session invalidated"),
            _login_result(),
            _result(),
        )
        api = StateGridAppApi(
            http,
            username="11111111111",
            password="saved-password",
            profile=await profile_provider(),
            login_session=_session(),
            profile_provider=profile_provider,
        )
        await api._async_authenticated_data("test/query", {})
        now += 3 * 86400
        await api._async_authenticated_data("test/query", {})

        first, rejected, login, retried = [item["headers"] for item in http.requests]
        assert first["deviceTokenTX"] != rejected["deviceTokenTX"]
        assert (
            rejected["deviceTokenTX"]
            == login["deviceTokenTX"]
            == retried["deviceTokenTX"]
        )
        assert first["AppGuid"] == login["AppGuid"]
        assert login["deviceTokenTXTime"] == str(now)
        assert first["t"] == rejected["t"] == "old-token"
        assert login["t"] == ""
        assert retried["t"] == "renewed-token"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("code", "error_type"),
    [
        ("RK008", StateGridInteractiveChallengeRequired),
        ("4006", StateGridDeviceVerificationRequired),
    ],
)
def test_query_challenge_does_not_trigger_password_login(code, error_type):
    http = FakeHttp(_result(code, "security check"))
    session = LoginSession("valid-token", "test-user", 9999999999)
    api = StateGridAppApi(
        http,
        username="11111111111",
        password="saved-password",
        profile=_profile(),
        login_session=session,
    )
    with pytest.raises(error_type):
        asyncio.run(api._async_authenticated_data("test/query", {}))
    assert len(http.requests) == 1
    assert api.login_session is session


def test_failed_relogin_retains_both_upstream_errors():
    http = FakeHttp(
        _result("-200", "session invalidated"),
        _result("RK008", "security check failed"),
    )
    api = StateGridAppApi(
        http,
        username="11111111111",
        password="saved-password",
        profile=_profile(),
        login_session=LoginSession("old-token", "test-user", 9999999999),
    )
    with pytest.raises(StateGridInteractiveChallengeRequired) as caught:
        asyncio.run(api._async_authenticated_data("test/query", {}))
    assert caught.value.code == "RK008"
    assert caught.value.__cause__.code == "-200"
    assert api.login_session is None
    assert len(http.requests) == 2


def test_rejected_replacement_token_is_cleared_without_more_logins():
    http = FakeHttp(_result("-200"), _login_result(), _result("-201"))
    api = StateGridAppApi(
        http,
        username="11111111111",
        password="saved-password",
        profile=_profile(),
        login_session=LoginSession("old-token", "test-user", 9999999999),
    )
    with pytest.raises(StateGridAuthenticationError) as caught:
        asyncio.run(api._async_authenticated_data("test/query", {}))
    assert caught.value.code == "-201"
    assert api.login_session is None
    assert len(http.requests) == 3


def test_concurrent_login_requests_share_one_session(monkeypatch):
    original_text = FakeResponse.text

    async def delayed_text(self):
        await asyncio.sleep(0)
        return await original_text(self)

    monkeypatch.setattr(FakeResponse, "text", delayed_text)
    http = FakeHttp(_login_result())
    api = StateGridAppApi(
        http, username="11111111111", password="saved-password", profile=_profile()
    )

    async def scenario():
        sessions = await asyncio.gather(
            api.async_ensure_login(), api.async_ensure_login()
        )
        assert sessions[0] is sessions[1]

    asyncio.run(scenario())
    assert len(http.requests) == 1


def test_profile_refresh_does_not_change_the_request_session():
    """An old in-flight request must not clear a newer login's token."""
    http = FakeHttp(_result("-200", "old session rejected"), _result())
    original = LoginSession("old-token", "test-user", 9999999999)
    replacement = LoginSession("replacement", "test-user", 9999999999)
    profile = _profile()

    async def provider():
        # Simulate another login finishing while the profile executor runs.
        api.login_session = replacement
        await asyncio.sleep(0)
        return profile

    api = StateGridAppApi(
        http,
        username="11111111111",
        password="saved-password",
        profile=profile,
        login_session=original,
        profile_provider=provider,
    )
    asyncio.run(api._async_authenticated_data("test/query", {}))
    assert [request["headers"]["t"] for request in http.requests] == [
        "old-token",
        "replacement",
    ]
    assert api.login_session is replacement
    assert all(request["url"].endswith("test/query") for request in http.requests)
