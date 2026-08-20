from datetime import date

import pytest

from custom_components.state_grid.api import (
    StateGridAppApi,
    StateGridDeviceVerificationRequired,
    StateGridInteractiveChallengeRequired,
    build_daily_usage_payload,
)
from custom_components.state_grid.models import AccountUsage, DailyReading, PowerAccount


def _account(elec_type: str = "01", pro_no: str = "42101") -> PowerAccount:
    return PowerAccount.from_api(
        {
            "id": "account-1",
            "powerUserNo": "raw-cons-no",
            "powerUserNo_dst": "masked-cons-no",
            "proNo": pro_no,
            "orgNo": "org",
            "elecType": elec_type,
            "consName": "家庭",
        }
    )


def test_daily_payload_matches_recovered_micro_app_map() -> None:
    payload = build_daily_usage_payload(_account(), date(2026, 8, 1), date(2026, 8, 31))
    assert list(payload) == ["serviceCode", "source", "target", "data"]
    assert payload["serviceCode"] == "BCP_000026"
    assert payload["source"] == "app"
    assert payload["data"]["channelCode"] == "SGAPP"
    assert payload["data"]["consNo"] == "raw-cons-no"
    assert payload["data"]["consNosrc"] == "masked-cons-no"
    assert payload["data"]["funcCode"] == "ALIPAY_01"
    assert payload["data"]["startTime"] == "2026-08-01"
    assert payload["data"]["endTime"] == "2026-08-31"


@pytest.mark.parametrize(
    ("elec_type", "pro_no", "expected"),
    [("04", "42101", "02"), ("02", "11102", "02"), ("02", "42101", "01")],
)
def test_cons_type_rule(elec_type: str, pro_no: str, expected: str) -> None:
    assert _account(elec_type, pro_no).cons_type == expected


def test_daily_reading_and_month_aggregation() -> None:
    readings = tuple(
        DailyReading.from_api(item)
        for item in (
            {"day": "20260801", "dayElePq": "1.2", "thisVPq": "0.2"},
            {"day": "20260802", "dayElePq": "2.3", "thisVPq": "-"},
        )
    )
    usage = AccountUsage(_account(), readings, None)
    assert usage.latest.day == date(2026, 8, 2)
    assert usage.month_sum("usage", date(2026, 8, 19)) == 3.5
    assert usage.month_sum("valley", date(2026, 8, 19)) == 0.2
    assert readings[1].valley is None


def test_4006_is_device_verification_not_bad_password() -> None:
    with pytest.raises(StateGridDeviceVerificationRequired) as caught:
        StateGridAppApi._raise_for_error(
            {
                "code": 1,
                "data": {
                    "srvrt": {
                        "resultCode": "4006",
                        "resultMessage": "new device verification required",
                    }
                },
            }
        )
    assert caught.value.source == "srvrt"
    assert caught.value.code == "4006"
    assert caught.value.message == "new device verification required"


def test_rk008_is_interactive_challenge_not_bad_password() -> None:
    with pytest.raises(StateGridInteractiveChallengeRequired) as caught:
        StateGridAppApi._raise_for_error(
            {
                "code": 1,
                "data": {
                    "srvrt": {
                        "resultCode": "RK008",
                        "resultMessage": "interactive challenge required",
                    }
                },
            }
        )
    assert caught.value.source == "srvrt"
    assert caught.value.code == "RK008"
    assert caught.value.message == "interactive challenge required"
