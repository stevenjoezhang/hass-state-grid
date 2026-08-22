from datetime import date

import pytest

from custom_components.state_grid.api import (
    StateGridAppApi,
    StateGridDeviceVerificationRequired,
    StateGridInteractiveChallengeRequired,
    build_account_balance_payload,
    build_daily_usage_payload,
    build_meter_payload,
    build_monthly_bills_payload,
)
from custom_components.state_grid.models import (
    AccountBalance,
    AccountUsage,
    DailyReading,
    PowerAccount,
    YearlyBilling,
)


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


def test_monthly_payload_matches_recovered_micro_app_map() -> None:
    payload = build_monthly_bills_payload(_account(), 2026)

    assert payload == {
        "serviceCode": "BCP_000026",
        "source": "app",
        "target": "42101",
        "data": {
            "year": 2026,
            "consNo": "raw-cons-no",
            "provinceCode": "42101",
            "startYm": "202601",
            "endYm": "202612",
            "funcCode": "ALIPAY_01",
        },
    }


def test_balance_payload_matches_recovered_native_home_map() -> None:
    payload = build_account_balance_payload(_account(), "user-id")

    assert payload == {
        "serviceCode": "0101143",
        "source": "app",
        "target": "42101",
        "data": {
            "srvCode": "",
            "serialNo": "",
            "channelCode": "0902",
            "funcCode": "A1007200",
            "acctId": "user-id",
            "userName": "acctid01",
            "promotType": "1",
            "promotCode": "1",
            "userAccountId": "user-id",
            "list": [
                {
                    "consNoSrc": "masked-cons-no",
                    "proCode": "42101",
                    "sceneType": "01",
                    "consNo": "raw-cons-no",
                    "orgNo": "org",
                }
            ],
        },
    }


def test_meter_payload_matches_recovered_micro_app_map() -> None:
    payload = build_meter_payload(
        _account(), date(2026, 7, 31), meter_bar_code="meter-1"
    )

    assert payload["serviceCode"] == "0102719"
    assert payload["source"] == "app"
    assert payload["data"]["funcCode"] == "A10071400"
    assert payload["data"]["consNo"] == "masked-cons-no"
    assert payload["data"]["ymd"] == "2026-07-31"
    assert payload["data"]["meterBarCode"] == "meter-1"


def test_monthly_billing_parses_current_app_response() -> None:
    billing = YearlyBilling.from_api(
        {
            "yearPq": "636.04",
            "yearAmt": "310.56",
            "list": [
                {
                    "ym": "202607",
                    "monthPq": "269",
                    "eleList": [
                        {
                            "begDate": "2026/07/01",
                            "endDate": "2026/07/31",
                            "pq": "269",
                            "amt": "131.35",
                        }
                    ],
                },
                {
                    "ym": "202606",
                    "monthPq": "367.04",
                    "eleList": [
                        {"pq": "300", "amt": "150"},
                        {"pq": "67.04", "amt": "29.21"},
                    ],
                },
            ],
        },
        2026,
    )

    assert billing.usage == 636.04
    assert billing.charge == 310.56
    assert [bill.month.isoformat() for bill in billing.bills] == [
        "2026-06-01",
        "2026-07-01",
    ]
    assert billing.bills[0].usage == 367.04
    assert billing.bills[0].charge == 179.21
    assert billing.bills[1].usage == 269
    assert billing.bills[1].charge == 131.35
    assert billing.bills[1].start_date == date(2026, 7, 1)
    assert billing.bills[1].end_date == date(2026, 7, 31)


def test_daily_reading_and_month_aggregation() -> None:
    readings = tuple(
        DailyReading.from_api(item)
        for item in (
            {
                "day": "20260801",
                "dayElePq": "1.2",
                "thisVPq": "0.2",
                "thisAmt": "0.66",
            },
            {"day": "20260802", "dayElePq": "2.3", "thisVPq": "-"},
            {"day": "20260803", "dayElePq": "-"},
        )
    )
    usage = AccountUsage(_account(), readings, None)
    assert usage.latest.day == date(2026, 8, 2)
    assert usage.latest.usage == 2.3
    assert usage.month_sum("usage", date(2026, 8, 19)) == 3.5
    assert usage.month_sum("valley", date(2026, 8, 19)) == 0.2
    assert readings[1].valley is None


def test_prepaid_balance_and_postpaid_amount_due_are_separate() -> None:
    prepaid = AccountBalance.from_api(
        {"consType": "1", "sumMoney": "86.50", "prepayBal": "0"}
    )
    postpaid = AccountBalance.from_api(
        {"consType": "0", "sumMoney": "42.30", "historyOwe": "5"}
    )

    assert prepaid.balance == 86.5
    assert prepaid.amount_due is None
    assert postpaid.balance is None
    assert postpaid.amount_due == 42.3


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
