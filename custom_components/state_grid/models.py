"""Data models for the 国家电网 integration."""

from __future__ import annotations

import re
import secrets
import string
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from typing import Any
from zoneinfo import ZoneInfo

from .crypto import HEX_64_RE, normalize_public_key

DEFAULT_BASE_URL = "https://csc-service.sgcc.com.cn:28630"
CHINA_TZ = ZoneInfo("Asia/Shanghai")


def generate_app_guid() -> str:
    """Generate the 60-character value produced by UUIDUtils.getAppGuidNew."""
    alphabet = string.ascii_letters + string.digits
    prefix = "".join(secrets.choice(alphabet) for _ in range(40))
    stamp = datetime.now(CHINA_TZ).strftime("%Y%m%d%H%M%S%f")[:17]
    return f"{prefix}{stamp}{secrets.randbelow(900) + 100}"


@dataclass(frozen=True)
class DeviceProfile:
    """Stable App identity and cryptographic material exported from Android."""

    server_public_key: str
    client_private_key: str
    device_token_tx: str
    device_token_tx_time: str
    app_guid: str
    device_id: str = "000000"
    device_model: str = "sdk_gphone64_arm64"
    android_release: str = "13"
    device_ip: str = "127.0.0.1"
    operator_type: str = ""
    push_id: str = "000000"
    push_token_ali: str = "000000"
    address_province: str = ""
    address_city: str = ""
    address_region: str = ""
    province_header: str = ""
    datacenter: str = "99"
    base_url: str = DEFAULT_BASE_URL

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> DeviceProfile:
        aliases = {
            "key1": "server_public_key",
            "key2": "client_private_key",
            "device_token": "device_token_tx",
            "device_token_time": "device_token_tx_time",
        }
        normalized = {
            aliases.get(str(key), str(key)): item for key, item in value.items()
        }
        allowed = set(cls.__dataclass_fields__)
        profile = cls(
            **{key: str(item) for key, item in normalized.items() if key in allowed}
        )
        profile.validate()
        return profile

    def validate(self) -> None:
        normalize_public_key(self.server_public_key)
        if not HEX_64_RE.fullmatch(self.client_private_key):
            raise ValueError(
                "client_private_key must be exactly 64 hexadecimal characters"
            )
        if not self.device_token_tx:
            raise ValueError("device_token_tx is required")
        if not re.fullmatch(r"\d{10,13}", self.device_token_tx_time):
            raise ValueError("device_token_tx_time must contain 10 to 13 digits")
        if not re.fullmatch(r"[A-Za-z0-9]{60}", self.app_guid):
            raise ValueError(
                "app_guid must be the 60-character value from the same App device"
            )
        if self.datacenter not in {"98", "99"}:
            raise ValueError("datacenter must be 98 or 99")
        if not self.base_url.startswith("https://"):
            raise ValueError("base_url must use HTTPS")

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class LoginSession:
    token: str
    user_id: str
    expires_at: float
    user_info: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any] | None) -> LoginSession | None:
        if not value or not value.get("token"):
            return None
        return cls(
            token=str(value["token"]),
            user_id=str(value.get("user_id", "0")),
            expires_at=float(value.get("expires_at", 0)),
            user_info=dict(value.get("user_info") or {}),
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PowerAccount:
    account_id: str
    cons_no: str
    cons_no_src: str
    pro_no: str
    org_no: str
    elec_type: str
    name: str
    address: str
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @classmethod
    def from_api(cls, value: Mapping[str, Any]) -> PowerAccount:
        def first(*keys: str, default: str = "") -> str:
            for key in keys:
                item = value.get(key)
                if item not in (None, ""):
                    return str(item)
            return default

        cons_no = first("powerUserNo", "consNo")
        cons_no_src = first("powerUserNo_dst", "consNo_dst", default=cons_no)
        account_id = first(
            "id", "userId", "consNo_dst", "powerUserNo_dst", default=cons_no
        )
        if not account_id or not cons_no:
            raise ValueError(
                "power account does not contain a usable account/consumption number"
            )
        return cls(
            account_id=account_id,
            cons_no=cons_no,
            cons_no_src=cons_no_src,
            pro_no=first("proNo", "provinceId"),
            org_no=first("orgNo"),
            elec_type=first("elecType", "constType"),
            name=first(
                "consName", "userName", "nickname", "loginAccount", default="用电户号"
            ),
            address=first("elecAddr", "address", "consAddress"),
            raw=dict(value),
        )

    @property
    def masked_number(self) -> str:
        if not self.cons_no_src:
            return ""
        return "*" * max(0, len(self.cons_no_src) - 4) + self.cons_no_src[-4:]

    @property
    def cons_type(self) -> str:
        if self.elec_type == "04" or (
            self.elec_type == "02" and self.pro_no == "11102"
        ):
            return "02"
        return "01"


def _number(value: Any) -> float | None:
    if value in (None, "", "-", "--"):
        return None
    try:
        return float(str(value).replace(",", ""))
    except ValueError:
        return None


def _day(value: Any) -> date:
    text = str(value)
    for pattern in ("%Y%m%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, pattern).date()
        except ValueError:
            continue
    raise ValueError(f"unsupported electricity date: {text!r}")


def _month(value: Any) -> date:
    text = str(value).strip()
    for pattern in ("%Y%m", "%Y-%m", "%Y/%m"):
        try:
            parsed = datetime.strptime(text, pattern)
        except ValueError:
            continue
        return date(parsed.year, parsed.month, 1)
    raise ValueError(f"unsupported electricity month: {text!r}")


def _sum_numbers(values: list[Any]) -> float | None:
    numbers = [number for value in values if (number := _number(value)) is not None]
    return round(sum(numbers), 6) if numbers else None


@dataclass(frozen=True)
class DailyReading:
    day: date
    usage: float | None
    charge: float | None
    valley: float | None
    flat: float | None
    peak: float | None
    tip: float | None

    @classmethod
    def from_api(cls, value: Mapping[str, Any]) -> DailyReading:
        return cls(
            day=_day(value.get("day")),
            usage=_number(value.get("dayElePq")),
            charge=_number(value.get("thisAmt")),
            valley=_number(value.get("thisVPq")),
            flat=_number(value.get("thisNPq")),
            peak=_number(value.get("thisPPq")),
            tip=_number(value.get("thisTPq")),
        )

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["day"] = self.day.isoformat()
        return result


@dataclass(frozen=True)
class MonthlyBill:
    """One settled billing month returned by the App monthly-charge endpoint."""

    month: date
    usage: float | None
    charge: float | None

    @classmethod
    def from_api(cls, value: Mapping[str, Any]) -> MonthlyBill:
        settlements = value.get("eleList")
        if not isinstance(settlements, list):
            settlements = []
        mappings = [item for item in settlements if isinstance(item, Mapping)]

        usage = _number(value.get("monthPq", value.get("monthEleNum", value.get("pq"))))
        if usage is None:
            usage = _sum_numbers([item.get("pq") for item in mappings])

        charge = _number(
            value.get("monthAmt", value.get("monthEleCost", value.get("amt")))
        )
        if charge is None:
            charge = _sum_numbers([item.get("amt") for item in mappings])

        return cls(
            month=_month(value.get("ym", value.get("month"))),
            usage=usage,
            charge=charge,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "month": self.month.strftime("%Y-%m"),
            "usage": self.usage,
            "charge": self.charge,
        }


@dataclass(frozen=True)
class YearlyBilling:
    """Settled monthly bills and annual totals for one calendar year."""

    year: int
    bills: tuple[MonthlyBill, ...]
    usage: float | None
    charge: float | None

    @classmethod
    def from_api(cls, value: Mapping[str, Any], year: int) -> YearlyBilling:
        raw_bills = value.get("list")
        if not isinstance(raw_bills, list):
            raw_bills = value.get("mothEleList")
        if not isinstance(raw_bills, list):
            raw_bills = []

        by_month: dict[date, MonthlyBill] = {}
        for item in raw_bills:
            if not isinstance(item, Mapping):
                continue
            try:
                bill = MonthlyBill.from_api(item)
            except ValueError:
                continue
            by_month[bill.month] = bill
        bills = tuple(by_month[month] for month in sorted(by_month))

        usage = _number(value.get("yearPq"))
        if usage is None:
            usage = _sum_numbers([bill.usage for bill in bills])
        charge = _number(value.get("yearAmt"))
        if charge is None:
            charge = _sum_numbers([bill.charge for bill in bills])
        return cls(year=year, bills=bills, usage=usage, charge=charge)


@dataclass(frozen=True)
class AccountUsage:
    """Merged daily history for one power account."""

    account: PowerAccount
    readings: tuple[DailyReading, ...]
    current_month_total: float | None
    as_of: date = field(default_factory=lambda: datetime.now(CHINA_TZ).date())
    monthly_bills: tuple[MonthlyBill, ...] = ()
    current_year_usage: float | None = None
    current_year_charge: float | None = None

    @property
    def latest(self) -> DailyReading | None:
        return self.readings[-1] if self.readings else None

    @property
    def latest_bill(self) -> MonthlyBill | None:
        return self.monthly_bills[-1] if self.monthly_bills else None

    def month_sum(self, field_name: str, today: date | None = None) -> float | None:
        today = today or self.as_of
        values = [
            getattr(reading, field_name)
            for reading in self.readings
            if reading.day.year == today.year
            and reading.day.month == today.month
            and getattr(reading, field_name) is not None
        ]
        return round(sum(values), 6) if values else None
