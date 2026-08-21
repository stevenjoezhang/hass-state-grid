"""Async client for the recovered 网上国网 Android App API."""

from __future__ import annotations

import asyncio
import calendar
import json
import secrets
import time
from collections.abc import Mapping
from datetime import date, datetime
from typing import Any
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

from aiohttp import ClientError, ClientResponse, ClientSession, ClientTimeout

from .crypto import build_request_envelope, decrypt_response_envelope
from .login import (
    LoginMapContext,
    build_device_sms_payload,
    build_login_sms_payload,
    build_password_login_map,
    build_sms_login_map,
    login_header_md5,
)
from .models import (
    AccountBalance,
    AccountUsage,
    DailyReading,
    DeviceProfile,
    LoginSession,
    MeterReading,
    MonthlyBill,
    PowerAccount,
    YearlyBilling,
)

LOGIN_PATH = "emss-uia-center-front/member/c2/f01"
DEVICE_SMS_PATH = "emss-uia-center-front/member/c1/f01"
SMS_LOGIN_PATH = "emss-uia-center-front/member/c2/f02"
DAILY_USAGE_PATH = "emss-bia-bill-front/member/c11/f01"
MONTHLY_BILLS_PATH = "emss-bia-bill-front/member/c51/f04"
ACCOUNT_BALANCE_PATH = "emss-bia-balance-front/member/c16/f01"
METER_LIST_PATH = "emss-bia-bill-front/member/c11/f09"
METER_DETAIL_PATH = "emss-bia-bill-front/member/c11/f10"
AUTH_ERROR_CODES = {"-200", "-201"}
DEVICE_VERIFICATION_CODE = "4006"
INTERACTIVE_CHALLENGE_CODES = {"RK008"}
CHINA_TZ = ZoneInfo("Asia/Shanghai")


class StateGridError(Exception):
    """Base integration error."""


class StateGridNetworkError(StateGridError):
    """The API could not be reached or returned malformed transport data."""


class StateGridApiError(StateGridError):
    """The service rejected a request."""

    def __init__(self, code: str, message: str, *, source: str = "service") -> None:
        self.code = code
        self.message = message
        self.source = source
        super().__init__(f"State Grid API {source} error: {code} {message}".strip())


class StateGridAuthenticationError(StateGridApiError):
    """Credentials or a saved login token are no longer accepted."""


class StateGridDeviceVerificationRequired(StateGridAuthenticationError):
    """A password login requires one-time new-device SMS verification."""


class StateGridInteractiveChallengeRequired(StateGridAuthenticationError):
    """The server requires a browser or App-based interactive challenge."""


def _app_guid_new() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    prefix = "".join(secrets.choice(alphabet) for _ in range(40))
    stamp = datetime.now(CHINA_TZ).strftime("%Y%m%d%H%M%S%f")[:17]
    return f"{prefix}{stamp}{secrets.randbelow(900) + 100}"


def _request_timestamp() -> str:
    """Match DateUtil.getCurrentTimeSSS: 17 date digits plus 6 random digits."""
    stamp = datetime.now(CHINA_TZ).strftime("%Y%m%d%H%M%S%f")[:17]
    suffix = "".join(str(secrets.randbelow(10)) for _ in range(6))
    return stamp + suffix


def _month_period(base: date, offset: int) -> tuple[date, date]:
    month_index = base.year * 12 + base.month - 1 - offset
    year, month_zero = divmod(month_index, 12)
    month = month_zero + 1
    return date(year, month, 1), date(year, month, calendar.monthrange(year, month)[1])


def build_daily_usage_payload(
    account: PowerAccount, start_date: date, end_date: date
) -> dict[str, Any]:
    """Build the A10071400 Dailyelectricity request object."""
    return {
        "serviceCode": "BCP_000026",
        "source": "app",
        "target": account.pro_no,
        "data": {
            "acctId": "acctid01",
            "channelCode": "SGAPP",
            "consNo": account.cons_no,
            "consNosrc": account.cons_no_src,
            "endTime": end_date.isoformat(),
            "consType": account.cons_type,
            "funcCode": "ALIPAY_01",
            "orgNo": account.org_no,
            "proCode": account.pro_no,
            "promotCode": "1",
            "promotType": "1",
            "serialNo": "",
            "srvCode": "",
            "startTime": start_date.isoformat(),
            "userName": "acctid01",
        },
    }


def build_monthly_bills_payload(account: PowerAccount, year: int) -> dict[str, Any]:
    """Build the A10071400 Monthlycharge request object."""
    return {
        "serviceCode": "BCP_000026",
        "source": "app",
        "target": account.pro_no,
        "data": {
            "year": year,
            "consNo": account.cons_no,
            "provinceCode": account.pro_no,
            "startYm": f"{year}01",
            "endYm": f"{year}12",
            "funcCode": "ALIPAY_01",
        },
    }


def build_account_balance_payload(
    account: PowerAccount, user_id: str
) -> dict[str, Any]:
    """Build the native home-card account balance request object."""
    return {
        "serviceCode": "0101143",
        "source": "app",
        "target": account.pro_no,
        "data": {
            "srvCode": "",
            "serialNo": "",
            "channelCode": "0902",
            "funcCode": "A1007200",
            "acctId": user_id,
            "userName": "acctid01",
            "promotType": "1",
            "promotCode": "1",
            "userAccountId": user_id,
            "list": [
                {
                    "consNoSrc": account.cons_no_src,
                    "proCode": account.pro_no,
                    "sceneType": account.elec_type,
                    "consNo": account.cons_no,
                    "orgNo": account.org_no,
                }
            ],
        },
    }


def build_meter_payload(
    account: PowerAccount,
    reading_date: date,
    *,
    meter_bar_code: str = "",
) -> dict[str, Any]:
    """Build the A10071400 meter-list or meter-detail request object."""
    data = {
        "promotCode": "1",
        "promotType": "1",
        "funcCode": "A10071400",
        "acctId": "acctid01",
        "userName": "acctid01",
        "serialNo": "",
        "srvCode": "123",
        "channelCode": "SGAPP",
        "consNo": account.cons_no_src,
        "proCode": account.pro_no,
        "ymd": reading_date.isoformat(),
    }
    if meter_bar_code:
        data["meterBarCode"] = meter_bar_code
    return {
        "serviceCode": "0102719",
        "source": "app",
        "target": account.pro_no,
        "data": data,
    }


def _srvrt(response: Mapping[str, Any]) -> tuple[str, str, Mapping[str, Any]]:
    data = response.get("data")
    if not isinstance(data, Mapping):
        return "", str(response.get("message", "")), {}
    server = data.get("srvrt")
    if not isinstance(server, Mapping):
        return "", str(response.get("message", "")), data
    return (
        str(server.get("resultCode", "")),
        str(server.get("resultMessage", "")),
        data,
    )


def _power_accounts(user_info: Mapping[str, Any]) -> list[PowerAccount]:
    raw_accounts = user_info.get("powerUserList")
    if not isinstance(raw_accounts, list):
        raw_accounts = []
    result: list[PowerAccount] = []
    seen: set[str] = set()
    for value in raw_accounts:
        if not isinstance(value, Mapping):
            continue
        try:
            account = PowerAccount.from_api(value)
        except ValueError:
            continue
        if account.account_id not in seen:
            result.append(account)
            seen.add(account.account_id)
    return result


def _minimize_user_info(user_info: Mapping[str, Any]) -> dict[str, Any]:
    """Persist only fields needed for headers, devices and electricity queries."""
    result = {
        key: user_info[key]
        for key in ("userId", "addressProvince", "addressCity", "addressRegion")
        if key in user_info
    }
    account_keys = {
        "id",
        "userId",
        "powerUserNo",
        "consNo",
        "powerUserNo_dst",
        "consNo_dst",
        "proNo",
        "provinceId",
        "orgNo",
        "elecType",
        "constType",
        "consName",
        "userName",
        "nickname",
        "loginAccount",
        "elecAddr",
        "address",
        "consAddress",
    }
    raw_accounts = user_info.get("powerUserList")
    if isinstance(raw_accounts, list):
        result["powerUserList"] = [
            {key: value[key] for key in account_keys if key in value}
            for value in raw_accounts
            if isinstance(value, Mapping)
        ]
    return result


class StateGridAppApi:
    """Stateful async App API session."""

    def __init__(
        self,
        http: ClientSession,
        *,
        username: str,
        password: str,
        profile: DeviceProfile,
        login_session: LoginSession | None = None,
    ) -> None:
        self.http = http
        self.username = username
        self.password = password
        self.profile = profile
        self.login_session = login_session
        self._login_lock = asyncio.Lock()
        self._meter_cache: dict[tuple[str, date], MeterReading] = {}

    @property
    def context(self) -> LoginMapContext:
        return LoginMapContext(
            push_id=self.profile.push_id,
            push_token_ali=self.profile.push_token_ali,
            city_id=self.profile.address_city,
            province_id=self.profile.address_province,
            district_id=self.profile.address_region,
            device_ip=self.profile.device_ip,
            device_id=self.profile.device_id,
            android_release=self.profile.android_release,
            operator_type=self.profile.operator_type,
            device_model=self.profile.device_model,
        )

    @property
    def accounts(self) -> list[PowerAccount]:
        if self.login_session is None:
            return []
        return _power_accounts(self.login_session.user_info)

    def _province(self) -> str:
        if self.login_session:
            value = self.login_session.user_info.get("addressProvince")
            if value not in (None, ""):
                return str(value)
        return self.profile.province_header or self.profile.address_province

    def _headers(
        self,
        *,
        login_params: Mapping[str, Any] | None = None,
        authenticated: bool,
    ) -> dict[str, str]:
        current = self.login_session if authenticated else None
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "timeStamp": (
                datetime.now(CHINA_TZ).strftime("%Y%m%d%H%M%S")
                if login_params is not None
                else _request_timestamp()
            ),
            "t": current.token if current else "",
            "userid": current.user_id if current else "0",
            "AppGuid": self.profile.app_guid,
            "AppGuidNew": _app_guid_new(),
            "security": "android",
            "appcode": "WSGW-SG1001-APP",
            "datacenter": self.profile.datacenter,
            "AccessMethod": "App",
            "deviceTokenTX": self.profile.device_token_tx,
            "deviceTokenTXTime": self.profile.device_token_tx_time,
            "province": self._province() if authenticated else "",
            "version": "3.2.3",
            "wsgwType": "android",
            "ip": self.profile.device_ip,
            "os": "android",
            "User-Agent": "okhttp/3.14.9",
        }
        if login_params is not None:
            headers["md5"] = login_header_md5(login_params)
        return headers

    async def _post(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        authenticated: bool,
        login_params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        envelope = build_request_envelope(payload, self.profile.server_public_key)
        url = urljoin(self.profile.base_url.rstrip("/") + "/", path)
        try:
            async with self.http.post(
                url,
                data=json.dumps(envelope, ensure_ascii=False, separators=(",", ":")),
                headers=self._headers(
                    login_params=login_params, authenticated=authenticated
                ),
                timeout=ClientTimeout(total=30),
            ) as response:
                outer = await self._response_json(response)
        except (TimeoutError, ClientError) as error:
            raise StateGridNetworkError(
                "cannot reach the State Grid App gateway"
            ) from error
        try:
            if "respKey" not in outer or "encryptData" not in outer:
                raise ValueError("encrypted response fields are missing")
            plain = decrypt_response_envelope(outer, self.profile.client_private_key)
        except (KeyError, TypeError, ValueError, UnicodeError) as error:
            raise StateGridNetworkError(
                "cannot decrypt the State Grid App response"
            ) from error
        if not isinstance(plain, dict):
            raise StateGridNetworkError("State Grid App response is not a JSON object")
        return plain

    @staticmethod
    async def _response_json(response: ClientResponse) -> dict[str, Any]:
        text = await response.text()
        if response.status >= 500:
            raise StateGridNetworkError(
                f"State Grid gateway returned HTTP {response.status}"
            )
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:
            raise StateGridNetworkError(
                "State Grid gateway returned invalid JSON"
            ) from error
        if not isinstance(value, dict):
            raise StateGridNetworkError(
                "State Grid gateway returned an invalid envelope"
            )
        return value

    @staticmethod
    def _raise_for_error(response: Mapping[str, Any]) -> Mapping[str, Any]:
        top_code = str(response.get("code", ""))
        srv_code, message, data = _srvrt(response)
        code = srv_code or top_code
        source = "srvrt" if srv_code else "gateway"
        if code == DEVICE_VERIFICATION_CODE:
            raise StateGridDeviceVerificationRequired(code, message, source=source)
        if code in INTERACTIVE_CHALLENGE_CODES:
            raise StateGridInteractiveChallengeRequired(code, message, source=source)
        if code in AUTH_ERROR_CODES:
            raise StateGridAuthenticationError(code, message, source=source)
        if srv_code and srv_code != "0000":
            raise StateGridApiError(srv_code, message, source="srvrt")
        if top_code not in {"", "0", "1"}:
            raise StateGridApiError(
                top_code,
                message or str(response.get("message", "")),
                source="gateway",
            )
        return data

    async def async_login(
        self, *, verification_code: str = "", code_key: str = ""
    ) -> LoginSession:
        """Password login, optionally retrying with one-shot device SMS data."""
        if bool(verification_code) != bool(code_key):
            raise ValueError("verification_code and code_key must be provided together")
        if verification_code and (
            len(verification_code) != 6 or not verification_code.isdigit()
        ):
            raise ValueError("verification_code must contain exactly six digits")
        base = self.context
        context = LoginMapContext(
            **{
                **base.__dict__,
                "code": verification_code,
                "code_key": code_key,
            }
        )
        params = build_password_login_map(self.username, self.password, context=context)
        async with self._login_lock:
            response = await self._post(
                LOGIN_PATH,
                params,
                authenticated=False,
                login_params=params,
            )
            try:
                data = self._raise_for_error(response)
            except (
                StateGridDeviceVerificationRequired,
                StateGridInteractiveChallengeRequired,
            ):
                raise
            except StateGridApiError as error:
                raise StateGridAuthenticationError(
                    error.code, error.message, source=error.source
                ) from error
            bizrt = data.get("bizrt")
            if not isinstance(bizrt, Mapping) or not bizrt.get("token"):
                raise StateGridAuthenticationError(
                    "invalid_auth", "login returned no token"
                )
            raw_user_info = bizrt.get("userInfo")
            if isinstance(raw_user_info, list):
                user_info = next(
                    (dict(item) for item in raw_user_info if isinstance(item, Mapping)),
                    {},
                )
            elif isinstance(raw_user_info, Mapping):
                user_info = dict(raw_user_info)
            else:
                user_info = {}
            user_info = _minimize_user_info(user_info)
            user_id = str(user_info.get("userId") or bizrt.get("userId") or "0")
            try:
                lifetime = int(bizrt.get("tokenExpireTime") or 1296000)
            except (TypeError, ValueError):
                lifetime = 1296000
            self.login_session = LoginSession(
                token=str(bizrt["token"]),
                user_id=user_id,
                expires_at=time.time() + max(300, lifetime),
                user_info=user_info,
            )
            return self.login_session

    def _save_login_session(self, bizrt: Mapping[str, Any]) -> LoginSession:
        raw_user_info = bizrt.get("userInfo")
        if isinstance(raw_user_info, list):
            user_info = next(
                (dict(item) for item in raw_user_info if isinstance(item, Mapping)),
                {},
            )
        elif isinstance(raw_user_info, Mapping):
            user_info = dict(raw_user_info)
        else:
            user_info = {}
        user_info = _minimize_user_info(user_info)
        user_id = str(user_info.get("userId") or bizrt.get("userId") or "0")
        try:
            lifetime = int(bizrt.get("tokenExpireTime") or 1296000)
        except (TypeError, ValueError):
            lifetime = 1296000
        self.login_session = LoginSession(
            token=str(bizrt["token"]),
            user_id=user_id,
            expires_at=time.time() + max(300, lifetime),
            user_info=user_info,
        )
        return self.login_session

    async def async_send_login_sms(self) -> str:
        response = await self._post(
            DEVICE_SMS_PATH,
            build_login_sms_payload(self.username, self.context),
            authenticated=False,
        )
        data = self._raise_for_error(response)
        bizrt = data.get("bizrt")
        code_key = str(bizrt.get("codeKey", "")) if isinstance(bizrt, Mapping) else ""
        if not code_key:
            raise StateGridApiError(
                "missing_code_key",
                "SMS response did not contain codeKey",
                source="srvrt",
            )
        return code_key

    async def async_sms_login(self, code: str, code_key: str) -> LoginSession:
        params = build_sms_login_map(
            self.username, code, code_key, context=self.context
        )
        response = await self._post(
            SMS_LOGIN_PATH,
            params,
            authenticated=False,
            login_params=params,
        )
        try:
            data = self._raise_for_error(response)
        except StateGridApiError as error:
            raise StateGridAuthenticationError(
                error.code, error.message, source=error.source
            ) from error
        bizrt = data.get("bizrt")
        if not isinstance(bizrt, Mapping) or not bizrt.get("token"):
            raise StateGridAuthenticationError(
                "invalid_auth", "SMS login returned no token"
            )
        return self._save_login_session(bizrt)

    async def async_send_device_verification_sms(self) -> str:
        """Send the ``logindevice`` SMS and return its short-lived codeKey."""
        response = await self._post(
            DEVICE_SMS_PATH,
            build_device_sms_payload(self.username, self.context),
            authenticated=False,
        )
        data = self._raise_for_error(response)
        bizrt = data.get("bizrt")
        code_key = str(bizrt.get("codeKey", "")) if isinstance(bizrt, Mapping) else ""
        if not code_key:
            raise StateGridApiError(
                "missing_code_key",
                "SMS response did not contain codeKey",
                source="srvrt",
            )
        return code_key

    async def async_ensure_login(self) -> LoginSession:
        if self.login_session and self.login_session.expires_at > time.time() + 300:
            return self.login_session
        if not self.password:
            raise StateGridAuthenticationError(
                "saved_password_required", "a saved password is required"
            )
        return await self.async_login()

    async def _async_authenticated_data(
        self, path: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Post one authenticated request and retry once after token renewal."""
        await self.async_ensure_login()
        for attempt in range(2):
            response = await self._post(path, payload, authenticated=True)
            try:
                return self._raise_for_error(response)
            except StateGridAuthenticationError:
                if attempt:
                    raise
                self.login_session = None
                if not self.password:
                    raise
                await self.async_login()
        raise RuntimeError("unreachable")  # pragma: no cover

    @staticmethod
    def _raise_for_business_error(data: Mapping[str, Any], operation: str) -> None:
        code = str(data.get("rtnCode", data.get("returnCode", "")))
        if code not in {"", "0", "1", "0000", "000000"}:
            raise StateGridApiError(
                code,
                str(
                    data.get("rtnMsg") or data.get("returnMsg") or f"{operation} failed"
                ),
                source="business",
            )

    async def async_query_daily_usage(
        self, account: PowerAccount, start_date: date, end_date: date
    ) -> tuple[list[DailyReading], float | None]:
        payload = build_daily_usage_payload(account, start_date, end_date)
        data = await self._async_authenticated_data(DAILY_USAGE_PATH, payload)
        self._raise_for_business_error(data, "daily usage query")
        raw_readings = data.get("sevenEleList")
        readings: list[DailyReading] = []
        if isinstance(raw_readings, list):
            for value in raw_readings:
                if not isinstance(value, Mapping):
                    continue
                try:
                    readings.append(DailyReading.from_api(value))
                except ValueError:
                    continue
        total: float | None
        try:
            total = (
                float(data["totalPq"])
                if data.get("totalPq") not in (None, "", "-")
                else None
            )
        except (TypeError, ValueError):
            total = None
        return readings, total

    async def async_query_monthly_bills(
        self, account: PowerAccount, year: int
    ) -> YearlyBilling:
        """Query settled monthly electricity and charge totals for one year."""
        payload = build_monthly_bills_payload(account, year)
        data = await self._async_authenticated_data(MONTHLY_BILLS_PATH, payload)
        self._raise_for_business_error(data, "monthly bill query")
        return YearlyBilling.from_api(data, year)

    async def async_query_account_balance(
        self, account: PowerAccount
    ) -> AccountBalance | None:
        """Query prepaid balance or postpaid amount for one power account."""
        session = await self.async_ensure_login()
        payload = build_account_balance_payload(account, session.user_id)
        data = await self._async_authenticated_data(ACCOUNT_BALANCE_PATH, payload)
        self._raise_for_business_error(data, "account balance query")
        raw_items = data.get("list")
        if not isinstance(raw_items, list):
            return None
        item = next((value for value in raw_items if isinstance(value, Mapping)), None)
        return AccountBalance.from_api(item) if item is not None else None

    async def async_query_month_end_meter(
        self, account: PowerAccount, bill: MonthlyBill
    ) -> MeterReading | None:
        """Query the last meter reading on the latest settled billing date."""
        cache_key = (account.account_id, bill.month)
        if cache_key in self._meter_cache:
            return self._meter_cache[cache_key]
        reading_date = bill.end_date or date(
            bill.month.year,
            bill.month.month,
            calendar.monthrange(bill.month.year, bill.month.month)[1],
        )
        meter_data = await self._async_authenticated_data(
            METER_LIST_PATH,
            build_meter_payload(account, reading_date),
        )
        self._raise_for_business_error(meter_data, "meter list query")
        raw_meters = meter_data.get("list")
        if not isinstance(raw_meters, list):
            return None
        meter = next(
            (value for value in raw_meters if isinstance(value, Mapping)), None
        )
        if meter is None or not meter.get("meterBarCode"):
            return None

        detail_data = await self._async_authenticated_data(
            METER_DETAIL_PATH,
            build_meter_payload(
                account,
                reading_date,
                meter_bar_code=str(meter["meterBarCode"]),
            ),
        )
        self._raise_for_business_error(detail_data, "meter detail query")
        raw_readings = detail_data.get("list")
        if not isinstance(raw_readings, list):
            return None
        readings: list[tuple[float, float]] = []
        for value in raw_readings:
            if not isinstance(value, Mapping):
                continue
            try:
                readings.append((float(value.get("time", 0)), float(value["readPq"])))
            except (KeyError, TypeError, ValueError):
                continue
        if not readings:
            return None
        transformer_ratio: float | None
        try:
            transformer_ratio = float(meter["tFactor"])
        except (KeyError, TypeError, ValueError):
            transformer_ratio = None
        result = MeterReading(
            day=reading_date,
            reading=max(readings, key=lambda value: value[0])[1],
            transformer_ratio=transformer_ratio,
        )
        self._meter_cache[cache_key] = result
        return result

    async def async_query_history(
        self, *, months: int = 2, today: date | None = None
    ) -> dict[str, AccountUsage]:
        """Query complete calendar months and merge daily readings per account."""
        if months < 1 or months > 3:
            raise ValueError("months must be between 1 and 3")
        today = today or datetime.now(CHINA_TZ).date()
        await self.async_ensure_login()
        if not self.accounts:
            raise StateGridApiError(
                "no_power_account", "login returned no bound power account"
            )
        result: dict[str, AccountUsage] = {}
        for account in self.accounts:
            by_day: dict[date, DailyReading] = {}
            current_total: float | None = None
            for offset in range(months):
                start_date, end_date = _month_period(today, offset)
                readings, total = await self.async_query_daily_usage(
                    account, start_date, end_date
                )
                by_day.update({reading.day: reading for reading in readings})
                if offset == 0:
                    current_total = total

            current_billing: YearlyBilling | None = None
            monthly_bills: tuple[MonthlyBill, ...] = ()
            try:
                current_billing = await self.async_query_monthly_bills(
                    account, today.year
                )
                monthly_bills = current_billing.bills
                if not monthly_bills:
                    previous_billing = await self.async_query_monthly_bills(
                        account, today.year - 1
                    )
                    monthly_bills = previous_billing.bills
            except StateGridAuthenticationError:
                raise
            except StateGridApiError:
                # Some regions or account types do not expose settled bills.
                # Daily electricity remains useful, so keep those entities online.
                pass

            billing_account: AccountBalance | None = None
            try:
                billing_account = await self.async_query_account_balance(account)
            except StateGridAuthenticationError:
                raise
            except (StateGridApiError, StateGridNetworkError):
                # Balance is supplementary and varies by province/account type.
                pass

            latest_month_meter: MeterReading | None = None
            if monthly_bills:
                try:
                    latest_month_meter = await self.async_query_month_end_meter(
                        account, monthly_bills[-1]
                    )
                except StateGridAuthenticationError:
                    raise
                except (StateGridApiError, StateGridNetworkError):
                    # The App exposes meter detail only in supported regions.
                    pass
            result[account.account_id] = AccountUsage(
                account=account,
                readings=tuple(by_day[key] for key in sorted(by_day)),
                current_month_total=current_total,
                as_of=today,
                monthly_bills=monthly_bills,
                current_year_usage=(
                    current_billing.usage if current_billing is not None else None
                ),
                current_year_charge=(
                    current_billing.charge if current_billing is not None else None
                ),
                billing_account=billing_account,
                latest_month_meter=latest_month_meter,
            )
        return result
