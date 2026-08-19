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
    AccountUsage,
    DailyReading,
    DeviceProfile,
    LoginSession,
    PowerAccount,
)

LOGIN_PATH = "emss-uia-center-front/member/c2/f01"
DEVICE_SMS_PATH = "emss-uia-center-front/member/c1/f01"
SMS_LOGIN_PATH = "emss-uia-center-front/member/c2/f02"
DAILY_USAGE_PATH = "emss-bia-bill-front/member/c11/f01"
AUTH_ERROR_CODES = {"-200", "-201"}
DEVICE_VERIFICATION_CODE = "4006"
CHINA_TZ = ZoneInfo("Asia/Shanghai")


class StateGridError(Exception):
    """Base integration error."""


class StateGridNetworkError(StateGridError):
    """The API could not be reached or returned malformed transport data."""


class StateGridApiError(StateGridError):
    """The service rejected a request."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(
            f"State Grid API rejected the request: {code} {message}".strip()
        )


class StateGridAuthenticationError(StateGridApiError):
    """Credentials or a saved login token are no longer accepted."""


class StateGridDeviceVerificationRequired(StateGridAuthenticationError):
    """A password login requires one-time new-device SMS verification."""


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
        if code == DEVICE_VERIFICATION_CODE:
            raise StateGridDeviceVerificationRequired(code, message)
        if code in AUTH_ERROR_CODES:
            raise StateGridAuthenticationError(code, message)
        if srv_code and srv_code != "0000":
            raise StateGridApiError(srv_code, message)
        if top_code not in {"", "0", "1"}:
            raise StateGridApiError(
                top_code, message or str(response.get("message", ""))
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
            except StateGridDeviceVerificationRequired:
                raise
            except StateGridApiError as error:
                raise StateGridAuthenticationError(error.code, error.message) from error
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
                "missing_code_key", "SMS response did not contain codeKey"
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
            raise StateGridAuthenticationError(error.code, error.message) from error
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
                "missing_code_key", "SMS response did not contain codeKey"
            )
        return code_key

    async def async_ensure_login(self) -> LoginSession:
        if self.login_session and self.login_session.expires_at > time.time() + 300:
            return self.login_session
        if not self.password:
            raise StateGridAuthenticationError(
                "sms_reauth_required", "SMS reauthentication is required"
            )
        return await self.async_login()

    async def async_query_daily_usage(
        self, account: PowerAccount, start_date: date, end_date: date
    ) -> tuple[list[DailyReading], float | None]:
        await self.async_ensure_login()
        payload = build_daily_usage_payload(account, start_date, end_date)
        for attempt in range(2):
            response = await self._post(
                DAILY_USAGE_PATH,
                payload,
                authenticated=True,
            )
            try:
                data = self._raise_for_error(response)
                break
            except StateGridAuthenticationError:
                if attempt:
                    raise
                self.login_session = None
                if not self.password:
                    raise
                await self.async_login()
        else:  # pragma: no cover - loop always breaks or raises
            raise RuntimeError("unreachable")
        return_code = str(data.get("returnCode", ""))
        if return_code not in {"", "0", "1", "0000"}:
            raise StateGridApiError(
                return_code,
                str(data.get("returnMsg") or "daily usage query failed"),
            )
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
            result[account.account_id] = AccountUsage(
                account=account,
                readings=tuple(by_day[key] for key in sorted(by_day)),
                current_month_total=current_total,
                as_of=today,
            )
        return result
