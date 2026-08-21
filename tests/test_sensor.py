"""Tests for Home Assistant sensor metadata compatibility."""

from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass

from custom_components.state_grid.sensor import REMOVED_SENSOR_KEYS, SENSORS


def test_historical_daily_sensors_do_not_claim_live_statistics() -> None:
    descriptions = {description.key: description for description in SENSORS}

    daily_usage = descriptions["latest_daily_usage"]
    assert daily_usage.device_class is SensorDeviceClass.ENERGY
    assert daily_usage.state_class is None

    daily_charge = descriptions["latest_daily_charge"]
    assert daily_charge.device_class is SensorDeviceClass.MONETARY
    assert daily_charge.state_class is None

    latest_month_usage = descriptions["latest_month_usage"]
    assert latest_month_usage.device_class is SensorDeviceClass.ENERGY
    assert latest_month_usage.state_class is None

    latest_month_charge = descriptions["latest_month_charge"]
    assert latest_month_charge.device_class is SensorDeviceClass.MONETARY
    assert latest_month_charge.state_class is None


def test_only_current_month_total_remains() -> None:
    descriptions = {description.key: description for description in SENSORS}

    assert descriptions["current_month_usage"].device_class is SensorDeviceClass.ENERGY
    assert descriptions["current_month_usage"].state_class is SensorStateClass.TOTAL
    assert REMOVED_SENSOR_KEYS.isdisjoint(descriptions)


def test_current_year_sensors_are_totals() -> None:
    descriptions = {description.key: description for description in SENSORS}

    assert descriptions["current_year_usage"].device_class is SensorDeviceClass.ENERGY
    assert descriptions["current_year_usage"].state_class is SensorStateClass.TOTAL
    assert (
        descriptions["current_year_charge"].device_class is SensorDeviceClass.MONETARY
    )
    assert descriptions["current_year_charge"].state_class is SensorStateClass.TOTAL


def test_balance_and_meter_sensors_use_compatible_metadata() -> None:
    descriptions = {description.key: description for description in SENSORS}

    for key in ("account_balance", "amount_due"):
        assert descriptions[key].device_class is SensorDeviceClass.MONETARY
        assert descriptions[key].state_class is None
    assert descriptions["latest_month_meter_reading"].device_class is None
    assert descriptions["latest_month_meter_reading"].state_class is None
