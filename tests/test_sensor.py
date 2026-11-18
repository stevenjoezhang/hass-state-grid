"""Tests for Home Assistant sensor metadata compatibility."""

from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass

from custom_components.state_grid.sensor import REMOVED_SENSOR_KEYS, SENSORS


def test_historical_daily_sensors_do_not_claim_live_statistics() -> None:
    descriptions = {description.key: description for description in SENSORS}

    daily_usage = descriptions["latest_daily_usage"]
    assert daily_usage.device_class is SensorDeviceClass.ENERGY
    assert daily_usage.state_class is None

    latest_month_usage = descriptions["latest_month_usage"]
    assert latest_month_usage.device_class is SensorDeviceClass.ENERGY
    assert latest_month_usage.state_class is None

    latest_month_charge = descriptions["latest_month_charge"]
    assert latest_month_charge.device_class is SensorDeviceClass.MONETARY
    assert latest_month_charge.state_class is None


def test_time_of_use_sensors_are_opt_in() -> None:
    descriptions = {description.key: description for description in SENSORS}

    assert descriptions["current_month_usage"].device_class is SensorDeviceClass.ENERGY
    assert (
        descriptions["current_month_usage"].state_class
        is SensorStateClass.TOTAL_INCREASING
    )
    assert REMOVED_SENSOR_KEYS.isdisjoint(descriptions)
    assert "latest_daily_charge" in REMOVED_SENSOR_KEYS

    for key in (
        "latest_daily_valley",
        "latest_daily_flat",
        "latest_daily_peak",
        "latest_daily_tip",
        "current_month_valley",
        "current_month_flat",
        "current_month_peak",
        "current_month_tip",
        "current_month_valley_share",
        "history_owe",
    ):
        assert descriptions[key].entity_registry_enabled_default is False

    assert descriptions["latest_daily_valley"].state_class is None
    assert (
        descriptions["current_month_valley"].state_class
        is SensorStateClass.TOTAL_INCREASING
    )
    assert descriptions["current_month_valley_share"].state_class is (
        SensorStateClass.MEASUREMENT
    )
    assert descriptions["history_owe"].device_class is SensorDeviceClass.MONETARY
    assert descriptions["history_owe"].state_class is None


def test_current_year_sensors_are_totals() -> None:
    descriptions = {description.key: description for description in SENSORS}

    assert descriptions["current_year_usage"].device_class is SensorDeviceClass.ENERGY
    assert (
        descriptions["current_year_usage"].state_class
        is SensorStateClass.TOTAL_INCREASING
    )
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
