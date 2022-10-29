from datetime import timedelta
import logging
import uuid

from django.apps import apps as django_apps
import pytest

from velodrome.advanced_devices.api import (
    actual_device_firmware_version, get_device_firmware,
)
from velodrome.advanced_devices.const import (
    DJANGO_APP_NAME, DeviceStatusEnum, DeviceTypeEnum, FirmwareTypeEnum,
    StateTypeEnum,
)


@pytest.fixture
def device_with_new_firmware(org, get_firmware_hex):
    """Device with available version.
    """
    version = (0, 1, 2)
    device_model = django_apps.get_model(DJANGO_APP_NAME, "DeviceModel")

    device = device_model(
        organization=org,
        serial_number=uuid.uuid4().hex[:16],
        device_type=DeviceTypeEnum.DISPENSER,
        status=DeviceStatusEnum.ACTIVE,
        firmware_type=FirmwareTypeEnum.ANY_DEVICE
    )
    device.save()
    state_model = django_apps.get_model(DJANGO_APP_NAME, "DeviceStateModel")

    state = state_model(
        device=device,
        state_type=StateTypeEnum.FIRMWARE_AVAILABLE,
        attributes={"version": list(version)}
    )
    state.save()

    state_model(
        created=state.created - timedelta(hours=1),
        device=device,
        state_type=StateTypeEnum.BATTERY_STATUS,
        value=70
    ).save()

    state_model(
        created=state.created - timedelta(hours=2),
        device=device,
        state_type=StateTypeEnum.LOCATION_CHANGED,
        point="POINT(55.49154584941143 92.37684689210734)"
    ).save()

    AdvDeviceFirmwareModel = django_apps.get_model(
        DJANGO_APP_NAME, "AdvDeviceFirmwareModel"
    )

    AdvDeviceFirmwareModel(
        organization=org,
        version_content=".".join(map(str, version)),
        binary=get_firmware_hex("fw_mercury"),
        firmware_type=FirmwareTypeEnum.ANY_DEVICE
    ).save()

    return device


@pytest.mark.django_db(databases=["default", "trackings"])
def test_check_firmware_version(device_with_new_firmware):
    """Test for handler to check last available version.
    """
    logger = logging.getLogger()
    sn = device_with_new_firmware.serial_number
    result = actual_device_firmware_version(
        logger, sn, "0.0.8", FirmwareTypeEnum.SANITIZING_STATION
    )
    assert result
    assert result == "0.1.2"

    result = actual_device_firmware_version(
        logger, sn, "0,1,2", FirmwareTypeEnum.SANITIZING_STATION
    )
    assert result == ""

    result = actual_device_firmware_version(
        logger, sn, "0.1.3", FirmwareTypeEnum.SANITIZING_STATION
    )
    assert result == ""

    result = actual_device_firmware_version(
        logger, f"{sn}0001", "0.1.0", FirmwareTypeEnum.SANITIZING_STATION
    )
    assert result == ""


@pytest.mark.django_db(databases=["default", "trackings"])
def test_check_firmware_file_data(device_with_new_firmware):
    """Test for handler to get file of last available version.
    """
    logger = logging.getLogger()
    sn = device_with_new_firmware.serial_number

    data = get_device_firmware(logger, sn, "0,1,2")
    assert data

    data = get_device_firmware(logger, sn, "0.1.1")
    assert data == b""
