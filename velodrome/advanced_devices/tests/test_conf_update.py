import logging
import uuid

from django.apps import apps as django_apps
import pytest

from velodrome.advanced_devices.api import get_new_device_config_content
from velodrome.advanced_devices.const import (
    DJANGO_APP_NAME, DeviceStatusEnum, DeviceTypeEnum, FirmwareTypeEnum,
)
from velodrome.advanced_devices.helpers import clear_ini_config_content


@pytest.fixture
def device_with_conf_record(org):
    """Device with configuration version.
    """
    device_model = django_apps.get_model(DJANGO_APP_NAME, "DeviceModel")
    conf_model = django_apps.get_model(
        DJANGO_APP_NAME, "DeviceConfigContentModel"
    )

    device = device_model(
        organization=org,
        serial_number=uuid.uuid4().hex[:16],
        device_type=DeviceTypeEnum.DISPENSER,
        status=DeviceStatusEnum.ACTIVE,
        firmware_type=FirmwareTypeEnum.ANY_DEVICE
    )
    device.save()
    conf = conf_model(
        device_type=DeviceTypeEnum.DISPENSER,
        content="[test]\nkey = {}\n".format(uuid.uuid4()),
        organization=org,
    )
    conf.save()
    conf.devices.set([device])

    return device, conf.content


@pytest.mark.django_db(databases=["default", "trackings"])
def test_get_new_device_config_content(device_with_conf_record):
    device, true_content = device_with_conf_record
    logger = logging.getLogger()
    data = get_new_device_config_content(
        logger, device.serial_number, uuid.uuid4().hex
    )
    assert data
    _, clear_content = clear_ini_config_content(true_content)
    assert data == {
        "content": clear_content
    }
