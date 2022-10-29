import logging

from django.db import transaction

from .const import FirmwareTypeEnum
from .helpers import clear_ini_config_content, get_version
from .models import (
    AdvDeviceFirmwareModel, DeviceConfigContentModel, DeviceModel,
    DeviceStatusEnum,
)


def actual_device_firmware_version(
    logger: logging.Logger,
    serial_number: str,
    version: str,
    firmware_type: int
) -> str:
    """Check the last available version.
    """
    current_version = get_version(version)
    options = []
    try:
        firmware_type = FirmwareTypeEnum(firmware_type).value
    except (TypeError, ValueError):
        logger.error(
            f"Unknown firmware type {firmware_type} in "
            f"request from {serial_number}"
        )
        return ""

    with transaction.atomic():
        devices = DeviceModel.objects.no_organizations().filter(
            serial_number=serial_number,
            firmware_type__in=(
                firmware_type, FirmwareTypeEnum.ANY_DEVICE.value
            ),
            status=DeviceStatusEnum.ACTIVE
        ).iterator()

        for device in devices:
            new_version = tuple(device.firmware_available_version)
            if new_version == (0, 0, 0):
                logger.warning(
                    "Not available firmware version for %s",
                    device
                )
                continue

            if new_version > current_version:
                options.append(new_version)

    ver = ""
    if len(options) > 1:
        logger.warning(
            "Check the unique of devices with SN: %s", serial_number
        )
    elif options:
        ver, *_ = options
        ver = ".".join(map(str, ver))

    return ver


def get_device_firmware(
    logger: logging.Logger,
    serial_number: str,
    version: str
) -> bytes:
    """Get data of firmware file.
    """

    organizations = DeviceModel.objects.no_organizations().filter(
        serial_number=serial_number,
        status=DeviceStatusEnum.ACTIVE
    ).values_list(
        "organization", flat=True
    )
    version = ".".join(map(str, get_version(version)))

    with transaction.atomic():
        record = AdvDeviceFirmwareModel.objects.no_organizations().filter(
            version_content=version,
            organization__in=organizations
        ).first()

    if record:
        data = record.binary.read()
        logger.info(
            "%s for SN: %s (data size %d)", record, serial_number, len(data)
        )
    else:
        data = b""

    return data


def get_new_device_config_content(
    logger: logging.Logger,
    serial_number: str,
    checksum: str
) -> dict:
    """Search last configuration by device list ot device type.
    """
    result = {}
    devices = DeviceModel.objects.filter(serial_number=serial_number)
    if devices.exists():
        actual_conf = DeviceConfigContentModel.objects.filter(
            devices__in=devices
        ).order_by("-updated").first()
        if not actual_conf:
            actual_conf = DeviceConfigContentModel.objects.filter(
                device_type__in=devices.values_list("device_type", flat=True)
            ).order_by("-updated").first()

        if actual_conf:
            chsm, content = clear_ini_config_content(actual_conf.content)
            result["content"] = content if chsm != checksum else None
            logger.debug(
                "Device '%s' configuration at %s updated: %s",
                serial_number,
                actual_conf.updated,
                "yes" if chsm != checksum else "no"
            )

    return result
