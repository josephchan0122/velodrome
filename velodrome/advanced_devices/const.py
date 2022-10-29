# common module with enums and constants to use in AWS Lambda
# and backend project
from enum import IntEnum, unique

ADV_DEVICE_TABLE = "velodrome_adv_device"
ADV_DEVICE_FIRMWARE_TABLE = "velodrome_adv_device_firmware"
ADV_DEVICE_STATE_TABLE = "velodrome_adv_device_state"
ADV_DEVICE_CONFIG_CONTENT_TABLE = "velodrome_adv_device_config"
ADV_DEVICE_CONFIG_DEVICES_TABLE = "velodrome_adv_device_with_config"
ADV_DEVICE_DATA_STREAM_SAMPLES = "velodrome_adv_device_data_stream"
ADV_DEVICE_TYPE_TABLE = "velodrome_adv_device_type"

DJANGO_APP_NAME = "advanced_devices"


@unique
class FirmwareTypeEnum(IntEnum):
    """Supported firmware types for devices.
    """
    ANY_DEVICE = 1
    SANITIZING_STATION = 2


@unique
class DeviceStatusEnum(IntEnum):
    """Statuses.
    """
    ACTIVE = 1
    OUT_OF_SERVICE = 2


@unique
class DeviceTypeEnum(IntEnum):
    """Types of advanced devices.
    """
    DISPENSER = 1
    SOAP_DISPENSER = 2


@unique
class StateTypeEnum(IntEnum):
    """Device state types.
    """

    LOCATION_CHANGED = 1
    BATTERY_STATUS = 2
    FLUID_STATUS = 3
    FIRMWARE_AVAILABLE = 4
    FIRMWARE_INSTALLED = 5
    DISPLAY_STATUS = 6
    SERVICED = 7
    AMBIENT_STATE = 8


@unique
class DataStreamTypeEnum(IntEnum):
    """Types of values in data stream.
    """
    UNKNOWN = 0
    DEBUG_SENSOR_EVENT_VALID = 1
    DEBUG_SENSOR_EVENT_INVALID = 2


@unique
class DataStreamStatusEnum(IntEnum):
    """Statuses of the analysis results.
    """
    NEW = 1
    VALID = 2
    INVALID = 3
