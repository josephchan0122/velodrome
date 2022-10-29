# - don't use mexins for models clsses
# - don't inject business logic in models classes,
#   keep it as simple active record models
# - don't expect that django signals will implement logic with instances,
#   it usually means you should to have one more level of
#   abstraction above the model

from collections.abc import Iterable
from datetime import datetime
from decimal import Decimal
from enum import Enum
import typing
import uuid

from django.contrib.gis.db.models import PointField
from django.contrib.postgres.fields import ArrayField, JSONField
from django.core.exceptions import ValidationError
from django.db import models, transaction

from .const import (
    ADV_DEVICE_CONFIG_CONTENT_TABLE, ADV_DEVICE_CONFIG_DEVICES_TABLE,
    ADV_DEVICE_DATA_STREAM_SAMPLES, ADV_DEVICE_FIRMWARE_TABLE,
    ADV_DEVICE_STATE_TABLE, ADV_DEVICE_TABLE, ADV_DEVICE_TYPE_TABLE,
    DataStreamStatusEnum, DataStreamTypeEnum, DeviceStatusEnum, DeviceTypeEnum,
    FirmwareTypeEnum, StateTypeEnum,
)
from .helpers import clear_ini_config_content, create_chsum_uuid, get_version
from .storage_api import private_storage

DEFAULT_DECIMAL_OPTIONS = dict(max_digits=12, decimal_places=3, default=0)


def create_choices_items(
    enum_class: typing.Type[Enum]
) -> typing.List[typing.Tuple[typing.Any, typing.Any]]:
    """Create list of variants to choise.
    """
    assert issubclass(enum_class, Enum)
    return sorted(
        (val, enum_item.name)
        for val, enum_item in enum_class._value2member_map_.items()
    )


class QueryManager(models.Manager):
    """Organization filter.
    """
    _state = {}

    filter_field = {
        ADV_DEVICE_TABLE: "organization__in",
        ADV_DEVICE_FIRMWARE_TABLE: "organization__in",
        ADV_DEVICE_STATE_TABLE: "device__organization__in",
        ADV_DEVICE_CONFIG_CONTENT_TABLE: "organization__in",
        ADV_DEVICE_DATA_STREAM_SAMPLES: "device__organization__in",
    }

    def no_organizations(self):
        self._state["organizations"] = None
        return self.get_queryset()

    def get_queryset(self):
        table = self.model._meta.db_table
        queryset = super().get_queryset()
        field = self.filter_field.get(table)
        organizations = self._state.get("organizations")
        if field and organizations:
            queryset = queryset.filter(**{field: organizations})

        return queryset


class DeviceTypeModel(models.Model):
    """Brand and types of devices.
    """

    brand = models.CharField("Brand", max_length=64)
    device_type = models.IntegerField(
        "Type",
        choices=create_choices_items(DeviceTypeEnum)
    )
    unique_key = models.CharField(
        "Unique key", max_length=36, default="", unique=True
    )
    name = models.CharField("Product name", max_length=64, default="")
    model = models.CharField("Model (or incept date)", max_length=64)
    formula = models.CharField(
        "Formula",
        max_length=64,
        default="",
        choices=(
            ("", "unknown"),
            ("gel or liquid", "gel or liquid"),
            ("gel", "gel"),
            ("liquid", "liquid"),
            ("foam", "foam"),
        )
    )
    amount_dispensed = models.DecimalField(
        "Amount dispensed", **DEFAULT_DECIMAL_OPTIONS
    )
    reservoir = models.DecimalField(
        "Size of reservoir", **DEFAULT_DECIMAL_OPTIONS
    )
    attributes = JSONField("Attributes", default=dict, blank=True)

    class Meta:
        db_table = ADV_DEVICE_TYPE_TABLE
        verbose_name = "Advanced devices type"

    def __str__(self) -> str:
        """Device type info
        """
        return f"{self.name} {self.model}"

    @property
    def percent_dispensed(self) -> Decimal:
        """Dispensed percent.
        """
        return Decimal(
            self.amount_dispensed / (self.reservoir or 1) * 1000
        ).quantize(Decimal("0.0001"))


class DeviceModel(models.Model):
    """All possible combination
    """
    objects = QueryManager()

    _state_cache: typing.Optional[
        typing.List[
            typing.Tuple[datetime, StateTypeEnum, Decimal, dict, float, float]
        ]
    ]

    organization = models.ForeignKey(
        "lock8.Organization",
        verbose_name="Organization",
        related_name="adv_devices",
        related_query_name="adv_devices",
        on_delete=models.CASCADE
    )
    serial_number = models.CharField("SN", max_length=64)
    device_model = models.ForeignKey(
        DeviceTypeModel,
        null=True,
        verbose_name="Model (type)",
        related_name="adv_devices",
        related_query_name="adv_devices",
        on_delete=models.CASCADE
    )
    device_type = models.IntegerField(
        "Device base type/group",
        db_index=True,
        choices=create_choices_items(DeviceTypeEnum)
    )
    status = models.IntegerField(
        "System status",
        choices=create_choices_items(DeviceStatusEnum)
    )
    firmware_type = models.IntegerField(
        "Firmware type",
        choices=create_choices_items(FirmwareTypeEnum)
    )

    class Meta:
        db_table = ADV_DEVICE_TABLE
        verbose_name = "Advanced device"
        indexes = [
            models.Index(fields=["organization", "serial_number"]),
        ]

    def __str__(self) -> str:
        """Device info
        """
        if self.device_type:
            device_type = DeviceTypeEnum(self.device_type).name
        else:
            device_type = "Unknown"

        return (
            f"{device_type} (sn: {self.serial_number} "
            f"id: {self.pk} org: {self.organization_id})"
        )

    def save(self, *args, **kwargs):
        if self.device_model:
            self.device_type = self.device_model.device_type

        return super().save(args, kwargs)

    def get_state_history(self) -> typing.List[
        typing.Tuple[datetime, StateTypeEnum, Decimal, dict, str, str]
    ]:
        """All states from log.
        """
        state_cache = getattr(self, "_state_cache", None)
        if not isinstance(state_cache, list):
            with transaction.atomic():
                state_cache = [
                    (
                        dt,
                        StateTypeEnum(state),
                        Decimal(val),
                        md or {},
                        str(p.x if p else ""),
                        str(p.y if p else ""),
                    )
                    for dt, state, val, md, p in
                    self.state_history.order_by("created").values_list(
                        "created",
                        "state_type",
                        "value",
                        "attributes",
                        "point"
                    )
                ]

        self._state_cache = state_cache
        return state_cache

    @property
    def firmware_version(self) -> typing.Tuple[int, int, int]:
        """Last soft version.
        """
        result = None
        for _, state, _, attributes, *_ in self.get_state_history():
            if state == StateTypeEnum.FIRMWARE_INSTALLED:
                result = attributes.get("version")
                break

        if not result:
            result = [0, 0, 0]

        return tuple(result)

    @property
    def firmware_available_version(self) -> typing.Tuple[int, int, int]:
        """Available soft version.
        """
        result = None
        for _, state, _, attributes, *_ in self.get_state_history():
            if state == StateTypeEnum.FIRMWARE_AVAILABLE:
                result = attributes.get("version")
                break

        if not result:
            result = [0, 0, 0]

        return tuple(result)

    @property
    def battery_status(self) -> Decimal:
        """Last battery status.
        """
        result = Decimal(0)
        for _, state, val, *_ in self.get_state_history():
            if state == StateTypeEnum.FIRMWARE_INSTALLED:
                result = val
                break

        return result

    @property
    def display_status_name(self) -> str:
        """Status name.
        """
        result = "UNKNOWN"
        for _, state, _, data, *_ in self.get_state_history():
            if state == StateTypeEnum.DISPLAY_STATUS:
                if data:
                    result = data.get("name") or ""

                break

        return result


class AdvDeviceFirmwareModel(models.Model):
    """Advanced devices firmware
    """
    objects = QueryManager()

    organization = models.ForeignKey(
        "lock8.Organization",
        verbose_name="Organization",
        related_name="adv_device_firmwares",
        related_query_name="adv_device_firmwares",
        on_delete=models.CASCADE
    )

    version_content = models.CharField(max_length=54)
    binary = models.FileField(
        upload_to="adv_device_firmwares",
        storage=private_storage,
        max_length=1024
    )
    firmware_type = models.IntegerField(
        "Firmware type",
        choices=create_choices_items(FirmwareTypeEnum)
    )

    class Meta:
        db_table = ADV_DEVICE_FIRMWARE_TABLE
        verbose_name = "Advanced devices firmware"

    @property
    def version(self) -> typing.Tuple[int, int, int]:
        """Three part format of version.
        """
        return get_version(self.version_content)

    @version.setter
    def version_setup(self, value: typing.Any):
        """Three part format of version.
        """
        if value:
            if isinstance(value, str):
                self.version_content = value
            elif isinstance(value, Iterable):
                self.version_content = ",".join(value)
            else:
                self.version_content = str(value)

        self.version_content = ",".join(map(str, self.version))

    def __str__(self) -> str:
        if self.firmware_type:
            firmware_type = FirmwareTypeEnum(self.firmware_type).name
        else:
            firmware_type = "unknown"

        return f"{firmware_type} {self.version}"


class DeviceStateModel(models.Model):
    """States of the devices.
    """
    objects = QueryManager()

    device = models.ForeignKey(
        DeviceModel,
        verbose_name="Device",
        related_name="state_history",
        related_query_name="state_history",
        on_delete=models.CASCADE
    )
    created = models.DateTimeField("Datetime", auto_now=True)
    state_type = models.IntegerField(
        "State type",
        choices=create_choices_items(StateTypeEnum)
    )
    attributes = JSONField("Attributes", default=dict, blank=True)
    value = models.DecimalField("Decimal value", **DEFAULT_DECIMAL_OPTIONS)
    point = PointField(
        verbose_name="Location (latitude, longitude)",
        null=True,
        default=None,
        blank=True
    )

    class Meta:
        db_table = ADV_DEVICE_STATE_TABLE
        verbose_name = "Advanced devices state"
        ordering = ["-created"]

    def __str__(self) -> str:
        return f"{self.device} {self.created} {self.state_type}"


class DeviceConfigContentModel(models.Model):
    """Content of the device configuration.
    """
    objects = QueryManager()

    organization = models.ForeignKey(
        "lock8.Organization",
        verbose_name="Organization",
        related_name="adv_device_config_list",
        related_query_name="adv_device_config_list",
        on_delete=models.CASCADE
    )
    updated = models.DateTimeField("Updated at", auto_now=True)
    device_type = models.IntegerField(
        "Device type",
        db_index=True,
        choices=create_choices_items(DeviceTypeEnum)
    )
    content = models.TextField("Content (ini)", default="")
    devices = models.ManyToManyField(
        DeviceModel,
        blank=True,
        related_name="config_records",
        db_table=ADV_DEVICE_CONFIG_DEVICES_TABLE,
    )

    class Meta:
        db_table = ADV_DEVICE_CONFIG_CONTENT_TABLE
        verbose_name = "Advanced devices config content"
        ordering = ["-updated"]

    def clean(self, *args, **kwargs):
        result = super().clean(*args, **kwargs)
        chsm, _ = clear_ini_config_content(self.content)
        if self.content and not chsm:
            raise ValidationError("Incorrect configuration format")

        return result

    def __str__(self) -> str:
        chsm, _ = clear_ini_config_content(self.content or "")
        return f"{self.updated} {chsm}"


class DataStreamSampleModel(models.Model):
    """Samples of data streams from devices.
    """
    objects = QueryManager()

    uuid = models.UUIDField(
        "pk", primary_key=True, default=uuid.uuid4, editable=False
    )
    created = models.DateTimeField("Created at client")
    updated = models.DateTimeField("Updated at", auto_now=True)
    status = models.IntegerField(
        "Status",
        default=DataStreamStatusEnum.NEW.value,
        choices=create_choices_items(DataStreamStatusEnum)
    )
    device = models.ForeignKey(
        DeviceModel,
        verbose_name="Device",
        related_name="stream_samples",
        related_query_name="stream_samples",
        on_delete=models.CASCADE
    )
    data_type = models.IntegerField(
        "Content type",
        db_index=True,
        choices=create_choices_items(DataStreamTypeEnum)
    )
    sample = models.IntegerField("Sample", default=0)
    quantum = models.FloatField("Quantum (ms)", default=0)
    index_position = JSONField("Position metadata", default=dict)
    values = ArrayField(
        models.FloatField(), verbose_name="Stream values", default=list
    )

    class Meta:
        db_table = ADV_DEVICE_DATA_STREAM_SAMPLES
        verbose_name = "Device data stream sample"
        ordering = ["-created"]

    def save(self, *args, **kwargs):
        """Create uuid primary key.
        """
        device = self.device
        device = device.serial_number if device else ""
        self.pk = create_chsum_uuid(device, self.sample, self.created)
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        device = self.device
        if device:
            device = device.serial_number

        count = 0
        if self.values:
            count = len(self.values or [])

        return f"{self.created} {device} sample {self.sample}: {count} values"
