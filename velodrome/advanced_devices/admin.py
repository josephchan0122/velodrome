from django.contrib import admin
from django.db.models import Q
from django.forms import BaseInlineFormSet

from .helpers import clear_ini_config_content
from .models import (
    AdvDeviceFirmwareModel, DataStreamSampleModel, DeviceConfigContentModel,
    DeviceModel, DeviceStateModel, DeviceTypeModel,
)


class DeviceStatesFormSet(BaseInlineFormSet):
    """State list form with the limits of count for each state.
    """

    IN_STATE_RECORDS_LIMIT = 8  # records of each state

    def __init__(self, *args, **kwargs):
        result = super().__init__(*args, **kwargs)
        rec_filter = {self.fk.name: kwargs["instance"]}
        queryset = kwargs["queryset"].filter(**rec_filter)
        states = queryset.values_list("state_type", flat=True).iterator()
        limit_filter = None
        limit = self.IN_STATE_RECORDS_LIMIT
        for state in states:
            state_filter = Q(
                id__in=queryset.filter(
                    state_type=state
                )[:limit].values_list("id", flat=True)
            )
            if limit_filter is None:
                limit_filter = state_filter
            else:
                limit_filter |= state_filter

        self.queryset = (
            queryset.filter(limit_filter) if limit_filter else queryset
        )
        return result


class DeviceStateInline(admin.TabularInline):
    """Table with states.
    """
    model = DeviceStateModel
    formset = DeviceStatesFormSet
    ordering = ["-created"]
    extra = 1


@admin.register(DeviceModel)
class DeviceModelAdmin(admin.ModelAdmin):
    """Admin class for DeviceModel.
    """

    list_display = (
        "id",
        "serial_number",
        "device_type",
        "device_model",
        "firmware_type",
        "firmware_version_str",
        "status",
        "display_status_name",
        "config_updated",
    )

    list_select_related = (
        "device_model",
        "organization",
    )

    list_display_links = (
        "id",
    )

    list_filter = (
        "device_type",
        "status",
        "firmware_type",
        "device_model__model",
    )

    readonly_fields = (
        "device_type",
    )

    search_fields = (
        "device_model__name",
    )

    inlines = (
        DeviceStateInline,
    )

    def get_search_results(self, request, queryset, search_term: str = ""):
        """Search by SN or model name"""
        search_term = search_term.strip()
        if search_term:
            queryset = queryset.filter(
                Q(
                    serial_number__contains=search_term
                ) | Q(
                    device_model__name__contains=search_term
                )
            )

        return queryset, False

    def changeform_view(
        self, request, object_id=None, form_url="", extra_context=None
    ):
        """Info message in title.
        """
        if not extra_context:
            extra_context = {"title": ""}
        extra_context["title"] = (
            "{} Only {} last states of each type are displayed"
        ).format(
            extra_context.get("title") or "",
            DeviceStateInline.formset.IN_STATE_RECORDS_LIMIT
        )
        return super().changeform_view(
            request,
            object_id=object_id,
            form_url=form_url,
            extra_context=extra_context
        )

    def firmware_version_str(self, record: DeviceModel) -> str:
        """Current version of firmware.
        """
        part_m, part_mi, part_p = record.firmware_version
        if part_m or part_mi or part_p:
            result = f"{part_m}.{part_mi}.{part_p}"
        else:
            result = "unknown"

        return result

    def config_updated(self, record: DeviceModel) -> str:
        """Actual datetime of configuration for the device.
        """

        dt = record.config_records.filter(
            device_type=record.device_type,
            organization=record.organization
        ).order_by("-updated").values_list(
            "updated", flat=True
        ).first()

        if not dt:
            dt = DeviceConfigContentModel.objects.filter(
                device_type=record.device_type,
                organization=record.organization
            ).order_by("-updated").values_list(
                "updated", flat=True
            ).first()

        if dt:
            return dt.isoformat()[:19]
        else:
            return ""


@admin.register(DeviceTypeModel)
class DeviceTypeModelAmin(admin.ModelAdmin):
    """Admin class for DeviceTypeModel.
    """

    list_display = (
        "unique_key",
        "brand",
        "device_type",
        "name",
        "model",
        "formula",
        "amount_dispensed",
        "percent_dispensed",
        "reservoir",
    )

    list_display_links = (
        "unique_key",
    )

    list_filter = (
        "device_type", "brand"
    )

    def change_view(self, request, object_id, extra_context=None):
        if not request.user.is_superuser:
            extra_context = extra_context or {}
            extra_context["readonly"] = True

        return super().change_view(
            request, object_id, extra_context=extra_context
        )


@admin.register(AdvDeviceFirmwareModel)
class AdvDeviceFirmwareModelAmin(admin.ModelAdmin):
    """Admin class for AdvDeviceFirmwareModel.
    """

    list_display = (
        "id",
        "version_content",
        "firmware_type",
        "binary",
    )

    list_display_links = (
        "id",
    )

    list_filter = (
        "firmware_type",
    )


@admin.register(DeviceConfigContentModel)
class DeviceConfigContentModelAmin(admin.ModelAdmin):
    """Admin class for DeviceConfigContentModel.
    """

    list_display = (
        "id",
        "updated",
        "device_type",
        "for_all_devices",
        "content_checksum",
    )

    list_display_links = (
        "id",
    )

    list_filter = (
        "device_type",
    )

    def for_all_devices(self, record: DeviceConfigContentModel) -> bool:
        """Default record for all devices.
        """
        devices = record.devices
        return (devices is None or not devices.exists())

    def content_checksum(self, record: DeviceConfigContentModel) -> str:
        """Clear content md5 hash.
        """

        chsm, _ = clear_ini_config_content(record.content or "")
        return chsm


@admin.register(DataStreamSampleModel)
class AdminDataStreamSampleModel(admin.ModelAdmin):
    """Admin class for DataStreamSampleModel
    """

    list_display = (
        "uuid",
        "data_type",
        "created",
        "updated",
        "status",
        "device",
        "stream_size",
        "sample",
    )

    list_display_links = (
        "uuid",
    )

    list_filter = (
        "data_type",
        "status",
    )

    def stream_size(self, record: DataStreamSampleModel) -> int:
        return len(record.values or [])
