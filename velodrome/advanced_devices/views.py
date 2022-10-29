import typing

from django.apps import apps as django_apps
from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import serializers, status, viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .const import DeviceStatusEnum, StateTypeEnum
from .models import (
    DeviceModel, DeviceStateModel, DeviceTypeEnum, DeviceTypeModel,
    FirmwareTypeEnum,
)


class DeviceModelAddSerializer(serializers.ModelSerializer):

    battery_status = serializers.SerializerMethodField()
    fluid_level = serializers.SerializerMethodField()
    model = serializers.SerializerMethodField()

    def get_battery_status(self, rec=None) -> int:
        return self.initial_data.get("battery_status") or 0

    def get_fluid_level(self, rec=None) -> int:
        return self.initial_data.get("fluid_level") or 0

    def get_model(self, rec=None) -> int:
        return self.initial_data.get("model") or ""

    class Meta:
        model = DeviceModel
        fields = [
            "serial_number",
            "model",
            "device_model",
            "battery_status",
            "fluid_level",
        ]

    def create(self, validated_data: dict):
        """Setup organization and model (type) of device.
        """
        request = self._context["request"]
        organizations = request.user.get_descendants_organizations()
        organization = organizations.first()
        validated_data["organization"] = organization
        try:
            device_model = DeviceTypeModel.objects.get(
                unique_key=self.get_model()
            )
            validated_data["device_model"] = device_model
        except DeviceTypeModel.DoesNotExist:
            raise ValidationError(
                {"model": "Unknown model of device with that unique key"}
            )

        if device_model.device_type in (
            DeviceTypeEnum.DISPENSER.value,
            DeviceTypeEnum.SOAP_DISPENSER.value,
        ):
            # #
            validated_data[
                "firmware_type"
            ] = FirmwareTypeEnum.SANITIZING_STATION
        else:
            validated_data[
                "firmware_type"
            ] = FirmwareTypeEnum.ANY_DEVICE

        cls = self.Meta.model
        sn = validated_data.get("serial_number")

        if cls.objects.filter(serial_number=sn).exists():
            raise ValidationError(
                {"serial_number": f"Device with SN '{sn}' exist"}
            )
        else:
            lock_model = django_apps.get_model("lock8", "Lock")
            lock_exist = lock_model.objects.filter(
                organization__in=organizations,
                serial_number=sn
            ).exists()

            if not lock_exist:
                raise ValidationError(
                    {
                        "serial_number": (
                            f"No record with SN '{sn}' exist in the "
                            f"table '{lock_model._meta.db_table}'"
                        )
                    }
                )

        rec = cls(status=DeviceStatusEnum.ACTIVE, **validated_data)
        rec.save()
        return rec


class DeviceModelViewSerializer(serializers.ModelSerializer):
    current_state = serializers.SerializerMethodField()

    class Meta:
        model = DeviceModel
        fields = ["id", "serial_number", "device_type", "current_state"]

    def get_current_state(self, record: DeviceModel) -> dict:
        """All values of corrent state by state names.
        """
        result = {}
        states = record.get_state_history()

        for _, state, num, attrs, latitude, longitude in states:
            field_name = state.name.lower()
            if field_name in result:
                # last state exists
                continue

            if state == StateTypeEnum.LOCATION_CHANGED:
                value = [latitude, longitude]
            elif attrs:
                value = attrs
            else:
                value = num

            result[field_name] = value

        return result


class DeviceTypesViewSerializer(serializers.ModelSerializer):
    """Base data field of DeviceTypeModel.
    """
    class Meta:
        model = DeviceTypeModel
        fields = [
            "id",
            "unique_key",
            "brand",
            "device_type",
            "name",
            "model",
            "formula",
            "amount_dispensed",
            "reservoir",
            "attributes",
        ]


class DeviceTypesViewSet(viewsets.ReadOnlyModelViewSet):
    """Dictionary of the devices models/types
    """
    model = DeviceTypeModel
    queryset = model.objects
    permission_classes = [IsAuthenticated]
    serializer_class = DeviceTypesViewSerializer
    filter_backends = [DjangoFilterBackend]
    filter_fields = ["device_type"]
    paginate_by = 2000


class CurrentStateDeviceViewSet(viewsets.ModelViewSet):
    """Devices with current status for user
    """
    model = DeviceModel
    queryset = model.objects
    permission_classes = [IsAuthenticated]
    serializer_class = DeviceModelViewSerializer
    filter_backends = [DjangoFilterBackend]
    filter_fields = ["device_type", "status"]
    paginate_by = 1000

    def get_serializer_class(self) -> typing.Type[serializers.ModelSerializer]:
        """Default class or class for REST opteration - create.
        """
        if self.action == "create":
            return DeviceModelAddSerializer
        else:
            return super().get_serializer_class()

    def get_queryset(self):
        """With organization filter by model query manager.
        """
        return self.model.objects.all().order_by("id")

    def perform_create(self, serializer: DeviceModelAddSerializer):
        """Create states.
        """
        super().perform_create(serializer)
        data = serializer.data
        device = serializer.instance
        battery_status = float(data.get("battery_status") or 0)
        fluid_level = float(data.get("fluid_level") or 0)

        if fluid_level:
            if not (0 < fluid_level <= 100):
                raise ValidationError({
                    "fluid_level": "Incorrect range of value"
                })

            DeviceStateModel(
                device=device,
                state_type=StateTypeEnum.FLUID_STATUS,
                value=fluid_level,
                attributes={"from_api": True}
            ).save()

        if battery_status:
            if not (0 < battery_status <= 100):
                raise ValidationError({
                    "fluid_level": "Incorrect range of value"
                })

            DeviceStateModel(
                device=device,
                state_type=StateTypeEnum.BATTERY_STATUS,
                value=battery_status,
                attributes={"from_api": True}
            ).save()


class RefillRequestParamSerializer(serializers.Serializer):
    """Refill request.
    """
    serial_number = serializers.CharField(
        required=True, min_length=1, max_length=64
    )
    value = serializers.FloatField(
        required=False, min_value=0, max_value=100, default=100
    )


class RefillDeviceView(GenericAPIView):
    """Fast refill a device controller.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = RefillRequestParamSerializer

    def post(self, request, **kwargs):
        """Create a new state
        """
        answer = {}
        user = request.user if hasattr(request, "user") else None
        if user and not user.is_anonymous:
            serializer = self.get_serializer(
                data=self.request.data or request.POST
            )
            serializer.is_valid(raise_exception=True)
            serial_number = serializer.data.get("serial_number")
            new_value = serializer.data.get("value")

            exists = False
            new_status = status.HTTP_200_OK
            with transaction.atomic():
                devices = DeviceModel.objects.filter(
                    serial_number=serial_number
                )
                for dev in devices.iterator():
                    exists = True
                    current_value = DeviceStateModel.objects.filter(
                        device=dev,
                        state_type=StateTypeEnum.FLUID_STATUS.value
                    ).order_by(
                        "-created"
                    ).values_list(
                        "value", flat=True
                    ).first() or 0
                    if current_value != new_value:
                        DeviceStateModel.objects.create(
                            device=dev,
                            attributes={"refill": True, "user": user.pk},
                            state_type=StateTypeEnum.FLUID_STATUS.value,
                            value=new_value
                        )
                        answer["message"] = "New state created"
                    else:
                        answer["message"] = "Current value the same"

            if not exists:
                answer["error"] = "Device does not exist"
                new_status = status.HTTP_404_NOT_FOUND
        else:
            new_status = status.HTTP_403_FORBIDDEN
            answer["error"] = "No user"

        return Response(data=answer, status=new_status)
