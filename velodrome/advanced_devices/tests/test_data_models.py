from unittest import mock
import uuid

from django.apps import apps as django_apps
from django.contrib.admin.sites import site
from django.urls import reverse
import pytest
from rest_framework import status

from velodrome.advanced_devices.const import (
    DJANGO_APP_NAME, DeviceStatusEnum, DeviceTypeEnum, FirmwareTypeEnum,
)


@pytest.fixture(autouse=True)
def device_template():
    device_model = django_apps.get_model(DJANGO_APP_NAME, "DeviceModel")

    return device_model(
        serial_number=uuid.uuid4().hex[:16],
        device_type=DeviceTypeEnum.DISPENSER,
        status=DeviceStatusEnum.ACTIVE,
        firmware_type=FirmwareTypeEnum.ANY_DEVICE
    )


@pytest.mark.django_db(databases=["default", "trackings"])
def test_organization_filter_for_requsts(
    drf_admin, device_template, settings
):
    """Test for requsts data in QuerySet filter.
    """
    device_model = django_apps.get_model(DJANGO_APP_NAME, "DeviceModel")
    meta = device_model._meta

    admin_user = drf_admin.user

    organizations = admin_user.get_descendants_organizations()
    admin_user.is_superuser = True
    admin_user.is_staff = True
    admin_user.save()

    device = device_template
    device.organization, *_ = organizations
    device.save()

    url = reverse(
        f"admin:{meta.app_label}_{meta.model_name}_change",
        args=[device.pk]
    )
    url = f"{settings.STS_BASE_URL}{url}"
    drf_admin.force_login(admin_user)

    tmp_registry = {}
    for cls_model, a_cls in site._registry.items():
        if cls_model._meta.app_label == DJANGO_APP_NAME:
            tmp_registry[cls_model] = a_cls

    with mock.patch.object(site, "_registry", tmp_registry):
        response = drf_admin.get(url)

    assert response.status_code == status.HTTP_200_OK
