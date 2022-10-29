from datetime import timedelta
import uuid

from django.apps import apps as django_apps
from django.urls import reverse
import pytest
from rest_framework import status

from velodrome.advanced_devices.const import (
    DJANGO_APP_NAME, DeviceStatusEnum, DeviceTypeEnum, FirmwareTypeEnum,
    StateTypeEnum,
)


@pytest.fixture
def device_type_common():
    """Instance of DeviceTypeModel.
    """
    model = django_apps.get_model(DJANGO_APP_NAME, "DeviceTypeModel")

    rec = model(
        brand="Noa",
        device_type=DeviceTypeEnum.DISPENSER,
        unique_key="key-001",
        name="Noa device",
        model="2021",
        formula="gel",
        amount_dispensed=0.9,
        reservoir=1100
    )
    rec.save()
    return rec


@pytest.fixture
def device_with_location(org, device_type_common):
    """Device with a location and a battery history.
    """
    device_model = django_apps.get_model(DJANGO_APP_NAME, "DeviceModel")

    device = device_model(
        organization=org,
        device_model=device_type_common,
        serial_number=uuid.uuid4().hex[:16],
        device_type=DeviceTypeEnum.DISPENSER,
        status=DeviceStatusEnum.ACTIVE,
        firmware_type=FirmwareTypeEnum.ANY_DEVICE
    )
    device.save()
    state_model = django_apps.get_model(DJANGO_APP_NAME, "DeviceStateModel")

    state = state_model(
        device=device,
        state_type=StateTypeEnum.BATTERY_STATUS,
        value=80
    )
    state.save()

    state_model(
        created=state.created - timedelta(hours=1),
        device=device,
        state_type=StateTypeEnum.BATTERY_STATUS,
        value=70
    ).save()

    state_model(
        created=state.created - timedelta(hours=1),
        device=device,
        state_type=StateTypeEnum.FLUID_STATUS,
        value=80
    ).save()

    state_model(
        created=state.created - timedelta(hours=2),
        device=device,
        state_type=StateTypeEnum.LOCATION_CHANGED,
        point="POINT(55.49154584941143 92.37684689210734)"
    ).save()

    return device


@pytest.mark.django_db(databases=["default", "trackings"])
def test_device_list(settings, drf_admin, device_with_location):
    """Test for requsts data in QuerySet filter.
    """
    device_id = device_with_location.pk
    sn = device_with_location.serial_number
    # copy device
    device_with_location.pk = device_with_location.id = None
    device_with_location.serial_number = "00000001"
    device_with_location.status = DeviceStatusEnum.OUT_OF_SERVICE
    device_with_location.save()
    user = drf_admin.user
    user.is_superuser = True
    user.save()

    url = reverse("devices-api:current-state-list")

    url = f"{settings.STS_BASE_URL}{url}"
    drf_admin.force_login(user)
    response = drf_admin.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert "results" in response.data
    assert len(response.data.get("results")) == 2

    response = drf_admin.get(url, {"status": DeviceStatusEnum.ACTIVE.value})
    assert response.status_code == status.HTTP_200_OK
    assert "results" in response.data
    assert len(response.data.get("results")) == 1

    device_data, *_ = response.data.get("results")
    assert device_data
    assert device_data == {
        "id": device_id,
        "serial_number": sn,
        "device_type": DeviceTypeEnum.DISPENSER.value,
        "current_state": {
            StateTypeEnum.LOCATION_CHANGED.name.lower(): [
                "55.49154584941143", "92.37684689210734"
            ],
            StateTypeEnum.BATTERY_STATUS.name.lower(): 80,
            StateTypeEnum.FLUID_STATUS.name.lower(): 80,
        },
    }


@pytest.mark.django_db(databases=["default", "trackings"])
def test_device_in_sub_organization(
    settings, drf_admin, device_with_location, org
):
    """Test for access to devices with not admin uesr.
    """

    user = drf_admin.user
    user.is_superuser = False
    user.is_staff = False
    user.save()

    org.pk = org.id = None
    org.name = "Copy"
    org.uuid = uuid.uuid4()
    org.save()

    device_with_location.organization = org
    device_with_location.save()

    url = reverse("devices-api:current-state-list")

    url = f"{settings.STS_BASE_URL}{url}"
    drf_admin.force_login(user)
    response = drf_admin.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert "results" in response.data
    assert len(response.data.get("results")) == 1


@pytest.mark.django_db(databases=["default", "trackings"])
def test_device_in_other_organization(
    settings, drf_admin, device_with_location, org
):
    """Test for acces to devices from other organization.
    """

    user = drf_admin.user
    user.is_superuser = False
    user.is_staff = False
    user.save()

    org.pk = org.id = None
    org.name = "Copy"
    org.tree_id = org.tree_id + 1
    org.uuid = uuid.uuid4()
    org.save()

    device_with_location.organization = org
    device_with_location.save()

    url = reverse("devices-api:current-state-list")

    url = f"{settings.STS_BASE_URL}{url}"
    drf_admin.force_login(user)
    response = drf_admin.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert "results" in response.data
    assert len(response.data.get("results")) == 0


@pytest.mark.django_db(databases=["default", "trackings"])
def test_refill_api(
    settings, drf_admin, device_with_location, org
):
    """Test API of refill.
    """

    user = drf_admin.user
    user.is_superuser = False
    user.is_staff = False
    user.save()

    device_with_location.organization = org
    device_with_location.save()

    url = reverse("devices-api:device-refill")

    url = f"{settings.STS_BASE_URL}{url}"
    drf_admin.force_login(user)
    response = drf_admin.post(
        url,
        data={
            "serial_number": device_with_location.serial_number,
            "value": 90,
        }
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.data == {"message": "New state created"}

    response = drf_admin.post(
        url,
        data={
            "serial_number": device_with_location.serial_number + "1",
            "value": 90,
        }
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.data == {"error": "Device does not exist"}

    response = drf_admin.post(
        url,
        data={
            "serial_number": device_with_location.serial_number,
            "value": -40,
        }
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data


@pytest.mark.django_db(databases=["default", "trackings"])
def test_device_create_api(
    settings,
    drf_admin,
    device_with_location,
    org,
    device_type_common,
    lock
):
    """Test API of creating the device.
    """

    user = drf_admin.user
    user.is_superuser = True
    user.is_staff = True
    user.save()

    exists_serial_number = device_with_location.serial_number
    device_with_location.organization = org
    device_with_location.save()

    url = reverse("devices-api:current-state-list")

    url = f"{settings.STS_BASE_URL}{url}"
    drf_admin.force_login(user)
    response = drf_admin.post(
        url,
        data={
            "serial_number": exists_serial_number,
            "model": device_type_common.unique_key,
            "fluid_level": 50,
            "battery_status": 100,
        }
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST

    sn = f"00{exists_serial_number}"
    lock.serial_number = sn
    lock.organization = org
    lock.save()

    response = drf_admin.post(
        url,
        data={
            "serial_number": sn,
            "model": device_type_common.unique_key,
        }
    )

    assert response.status_code == status.HTTP_201_CREATED

    response = drf_admin.post(
        url,
        data={
            "serial_number": f"11{sn}",
            "model": device_type_common.unique_key,
        }
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST

    response = drf_admin.post(
        url,
        data={
            "serial_number": f"0{exists_serial_number}",
            "model": device_type_common.unique_key,
            "fluid_level": 50,
            "battery_status": 101,
        }
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST

    response = drf_admin.post(
        url,
        data={
            "serial_number": f"0{exists_serial_number}",
            "model": exists_serial_number
        }
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
