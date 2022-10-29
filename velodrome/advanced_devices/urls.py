from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (
    CurrentStateDeviceViewSet, DeviceTypesViewSet, RefillDeviceView,
)

router = DefaultRouter()
router.register(
    r"current-state", CurrentStateDeviceViewSet, basename="current-state"
)

router.register(
    r"model-dictionary", DeviceTypesViewSet, basename="model-dictionary"
)

urlpatterns = [
    path("refill/", RefillDeviceView.as_view(), name="device-refill"),
]

urlpatterns.extend(router.urls)
