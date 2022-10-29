import logging
import typing

from django.apps import apps as django_apps
from django.db import transaction
from rest_framework.authentication import BasicAuthentication

from .const import DJANGO_APP_NAME

logger = logging.getLogger(__name__)


class OrganizationInThreadMiddleware:
    """Setup organization for filter in current thread.
    """
    state_store: typing.Optional[dict]
    main_model_name: str = "DeviceModel"

    def __init__(self, get_response):
        self.get_response = get_response
        self.state_store = None

    def __call__(self, request):
        """Setup organization context by user.
        """
        user = request.user if hasattr(request, "user") else None
        organizations = None
        if not user:
            user = None
        elif user.is_anonymous:
            user = None
            user_auth_res = BasicAuthentication().authenticate(request)
            if user_auth_res:
                user, *_ = user_auth_res
        elif user.is_staff or user.is_superuser:
            organizations = []

        if organizations is None:
            organizations = [-1]
            if user:
                organizations = user.get_descendants_organizations()
                try:
                    with transaction.atomic():
                        if not organizations.exists():
                            organizations = [-1]
                except Exception as err:
                    logger.error(
                        "Error in organizations list for %s: %s", user, err
                    )

        if self.state_store is None:
            device_model = django_apps.get_model(
                DJANGO_APP_NAME, self.main_model_name
            )
            state = getattr(
                device_model.objects.__class__, "_state", None
            )
            if isinstance(state, dict):
                self.state_store = state
            else:
                self.state_store = {}
                logger.error(
                    f"Query manager of model '{self.main_model_name}' "
                    f"don't support organization filter"
                )

        self.state_store["organizations"] = organizations
        response = self.get_response(request)
        return response
