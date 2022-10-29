from django.utils.translation import ugettext as _
from rest_framework import status
from rest_framework.exceptions import APIException


class DuplicateContentError(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _('A resource already exists.')
    default_code = 'duplicated_content'


class InternalServerError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = _('Internal Server Error.')
    default_code = 'server_error'


class SubscriptionExistsError(Exception):
    """Raised on subscribe_user when a subscription already exists."""


class SkipValidationError(Exception):
    """Used to give control to the view over validation."""
