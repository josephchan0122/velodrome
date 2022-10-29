from collections.abc import Callable, Iterable
import logging
import re
import time
from uuid import UUID

from django.conf import settings
from django.db import connection
from django.http import HttpResponse
from django.utils.http import http_date
from raven.contrib.django.models import get_client as get_sentry_client
from rest_framework import status

import velodrome

from .const import FILTER_FIELD_ORG_LIST

logger = logging.getLogger(__name__)


class ELBHealthCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path.strip("/")
        if path == settings.ELB_HEALTH_CHECK_PATH:
            response = HttpResponse('')
            # Normally done in ConditionalGetMiddleware, but short-circuited.
            response['Content-Length'] = '0'
            response['Date'] = http_date()
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

            try:
                cursor = connection.cursor()
                cursor.execute("SELECT 'all_good'")
                if cursor.fetchone() == ('all_good',):
                    response.status_code = status.HTTP_200_OK
            except Exception as e:
                logger.warning('Exception when testing DB connection: %s', e)

            return response
        return self.get_response(request)


class VersionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['X-Noa-Version'] = velodrome.VERSION
        return response


class EC2InstanceIdMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['X-Noa-From'] = settings.EC2_INSTANCE_ID
        return response


class LogSlowRequestsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start = time.time()

        response = self.get_response(request)

        duration = time.time() - start
        if duration > settings.SENTRY_SLOW_REQUEST_DURATION_THRESHOLD:

            # After the latest Django upgrade, get_transaction_from_request
            # begins to return wrong request path. Now it adds capital Z in the
            # end of string. Probably they changed something in Django Response
            # object and authors of deprecated Raven lib haven't fixed this.
            name = get_sentry_client().get_transaction_from_request(request)
            if name != request.path and name.endswith("Z"):
                # Ugly workaround until we switch to newer Sentry lib
                name = name[:-1]

            try:
                name += ": " + request._action_name_for_sentry
            except AttributeError:
                pass

            if duration > 5.0:
                msg = 'Request for "%s" took longer than 5s: %.2f'
                fingerprint = ['duration-5']
                tag_value = round(duration)
            else:
                # Ignore some expected slow responses.
                if name in ('/api/alerts/', '/api/trips/'):
                    return response

                if duration > 1.0:
                    msg = 'Request for "%s" took longer than 1s: %.2f'
                    fingerprint = ['duration-1']
                    tag_value = round(duration)
                else:
                    msg = 'Request for "%s" took longer than 0.5s: %.2f'
                    fingerprint = ['duration-0.5']
                    tag_value = round(duration, 1)

            fingerprint += [name]

            logger.warning(msg, name, duration, extra={
                'tags': {
                    'duration': tag_value,
                },
                'fingerprint': fingerprint,
            })
        return response


class OrganizationFilterMiddleware:
    """Organizations filter middleware
    """

    get_response: Callable
    uuid_regx = re.compile(r"[\-0-9a-fA-F]{32,64}")

    def __init__(self, get_response: Callable):
        self.get_response = get_response

    def __call__(self, request):
        """Setup the organizations list filter.
        """
        user = request.user if hasattr(request, "user") else None
        if user and not user.is_anonymous:
            data = None
            if request.method == "GET":
                data = request.GET or getattr(request, "data", None)
            elif request.method == "POST":
                data = request.POST or getattr(request, "data", None)

            if data:
                values = data.get(FILTER_FIELD_ORG_LIST)
                if isinstance(values, str):
                    values = self.uuid_regx.findall(values)
                elif isinstance(values, Iterable):
                    result_values = []
                    for part in map(str, values):
                        result_values.extend(self.uuid_regx.findall(part))
                    values = result_values
                else:
                    values = []

                if values:
                    try:
                        setattr(
                            request,
                            FILTER_FIELD_ORG_LIST,
                            sorted(map(UUID, values))
                        )
                    except ValueError:
                        pass

        response = self.get_response(request)
        return response
