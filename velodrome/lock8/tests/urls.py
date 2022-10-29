from django.http import HttpResponse
from django.urls import path


class TestException(Exception):
    pass


def view_exception(request):
    exc = TestException(request)
    exc.sentry_extra = {'some': {'extra': 'information'}}
    raise exc


urlpatterns = [
    path('exception', view_exception, name='exception'),
    # Used/checked in show_debug_toolbar.
    path('api-docs', lambda x: HttpResponse("api-docs-test"), name='api-docs'),
]
